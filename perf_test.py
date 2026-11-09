"""
Performance evaluation (called by: sudo python3 topology.py --perf).

Measures and writes results/perf.json:
  1. latency     - login time, login -> first allowed packet, logout -> first dropped packet
  2. scalability - access latency when 1..30 clients log in at the same moment
  3. throughput  - iperf to the fileserver for admin, staff, guest (rate-limited), unauthenticated
  4. comparison  - the same network with no SDN access control (all traffic allowed)
Then run: python3 plot_results.py
"""
import json
import os
import statistics
import time

from mininet.log import info

TRIALS = 15
LOAD_STEPS = [1, 5, 10, 20, 30]


def jrun(h, here, args):
    out = h.cmd(f"cd {here} && python3 perf_client.py {args}").strip().splitlines()
    try:
        return json.loads(out[-1])
    except (IndexError, ValueError):
        return {"error": out}


def summary(values):
    values = sorted(values)
    return {"mean": statistics.mean(values), "median": statistics.median(values),
            "p95": values[min(len(values) - 1, int(0.95 * len(values)))],
            "min": values[0], "max": values[-1], "n": len(values)}


def iperf(h, ip="10.0.0.4", secs=5):
    out = h.cmd(f"iperf -c {ip} -p 5001 -t {secs} -y C 2>/dev/null").strip().splitlines()
    try:
        return int(out[-1].split(",")[-1]) / 1e6
    except (IndexError, ValueError):
        return 0.0


def login_bg(h, here, user, pw, hold):
    h.cmd(f"cd {here} && python3 auth_client.py login {user} {pw} --hold {hold} > /dev/null 2>&1 &")


def run(net, here):
    g = net.get
    res = {}
    os.makedirs(os.path.join(here, "results"), exist_ok=True)

    # 1. latency ---------------------------------------------------------------
    info(f"\n*** [perf] latency: {TRIALS} login/logout cycles from h2\n")
    rows = []
    for _ in range(TRIALS):
        r = jrun(g("h2"), here, "latency alice alice123")
        if "error" not in r:
            rows.append(r)
        time.sleep(0.2)
    res["latency"] = {k: summary([r[k] for r in rows]) for k in ("auth_ms", "access_ms", "revoke_ms")}
    res["latency"]["raw"] = rows
    for k in ("auth_ms", "access_ms", "revoke_ms"):
        info(f"    {k:10s} mean {res['latency'][k]['mean']:7.1f} ms   p95 {res['latency'][k]['p95']:7.1f} ms\n")

    # 2. scalability -----------------------------------------------------------
    res["scalability"] = []
    for n in LOAD_STEPS:
        info(f"*** [perf] scalability: {n} clients log in simultaneously\n")
        hosts = [g(f"c{i}") for i in range(1, n + 1)]
        for h in hosts:
            h.cmd(f"cd {here} && python3 perf_client.py latency alice alice123 > /tmp/perf_{h.name}.json 2>&1 &")
        time.sleep(1)
        deadline = time.time() + 60
        while time.time() < deadline and any(h.cmd("jobs -r").strip() for h in hosts):
            time.sleep(0.5)
        vals, errors = [], 0
        for h in hosts:
            try:
                r = json.loads(h.cmd(f"cat /tmp/perf_{h.name}.json").strip().splitlines()[-1])
                vals.append(r["access_ms"])
            except (IndexError, ValueError, KeyError):
                errors += 1
        row = {"clients": n, "errors": errors, **(summary(vals) if vals else {})}
        res["scalability"].append(row)
        info(f"    {n:3d} clients: mean access {row.get('mean', 0):7.1f} ms, max {row.get('max', 0):7.1f} ms, "
             f"errors {errors}\n")
        time.sleep(1)

    # 3. throughput per role ---------------------------------------------------
    info("*** [perf] throughput (iperf 5 s to fileserver)\n")
    tp = {}
    for label, h, user in (("admin", "h7", "admin"), ("staff", "h2", "alice"), ("guest", "h3", "guest")):
        login_bg(g(h), here, user, f"{user}123", 12)
        time.sleep(1.5)
        tp[label] = iperf(g(h))
        time.sleep(7)
    tp["unauthenticated"] = iperf(g("h8"), secs=3)
    res["throughput_mbps"] = tp
    for k, v in tp.items():
        info(f"    {k:16s} {v:9.2f} Mbit/s\n")

    # 4. comparison: no SDN access control --------------------------------------
    info("*** [perf] baseline: same network, no SDN access control\n")
    g("h1").cmd("pkill -f auth_server.py")
    time.sleep(0.5)
    for sw in ("s1", "s2", "s3"):
        g("h1").cmd(f"ovs-ofctl -O OpenFlow13 del-flows {sw}; ovs-ofctl -O OpenFlow13 del-meters {sw}; "
                    f"ovs-ofctl -O OpenFlow13 add-flow {sw} priority=0,actions=normal")
    conn = [jrun(g("h2"), here, "connect")["connect_ms"] for _ in range(TRIALS)]
    res["baseline"] = {"connect_ms": summary(conn), "throughput_mbps": iperf(g("h2")),
                       "unauthenticated_throughput_mbps": iperf(g("h8"), secs=3)}
    info(f"    no-SDN connect {res['baseline']['connect_ms']['mean']:.1f} ms, "
         f"throughput {res['baseline']['throughput_mbps']:.2f} Mbit/s, "
         f"unauthenticated host gets {res['baseline']['unauthenticated_throughput_mbps']:.2f} Mbit/s\n")

    # restore the SDN-controlled network
    g("h1").cmd(f"cd {here} && python3 -u auth_server.py >> logs/auth_server.out 2>&1 &")
    time.sleep(2)

    path = os.path.join(here, "results", "perf.json")
    with open(path, "w") as f:
        json.dump(res, f, indent=1)
    info(f"*** [perf] saved {path}. Make graphs with: python3 plot_results.py\n")
