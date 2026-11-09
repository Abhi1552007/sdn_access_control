#!/usr/bin/env python3
"""
D2 Mininet network: 3 switches, 8 hosts, 2 protected services.

  sudo python3 topology.py            network + Mininet CLI
  sudo python3 topology.py --test     run all test scenarios, then CLI
  sudo python3 topology.py --perf     run the performance evaluation (results/perf.json)
  add --no-cli to exit when done

                    s1 (core)
          h1 auth   h4 fileserver   h6 dbserver
            /                 \\
       s2 (dept A)          s3 (dept B)
   h2 alice  h3 guest     h5 blacklisted
   h7 admin               h8 bob / attacker
"""
import json
import os
import sys
import time
from functools import partial

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run")

HOSTS = {  # name: (last IP octet, switch)
    "h1": (1, "s1"), "h4": (4, "s1"), "h6": (6, "s1"),
    "h2": (2, "s2"), "h3": (3, "s2"), "h7": (7, "s2"),
    "h5": (5, "s3"), "h8": (8, "s3"),
}
N_LOAD = 30   # extra client hosts c1..c30 used only by --perf (scalability test)


class D2Topo(Topo):
    def build(self, load_hosts=0):
        for sw in ("s1", "s2", "s3"):
            self.addSwitch(sw, protocols="OpenFlow13", failMode="secure")
        self.addLink("s2", "s1")
        self.addLink("s3", "s1")
        for name, (octet, sw) in HOSTS.items():
            self.addLink(self.addHost(name, ip=f"10.0.0.{octet}/24"), sw)
        for i in range(1, load_hosts + 1):
            self.addLink(self.addHost(f"c{i}", ip=f"10.0.0.{100 + i}/24"), "s2" if i % 2 else "s3")


def write_topology_json(net):
    """Record where every host is attached so the controller can build path and anti-spoofing rules."""
    hosts, links = {}, []
    for link in net.links:
        a, b = link.intf1, link.intf2
        na, nb = a.node, b.node
        if na.name.startswith("s") and nb.name.startswith("s"):
            links.append({"a": na.name, "a_port": na.ports[a], "b": nb.name, "b_port": nb.ports[b]})
            continue
        h, hi, s, si = (na, a, nb, b) if not na.name.startswith("s") else (nb, b, na, a)
        hosts[h.name] = {"ip": h.IP(), "mac": h.MAC(), "switch": s.name, "port": s.ports[si]}
    os.makedirs(RUN, exist_ok=True)
    with open(os.path.join(RUN, "topology.json"), "w") as f:
        json.dump({"switches": [s.name for s in net.switches], "hosts": hosts, "links": links}, f, indent=1)


def start_services(net):
    h1, h4, h6 = net.get("h1"), net.get("h4"), net.get("h6")
    h1.cmd(f"cd {HERE} && python3 -u auth_server.py > logs/auth_server.out 2>&1 &")
    h4.cmd(f"cd {HERE} && python3 -u protected_service.py --name fileserver --port 9000 > logs/fileserver.out 2>&1 &")
    h6.cmd(f"cd {HERE} && python3 -u protected_service.py --name dbserver --port 9100 > logs/dbserver.out 2>&1 &")
    for h in (h4, h6):
        h.cmd("iperf -s -p 5001 > /dev/null 2>&1 &")
    for _ in range(50):     # wait until the auth server is listening
        if "5000" in h1.cmd("ss -ltn"):
            break
        time.sleep(0.2)
    time.sleep(1)


def stop_services(net):
    for h in ("h1", "h4", "h6"):
        net.get(h).cmd("pkill -f auth_server.py; pkill -f protected_service.py; pkill iperf")


def flows(net):
    out = ""
    for sw in ("s1", "s2", "s3"):
        out += f"--- {sw} ---\n" + net.get("h1").cmd(f"ovs-ofctl -O OpenFlow13 dump-flows {sw} --no-stats")
    return out


# --------------------------------------------------------------------------- scenarios
def run(h, cmd):
    info(f"\n{h.name}$ {cmd}\n")
    out = h.cmd(f"cd {HERE} && {cmd}")
    info(out)
    return out


def banner(t):
    info(f"\n{'=' * 70}\n {t}\n{'=' * 70}\n")


def iperf(h, ip, secs=4):
    out = h.cmd(f"iperf -c {ip} -p 5001 -t {secs} -y C 2>/dev/null").strip().splitlines()
    try:
        return int(out[-1].split(",")[-1]) / 1e6
    except (IndexError, ValueError):
        return 0.0


def scenarios(net):
    g = net.get
    h1, h2, h3, h5, h7, h8 = g("h1"), g("h2"), g("h3"), g("h5"), g("h7"), g("h8")
    C = "python3 auth_client.py"
    A = "python3 admin_client.py admin admin123"

    banner("1. Default deny: unauthenticated hosts reach no protected service")
    run(h2, f"{C} access --service both")

    banner("2. Role rules: staff (alice) gets fileserver only, not dbserver")
    run(h2, f"{C} login alice alice123 --service both --hold 0")

    banner("3. Admin role gets both services")
    run(h7, f"{C} login admin admin123 --service both --hold 0")

    banner("4. Restrict: guest is rate-limited by an OpenFlow meter (iperf, 4 s each)")
    h2.cmd(f"cd {HERE} && {C} login alice alice123 --hold 25 > /tmp/s4a.txt 2>&1 &")
    h3.cmd(f"cd {HERE} && {C} login guest guest123 --hold 25 > /tmp/s4g.txt 2>&1 &")
    time.sleep(2)
    staff, guest = iperf(h2, "10.0.0.4"), iperf(h3, "10.0.0.4")
    info(f"\n   staff (alice, full speed)      : {staff:8.2f} Mbit/s\n"
         f"   guest (meter caps at 1 Mbit/s) : {guest:8.2f} Mbit/s\n")
    info("\nEdge switch s2 rules (note in_port + MAC binding and meter on guest):\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s2 --no-stats | grep priority=200"))
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-meters s2"))

    banner("5. Anti-spoofing: h3 fakes alice's IP while alice is logged in")
    h3.cmd("ip addr add 10.0.0.2/32 dev h3-eth0")
    run(h3, f"{C} access --src 10.0.0.2")
    h3.cmd("ip addr del 10.0.0.2/32 dev h3-eth0")
    info("   -> blocked: the grant on s2 matches alice's switch port and MAC, not just her IP\n")
    time.sleep(24)  # let the two background sessions from scenario 4 finish

    banner("6. Blacklisted host h5 is denied even with valid credentials")
    run(h5, f"{C} login alice alice123 --hold 0")

    banner("7. Time-based rule: contractor carol may log in only 09:00-18:00")
    info(f"   current hour: {time.strftime('%H:%M')}\n")
    run(h8, f"{C} login carol carol123 --service db --hold 0")

    banner("8. Brute force: 3 wrong passwords -> SDN blocks h8 everywhere for 20 s")
    for _ in range(3):
        run(h8, f"{C} login bob wrong --hold 0")
    time.sleep(1)
    info("\nh8 ping auth server while blocked:\n" + h8.cmd("ping -c 2 -W 1 10.0.0.1 | tail -2"))
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s3 --no-stats | grep priority=400"))
    info("   waiting for the block to expire (hard_timeout)...\n")
    time.sleep(21)
    run(h8, f"{C} login bob bob123 --hold 0")

    banner("9. Admin kicks a user mid-session -> access revoked immediately")
    h2.cmd(f"cd {HERE} && {C} login alice alice123 --hold 22 > /tmp/s9.txt 2>&1 &")
    time.sleep(3)
    run(h7, f"{A} sessions")
    run(h7, f"{A} kick alice")
    time.sleep(21)
    info("\n--- alice's client output ---\n" + h2.cmd("cat /tmp/s9.txt"))

    banner("10. Live policy reload: give guests the dbserver without restarting")
    h3.cmd(f"cd {HERE} && {C} login guest guest123 --hold 20 > /dev/null 2>&1 &")
    time.sleep(3)
    run(h3, f'{C} access --service db --label "guest logged in, before reload"')
    policy = os.path.join(HERE, "policy.json")
    original = open(policy).read()
    p = json.loads(original)
    p["roles"]["guest"]["services"].append("dbserver")
    open(policy, "w").write(json.dumps(p, indent=2))
    run(h7, f"{A} reload")
    run(h3, f'{C} access --service db --label "after reload: guests now allowed dbserver"')
    open(policy, "w").write(original)
    run(h7, f"{A} reload")
    run(h3, f'{C} access --service db --label "after restoring the original policy"')
    time.sleep(16)

    banner("11. Auth server crash: access survives, session is restored after restart")
    h2.cmd(f"cd {HERE} && {C} login alice alice123 --hold 32 > /tmp/s11.txt 2>&1 &")
    time.sleep(3)
    info("   killing auth server (kill -9)...\n")
    h1.cmd("pkill -9 -f auth_server.py")
    time.sleep(1)
    run(h2, f'{C} access --label "alice logged in, auth server DOWN"')
    info("   restarting auth server...\n")
    h1.cmd(f"cd {HERE} && python3 -u auth_server.py >> logs/auth_server.out 2>&1 &")
    time.sleep(3)
    run(h2, f"{C} status")
    time.sleep(28)
    info("\n--- alice's client output ---\n" + h2.cmd("cat /tmp/s11.txt"))
    info(f"   grant rules carry hard_timeout={60 + 10}s and are refreshed by heartbeats,\n"
         "   so if the server stayed down they would expire on their own (fail closed).\n")

    banner("12. Concurrency: alice (h2), guest (h3), admin (h7), bob (h8) at once")
    for h, u in ((h2, "alice"), (h3, "guest"), (h7, "admin"), (h8, "bob")):
        h.cmd(f"cd {HERE} && {C} login {u} {u}123 --service both --hold 6 > /tmp/c_{h.name}.txt 2>&1 &")
    time.sleep(3)
    run(h2, f"{C} status")
    info("\nFlow tables while all four are logged in:\n" + flows(net))
    time.sleep(12)
    for h in (h2, h3, h7, h8):
        info(f"\n--- {h.name} ---\n" + h.cmd(f"cat /tmp/c_{h.name}.txt"))

    banner("Done. Logs: logs/auth.log, logs/access.log")
    info("Timeout demo (~70 s):\n"
         f"  mininet> h2 cd {HERE} && python3 auth_client.py login alice alice123 --no-heartbeat --hold 70\n")


def main():
    setLogLevel("info")
    test, perf = "--test" in sys.argv, "--perf" in sys.argv
    userspace = "--userspace" in sys.argv          # for machines without the OVS kernel module
    os.system("mn -c > /dev/null 2>&1")
    if os.path.exists(os.path.join(RUN, "sessions.json")):
        os.remove(os.path.join(RUN, "sessions.json"))
    switch = partial(OVSSwitch, datapath="user") if userspace else OVSSwitch
    net = Mininet(topo=D2Topo(load_hosts=N_LOAD if perf else 0), switch=switch,
                  controller=None, autoSetMacs=True, waitConnected=False)
    net.start()
    if userspace:   # userspace datapath needs TCP checksum offload off on the hosts
        for h in net.hosts:
            for intf in h.intfList():
                h.cmd(f"ethtool -K {intf} tx off > /dev/null 2>&1")
    write_topology_json(net)
    start_services(net)
    info("*** Auth server on h1:5000, fileserver on h4:9000, dbserver on h6:9100\n")
    info(flows(net))

    if test:
        scenarios(net)
    if perf:
        import perf_test
        perf_test.run(net, HERE)

    if "--no-cli" not in sys.argv:
        CLI(net)
    stop_services(net)
    net.stop()


if __name__ == "__main__":
    main()
