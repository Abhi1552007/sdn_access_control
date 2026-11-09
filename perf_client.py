"""
Measurement client used by perf_test.py (runs on a Mininet host, prints one JSON line).

  perf_client.py latency USER PASS     login -> access, logout -> revoke timings (ms)
  perf_client.py connect               time to open a TCP connection to the fileserver, no login (ms)
"""
import json
import socket
import sys
import time

AUTH = ("10.0.0.1", 5000)
FILE = ("10.0.0.4", 9000)
PROBE_TIMEOUT = 0.05


def reachable(timeout=PROBE_TIMEOUT):
    try:
        with socket.create_connection(FILE, timeout=timeout):
            return True
    except OSError:
        return False


def latency(user, pw):
    s = socket.create_connection(AUTH, timeout=10)
    f = s.makefile("rw")

    def send(o):
        f.write(json.dumps(o) + "\n")
        f.flush()
        return json.loads(f.readline())

    t0 = time.perf_counter()
    r = send({"cmd": "login", "user": user, "password": pw})
    t_auth = time.perf_counter()
    if r.get("status") != "ok":
        return {"error": r}
    while not reachable():                 # first moment the SDN rule lets traffic through
        if time.perf_counter() - t0 > 10:
            return {"error": "never reachable"}
    t_access = time.perf_counter()

    t_lo = time.perf_counter()
    send({"cmd": "logout", "token": r["token"]})
    while True:                            # first probe that is dropped after logout
        t_probe = time.perf_counter()
        if not reachable():
            break
        if t_probe - t_lo > 10:
            return {"error": "never revoked"}
    s.close()
    return {"auth_ms": (t_auth - t0) * 1e3, "access_ms": (t_access - t0) * 1e3,
            "revoke_ms": (t_probe - t_lo) * 1e3}


def connect():
    t0 = time.perf_counter()
    ok = reachable(timeout=2)
    return {"connect_ms": (time.perf_counter() - t0) * 1e3, "ok": ok}


if __name__ == "__main__":
    if sys.argv[1] == "latency":
        print(json.dumps(latency(sys.argv[2], sys.argv[3])))
    else:
        print(json.dumps(connect()))
