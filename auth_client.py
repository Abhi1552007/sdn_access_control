"""
TCP authentication client (D2) - runs on client hosts (h2, h3, h7, h8 ...).

  auth_client.py access [--service db] [--src IP] [--label TEXT]   try to reach a service
  auth_client.py login USER PASS [--hold N] [--service file|db|both] [--no-heartbeat]
  auth_client.py status                                 list active sessions

--src binds the connection to a given source IP (used for the spoofing test).
Heartbeats reconnect automatically if the auth server restarts.
"""
import argparse
import json
import socket
import sys
import threading
import time

AUTH = ("10.0.0.1", 5000)
SERVICES = {"file": ("10.0.0.4", 9000), "db": ("10.0.0.6", 9100)}


class AuthConnection:
    def __init__(self):
        self.lock = threading.Lock()
        self._connect()

    def _connect(self):
        self.sock = socket.create_connection(AUTH, timeout=5)
        self.f = self.sock.makefile("rw")

    def send(self, obj, retry=True):
        with self.lock:
            try:
                self.f.write(json.dumps(obj) + "\n")
                self.f.flush()
                line = self.f.readline()
                if not line:
                    raise ConnectionError("server closed connection")
                return json.loads(line)
            except (OSError, ConnectionError, ValueError):
                if not retry:
                    raise
                self.sock.close()
                self._connect()          # auth server restarted: reconnect once and resend
                self.f.write(json.dumps(obj) + "\n")
                self.f.flush()
                return json.loads(self.f.readline())

    def close(self):
        self.sock.close()


def try_service(name="file", label="", src=None, timeout=3):
    host, port = SERVICES[name]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if src:
            s.bind((src, 0))
        with s:
            s.connect((host, port))
            greeting = s.recv(1024).decode().strip()
            s.sendall(b"GET report.txt\n")
            reply = s.recv(1024).decode().strip()
        print(f"[ALLOWED]{label} {name}: {greeting} | {reply}", flush=True)
        return True
    except OSError:
        print(f"[BLOCKED]{label} {name}: could not reach {host}:{port}", flush=True)
        return False


def services_for(arg):
    return ["file", "db"] if arg == "both" else [arg]


def cmd_login(a):
    conn = AuthConnection()
    r = conn.send({"cmd": "login", "user": a.user, "password": a.password})
    print("login ->", r, flush=True)
    svcs = services_for(a.service)
    if r.get("status") != "ok":
        conn.close()
        for s in svcs:
            try_service(s, " (after failed login)")
        return

    token = r["token"]
    time.sleep(0.5)
    for s in svcs:
        try_service(s, " (after login)")

    stop = threading.Event()
    if not a.no_heartbeat:
        def beat():
            while not stop.wait(r["timeout"] / 3):
                try:
                    hb = conn.send({"cmd": "heartbeat", "token": token})
                    if hb.get("status") != "ok":
                        print("heartbeat ->", hb, flush=True)
                except OSError as e:
                    print("heartbeat failed (auth server down?):", e, flush=True)
        threading.Thread(target=beat, daemon=True).start()
    else:
        print(f"heartbeats OFF: session should expire after ~{r['timeout']}s", flush=True)

    start, end = time.time(), time.time() + a.hold
    while time.time() < end:
        time.sleep(min(10, max(0, end - time.time())))
        if time.time() < end:
            for s in svcs:
                try_service(s, f" (t+{int(time.time() - start)}s)")

    stop.set()
    if not a.no_heartbeat:
        try:
            print("logout ->", conn.send({"cmd": "logout", "token": token}), flush=True)
        except OSError as e:
            print("logout failed:", e, flush=True)
        time.sleep(0.5)
    for s in svcs:
        try_service(s, " (after logout/expiry)")
    conn.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    ac = sub.add_parser("access")
    ac.add_argument("--service", default="file", choices=["file", "db", "both"])
    ac.add_argument("--src")
    ac.add_argument("--label", default="no login")
    sub.add_parser("status")
    lp = sub.add_parser("login")
    lp.add_argument("user")
    lp.add_argument("password")
    lp.add_argument("--hold", type=int, default=5)
    lp.add_argument("--service", default="file", choices=["file", "db", "both"])
    lp.add_argument("--no-heartbeat", action="store_true")
    a = p.parse_args()

    if a.cmd == "access":
        for s in services_for(a.service):
            try_service(s, f" (spoofed src {a.src})" if a.src else f" ({a.label})", src=a.src)
    elif a.cmd == "status":
        c = AuthConnection()
        print(json.dumps(c.send({"cmd": "status"}), indent=2))
        c.close()
    else:
        cmd_login(a)


if __name__ == "__main__":
    sys.exit(main())
