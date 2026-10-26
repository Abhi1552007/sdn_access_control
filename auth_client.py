"""
TCP authentication client (runs on h2, h3, h5 ...).

Usage (inside Mininet, e.g. "h2 python3 auth_client.py ..."):
  auth_client.py access                         try the protected service without logging in
  auth_client.py login USER PASS [--hold N]     log in, use the service, stay logged in N seconds, log out
  auth_client.py login USER PASS --no-heartbeat log in and stop heartbeats (shows session timeout)
  auth_client.py status                         list active sessions on the auth server
"""
import socket
import json
import sys
import time
import threading
import argparse

AUTH = ("10.0.0.1", 5000)
SERVICE = ("10.0.0.4", 9000)


class AuthConnection:
    def __init__(self):
        self.sock = socket.create_connection(AUTH, timeout=5)
        self.f = self.sock.makefile("rw")
        self.lock = threading.Lock()

    def send(self, obj):
        with self.lock:
            self.f.write(json.dumps(obj) + "\n")
            self.f.flush()
            return json.loads(self.f.readline())

    def close(self):
        self.sock.close()


def try_service(label=""):
    try:
        with socket.create_connection(SERVICE, timeout=3) as s:
            greeting = s.recv(1024).decode().strip()
            s.sendall(b"GET report.txt\n")
            reply = s.recv(1024).decode().strip()
            print(f"[ALLOWED]{label} {greeting} | {reply}")
            return True
    except (socket.timeout, OSError):
        print(f"[BLOCKED]{label} could not reach protected service {SERVICE[0]}:{SERVICE[1]}")
        return False


def cmd_login(a):
    conn = AuthConnection()
    r = conn.send({"cmd": "login", "user": a.user, "password": a.password})
    print("login ->", r)
    if r.get("status") != "ok":
        conn.close()
        try_service(" (after failed login)")
        return

    token = r["token"]
    time.sleep(0.5)  # give the switch a moment to install the rule
    try_service(" (after login)")

    stop = threading.Event()
    if not a.no_heartbeat:
        def beat():
            while not stop.wait(r["timeout"] / 3):
                conn.send({"cmd": "heartbeat", "token": token})
        threading.Thread(target=beat, daemon=True).start()
    else:
        print(f"heartbeats OFF: session should expire after ~{r['timeout']}s")

    end = time.time() + a.hold
    while time.time() < end:
        time.sleep(min(10, max(0, end - time.time())))
        if time.time() < end:
            try_service(f" (t+{int(a.hold - (end - time.time()))}s)")

    stop.set()
    if not a.no_heartbeat:
        print("logout ->", conn.send({"cmd": "logout", "token": token}))
        time.sleep(0.5)
    try_service(" (after logout/expiry)")
    conn.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("access")
    sub.add_parser("status")
    lp = sub.add_parser("login")
    lp.add_argument("user")
    lp.add_argument("password")
    lp.add_argument("--hold", type=int, default=5, help="seconds to stay logged in")
    lp.add_argument("--no-heartbeat", action="store_true")
    a = p.parse_args()

    if a.cmd == "access":
        try_service(" (no login)")
    elif a.cmd == "status":
        c = AuthConnection()
        print(json.dumps(c.send({"cmd": "status"}), indent=2))
        c.close()
    else:
        cmd_login(a)


if __name__ == "__main__":
    sys.exit(main())
