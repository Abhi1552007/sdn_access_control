"""
TCP authentication server (runs on h1, 10.0.0.1:5000).

Protocol: one JSON object per line.
  -> {"cmd": "login", "user": "alice", "password": "alice123"}
  <- {"status": "ok", "token": "...", "timeout": 60, "granted": ["fileserver"]}
  -> {"cmd": "heartbeat", "token": "..."}      keeps the session alive
  -> {"cmd": "logout",    "token": "..."}
  -> {"cmd": "status"}                         lists active sessions

Each client connection is handled in its own thread, so many users can log in at once.
A background thread expires sessions that stop sending heartbeats and revokes their SDN rules.
"""
import socket
import threading
import json
import time
import hashlib
import hmac
import secrets
import logging
import os

from sdn_controller import SDNController

HERE = os.path.dirname(os.path.abspath(__file__))
HOST, PORT = "0.0.0.0", 5000

os.makedirs(os.path.join(HERE, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    handlers=[logging.FileHandler(os.path.join(HERE, "logs", "auth.log")), logging.StreamHandler()],
)
log = logging.getLogger("auth")

with open(os.path.join(HERE, "users.json")) as f:
    USERS = json.load(f)
with open(os.path.join(HERE, "policy.json")) as f:
    POLICY = json.load(f)

SERVICES = POLICY["protected_services"]
TIMEOUT = POLICY["session_timeout_sec"]
MAX_FAILS = POLICY["max_failed_attempts"]

sdn = SDNController(protected_ips=sorted({s["ip"] for s in SERVICES.values()}))

sessions = {}          # token -> {user, ip, cookie, expires, services}
failed = {}            # ip -> count of failed attempts
state_lock = threading.Lock()
next_cookie = [0x1000]


def check_password(user, password):
    rec = USERS.get(user)
    if not rec:
        return False
    digest = hashlib.sha256((rec["salt"] + password).encode()).hexdigest()
    return hmac.compare_digest(digest, rec["password_sha256"])


def end_session(token, reason):
    with state_lock:
        s = sessions.pop(token, None)
    if s:
        sdn.revoke(s["cookie"])
        log.info("SESSION END user=%s ip=%s reason=%s", s["user"], s["ip"], reason)


def handle_login(req, ip):
    user, pw = req.get("user", ""), req.get("password", "")

    if ip in POLICY["host_deny"]:
        log.warning("DENY host-blacklisted ip=%s user=%s", ip, user)
        return {"status": "denied", "reason": "host is blacklisted"}

    with state_lock:
        if failed.get(ip, 0) >= MAX_FAILS:
            log.warning("DENY locked-out ip=%s user=%s", ip, user)
            return {"status": "denied", "reason": "too many failed attempts"}

    if not check_password(user, pw):
        with state_lock:
            failed[ip] = failed.get(ip, 0) + 1
            n = failed[ip]
        log.warning("LOGIN FAIL user=%s ip=%s attempt=%d/%d", user, ip, n, MAX_FAILS)
        return {"status": "fail", "reason": "invalid credentials", "attempts_left": MAX_FAILS - n}

    role = USERS[user]["role"]
    allowed = POLICY["role_allow"].get(role, [])

    # one session per host: replace an old one if present
    with state_lock:
        old = [t for t, s in sessions.items() if s["ip"] == ip]
    for t in old:
        end_session(t, "replaced by new login")

    with state_lock:
        failed.pop(ip, None)
        token = secrets.token_hex(16)
        cookie = next_cookie[0]
        next_cookie[0] += 1
        sessions[token] = {"user": user, "ip": ip, "cookie": cookie,
                           "expires": time.time() + TIMEOUT, "services": allowed}

    for name in allowed:
        svc = SERVICES[name]
        sdn.grant(cookie, ip, svc["ip"], svc["port"])

    log.info("LOGIN OK user=%s role=%s ip=%s granted=%s", user, role, ip, allowed)
    return {"status": "ok", "token": token, "timeout": TIMEOUT, "role": role, "granted": allowed}


def handle_request(req, ip):
    cmd = req.get("cmd")
    if cmd == "login":
        return handle_login(req, ip)

    if cmd == "status":
        with state_lock:
            return {"status": "ok", "sessions": [
                {"user": s["user"], "ip": s["ip"], "expires_in": int(s["expires"] - time.time())}
                for s in sessions.values()]}

    token = req.get("token", "")
    with state_lock:
        s = sessions.get(token)
        valid = s is not None and s["ip"] == ip
        if valid and cmd == "heartbeat":
            s["expires"] = time.time() + TIMEOUT
    if not valid:
        return {"status": "fail", "reason": "invalid or expired session"}

    if cmd == "heartbeat":
        return {"status": "ok", "timeout": TIMEOUT}
    if cmd == "logout":
        end_session(token, "logout")
        return {"status": "ok"}
    return {"status": "fail", "reason": "unknown command"}


def client_thread(conn, addr):
    ip = addr[0]
    log.info("CONNECT %s:%s", ip, addr[1])
    try:
        with conn, conn.makefile("rw") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    resp = handle_request(json.loads(line), ip)
                except json.JSONDecodeError:
                    resp = {"status": "fail", "reason": "bad json"}
                f.write(json.dumps(resp) + "\n")
                f.flush()
    except (ConnectionResetError, BrokenPipeError):
        pass
    log.info("DISCONNECT %s:%s", ip, addr[1])


def reaper():
    """Expire sessions whose heartbeat stopped, and revoke their network access."""
    while True:
        time.sleep(2)
        now = time.time()
        with state_lock:
            expired = [t for t, s in sessions.items() if s["expires"] < now]
        for t in expired:
            end_session(t, "timeout")


def main():
    sdn.install_base_policy(POLICY["host_deny"])
    threading.Thread(target=reaper, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    log.info("Auth server listening on %s:%d (timeout=%ss)", HOST, PORT, TIMEOUT)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
