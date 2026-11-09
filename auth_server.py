"""
TCP authentication server (D2) - runs on h1, 10.0.0.1:5000.

Protocol: one JSON object per line over TCP.
  {"cmd": "login", "user": "alice", "password": "alice123"}
  {"cmd": "heartbeat", "token": "..."}       keeps the session (and its SDN rules) alive
  {"cmd": "logout", "token": "..."}
  {"cmd": "status"}                           active sessions
  {"cmd": "admin", "token": "<admin token>", "action": "...", ...}
      actions: sessions | kick (user) | block (ip, seconds) | unblock (ip) | reload | flows

Features
  - one thread per client connection (concurrent users)
  - salted SHA-256 passwords (users.json), roles and policies (policy.json)
  - per-role services, bandwidth limits and allowed hours
  - session timeout via heartbeats; grants are refreshed on each heartbeat
  - brute force: too many failures -> the SDN controller blocks the host for a while
  - admin actions at runtime, including live policy reload
  - sessions are saved to run/sessions.json and restored after a crash/restart
"""
import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time

from sdn_controller import SDNController

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run")
LOGS = os.path.join(HERE, "logs")
os.makedirs(RUN, exist_ok=True)
os.makedirs(LOGS, exist_ok=True)
SESSIONS_FILE = os.path.join(RUN, "sessions.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    handlers=[logging.FileHandler(os.path.join(LOGS, "auth.log")), logging.StreamHandler()],
)
log = logging.getLogger("auth")

AUTH_IP, PORT = "10.0.0.1", 5000

state_lock = threading.Lock()
sessions = {}      # token -> session dict
failed = {}        # ip -> failed attempts
blocked = {}       # ip -> unblock time
cfg = {}           # "users", "policy"
next_cookie = [0x1000]


# ------------------------------------------------------------------- config
def load_config():
    with open(os.path.join(HERE, "users.json")) as f:
        users = json.load(f)
    with open(os.path.join(HERE, "policy.json")) as f:
        policy = json.load(f)
    cfg["users"], cfg["policy"] = users, policy


def P():
    return cfg["policy"]


def protected_ips():
    return {s["ip"] for s in P()["services"].values()}


def role_rules(role):
    return P()["roles"].get(role, {"services": []})


def within_hours(role, now=None):
    start, end = role_rules(role).get("hours", [0, 24])
    h = (now or datetime.datetime.now()).hour
    return start <= h < end


def hb_timeout():
    return P()["session_timeout_sec"] + 10   # grant rules die on their own 10 s after a missed timeout


sdn = None


# ------------------------------------------------------------- persistence
def save_sessions():
    with state_lock:
        data = list(sessions.values())
    tmp = SESSIONS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, SESSIONS_FILE)


def apply_grants(s, refresh=False):
    rules = role_rules(s["role"])
    rate = rules.get("rate_kbps", 0)
    for name in s["services"]:
        svc = P()["services"][name]
        fn = sdn.refresh if refresh else sdn.grant
        fn(s["cookie"], s["ip"], svc["ip"], svc["ports"], rate, hb_timeout())


def restore_sessions():
    if not os.path.exists(SESSIONS_FILE):
        return
    try:
        with open(SESSIONS_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    now = time.time()
    for s in data:
        if s["expires"] > now and s["user"] in cfg["users"]:
            sessions[s["token"]] = s
            next_cookie[0] = max(next_cookie[0], s["cookie"] + 1)
            apply_grants(s)
            log.info("RESTORED session user=%s ip=%s (expires in %ds)", s["user"], s["ip"], s["expires"] - now)
    save_sessions()


# ----------------------------------------------------------------- sessions
def check_password(user, password):
    rec = cfg["users"].get(user)
    if not rec:
        return False
    digest = hashlib.sha256((rec["salt"] + password).encode()).hexdigest()
    return hmac.compare_digest(digest, rec["password_sha256"])


def end_session(token, reason):
    with state_lock:
        s = sessions.pop(token, None)
    if s:
        sdn.revoke(s["cookie"], s["ip"])
        log.info("SESSION END user=%s ip=%s reason=%s", s["user"], s["ip"], reason)
        save_sessions()
    return s


def block_host(ip, seconds, reason):
    with state_lock:
        blocked[ip] = time.time() + seconds
        tokens = [t for t, s in sessions.items() if s["ip"] == ip]
    for t in tokens:
        end_session(t, "host blocked")
    sdn.block(ip, seconds)
    log.warning("AUTO-BLOCK ip=%s for %ss reason=%s", ip, seconds, reason)


def handle_login(req, ip):
    user, pw = req.get("user", ""), req.get("password", "")
    pol = P()

    if ip in pol["host_deny"]:
        log.warning("DENY blacklisted ip=%s user=%s", ip, user)
        return {"status": "denied", "reason": "host is blacklisted"}
    if sdn.host(ip) is None:
        log.warning("DENY unknown host ip=%s user=%s", ip, user)
        return {"status": "denied", "reason": "unknown host"}

    if not check_password(user, pw):
        with state_lock:
            failed[ip] = failed.get(ip, 0) + 1
            n = failed[ip]
        log.warning("LOGIN FAIL user=%s ip=%s attempt=%d/%d", user, ip, n, pol["max_failed_attempts"])
        if n >= pol["max_failed_attempts"]:
            with state_lock:
                failed.pop(ip, None)
            threading.Timer(0.3, block_host, (ip, pol["block_duration_sec"], "brute force")).start()
            return {"status": "denied", "reason": f"too many failed attempts, host blocked for "
                                                  f"{pol['block_duration_sec']}s"}
        return {"status": "fail", "reason": "invalid credentials",
                "attempts_left": pol["max_failed_attempts"] - n}

    role = cfg["users"][user]["role"]
    if not within_hours(role):
        log.warning("DENY outside allowed hours user=%s role=%s ip=%s", user, role, ip)
        return {"status": "denied", "reason": f"role '{role}' allowed only during hours "
                                              f"{role_rules(role).get('hours')}"}

    # one session per host: a new login replaces the old one
    with state_lock:
        old = [t for t, s in sessions.items() if s["ip"] == ip]
    for t in old:
        end_session(t, "replaced by new login")

    rules = role_rules(role)
    with state_lock:
        failed.pop(ip, None)
        token = secrets.token_hex(16)
        cookie = next_cookie[0]
        next_cookie[0] += 1
        s = {"token": token, "user": user, "role": role, "ip": ip, "cookie": cookie,
             "services": list(rules.get("services", [])),
             "expires": time.time() + pol["session_timeout_sec"]}
        sessions[token] = s
    apply_grants(s)
    save_sessions()
    log.info("LOGIN OK user=%s role=%s ip=%s granted=%s rate=%s", user, role, ip, s["services"],
             rules.get("rate_kbps", 0) or "full")
    return {"status": "ok", "token": token, "timeout": pol["session_timeout_sec"], "role": role,
            "granted": s["services"], "rate_kbps": rules.get("rate_kbps", 0)}


def session_for(token, ip):
    with state_lock:
        s = sessions.get(token)
        return s if s and s["ip"] == ip else None


def handle_admin(req, ip):
    s = session_for(req.get("token", ""), ip)
    if not s or not role_rules(s["role"]).get("admin"):
        log.warning("ADMIN DENIED ip=%s", ip)
        return {"status": "denied", "reason": "admin session required"}
    action = req.get("action")
    log.info("ADMIN %s by %s: %s", action, s["user"], {k: v for k, v in req.items() if k not in ("token", "cmd")})

    if action == "sessions":
        with state_lock:
            return {"status": "ok", "sessions": [
                {"user": x["user"], "role": x["role"], "ip": x["ip"], "services": x["services"],
                 "expires_in": int(x["expires"] - time.time())} for x in sessions.values()],
                "blocked": {k: int(v - time.time()) for k, v in blocked.items()}}
    if action == "kick":
        with state_lock:
            tokens = [t for t, x in sessions.items() if x["user"] == req.get("user")]
        for t in tokens:
            end_session(t, f"kicked by admin {s['user']}")
        return {"status": "ok", "kicked": len(tokens)}
    if action == "block":
        block_host(req["ip"], int(req.get("seconds", 60)), f"admin {s['user']}")
        return {"status": "ok"}
    if action == "unblock":
        with state_lock:
            blocked.pop(req["ip"], None)
        sdn.unblock(req["ip"])
        return {"status": "ok"}
    if action == "reload":
        return reload_policy()
    if action == "flows":
        return {"status": "ok", "flows": sdn.dump()}
    return {"status": "fail", "reason": "unknown admin action"}


def reload_policy():
    """Re-read users.json and policy.json and re-apply every rule without dropping valid sessions."""
    load_config()
    sdn.protected_ips = sorted(protected_ips())
    sdn.install_base_policy(P()["host_deny"])
    now = time.time()
    with state_lock:
        for ip, until in blocked.items():
            if until > now:
                sdn.block(ip, int(until - now))
        current = list(sessions.items())
    changed = []
    for t, s in current:
        if s["user"] not in cfg["users"] or s["ip"] in P()["host_deny"]:
            end_session(t, "removed by policy reload")
            continue
        role = cfg["users"][s["user"]]["role"]
        new_services = list(role_rules(role).get("services", []))
        if new_services != s["services"] or role != s["role"]:
            changed.append(s["user"])
        s["role"], s["services"] = role, new_services
        apply_grants(s)
    save_sessions()
    log.info("POLICY RELOADED sessions_updated=%s", changed)
    return {"status": "ok", "updated": changed}


def handle_request(req, ip):
    cmd = req.get("cmd")
    if cmd == "login":
        return handle_login(req, ip)
    if cmd == "status":
        with state_lock:
            return {"status": "ok", "sessions": [
                {"user": s["user"], "ip": s["ip"], "expires_in": int(s["expires"] - time.time())}
                for s in sessions.values()]}
    if cmd == "admin":
        return handle_admin(req, ip)

    token = req.get("token", "")
    s = session_for(token, ip)
    if not s:
        return {"status": "fail", "reason": "invalid or expired session"}
    if cmd == "heartbeat":
        with state_lock:
            s["expires"] = time.time() + P()["session_timeout_sec"]
        apply_grants(s, refresh=True)
        save_sessions()
        return {"status": "ok", "timeout": P()["session_timeout_sec"]}
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
                except Exception as e:          # never let one bad request kill the thread silently
                    log.exception("request error from %s", ip)
                    resp = {"status": "fail", "reason": f"server error: {e}"}
                f.write(json.dumps(resp) + "\n")
                f.flush()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    log.info("DISCONNECT %s:%s", ip, addr[1])


def reaper():
    """Expire silent sessions, out-of-hours sessions and finished blocks."""
    while True:
        time.sleep(1)
        now = time.time()
        with state_lock:
            expired = [t for t, s in sessions.items() if s["expires"] < now]
            off_hours = [t for t, s in sessions.items() if not within_hours(s["role"])]
            unblock = [ip for ip, until in blocked.items() if until < now]
            for ip in unblock:
                blocked.pop(ip)
        for t in expired:
            end_session(t, "timeout")
        for t in off_hours:
            end_session(t, "outside allowed hours")
        for ip in unblock:
            log.info("BLOCK EXPIRED ip=%s", ip)


def main():
    global sdn
    load_config()
    sdn = SDNController(os.path.join(RUN, "topology.json"), protected_ips(), AUTH_IP)
    sdn.install_base_policy(P()["host_deny"])
    restore_sessions()
    threading.Thread(target=reaper, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(128)
    log.info("Auth server listening on %d (timeout=%ss, restored=%d sessions)",
             PORT, P()["session_timeout_sec"], len(sessions))
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
