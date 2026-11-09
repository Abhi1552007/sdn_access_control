"""
Admin client (D2) - run on the admin host h7.

  admin_client.py USER PASS sessions
  admin_client.py USER PASS kick <username>
  admin_client.py USER PASS block <ip> [seconds]
  admin_client.py USER PASS unblock <ip>
  admin_client.py USER PASS reload              re-read users.json and policy.json live
  admin_client.py USER PASS flows               show the flow tables of all switches

It logs in (the user must have an admin role), runs one action, and logs out.
"""
import json
import sys

from auth_client import AuthConnection


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    user, pw, action, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    conn = AuthConnection()
    r = conn.send({"cmd": "login", "user": user, "password": pw})
    if r.get("status") != "ok":
        sys.exit(f"login failed: {r}")

    req = {"cmd": "admin", "token": r["token"], "action": action}
    if action == "kick":
        req["user"] = args[0]
    elif action == "block":
        req["ip"] = args[0]
        req["seconds"] = int(args[1]) if len(args) > 1 else 60
    elif action == "unblock":
        req["ip"] = args[0]

    resp = conn.send(req)
    if action == "flows" and resp.get("status") == "ok":
        for sw, text in resp["flows"].items():
            print(f"--- {sw} ---\n{text}")
    else:
        print(json.dumps(resp, indent=2))
    conn.send({"cmd": "logout", "token": r["token"]})
    conn.close()


if __name__ == "__main__":
    main()
