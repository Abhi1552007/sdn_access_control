"""
Add or update a user in users.json with a salted SHA-256 password hash.

  python3 add_user.py USER PASSWORD ROLE
  python3 add_user.py --remove USER

After changing users, tell a running server to reload:
  python3 admin_client.py admin admin123 reload      (from the admin host h7)
"""
import hashlib
import json
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
USERS = os.path.join(HERE, "users.json")
ROLES = json.load(open(os.path.join(HERE, "policy.json")))["roles"]


def main():
    users = json.load(open(USERS)) if os.path.exists(USERS) else {}
    if len(sys.argv) == 3 and sys.argv[1] == "--remove":
        users.pop(sys.argv[2], None)
        print("removed", sys.argv[2])
    elif len(sys.argv) == 4:
        user, pw, role = sys.argv[1:]
        if role not in ROLES:
            sys.exit(f"unknown role '{role}', choose from {list(ROLES)}")
        salt = secrets.token_hex(8)
        users[user] = {"salt": salt, "password_sha256": hashlib.sha256((salt + pw).encode()).hexdigest(),
                       "role": role}
        print(f"saved {user} ({role})")
    else:
        sys.exit(__doc__)
    with open(USERS, "w") as f:
        json.dump(users, f, indent=2)


if __name__ == "__main__":
    main()
