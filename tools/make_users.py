#!/usr/bin/env python3
"""Generate config/users.json with SCRAM credentials (no plaintext passwords stored).

Default accounts (username / password / role):
    alice / alice123 / student
    carol / carol123 / student
    bob   / bob123   / faculty
    admin / admin123 / admin
    user01..user30 / pass01..pass30 / student   (used for scalability tests)

Usage:  python3 tools/make_users.py            # regenerate defaults
        python3 tools/make_users.py dave pw faculty   # add/replace one user
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
from common import CONFIG_DIR, make_credentials  # noqa: E402

PATH = os.path.join(CONFIG_DIR, "users.json")


def main():
    if len(sys.argv) == 4:
        users = json.load(open(PATH)) if os.path.exists(PATH) else {}
        name, pw, role = sys.argv[1:]
        users[name] = dict(role=role, **make_credentials(pw))
    else:
        users = {}
        for name, pw, role in [("alice", "alice123", "student"),
                               ("carol", "carol123", "student"),
                               ("bob", "bob123", "faculty"),
                               ("admin", "admin123", "admin")]:
            users[name] = dict(role=role, **make_credentials(pw))
        for i in range(1, 31):
            users[f"user{i:02d}"] = dict(role="student", **make_credentials(f"pass{i:02d}"))
    with open(PATH, "w") as f:
        json.dump(users, f, indent=1)
    print(f"wrote {len(users)} users to {PATH}")


if __name__ == "__main__":
    main()
