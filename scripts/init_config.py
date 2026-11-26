import bcrypt
import getpass
import json
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
USERS = CONFIG / "users.json"
HMAC_KEY = CONFIG / "hmac.key"


def write_private(path, data):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def main():
    os.umask(0o077)
    CONFIG.mkdir(mode=0o700, exist_ok=True)
    CONFIG.chmod(0o700)

    if USERS.exists() or HMAC_KEY.exists():
        raise SystemExit(
            "ERROR: Configuration already exists"
        )

    username = "alice"

    print("=== Lab6 Security Configuration ===")
    print("Creating user:", username)

    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        raise SystemExit("ERROR: Passwords do not match")

    password_bytes = password.encode("utf-8")

    if len(password) < 12 or len(password_bytes) > 72:
        raise SystemExit(
            "ERROR: Password must be at least "
            "12 characters and at most 72 bytes"
        )

    password_hash = bcrypt.hashpw(
        password_bytes,
        bcrypt.gensalt(rounds=12)
    ).decode("ascii")

    users = {username: password_hash}

    write_private(
        USERS,
        json.dumps(users, indent=2).encode("utf-8")
    )

    write_private(
        HMAC_KEY,
        secrets.token_bytes(32)
    )

    print("User created successfully")
    print("bcrypt cost factor: 12")
    print("HMAC-SHA256 key: 256 bits")
    print("Security configuration initialized")


if __name__ == "__main__":
    main()
