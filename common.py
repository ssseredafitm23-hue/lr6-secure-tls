import json
import hmac
import hashlib
import os
import re

from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config"
LOG_DIR = ROOT / "logs"

MAX_FRAME = 32768
MAX_PAYLOAD = 4096
TIMEOUT = 15


class ProtocolError(Exception):
    pass


def load_hmac_key():
    key = (CONFIG / "hmac.key").read_bytes()

    if len(key) != 32:
        raise ValueError("Invalid HMAC key length")

    return key


def canonical(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False
    ).encode("utf-8")


def sign(key, obj):
    return hmac.new(
        key,
        canonical(obj),
        hashlib.sha256
    ).hexdigest()


def verify(key, obj):
    tag = obj.get("hmac")

    if not isinstance(tag, str):
        return False

    if not re.fullmatch(r"[0-9a-f]{64}", tag):
        return False

    body = {
        k: v for k, v in obj.items()
        if k != "hmac"
    }

    return hmac.compare_digest(
        sign(key, body), tag
    )


def send_frame(sock, obj):
    data = canonical(obj) + b"\n"

    if len(data) > MAX_FRAME:
        raise ProtocolError("Frame too large")

    sock.sendall(data)


def recv_frame(reader):
    line = reader.readline(MAX_FRAME + 1)

    if not line:
        return None

    if len(line) > MAX_FRAME:
        raise ProtocolError("Frame too large")

    if not line.endswith(b"\n"):
        raise ProtocolError("Incomplete frame")

    try:
        obj = json.loads(line.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError
        canonical(obj)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid JSON")

    return obj


def log_event(component, event, **fields):
    LOG_DIR.mkdir(mode=0o700, exist_ok=True)

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "component": component,
        "event": event,
        **fields
    }

    path = LOG_DIR / f"{component}.jsonl"

    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600
    )

    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(
            json.dumps(record, ensure_ascii=True)
            + "\n"
        )
