import argparse
import json

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

from common import LOG_DIR

AUTH_THRESHOLD = 3
WINDOW_SECONDS = 300

SECURITY_EVENTS = {
    "tls.handshake.fail",
    "tls.certificate.fail",
    "tls.error",
    "auth.fail",
    "data.invalid_token",
    "data.bad_hmac",
    "data.replay_rejected",
    "data.rejected",
    "protocol.error",
    "conn.error"
}


def load_events(paths):
    events = []
    malformed = 0

    for path in paths:
        if not path.exists():
            print("Missing log:", path.name)
            continue

        with path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)

                    if not isinstance(record, dict):
                        raise ValueError

                    timestamp = datetime.fromisoformat(
                        record["ts"]
                    )

                    if timestamp.tzinfo is None:
                        raise ValueError

                    if not isinstance(
                        record["event"], str
                    ):
                        raise ValueError

                    record["_time"] = timestamp
                    events.append(record)

                except (
                    ValueError, KeyError, TypeError
                ):
                    malformed += 1

    events.sort(key=lambda e: e["_time"])

    return events, malformed


def detect_auth_anomalies(events):
    windows = defaultdict(deque)
    anomalies = []

    for event in events:
        if (
            event.get("component") != "server"
            or event["event"] != "auth.fail"
        ):
            continue

        ip = event.get("ip", "unknown")
        user = event.get("user", "unknown")
        timestamp = event["_time"]

        group = (ip, user)
        window = windows[group]

        cutoff = timestamp - timedelta(
            seconds=WINDOW_SECONDS
        )

        while window and window[0] < cutoff:
            window.popleft()

        window.append(timestamp)

        if len(window) == AUTH_THRESHOLD:
            anomalies.append({
                "event": "AUTH_ANOMALY",
                "severity": "ALERT",
                "ts": timestamp.isoformat(),
                "ip": ip,
                "user": user,
                "failures": len(window),
                "window_seconds": WINDOW_SECONDS
            })

    return anomalies


def print_counter(counter):
    if not counter:
        print("None")
        return

    for name, count in counter.most_common():
        print(f"{name}: {count}")


def analyze(events, malformed):
    server = [
        e for e in events
        if e.get("component") == "server"
    ]

    client = [
        e for e in events
        if e.get("component") == "client"
    ]

    counts = Counter(e["event"] for e in server)

    print("=== LAB6 SECURITY LOG ANALYSIS ===")
    print("Total records:", len(events))
    print("Server records:", len(server))
    print("Client records:", len(client))
    print("Malformed records:", malformed)

    print("\n=== SERVER EVENTS ===")
    print_counter(counts)

    print("\n=== TLS STATISTICS ===")
    print("Successful handshakes:",
          counts["tls.handshake.ok"])
    print("Failed handshakes:",
          counts["tls.handshake.fail"])

    print("\nNegotiated TLS versions:")

    print_counter(Counter(
        e.get("tls_version", "unknown")
        for e in server
        if e["event"] == "tls.handshake.ok"
    ))

    print("\nNegotiated cipher suites:")

    print_counter(Counter(
        e.get("cipher", "unknown")
        for e in server
        if e["event"] == "tls.handshake.ok"
    ))

    print("\n=== AUTHENTICATION ===")
    print("Successful:", counts["auth.ok"])
    print("Failed:", counts["auth.fail"])

    print("\n=== DATA INTEGRITY AND ACCESS ===")
    print("Accepted messages:", counts["data.ok"])
    print("Invalid tokens:", counts["data.invalid_token"])
    print("Invalid HMAC:", counts["data.bad_hmac"])
    print("Rejected sequences:",
          counts["data.replay_rejected"])

    total_bytes = sum(
        e.get("bytes", 0)
        for e in server
        if e["event"] == "data.ok"
    )

    print("Accepted payload bytes:", total_bytes)

    print("\n=== SECURITY EVENTS ===")

    print_counter(Counter(
        e.get("component", "unknown")
        + ":" + e["event"]
        for e in events
        if e["event"] in SECURITY_EVENTS
    ))

    print("\n=== TLS FAILURE REASONS ===")

    print_counter(Counter(
        str(e.get("reason", e.get(
            "verify_code", "unknown"
        )))
        for e in events
        if e["event"] in {
            "tls.handshake.fail",
            "tls.certificate.fail",
            "tls.error"
        }
    ))

    anomalies = detect_auth_anomalies(events)

    print("\n=== ANOMALY DETECTION ===")
    print("Threshold:", AUTH_THRESHOLD)
    print("Window:", WINDOW_SECONDS, "seconds")
    print("Detected anomalies:", len(anomalies))

    for anomaly in anomalies:
        print(json.dumps(anomaly))

    print("\n=== SUMMARY ===")

    if anomalies:
        print("SECURITY ALERT: Repeated authentication failures")
    else:
        print("No repeated authentication anomalies detected")

    print("Analysis completed")


def main():
    parser = argparse.ArgumentParser(
        description="Lab6 Security Log Analyzer"
    )

    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[
            LOG_DIR / "server.jsonl",
            LOG_DIR / "client.jsonl"
        ]
    )

    args = parser.parse_args()

    events, malformed = load_events(args.paths)
    analyze(events, malformed)


if __name__ == "__main__":
    main()
