
from collections import defaultdict
from datetime import timedelta

RULE_ID = "JWT_ABUSE_001"
RULE_NAME = "Repeated JWT Authentication Failures"
THRESHOLD = 5
WINDOW_SECONDS = 60

REJECTION_REASONS = {
    "INVALID_SIGNATURE",
    "MALFORMED_TOKEN",
    "EXPIRED_TOKEN",
    "INVALID_ISSUER",
    "INVALID_AUDIENCE",
    "INVALID_TOKEN",
}


def detect(events: list[dict]) -> list[dict]:
    failures_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("event_type") == "JWT_REJECTED"
            and event.get("failure_reason") in REJECTION_REASONS
            and event.get("source_ip")
        ):
            failures_by_ip[event["source_ip"]].append(event)

    alerts = []

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["occurred_at"])

        for start_index, start_event in enumerate(failures):
            start_time = start_event["occurred_at"]
            end_time = start_time + timedelta(seconds=WINDOW_SECONDS)

            evidence = [
                event
                for event in failures[start_index:]
                if event["occurred_at"] <= end_time
            ][:THRESHOLD]

            if len(evidence) >= THRESHOLD:
                alerts.append({
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "MEDIUM",
                    "entity": source_ip,
                    "failure_count": len(evidence),
                    "window_seconds": WINDOW_SECONDS,
                    "first_seen": evidence[0]["occurred_at"],
                    "last_seen": evidence[-1]["occurred_at"],
                    "failure_reasons": sorted({
                        event["failure_reason"] for event in evidence
                    }),
                    "source_ips": [source_ip],
                    "request_ids": [
                        str(event["request_id"])
                        for event in evidence
                    ],
                })
                break

    return alerts
