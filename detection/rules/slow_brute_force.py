
from collections import defaultdict
from datetime import timedelta


RULE_ID = "SLOW_BRUTE_FORCE_001"
RULE_NAME = "Low-and-Slow Brute Force"
THRESHOLD = 5
WINDOW_SECONDS = 15 * 60


def detect(events: list[dict]) -> list[dict]:
    failures_by_email = defaultdict(list)

    for event in events:
        if (
            event["event_type"] == "LOGIN_FAILURE"
            and event["failure_reason"] == "INVALID_CREDENTIALS"
            and event["email"]
        ):
            failures_by_email[event["email"]].append(event)

    alerts = []

    for email, failures in failures_by_email.items():
        failures.sort(key=lambda event: event["occurred_at"])

        for start_index in range(len(failures)):
            start_time = failures[start_index]["occurred_at"]
            end_time = start_time + timedelta(
                seconds=WINDOW_SECONDS
            )

            matching = [
                event
                for event in failures[start_index:]
                if event["occurred_at"] <= end_time
            ]

            if len(matching) < THRESHOLD:
                continue

            evidence = matching[:THRESHOLD]

            # Avoid duplicating the existing rapid brute-force
            # alert when all five failures occur within 60 seconds.
            duration = (
                evidence[-1]["occurred_at"]
                - evidence[0]["occurred_at"]
            ).total_seconds()

            if duration <= 60:
                break

            alerts.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": "MEDIUM",
                "entity": email,
                "failure_count": len(evidence),
                "window_seconds": WINDOW_SECONDS,
                "first_seen": evidence[0]["occurred_at"],
                "last_seen": evidence[-1]["occurred_at"],
                "source_ips": sorted({
                    event["source_ip"]
                    for event in evidence
                    if event["source_ip"]
                }),
                "request_ids": [
                    str(event["request_id"])
                    for event in evidence
                ],
            })

            break

    return alerts
