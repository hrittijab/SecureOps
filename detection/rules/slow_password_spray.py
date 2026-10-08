from collections import defaultdict
from datetime import timedelta


RULE_ID = "SLOW_PASSWORD_SPRAY_001"
RULE_NAME = "Low-and-Slow Password Spray"

ACCOUNT_THRESHOLD = 8
WINDOW_SECONDS = 15 * 60


def detect(events: list[dict]) -> list[dict]:
    failures_by_source = defaultdict(list)

    for event in events:
        if (
            event["event_type"] == "LOGIN_FAILURE"
            and event["failure_reason"] == "INVALID_CREDENTIALS"
            and event["source_ip"]
            and event["email"]
        ):
            failures_by_source[event["source_ip"]].append(event)

    alerts = []

    for source_ip, failures in failures_by_source.items():
        failures.sort(
            key=lambda event: event["occurred_at"]
        )

        for start_index in range(len(failures)):
            start_time = failures[start_index]["occurred_at"]
            end_time = start_time + timedelta(
                seconds=WINDOW_SECONDS
            )

            window_events = [
                event
                for event in failures[start_index:]
                if event["occurred_at"] <= end_time
            ]

            accounts = {
                event["email"]
                for event in window_events
            }

            if len(accounts) < ACCOUNT_THRESHOLD:
                continue

            evidence = []
            seen_accounts = set()

            for event in window_events:
                email = event["email"]

                if email in seen_accounts:
                    continue

                evidence.append(event)
                seen_accounts.add(email)

                if len(seen_accounts) == ACCOUNT_THRESHOLD:
                    break

            alerts.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": "HIGH",
                "entity": source_ip,
                "distinct_accounts": len(seen_accounts),
                "window_seconds": WINDOW_SECONDS,
                "first_seen": evidence[0]["occurred_at"],
                "last_seen": evidence[-1]["occurred_at"],
                "targeted_accounts": sorted(seen_accounts),
                "request_ids": [
                    str(event["request_id"])
                    for event in evidence
                ]
            })

            break

    return alerts