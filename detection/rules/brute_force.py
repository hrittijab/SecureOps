from collections import defaultdict
from datetime import timedelta


RULE_ID = "BRUTE_FORCE_001"
RULE_NAME = "Repeated Authentication Failures"
THRESHOLD = 5
WINDOW_SECONDS = 60


def detect(events: list[dict]) -> list[dict]:
    """
    Detect at least five failed login attempts against the same
    account within a 60-second window.
    """

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

        failures.sort(
            key=lambda event: event["occurred_at"]
        )

        for start_index in range(len(failures)):
            start_time = failures[start_index]["occurred_at"]
            end_time = start_time + timedelta(
                seconds=WINDOW_SECONDS
            )

            matching_events = [
                event
                for event in failures[start_index:]
                if event["occurred_at"] <= end_time
            ]

            if len(matching_events) >= THRESHOLD:

                evidence = matching_events[:THRESHOLD]

                alerts.append({
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": "HIGH",
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
                    ]
                })

                # One alert per account for this evaluation pass.
                break

    return alerts