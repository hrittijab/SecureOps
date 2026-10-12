
from datetime import timedelta

RULE_ID = "DISTRIBUTED_PASSWORD_SPRAY_001"
RULE_NAME = "Distributed Authentication Failure Burst"

ACCOUNT_THRESHOLD = 8
IP_THRESHOLD = 8
WINDOW_SECONDS = 60


def detect(events: list[dict]) -> list[dict]:
    failures = sorted(
        [
            event
            for event in events
            if event.get("event_type") == "LOGIN_FAILURE"
            and event.get("failure_reason") == "INVALID_CREDENTIALS"
            and event.get("email")
            and event.get("source_ip")
            and event.get("occurred_at")
        ],
        key=lambda event: event["occurred_at"],
    )

    for start_index, first_event in enumerate(failures):
        end_time = first_event["occurred_at"] + timedelta(
            seconds=WINDOW_SECONDS
        )

        window = [
            event
            for event in failures[start_index:]
            if event["occurred_at"] <= end_time
        ]

        accounts = {event["email"] for event in window}
        ips = {event["source_ip"] for event in window}

        if (
            len(accounts) < ACCOUNT_THRESHOLD
            or len(ips) < IP_THRESHOLD
        ):
            continue

        # Require one failure per account and per IP.
        # This avoids treating repeated failures from one
        # account as distributed password spraying.
        if len(window) != len(accounts) or len(window) != len(ips):
            continue

        return [{
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": "MEDIUM",
            "entity": "authentication_service",
            "distinct_accounts": len(accounts),
            "distinct_source_ips": len(ips),
            "window_seconds": WINDOW_SECONDS,
            "first_seen": window[0]["occurred_at"],
            "last_seen": window[-1]["occurred_at"],
            "targeted_accounts": sorted(accounts),
            "source_ips": sorted(ips),
            "request_ids": [
                str(event["request_id"])
                for event in window
            ],
        }]

    return []
