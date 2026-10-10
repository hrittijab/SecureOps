
from collections import defaultdict
from datetime import datetime, timezone, timedelta

RULE_ID = "MASS_ASSIGNMENT_001"
RULE_NAME = "Repeated Mass Assignment Attempts"

THRESHOLD = 3
WINDOW_SECONDS = 60


def normalize_time(value):
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def detect(events: list[dict]) -> list[dict]:
    grouped = defaultdict(list)

    for event in events:
        if event.get("event_type") != "MASS_ASSIGNMENT_ATTEMPT":
            continue

        if event.get("outcome") != "BLOCKED":
            continue

        actor = event.get("actor_user_id")
        timestamp = event.get("occurred_at")

        if not actor or not timestamp:
            continue

        grouped[str(actor)].append(event)

    alerts = []

    for actor, actor_events in grouped.items():
        actor_events.sort(
            key=lambda e: normalize_time(e["occurred_at"])
        )

        window = []
        last_alert_time = None

        for event in actor_events:
            current_time = normalize_time(
                event["occurred_at"]
            )

            window.append(event)

            cutoff = current_time - timedelta(
                seconds=WINDOW_SECONDS
            )

            window = [
                item for item in window
                if normalize_time(item["occurred_at"]) >= cutoff
            ]

            if len(window) < THRESHOLD:
                continue

            # Avoid generating an alert for every additional
            # request in the same active detection window.
            if (
                last_alert_time is not None
                and current_time - last_alert_time
                < timedelta(seconds=WINDOW_SECONDS)
            ):
                continue

            alerts.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": "HIGH",
                "entity": actor,
                "attempt_count": len(window),
                "first_seen": normalize_time(
                    window[0]["occurred_at"]
                ),
                "last_seen": current_time,
                "attempted_fields": sorted({
                    field.strip()
                    for item in window
                    for field in (
                        item.get("attempted_fields") or ""
                    ).split(",")
                    if field.strip()
                }),
                "request_ids": [
                    str(item["request_id"])
                    for item in window
                ],
            })

            last_alert_time = current_time

    return alerts
