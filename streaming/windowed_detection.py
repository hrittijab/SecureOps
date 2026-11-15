from datetime import datetime, timedelta, timezone

from streaming.incremental_loader import load_event_batch
from streaming.detection_runner import RULES

WINDOW_MINUTES = 15


def parse_timestamp(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if parsed.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")

    return parsed.astimezone(timezone.utc)


def detect_in_batches(batch_size=3):
    checkpoint = 0
    recent_events = []
    detected_rules = set()

    while True:
        batch = load_event_batch(
            after_id=checkpoint,
            batch_size=batch_size,
        )

        if not batch:
            break

        recent_events.extend(
            item["event"] for item in batch
        )

        checkpoint = batch[-1]["ingestion_id"]

        latest = max(
            parse_timestamp(event["occurred_at"])
            for event in recent_events
        )

        cutoff = latest - timedelta(
            minutes=WINDOW_MINUTES
        )

        recent_events = [
            event
            for event in recent_events
            if parse_timestamp(event["occurred_at"]) >= cutoff
        ]

        alerts = []

        for rule in RULES:
            alerts.extend(rule(recent_events))

        for alert in alerts:
            rule_id = alert.get("rule_id")

            if rule_id:
                detected_rules.add(rule_id)

        print(
            f"Checkpoint candidate={checkpoint} "
            f"Window events={len(recent_events)} "
            f"Alerts={len(alerts)}"
        )

    return detected_rules
