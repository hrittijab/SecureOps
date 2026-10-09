from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid5, NAMESPACE_URL


SUSPICIOUS_TYPES = {
    "LOGIN_FAILURE",
    "LOGIN_FAILED",
}

SUSPICIOUS_OUTCOMES = {
    "CROSS_USER_ACCESS",
}


def parse_timestamp(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    if parsed.tzinfo is None:
        raise ValueError("Timestamp must have a timezone")

    return parsed.astimezone(timezone.utc)


def is_suspicious(event: dict) -> bool:
    return (
        event.get("event_type") in SUSPICIOUS_TYPES
        or event.get("outcome") in SUSPICIOUS_OUTCOMES
    )


def severity_for(events: list[dict]) -> str:
    if any(
        event.get("outcome") == "CROSS_USER_ACCESS"
        for event in events
    ):
        return "HIGH"

    if len(events) >= 10:
        return "HIGH"

    if len(events) >= 5:
        return "MEDIUM"

    return "LOW"


def correlate_events(
    events: list[dict],
    window_minutes: int = 15,
) -> list[dict]:

    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    grouped = defaultdict(list)

    for event in events:
        if not is_suspicious(event):
            continue

        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        grouped[source_ip].append(event)

    incidents = []
    window = timedelta(minutes=window_minutes)

    for source_ip, source_events in grouped.items():

        source_events.sort(
            key=lambda item: parse_timestamp(item["timestamp"])
        )

        current = []

        def flush():
            if not current:
                return

            first = current[0]
            last = current[-1]

            stable_key = (
                f"{source_ip}|"
                f"{first['timestamp']}|"
                f"{last['timestamp']}|"
                + ",".join(
                    sorted(
                        str(event["event_id"])
                        for event in current
                    )
                )
            )

            incident_id = str(
                uuid5(NAMESPACE_URL, stable_key)
            )

            incidents.append({
                "incident_id": incident_id,
                "source_ip": source_ip,
                "severity": severity_for(current),
                "event_count": len(current),
                "services": sorted({
                    event["service"]
                    for event in current
                }),
                "first_seen": first["timestamp"],
                "last_seen": last["timestamp"],
                "event_ids": [
                    event["event_id"]
                    for event in current
                ],
                "timeline": [
                    {
                        "timestamp": event["timestamp"],
                        "service": event["service"],
                        "event_type": event["event_type"],
                        "actor": event.get("actor"),
                        "target": event.get("target"),
                        "outcome": event.get("outcome"),
                    }
                    for event in current
                ],
            })

        for event in source_events:

            if not current:
                current = [event]
                continue

            elapsed = (
                parse_timestamp(event["timestamp"])
                - parse_timestamp(current[0]["timestamp"])
            )

            if elapsed <= window:
                current.append(event)

            else:
                flush()
                current = [event]

        flush()

    return sorted(
        incidents,
        key=lambda incident: incident["first_seen"],
    )