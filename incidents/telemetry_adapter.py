
from datetime import datetime, timezone


def normalize_security_event(event, service):
    """
    Convert database telemetry into investigation-compatible events.

    Preserve original fields while standardizing identifiers
    and timestamps.
    """
    request_id = event.get("request_id")
    occurred_at = event.get("occurred_at")

    if request_id is None:
        raise ValueError("Security event is missing request_id")

    if not isinstance(occurred_at, datetime):
        raise ValueError("Security event requires datetime occurred_at")

    if occurred_at.tzinfo is None:
        raise ValueError("Security event timestamp must be timezone-aware")

    normalized = dict(event)

    normalized["event_id"] = str(request_id)
    normalized["timestamp"] = occurred_at.astimezone(
        timezone.utc
    ).isoformat()
    normalized["service"] = service

    return normalized


def normalize_security_events(events, service):
    return [
        normalize_security_event(event, service)
        for event in events
    ]
