from datetime import datetime, timezone
from uuid import uuid4


def normalize_timestamp(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Timestamp must include timezone information")
        return value.astimezone(timezone.utc).isoformat()

    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timestamp must include timezone information")
        return parsed.astimezone(timezone.utc).isoformat()

    raise ValueError("Missing or invalid event timestamp")


def normalize_auth_event(event: dict) -> dict:
    return {
        "event_id": str(event.get("id") or uuid4()),
        "service": "auth-service",
        "event_type": event.get("event_type", "UNKNOWN"),
        "actor": event.get("email"),
        "target": event.get("email"),
        "source_ip": event.get("source_ip"),
        "outcome": event.get("outcome"),
        "timestamp": normalize_timestamp(event.get("occurred_at")),
        "metadata": {
            "user_id": str(event["user_id"]) if event.get("user_id") else None,
            "request_id": str(event["request_id"]) if event.get("request_id") else None,
            "failure_reason": event.get("failure_reason"),
        },
    }


def normalize_authorization_event(event: dict) -> dict:
    return {
        "event_id": str(event.get("id") or uuid4()),
        "service": "user-service",
        "event_type": event.get("action", "UNKNOWN"),
        "actor": str(event["actor_user_id"]) if event.get("actor_user_id") else None,
        "target": str(event["target_user_id"]) if event.get("target_user_id") else None,
        "source_ip": event.get("source_ip"),
        "outcome": event.get("outcome"),
        "timestamp": normalize_timestamp(event.get("occurred_at")),
        "metadata": {
            "request_id": str(event["request_id"]) if event.get("request_id") else None,
        },
    }