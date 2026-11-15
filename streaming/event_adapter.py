from datetime import datetime

from telemetry.normalize import normalize_timestamp


def kafka_to_auth_event(payload: dict) -> dict:
    """
    Convert a Kafka authentication event into the format
    expected by SecureOps' existing authentication rules.
    """
    if not isinstance(payload, dict):
        raise ValueError("Kafka payload must be an object")

    if payload.get("service") != "auth-service":
        raise ValueError("Expected an auth-service event")

    metadata = payload.get("metadata") or {}

    if not isinstance(metadata, dict):
        raise ValueError("Event metadata must be an object")

    timestamp = normalize_timestamp(payload.get("timestamp"))

    return {
        "id": payload.get("event_id"),
        "event_type": payload.get("event_type"),
        "user_id": metadata.get("user_id"),
        "email": payload.get("actor"),
        "source_ip": payload.get("source_ip"),
        "request_id": metadata.get("request_id"),
        "outcome": payload.get("outcome"),
        "failure_reason": metadata.get("failure_reason"),
        "occurred_at": datetime.fromisoformat(timestamp),
    }
