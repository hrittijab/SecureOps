from datetime import datetime, timezone
from uuid import uuid4

import pytest

from streaming.event_adapter import kafka_to_auth_event


def make_event():
    return {
        "event_id": str(uuid4()),
        "service": "auth-service",
        "event_type": "LOGIN_FAILURE",
        "timestamp": "2026-11-15T15:00:00Z",
        "actor": "security-test@example.com",
        "source_ip": "127.0.0.1",
        "outcome": "FAILURE",
        "metadata": {
            "request_id": str(uuid4()),
            "failure_reason": "INVALID_CREDENTIALS",
        },
    }


def test_kafka_event_maps_to_detection_schema():
    payload = make_event()

    event = kafka_to_auth_event(payload)

    assert event["id"] == payload["event_id"]
    assert event["event_type"] == "LOGIN_FAILURE"
    assert event["email"] == "security-test@example.com"
    assert event["source_ip"] == "127.0.0.1"
    assert event["request_id"] == payload["metadata"]["request_id"]
    assert event["failure_reason"] == "INVALID_CREDENTIALS"
    assert event["occurred_at"].tzinfo is not None


def test_timestamp_is_normalized_to_utc():
    payload = make_event()
    payload["timestamp"] = "2026-11-15T21:00:00+06:00"

    event = kafka_to_auth_event(payload)

    assert event["occurred_at"] == datetime(
        2026, 11, 15, 15, 0, tzinfo=timezone.utc
    )


def test_rejects_wrong_service():
    payload = make_event()
    payload["service"] = "unknown-service"

    with pytest.raises(ValueError):
        kafka_to_auth_event(payload)


def test_rejects_invalid_metadata():
    payload = make_event()
    payload["metadata"] = ["invalid"]

    with pytest.raises(ValueError):
        kafka_to_auth_event(payload)


def test_rejects_naive_timestamp():
    payload = make_event()
    payload["timestamp"] = "2026-11-15T15:00:00"

    with pytest.raises(ValueError):
        kafka_to_auth_event(payload)
