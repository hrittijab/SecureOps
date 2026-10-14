
from datetime import datetime, timezone
from uuid import UUID

import pytest

from incidents.telemetry_adapter import (
    normalize_security_event,
    normalize_security_events,
)


def test_normalizes_database_event():
    event = {
        "request_id": UUID(
            "12345678-1234-5678-1234-567812345678"
        ),
        "occurred_at": datetime(
            2026, 10, 10, 12, 0,
            tzinfo=timezone.utc,
        ),
        "event_type": "JWT_REJECTED",
        "source_ip": "127.0.0.1",
    }

    result = normalize_security_event(event, "user-service")

    assert result["event_id"] == str(event["request_id"])
    assert result["timestamp"] == (
        "2026-10-10T12:00:00+00:00"
    )
    assert result["service"] == "user-service"
    assert result["source_ip"] == "127.0.0.1"
    assert result["request_id"] == event["request_id"]


def test_rejects_missing_request_id():
    event = {
        "occurred_at": datetime.now(timezone.utc),
    }

    with pytest.raises(ValueError, match="request_id"):
        normalize_security_event(event, "auth-service")


def test_rejects_naive_timestamp():
    event = {
        "request_id": "request-1",
        "occurred_at": datetime(2026, 10, 10, 12, 0),
    }

    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_security_event(event, "auth-service")


def test_normalizes_multiple_events():
    events = [
        {
            "request_id": "request-1",
            "occurred_at": datetime.now(timezone.utc),
        },
        {
            "request_id": "request-2",
            "occurred_at": datetime.now(timezone.utc),
        },
    ]

    result = normalize_security_events(events, "auth-service")

    assert len(result) == 2
    assert result[0]["event_id"] == "request-1"
    assert result[1]["event_id"] == "request-2"
