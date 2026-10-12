
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.slow_brute_force import detect


START = datetime(2026, 10, 12, tzinfo=timezone.utc)


def failure(seconds, email="victim@example.test"):
    return {
        "event_type": "LOGIN_FAILURE",
        "failure_reason": "INVALID_CREDENTIALS",
        "email": email,
        "source_ip": "192.0.2.10",
        "request_id": uuid4(),
        "occurred_at": START + timedelta(seconds=seconds),
    }


def test_detects_slow_brute_force():
    events = [failure(i * 90) for i in range(5)]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SLOW_BRUTE_FORCE_001"
    assert alerts[0]["failure_count"] == 5


def test_below_threshold_does_not_alert():
    events = [failure(i * 90) for i in range(4)]

    assert detect(events) == []


def test_rapid_brute_force_does_not_duplicate_alert():
    events = [failure(i * 5) for i in range(5)]

    assert detect(events) == []


def test_outside_long_window_does_not_alert():
    events = [failure(i * 240) for i in range(5)]

    assert detect(events) == []


def test_different_accounts_are_not_combined():
    events = [
        failure(i * 90, email=f"user{i}@example.test")
        for i in range(5)
    ]

    assert detect(events) == []
