from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.slow_password_spray import detect


def make_failure(
    email: str,
    source_ip: str,
    occurred_at: datetime
) -> dict:
    return {
        "event_type": "LOGIN_FAILURE",
        "user_id": uuid4(),
        "email": email,
        "source_ip": source_ip,
        "request_id": uuid4(),
        "outcome": "FAILURE",
        "failure_reason": "INVALID_CREDENTIALS",
        "occurred_at": occurred_at
    }


def test_detects_low_and_slow_spray():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            "192.0.2.10",
            start + timedelta(seconds=i * 90)
        )
        for i in range(8)
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SLOW_PASSWORD_SPRAY_001"
    assert alerts[0]["distinct_accounts"] == 8


def test_does_not_alert_below_account_threshold():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            "192.0.2.10",
            start + timedelta(seconds=i * 90)
        )
        for i in range(7)
    ]

    alerts = detect(events)

    assert alerts == []


def test_does_not_combine_different_sources():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            f"192.0.2.{i + 1}",
            start + timedelta(seconds=i * 90)
        )
        for i in range(8)
    ]

    alerts = detect(events)

    assert alerts == []


def test_does_not_alert_outside_long_window():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            "192.0.2.10",
            start + timedelta(seconds=i * 140)
        )
        for i in range(8)
    ]

    alerts = detect(events)

    assert alerts == []