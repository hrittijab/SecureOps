from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.password_spray import detect


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


def test_detects_five_accounts_within_window():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            "192.0.2.10",
            start + timedelta(seconds=i * 5)
        )
        for i in range(5)
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "PASSWORD_SPRAY_001"
    assert alerts[0]["distinct_accounts"] == 5


def test_does_not_alert_below_account_threshold():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            "192.0.2.10",
            start + timedelta(seconds=i * 5)
        )
        for i in range(4)
    ]

    alerts = detect(events)

    assert alerts == []


def test_slow_password_spray_evades_sixty_second_window():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            "192.0.2.10",
            start + timedelta(seconds=i * 20)
        )
        for i in range(5)
    ]

    alerts = detect(events)

    assert alerts == []


def test_failures_from_different_sources_are_not_combined():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            f"user{i}@secureops.local",
            f"192.0.2.{i + 1}",
            start + timedelta(seconds=i)
        )
        for i in range(5)
    ]

    alerts = detect(events)

    assert alerts == []