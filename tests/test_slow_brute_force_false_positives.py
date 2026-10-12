
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.slow_brute_force import detect


START = datetime(2026, 10, 12, tzinfo=timezone.utc)


def make_event(seconds, success=False):
    return {
        "event_type": "LOGIN_SUCCESS" if success else "LOGIN_FAILURE",
        "failure_reason": None if success else "INVALID_CREDENTIALS",
        "email": "alice@example.test",
        "source_ip": "192.0.2.10",
        "request_id": uuid4(),
        "occurred_at": START + timedelta(seconds=seconds),
    }


def test_four_mistakes_do_not_alert():
    events = [make_event(i * 90) for i in range(4)]

    assert detect(events) == []


def test_successful_logins_do_not_count_as_failures():
    events = [
        make_event(0),
        make_event(90),
        make_event(180),
        make_event(270),
        make_event(360, success=True),
    ]

    assert detect(events) == []


def test_five_mistakes_can_generate_false_positive():
    """
    Documents a possible false positive:
    five legitimate mistakes over six minutes.
    """
    events = [make_event(i * 90) for i in range(5)]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SLOW_BRUTE_FORCE_001"


def test_failures_spread_beyond_window_do_not_alert():
    events = [make_event(i * 240) for i in range(5)]

    assert detect(events) == []
