
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.distributed_password_spray import detect


START = datetime(2026, 10, 12, tzinfo=timezone.utc)


def make_failure(index, seconds=None):
    return {
        "event_type": "LOGIN_FAILURE",
        "failure_reason": "INVALID_CREDENTIALS",
        "email": f"user{index}@example.test",
        "source_ip": f"192.0.2.{index + 10}",
        "request_id": uuid4(),
        "occurred_at": START + timedelta(
            seconds=index * 5 if seconds is None else seconds
        ),
    }


def test_detects_distributed_password_spray():
    events = [make_failure(i) for i in range(8)]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "DISTRIBUTED_PASSWORD_SPRAY_001"
    assert alerts[0]["distinct_accounts"] == 8
    assert alerts[0]["distinct_source_ips"] == 8


def test_seven_accounts_do_not_alert():
    events = [make_failure(i) for i in range(7)]

    assert detect(events) == []


def test_failures_outside_window_do_not_alert():
    events = [
        make_failure(i, seconds=i * 120)
        for i in range(8)
    ]

    assert detect(events) == []


def test_single_source_ip_does_not_alert():
    events = [make_failure(i) for i in range(8)]

    for event in events:
        event["source_ip"] = "192.0.2.100"

    assert detect(events) == []


def test_benign_multi_user_failures_can_trigger_alert():
    """
    Documents a potential false positive.

    Eight independent legitimate users can produce
    the same observable failure pattern as a
    distributed password-spraying attack.
    """
    events = [make_failure(i) for i in range(8)]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "MEDIUM"
