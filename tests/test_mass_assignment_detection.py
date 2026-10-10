
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.mass_assignment import detect


BASE = datetime(
    2026, 10, 10, 12, 0, tzinfo=timezone.utc
)


def make_event(
    actor="user-1",
    seconds=0,
    field="accountTier",
    outcome="BLOCKED",
):
    return {
        "event_type": "MASS_ASSIGNMENT_ATTEMPT",
        "actor_user_id": actor,
        "target_user_id": actor,
        "outcome": outcome,
        "attempted_fields": field,
        "source_ip": "127.0.0.1",
        "request_id": uuid4(),
        "occurred_at": BASE + timedelta(seconds=seconds),
    }


def test_three_attempts_trigger_alert():
    events = [
        make_event(seconds=0),
        make_event(seconds=10),
        make_event(seconds=20),
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "MASS_ASSIGNMENT_001"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["attempt_count"] == 3


def test_two_attempts_do_not_trigger():
    events = [
        make_event(seconds=0),
        make_event(seconds=10),
    ]

    assert detect(events) == []


def test_attempts_outside_window_do_not_trigger():
    events = [
        make_event(seconds=0),
        make_event(seconds=70),
        make_event(seconds=140),
    ]

    assert detect(events) == []


def test_different_users_not_combined():
    events = [
        make_event(actor="user-1", seconds=0),
        make_event(actor="user-2", seconds=5),
        make_event(actor="user-1", seconds=10),
    ]

    assert detect(events) == []


def test_successful_events_not_counted_as_blocked():
    events = [
        make_event(seconds=0, outcome="SUCCESS"),
        make_event(seconds=10),
        make_event(seconds=20),
    ]

    assert detect(events) == []


def test_attempted_fields_are_aggregated():
    events = [
        make_event(seconds=0, field="accountTier"),
        make_event(seconds=10, field="role"),
        make_event(seconds=20, field="accountTier"),
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["attempted_fields"] == [
        "accountTier",
        "role",
    ]


def test_repeated_requests_do_not_spam_alerts():
    events = [
        make_event(seconds=0),
        make_event(seconds=10),
        make_event(seconds=20),
        make_event(seconds=30),
        make_event(seconds=40),
    ]

    assert len(detect(events)) == 1
