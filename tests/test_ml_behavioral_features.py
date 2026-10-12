
from datetime import datetime, timedelta, timezone

from ml.behavioral_features import extract_behavioral_features


START = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def event(email, ip, seconds, success=False):
    return {
        "event_type": (
            "LOGIN_SUCCESS" if success else "LOGIN_FAILURE"
        ),
        "email": email,
        "source_ip": ip,
        "occurred_at": START + timedelta(seconds=seconds),
    }


def test_empty_events():
    assert extract_behavioral_features([]) == []


def test_password_recovery():
    events = [
        event("user@example.test", "192.0.2.10", 0),
        event("user@example.test", "192.0.2.10", 10),
        event("user@example.test", "192.0.2.10", 20, True),
    ]

    row = extract_behavioral_features(events)[0]

    assert row["recovered_accounts"] == 1
    assert row["failure_only_accounts"] == 0
    assert row["max_consecutive_failures"] == 2
    assert row["successful_login_rate"] == 1 / 3


def test_failure_only_account():
    events = [
        event("user@example.test", "192.0.2.10", 0),
        event("user@example.test", "192.0.2.10", 10),
    ]

    row = extract_behavioral_features(events)[0]

    assert row["recovered_accounts"] == 0
    assert row["failure_only_accounts"] == 1
    assert row["max_consecutive_failures"] == 2


def test_distinct_account_ip_pairs():
    events = [
        event("a@example.test", "192.0.2.10", 0),
        event("a@example.test", "192.0.2.11", 5),
        event("b@example.test", "192.0.2.10", 10),
    ]

    row = extract_behavioral_features(events)[0]

    assert row["unique_account_ip_pairs"] == 3


def test_consecutive_failures_reset_after_success():
    events = [
        event("user@example.test", "192.0.2.10", 0),
        event("user@example.test", "192.0.2.10", 5),
        event("user@example.test", "192.0.2.10", 10, True),
        event("user@example.test", "192.0.2.10", 15),
    ]

    row = extract_behavioral_features(events)[0]

    assert row["max_consecutive_failures"] == 2
    assert row["recovered_accounts"] == 1


def test_separate_windows():
    events = [
        event("user@example.test", "192.0.2.10", 0),
        event("user@example.test", "192.0.2.10", 65, True),
    ]

    rows = extract_behavioral_features(events)

    assert len(rows) == 2
    assert rows[0]["recovered_accounts"] == 0
    assert rows[1]["recovered_accounts"] == 0
