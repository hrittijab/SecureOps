
import pytest

from ml.auth_sessions import generate_authentication_sessions


def test_sessions_are_deterministic():
    first = generate_authentication_sessions(seed=42)
    second = generate_authentication_sessions(seed=42)

    assert first == second


def test_recovery_failures_are_generated():
    events = generate_authentication_sessions(
        recovery_sessions=10
    )

    recovery_events = [
        event for event in events
        if event["request_id"].startswith("RECOVERY-")
    ]

    assert 10 <= len(recovery_events) <= 30


def test_recovery_events_are_failures():
    events = generate_authentication_sessions(
        recovery_sessions=5
    )

    recovery_events = [
        event for event in events
        if event["request_id"].startswith("RECOVERY-")
    ]

    assert recovery_events

    assert all(
        event["event_type"] == "LOGIN_FAILURE"
        for event in recovery_events
    )


def test_events_are_chronological():
    events = generate_authentication_sessions()

    timestamps = [
        event["occurred_at"]
        for event in events
    ]

    assert timestamps == sorted(timestamps)


def test_invalid_recovery_count():
    with pytest.raises(ValueError):
        generate_authentication_sessions(
            recovery_sessions=-1
        )
