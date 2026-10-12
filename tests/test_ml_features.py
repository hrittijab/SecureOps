
from datetime import datetime, timedelta, timezone

import pytest

from ml.features import (
    FEATURE_NAMES,
    extract_features,
    to_feature_matrix,
)


START = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)


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
    assert extract_features([]) == []


def test_failure_features():
    events = [
        event("a@example.test", "192.0.2.10", 0),
        event("b@example.test", "192.0.2.10", 5),
        event("c@example.test", "192.0.2.11", 10),
    ]

    rows = extract_features(events)

    assert len(rows) == 1

    row = rows[0]

    assert row["event_count"] == 3
    assert row["failure_count"] == 3
    assert row["success_count"] == 0
    assert row["failure_rate"] == 1.0
    assert row["distinct_accounts"] == 3
    assert row["distinct_source_ips"] == 2
    assert row["failures_per_account"] == 1.0
    assert row["failures_per_ip"] == 1.5


def test_success_and_failure():
    events = [
        event("a@example.test", "192.0.2.10", 0),
        event("a@example.test", "192.0.2.10", 5, success=True),
    ]

    row = extract_features(events)[0]

    assert row["event_count"] == 2
    assert row["failure_count"] == 1
    assert row["success_count"] == 1
    assert row["failure_rate"] == 0.5


def test_separate_windows():
    events = [
        event("a@example.test", "192.0.2.10", 0),
        event("b@example.test", "192.0.2.11", 61),
    ]

    rows = extract_features(events)

    assert len(rows) == 2
    assert rows[0]["window_start"] != rows[1]["window_start"]


def test_feature_matrix():
    rows = extract_features([
        event("a@example.test", "192.0.2.10", 0),
    ])

    matrix = to_feature_matrix(rows)

    assert len(matrix) == 1
    assert len(matrix[0]) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in matrix[0])


def test_naive_timestamp_rejected():
    events = [{
        "event_type": "LOGIN_FAILURE",
        "email": "a@example.test",
        "source_ip": "192.0.2.10",
        "occurred_at": datetime(2026, 10, 12, 10, 0),
    }]

    with pytest.raises(ValueError):
        extract_features(events)


def test_invalid_window_size():
    with pytest.raises(ValueError):
        extract_features([], window_seconds=0)
