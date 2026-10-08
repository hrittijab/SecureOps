from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.rules.password_spray import (
    detect as detect_fast_spray
)
from detection.rules.slow_password_spray import (
    detect as detect_slow_spray
)


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


def build_slow_spray_events() -> list[dict]:
    start = datetime.now(timezone.utc)

    return [
        make_failure(
            email=f"spray{i + 1:02d}@secureops.local",
            source_ip="192.0.2.10",
            occurred_at=start + timedelta(seconds=i * 90)
        )
        for i in range(8)
    ]


def test_slow_spray_evades_fast_detector():
    events = build_slow_spray_events()

    alerts = detect_fast_spray(events)

    assert alerts == []


def test_slow_spray_is_detected_by_long_window_detector():
    events = build_slow_spray_events()

    alerts = detect_slow_spray(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule_id"] == "SLOW_PASSWORD_SPRAY_001"
    assert alert["distinct_accounts"] == 8
    assert alert["window_seconds"] == 900


def test_combined_detection_closes_evasion_gap():
    events = build_slow_spray_events()

    fast_alerts = detect_fast_spray(events)
    slow_alerts = detect_slow_spray(events)

    alerts = fast_alerts + slow_alerts

    rule_ids = {
        alert["rule_id"]
        for alert in alerts
    }

    assert "PASSWORD_SPRAY_001" not in rule_ids
    assert "SLOW_PASSWORD_SPRAY_001" in rule_ids
def test_benign_long_window_activity_stays_below_slow_threshold():
    start = datetime.now(timezone.utc)

    events = [
        make_failure(
            email=f"user{i + 1}@secureops.local",
            source_ip="192.0.2.20",
            occurred_at=start + timedelta(seconds=i * 100)
        )
        for i in range(7)
    ]

    alerts = detect_slow_spray(events)

    assert alerts == []


def test_successful_logins_do_not_contribute_to_slow_spray():
    start = datetime.now(timezone.utc)

    events = []

    # Four genuine authentication failures.
    for i in range(4):
        events.append(
            make_failure(
                email=f"failed{i + 1}@secureops.local",
                source_ip="192.0.2.30",
                occurred_at=start + timedelta(seconds=i * 60)
            )
        )

    # Additional successful logins from the same source.
    for i in range(6):
        events.append({
            "event_type": "LOGIN_SUCCESS",
            "user_id": uuid4(),
            "email": f"success{i + 1}@secureops.local",
            "source_ip": "192.0.2.30",
            "request_id": uuid4(),
            "outcome": "SUCCESS",
            "failure_reason": None,
            "occurred_at": (
                start + timedelta(seconds=300 + i * 60)
            )
        })

    alerts = detect_slow_spray(events)

    assert alerts == []