
from datetime import datetime, timedelta, timezone

from detection.rules.jwt_abuse import detect


BASE = datetime(2026, 10, 10, tzinfo=timezone.utc)


def event(index, ip="192.0.2.10", reason="INVALID_SIGNATURE"):
    return {
        "event_type": "JWT_REJECTED",
        "failure_reason": reason,
        "source_ip": ip,
        "request_id": f"req-{index}",
        "occurred_at": BASE + timedelta(seconds=index * 5),
    }


def test_detects_five_rejections():
    alerts = detect([event(i) for i in range(5)])
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "JWT_ABUSE_001"
    assert alerts[0]["failure_count"] == 5


def test_four_rejections_do_not_alert():
    assert detect([event(i) for i in range(4)]) == []


def test_different_ips_are_not_combined():
    events = [event(i, ip=f"192.0.2.{i + 1}") for i in range(5)]
    assert detect(events) == []


def test_failures_outside_window_do_not_alert():
    events = [event(i * 20) for i in range(5)]
    assert detect(events) == []


def test_unrelated_events_are_ignored():
    events = [
        {**event(i), "event_type": "LOGIN_FAILURE"}
        for i in range(5)
    ]
    assert detect(events) == []


def test_multiple_failure_reasons():
    events = [
        event(0, reason="INVALID_SIGNATURE"),
        event(1, reason="EXPIRED_TOKEN"),
        event(2, reason="INVALID_AUDIENCE"),
        event(3, reason="MALFORMED_TOKEN"),
        event(4, reason="INVALID_ISSUER"),
    ]
    alerts = detect(events)
    assert len(alerts) == 1
    assert len(alerts[0]["failure_reasons"]) == 5
