
from datetime import datetime, timezone

from incidents.detector_runner import normalize_alerts
from incidents.alert_correlator import correlate_alerts


NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


def test_jwt_alert_is_preserved():
    alert = {
        "rule_id": "JWT_ABUSE_001",
        "entity": "127.0.0.1",
        "source_ips": ["127.0.0.1"],
        "first_seen": NOW,
        "last_seen": NOW,
        "request_ids": ["jwt-1"],
    }

    normalized, uncorrelated = normalize_alerts(
        [alert], [], []
    )

    assert len(normalized) == 1
    assert uncorrelated == []
    assert normalized[0]["source_ip"] == "127.0.0.1"
    assert normalized[0]["event_ids"] == ["jwt-1"]


def test_mass_assignment_source_ip_resolution():
    alert = {
        "rule_id": "MASS_ASSIGNMENT_001",
        "entity": "user-123",
        "first_seen": NOW,
        "last_seen": NOW,
        "request_ids": ["mass-1"],
    }

    events = [{
        "event_type": "MASS_ASSIGNMENT_ATTEMPT",
        "actor_user_id": "user-123",
        "outcome": "BLOCKED",
        "source_ip": "127.0.0.1",
        "request_id": "mass-1",
    }]

    normalized, uncorrelated = normalize_alerts(
        [alert], [], events
    )

    assert len(normalized) == 1
    assert uncorrelated == []
    assert normalized[0]["source_ip"] == "127.0.0.1"
    assert normalized[0]["event_ids"] == ["mass-1"]


def test_missing_source_ip_is_reported():
    alert = {
        "rule_id": "MASS_ASSIGNMENT_001",
        "entity": "user-123",
        "first_seen": NOW,
        "last_seen": NOW,
        "request_ids": ["mass-1"],
    }

    normalized, uncorrelated = normalize_alerts(
        [alert], [], []
    )

    assert normalized == []
    assert len(uncorrelated) == 1


def test_cross_service_alerts_correlate():
    alerts = [
        {
            "rule_id": "PASSWORD_SPRAY_001",
            "timestamp": NOW.isoformat(),
            "source_ip": "127.0.0.1",
            "service": "auth-service",
            "event_ids": ["auth-1"],
        },
        {
            "rule_id": "JWT_ABUSE_001",
            "timestamp": NOW.isoformat(),
            "source_ip": "127.0.0.1",
            "service": "user-service",
            "event_ids": ["jwt-1"],
        },
    ]

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0]["risk_score"] == 80
    assert incidents[0]["severity"] == "HIGH"
    assert incidents[0]["event_ids"] == [
        "auth-1",
        "jwt-1",
    ]
def test_strict_correlation_preserves_related_cross_service_alerts():
    alerts = [
        {
            "rule_id": "PASSWORD_SPRAY_001",
            "timestamp": NOW.isoformat(),
            "source_ip": "127.0.0.1",
            "service": "auth-service",
            "event_ids": ["shared-request-1", "auth-2"],
        },
        {
            "rule_id": "BOLA_001",
            "timestamp": NOW.isoformat(),
            "source_ip": "127.0.0.1",
            "service": "user-service",
            "event_ids": ["shared-request-1", "bola-2"],
        },
    ]

    incidents = correlate_alerts(
        alerts,
        require_related_evidence=True,
    )

    assert len(incidents) == 1
    assert incidents[0]["rules"] == [
        "BOLA_001",
        "PASSWORD_SPRAY_001",
    ]
    assert incidents[0]["event_ids"] == [
        "auth-2",
        "bola-2",
        "shared-request-1",
    ]