from datetime import datetime, timezone
from uuid import uuid4

import pytest

from incidents.alert_adapter import (
    adapt_auth_alert,
    adapt_bola_alert,
    adapt_all_alerts,
)
from incidents.alert_correlator import correlate_alerts


NOW = datetime(
    2026, 10, 8, 10, 0,
    tzinfo=timezone.utc,
)


def test_brute_force_adapter():
    alert = {
        "rule_id": "BRUTE_FORCE_001",
        "entity": "alice@example.test",
        "last_seen": NOW,
        "source_ips": ["10.0.0.1"],
        "request_ids": ["req-1", "req-2"],
    }

    result = adapt_auth_alert(alert)

    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.1"
    assert result[0]["service"] == "auth-service"
    assert result[0]["event_ids"] == ["req-1", "req-2"]


def test_password_spray_adapter():
    alert = {
        "rule_id": "PASSWORD_SPRAY_001",
        "entity": "10.0.0.2",
        "last_seen": NOW,
        "targeted_accounts": ["a@test.local", "b@test.local"],
        "request_ids": ["req-3"],
    }

    result = adapt_auth_alert(alert)

    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.2"


def test_slow_spray_adapter():
    alert = {
        "rule_id": "SLOW_PASSWORD_SPRAY_001",
        "entity": "10.0.0.3",
        "last_seen": NOW,
        "request_ids": ["req-4"],
    }

    result = adapt_auth_alert(alert)

    assert result[0]["rule_id"] == "SLOW_PASSWORD_SPRAY_001"


def test_bola_adapter_resolves_source_ip():
    request_id = uuid4()

    alert = {
        "rule_id": "BOLA_001",
        "request_id": str(request_id),
        "occurred_at": NOW,
    }

    events = [{
        "request_id": request_id,
        "actor_user_id": "alice",
        "target_user_id": "bob",
        "source_ip": "10.0.0.4",
    }]

    result = adapt_bola_alert(alert, events)

    assert result["source_ip"] == "10.0.0.4"
    assert result["actor"] == "alice"
    assert result["target"] == "bob"


def test_missing_bola_evidence_is_rejected():
    alert = {
        "rule_id": "BOLA_001",
        "request_id": "missing",
        "occurred_at": NOW,
    }

    with pytest.raises(ValueError):
        adapt_bola_alert(alert, [])


def test_realistic_cross_service_correlation():
    request_id = uuid4()

    auth_alerts = [{
        "rule_id": "PASSWORD_SPRAY_001",
        "entity": "10.0.0.5",
        "last_seen": NOW,
        "request_ids": ["auth-1"],
    }]

    bola_alerts = [{
        "rule_id": "BOLA_001",
        "request_id": str(request_id),
        "occurred_at": NOW,
    }]

    authorization_events = [{
        "request_id": request_id,
        "actor_user_id": "alice",
        "target_user_id": "bob",
        "source_ip": "10.0.0.5",
    }]

    normalized = adapt_all_alerts(
        auth_alerts,
        bola_alerts,
        authorization_events,
    )

    incidents = correlate_alerts(normalized)

    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 2
    assert incidents[0]["services"] == [
        "auth-service",
        "user-service",
    ]
    assert incidents[0]["risk_score"] == 95


def test_unrelated_sources_stay_separate():
    auth_alerts = [{
        "rule_id": "BRUTE_FORCE_001",
        "entity": "alice@example.test",
        "last_seen": NOW,
        "source_ips": ["10.0.0.1"],
        "request_ids": ["auth-1"],
    }]

    normalized = adapt_all_alerts(
        auth_alerts,
        [],
        [],
    )

    normalized.append({
        "rule_id": "BOLA_001",
        "timestamp": NOW.isoformat(),
        "source_ip": "10.0.0.9",
        "service": "user-service",
        "actor": "alice",
        "target": "bob",
        "event_ids": ["bola-1"],
    })

    incidents = correlate_alerts(normalized)

    assert len(incidents) == 2