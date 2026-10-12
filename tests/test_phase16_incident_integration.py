
from datetime import datetime, timezone

from incidents.alert_adapter import adapt_auth_alert
from incidents.detector_runner import AUTH_RULES, normalize_alerts
from response.policy import recommend_responses


def make_alert(rule_id, entity, source_ips):
    return {
        "rule_id": rule_id,
        "entity": entity,
        "source_ips": source_ips,
        "targeted_accounts": [
            "user1@example.test",
            "user2@example.test",
        ],
        "last_seen": datetime.now(timezone.utc),
        "request_ids": ["req-1", "req-2"],
    }


def test_new_rules_are_supported():
    assert "SLOW_BRUTE_FORCE_001" in AUTH_RULES
    assert "DISTRIBUTED_PASSWORD_SPRAY_001" in AUTH_RULES


def test_slow_brute_force_normalization():
    alert = make_alert(
        "SLOW_BRUTE_FORCE_001",
        "victim@example.test",
        ["192.0.2.10"],
    )

    records = adapt_auth_alert(alert)

    assert len(records) == 1
    assert records[0]["source_ip"] == "192.0.2.10"
    assert records[0]["target"] == "victim@example.test"


def test_distributed_spray_preserves_source_ips():
    alert = make_alert(
        "DISTRIBUTED_PASSWORD_SPRAY_001",
        "authentication_service",
        ["192.0.2.20", "192.0.2.21"],
    )

    records = adapt_auth_alert(alert)

    assert len(records) == 2
    assert {record["source_ip"] for record in records} == {
        "192.0.2.20",
        "192.0.2.21",
    }

    for record in records:
        assert record["target"] == [
            "user1@example.test",
            "user2@example.test",
        ]


def test_new_rules_reach_incident_normalization():
    alerts = [
        make_alert(
            "SLOW_BRUTE_FORCE_001",
            "victim@example.test",
            ["192.0.2.10"],
        ),
        make_alert(
            "DISTRIBUTED_PASSWORD_SPRAY_001",
            "authentication_service",
            ["192.0.2.20", "192.0.2.21"],
        ),
    ]

    normalized, uncorrelated = normalize_alerts(
        alerts,
        authorization_events=[],
        mass_assignment_events=[],
    )

    assert len(normalized) == 3
    assert uncorrelated == []


def test_distributed_spray_requires_manual_review():
    incident = {
        "incident_id": "INC-TEST",
        "severity": "MEDIUM",
        "risk_score": 40,
        "rules": ["DISTRIBUTED_PASSWORD_SPRAY_001"],
    }

    response = recommend_responses(incident)

    assert response["status"] == "PENDING_REVIEW"

    recommendation = response["recommendations"][0]

    assert recommendation["action"] == (
        "INVESTIGATE_DISTRIBUTED_AUTH_ANOMALY"
    )
    assert recommendation["rule_id"] == (
        "DISTRIBUTED_PASSWORD_SPRAY_001"
    )
