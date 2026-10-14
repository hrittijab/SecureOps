
from incidents.investigation import build_investigation_report


def test_investigation_report_preserves_evidence_and_relationships():
    incidents = [
        {
            "incident_id": "inc-1",
            "source_ip": "10.0.0.5",
            "severity": "HIGH",
            "risk_score": 75,
            "rules": ["PASSWORD_SPRAY_001"],
            "event_ids": ["auth-1", "auth-2"],
        }
    ]

    events = [
        {
            "event_id": "auth-1",
            "timestamp": "2026-10-10T12:00:00+00:00",
            "service": "auth-service",
            "event_type": "LOGIN_FAILED",
        },
        {
            "event_id": "unrelated-1",
            "timestamp": "2026-10-10T12:01:00+00:00",
            "service": "auth-service",
            "event_type": "LOGIN_SUCCESS",
        },
    ]

    result = build_investigation_report(
        incidents,
        events,
        relationships=[],
    )

    assert result["investigation_count"] == 1

    investigation = result["investigations"][0]

    assert investigation["incident_id"] == "inc-1"
    assert investigation["severity"] == "HIGH"
    assert investigation["risk_score"] == 75
    assert investigation["rules"] == ["PASSWORD_SPRAY_001"]

    assert investigation["matched_evidence_count"] == 1
    assert investigation["missing_evidence_ids"] == ["auth-2"]
    assert [
        event["event_id"]
        for event in investigation["timeline"]
    ] == ["auth-1"]

    assert investigation["related_incidents"] == []


def test_investigation_report_attaches_relationships_to_both_incidents():
    incidents = [
        {"incident_id": "inc-1", "event_ids": []},
        {"incident_id": "inc-2", "event_ids": []},
    ]

    relationships = [
        {
            "incident_ids": ["inc-1", "inc-2"],
            "relationship_type": "POSSIBLE_RELATED_ACTIVITY",
            "shared_event_ids": [],
        }
    ]

    result = build_investigation_report(
        incidents,
        events=[],
        relationships=relationships,
    )

    for investigation in result["investigations"]:
        assert len(investigation["related_incidents"]) == 1


def test_investigation_report_handles_empty_input():
    result = build_investigation_report([], [], [])

    assert result == {
        "investigation_count": 0,
        "investigations": [],
    }
