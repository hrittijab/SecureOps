
from unittest.mock import patch

from incidents.detector_runner import build_report


def test_incident_response_end_to_end():
    auth_alert = {
        "rule_id": "PASSWORD_SPRAY_001",
        "entity": "127.0.0.1",
        "first_seen": "2026-10-10T12:00:00+00:00",
        "last_seen": "2026-10-10T12:00:00+00:00",
        "request_ids": ["auth-1"],
    }

    jwt_alert = {
        "rule_id": "JWT_ABUSE_001",
        "entity": "127.0.0.1",
        "source_ips": ["127.0.0.1"],
        "first_seen": "2026-10-10T12:01:00+00:00",
        "last_seen": "2026-10-10T12:01:00+00:00",
        "request_ids": ["jwt-1"],
    }

    with (
        patch(
            "incidents.detector_runner.run_detection",
            return_value=([], [auth_alert, jwt_alert]),
        ),
        patch(
            "incidents.detector_runner.load_authorization_events",
            return_value=[],
        ),
        patch(
            "incidents.detector_runner.load_mass_assignment_events",
            return_value=[],
        ),
    ):
        report = build_report()

    assert report["raw_alert_count"] == 2
    assert report["normalized_alert_count"] == 2
    assert report["incident_count"] == 2
    assert report["response_count"] == 2

    incidents_by_rule = {
        incident["rules"][0]: incident
        for incident in report["incidents"]
    }

    responses_by_id = {
        response["incident_id"]: response
        for response in report["responses"]
    }

    assert set(incidents_by_rule) == {
        "PASSWORD_SPRAY_001",
        "JWT_ABUSE_001",
    }

    expected = {
        "PASSWORD_SPRAY_001": {
            "evidence": ["auth-1"],
            "actions": {"REVIEW_IP_RATE_LIMIT"},
        },
        "JWT_ABUSE_001": {
            "evidence": ["jwt-1"],
            "actions": {"REVIEW_TOKEN_VALIDATION"},
        },
    }

    for rule_id, expectation in expected.items():
        incident = incidents_by_rule[rule_id]
        response = responses_by_id[incident["incident_id"]]

        assert incident["event_ids"] == expectation["evidence"]
        assert response["incident_id"] == incident["incident_id"]
        assert response["risk_score"] == incident["risk_score"]
        assert response["status"] == "PENDING_REVIEW"

        actions = {
            item["action"]
            for item in response["recommendations"]
        }

        assert actions == expectation["actions"]
