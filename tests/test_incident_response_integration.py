
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
    assert report["incident_count"] == 1
    assert report["response_count"] == 1

    incident = report["incidents"][0]
    response = report["responses"][0]

    assert response["incident_id"] == incident["incident_id"]
    assert response["risk_score"] == incident["risk_score"]
    assert response["status"] == "PENDING_REVIEW"

    actions = {
        item["action"]
        for item in response["recommendations"]
    }

    assert actions == {
        "REVIEW_IP_RATE_LIMIT",
        "REVIEW_TOKEN_VALIDATION",
    }
