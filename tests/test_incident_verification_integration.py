
from unittest.mock import patch

from incidents.detector_runner import build_report


def test_incident_verification_mapping():
    incidents = [
        {
            "incident_id": "INC-001",
            "severity": "HIGH",
            "risk_score": 75,
            "rules": [
                "MASS_ASSIGNMENT_001",
                "JWT_ABUSE_001",
            ],
            "services": ["user-service"],
            "source_ip": "127.0.0.1",
        }
    ]

    verification = {
        "verification_count": 1,
        "verifications": [
            {
                "rule_id": "MASS_ASSIGNMENT_001",
                "status": "VERIFIED",
                "control": "WRITABLE_FIELD_RESTRICTION",
                "verification_type": "COMPARATIVE_CONTROL_TEST",
                "source": "mass_assignment_replay.json",
            }
        ],
    }

    with (
        patch(
            "incidents.detector_runner.run_detection",
            return_value=([], []),
        ),
        patch(
            "incidents.detector_runner.load_authorization_events",
            return_value=[],
        ),
        patch(
            "incidents.detector_runner.load_mass_assignment_events",
            return_value=[],
        ),
        patch(
            "incidents.detector_runner.detect_bola",
            return_value=[],
        ),
        patch(
            "incidents.detector_runner.normalize_alerts",
            return_value=(
                [{"rule_id": "MASS_ASSIGNMENT_001"}],
                [],
            ),
        ),
        patch(
            "incidents.detector_runner.correlate_alerts",
            return_value=incidents,
        ),
        patch(
            "incidents.detector_runner.build_verification_report",
            return_value=verification,
        ),
    ):
        report = build_report()

    assert report["incident_count"] == 1
    assert report["response_count"] == 1
    assert report["control_verification_count"] == 1

    response = report["responses"][0]

    assert response["status"] == "PENDING_REVIEW"

    recommendations = {
        item["rule_id"]: item
        for item in response["recommendations"]
    }

    mass_assignment = recommendations[
        "MASS_ASSIGNMENT_001"
    ]["control_verification"]

    jwt = recommendations[
        "JWT_ABUSE_001"
    ]["control_verification"]

    assert mass_assignment["status"] == "VERIFIED"
    assert mass_assignment["evidence_scope"] == "SAVED_LAB_REPLAY"
    assert mass_assignment["source"] == "mass_assignment_replay.json"

    assert jwt["status"] == "NOT_EVALUATED"
    assert response["status"] == "PENDING_REVIEW"
