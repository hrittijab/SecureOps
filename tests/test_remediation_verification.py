
from evaluation.remediation import (
    verify_mass_assignment,
    verify_bola,
)


def test_mass_assignment_verified():
    report = {
        "results": {
            "vulnerable_mass_assignment": {
                "passed": True,
                "attack_succeeded": True,
                "http_status": 200,
            },
            "defended_mass_assignment": {
                "passed": True,
                "attack_blocked": True,
                "http_status": 400,
            },
            "original_tier_restored": {
                "passed": True,
            },
        }
    }

    result = verify_mass_assignment(report)

    assert result["status"] == "VERIFIED"
    assert result["verification_type"] == "COMPARATIVE_CONTROL_TEST"


def test_mass_assignment_failed():
    report = {
        "results": {
            "vulnerable_mass_assignment": {
                "passed": True,
                "attack_succeeded": True,
                "http_status": 200,
            },
            "defended_mass_assignment": {
                "passed": False,
                "attack_blocked": False,
                "http_status": 200,
            },
            "original_tier_restored": {
                "passed": True,
            },
        }
    }

    result = verify_mass_assignment(report)

    assert result["status"] == "FAILED"


def test_mass_assignment_missing_evidence():
    result = verify_mass_assignment(None)

    assert result["status"] == "INCONCLUSIVE"


def test_bola_verified():
    report = {
        "checks": {
            "legitimate_access_allowed": True,
            "cross_user_access_blocked": True,
            "spoofed_identity_blocked": True,
            "cross_user_data_not_returned": True,
        }
    }

    result = verify_bola(report)

    assert result["status"] == "VERIFIED"


def test_bola_failed():
    report = {
        "checks": {
            "legitimate_access_allowed": True,
            "cross_user_access_blocked": False,
            "spoofed_identity_blocked": True,
            "cross_user_data_not_returned": False,
        }
    }

    result = verify_bola(report)

    assert result["status"] == "FAILED"


def test_bola_missing_evidence():
    result = verify_bola(None)

    assert result["status"] == "INCONCLUSIVE"
