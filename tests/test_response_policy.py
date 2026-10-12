
from response.policy import recommend_responses


def make_incident(rules):
    return {
        "incident_id": "incident-123",
        "severity": "HIGH",
        "risk_score": 75,
        "rules": rules,
    }


def test_brute_force_response():
    result = recommend_responses(
        make_incident(["BRUTE_FORCE_001"])
    )

    assert result["status"] == "PENDING_REVIEW"
    assert result["recommendations"][0]["action"] == (
        "REVIEW_ACCOUNT_LOCKOUT"
    )


def test_multiple_rules_generate_multiple_actions():
    result = recommend_responses(
        make_incident([
            "PASSWORD_SPRAY_001",
            "JWT_ABUSE_001",
        ])
    )

    actions = {
        item["action"]
        for item in result["recommendations"]
    }

    assert actions == {
        "REVIEW_IP_RATE_LIMIT",
        "REVIEW_TOKEN_VALIDATION",
    }


def test_unknown_rule_requires_manual_review():
    result = recommend_responses(
        make_incident(["UNKNOWN_001"])
    )

    assert result["recommendations"][0]["action"] == (
        "MANUAL_SECURITY_REVIEW"
    )


def test_duplicate_rules_do_not_duplicate_actions():
    result = recommend_responses(
        make_incident([
            "BOLA_001",
            "BOLA_001",
        ])
    )

    assert len(result["recommendations"]) == 1
