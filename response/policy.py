
RESPONSE_ACTIONS = {
    "BRUTE_FORCE_001": {
        "action": "REVIEW_ACCOUNT_LOCKOUT",
        "description": "Review account lockout and rate-limit controls.",
    },
    "PASSWORD_SPRAY_001": {
        "action": "REVIEW_IP_RATE_LIMIT",
        "description": "Review source-IP rate limits and targeted accounts.",
    },
    "SLOW_PASSWORD_SPRAY_001": {
        "action": "REVIEW_DISTRIBUTED_AUTH_ABUSE",
        "description": "Investigate low-frequency authentication failures.",
    },
    "JWT_ABUSE_001": {
        "action": "REVIEW_TOKEN_VALIDATION",
        "description": "Investigate rejected tokens and validation controls.",
    },
    "MASS_ASSIGNMENT_001": {
        "action": "REVIEW_FIELD_ALLOWLIST",
        "description": "Verify writable-field restrictions on user updates.",
    },
    "BOLA_001": {
        "action": "REVIEW_OBJECT_AUTHORIZATION",
        "description": "Verify object-level access controls.",
    },
    "SLOW_BRUTE_FORCE_001": {
    "action": "REVIEW_SLOW_AUTH_ABUSE",
    "description": (
        "Investigate repeated authentication failures "
        "over an extended time window."
    ),
    },
    "DISTRIBUTED_PASSWORD_SPRAY_001": {
        "action": "INVESTIGATE_DISTRIBUTED_AUTH_ANOMALY",
        "description": (
            "Review cross-IP authentication failures and "
            "corroborate evidence before taking action."
        ),
    },
}


def recommend_responses(incident):
    recommendations = []

    for rule_id in sorted(set(incident.get("rules", []))):
        policy = RESPONSE_ACTIONS.get(rule_id)

        if policy is None:
            recommendations.append({
                "rule_id": rule_id,
                "action": "MANUAL_SECURITY_REVIEW",
                "description": "Investigate unrecognized detection rule.",
            })
            continue

        recommendations.append({
            "rule_id": rule_id,
            **policy,
        })

    return {
        "incident_id": incident["incident_id"],
        "severity": incident["severity"],
        "risk_score": incident["risk_score"],
        "status": "PENDING_REVIEW",
        "recommendations": recommendations,
    }
