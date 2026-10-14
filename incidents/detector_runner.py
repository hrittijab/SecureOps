
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from detection.runner import (
    run_detection,
    load_security_events,
    load_jwt_security_events,
    load_mass_assignment_events,
)
from detection.rules.bola import detect as detect_bola

from evaluation.remediation import (
    build_report as build_verification_report,
)

from incidents.alert_adapter import (
    adapt_auth_alert,
    adapt_bola_alert,
    adapt_jwt_alert,
    adapt_mass_assignment_alert,
)
from incidents.alert_correlator import correlate_alerts
from incidents.investigation import (
    find_incident_relationships,
    build_investigation_report,
)
from incidents.telemetry_adapter import normalize_security_events

from response.policy import recommend_responses


REPORT_PATH = Path("results/alert_incident_report.json")

AUTH_RULES = {
    "BRUTE_FORCE_001",
    "SLOW_BRUTE_FORCE_001",
    "PASSWORD_SPRAY_001",
    "SLOW_PASSWORD_SPRAY_001",
    "DISTRIBUTED_PASSWORD_SPRAY_001",
}

SUPPORTED_RULES = AUTH_RULES | {
    "BOLA_001",
    "JWT_ABUSE_001",
    "MASS_ASSIGNMENT_001",
}


def load_authorization_events():
    database_url = (
        os.getenv("DETECTION_USER_DB_URL")
        or os.environ["USER_DETECTION_DB_URL"]
    )

    query = """
        SELECT
            actor_user_id,
            target_user_id,
            action,
            outcome,
            request_id,
            source_ip,
            occurred_at
        FROM authorization_events
        ORDER BY occurred_at ASC
    """

    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)

            columns = [
                description.name
                for description in cursor.description
            ]

            return [
                dict(zip(columns, row))
                for row in cursor.fetchall()
            ]


def normalize_alerts(
    alerts,
    authorization_events,
    mass_assignment_events,
):
    normalized = []
    uncorrelated = []

    for alert in alerts:
        rule_id = alert["rule_id"]

        if rule_id in AUTH_RULES:
            converted = adapt_auth_alert(alert)

        elif rule_id == "BOLA_001":
            converted = [
                adapt_bola_alert(
                    alert,
                    authorization_events,
                )
            ]

        elif rule_id == "JWT_ABUSE_001":
            converted = adapt_jwt_alert(alert)

        elif rule_id == "MASS_ASSIGNMENT_001":
            converted = adapt_mass_assignment_alert(
                alert,
                mass_assignment_events,
            )

        else:
            converted = []

        if converted:
            normalized.extend(converted)

        else:
            reason = (
                "No source IP available"
                if rule_id in SUPPORTED_RULES
                else "Unsupported detection rule"
            )

            uncorrelated.append({
                "rule_id": rule_id,
                "entity": str(alert.get("entity")),
                "reason": reason,
            })

    return normalized, uncorrelated


def build_report():
    security_events, security_alerts = run_detection()

    authorization_events = load_authorization_events()
    mass_assignment_events = load_mass_assignment_events()

    bola_alerts = detect_bola(authorization_events)
    all_alerts = security_alerts + bola_alerts

    normalized, uncorrelated = normalize_alerts(
        all_alerts,
        authorization_events,
        mass_assignment_events,
    )

    # Strict incident correlation.
    incidents = correlate_alerts(
        normalized,
        require_related_evidence=True,
    )

    # Investigative links do not merge incidents.
    relationships = find_incident_relationships(incidents)

    # Collect normalized evidence for investigation timelines.
    investigation_events = []

    investigation_events.extend(
        normalize_security_events(
            load_security_events(),
            "auth-service",
        )
    )

    investigation_events.extend(
        normalize_security_events(
            load_jwt_security_events(),
            "user-service",
        )
    )

    investigation_events.extend(
        normalize_security_events(
            authorization_events,
            "user-service",
        )
    )

    investigation_events.extend(
        normalize_security_events(
            mass_assignment_events,
            "user-service",
        )
    )

    investigation_report = build_investigation_report(
        incidents,
        investigation_events,
        relationships,
    )

    # Remediation verification.
    verification_report = build_verification_report()

    verification_by_rule = {
        item["rule_id"]: item
        for item in verification_report["verifications"]
    }

    responses = []

    for incident in incidents:
        response = recommend_responses(incident)

        for recommendation in response["recommendations"]:
            evidence = verification_by_rule.get(
                recommendation["rule_id"]
            )

            if evidence is None:
                recommendation["control_verification"] = {
                    "status": "NOT_EVALUATED",
                    "reason": (
                        "No remediation verification "
                        "evidence available"
                    ),
                }

            else:
                recommendation["control_verification"] = {
                    "status": evidence["status"],
                    "control": evidence.get("control"),
                    "verification_type": evidence.get(
                        "verification_type"
                    ),
                    "source": evidence.get("source"),
                    "evidence_scope": "SAVED_LAB_REPLAY",
                }

        responses.append(response)

    return {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "security_events_analyzed": len(security_events),
        "authorization_events_analyzed": len(
            authorization_events
        ),
        "raw_alert_count": len(all_alerts),
        "normalized_alert_count": len(normalized),
        "uncorrelated_alert_count": len(uncorrelated),
        "incident_count": len(incidents),
        "relationship_count": len(relationships),
        "investigation_count": investigation_report[
            "investigation_count"
        ],
        "response_count": len(responses),
        "control_verification_count": verification_report[
            "verification_count"
        ],
        "incidents": incidents,
        "incident_relationships": relationships,
        "investigations": investigation_report["investigations"],
        "responses": responses,
        "uncorrelated_alerts": uncorrelated,
    }


def main():
    print("\n[SecureOps Unified Alert-Driven Incident Engine]")

    report = build_report()

    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_PATH.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    print(
        "Security events analyzed:",
        report["security_events_analyzed"],
    )
    print(
        "Authorization events analyzed:",
        report["authorization_events_analyzed"],
    )
    print(
        "Detection alerts:",
        report["raw_alert_count"],
    )
    print(
        "Normalized alert candidates:",
        report["normalized_alert_count"],
    )
    print(
        "Uncorrelated alerts:",
        report["uncorrelated_alert_count"],
    )
    print(
        "Incidents:",
        report["incident_count"],
    )
    print(
        "Investigations:",
        report["investigation_count"],
    )
    print(
        "Response plans:",
        report["response_count"],
    )
    print(
        "Controls evaluated:",
        report["control_verification_count"],
    )

    print("\n[Security Incidents]")

    for incident in report["incidents"]:
        print(
            f"\n[{incident['severity']}] "
            f"Risk={incident['risk_score']} "
            f"IP={incident['source_ip']}"
        )

        print(
            "Rules:",
            ", ".join(incident["rules"]),
        )

        print(
            "Services:",
            ", ".join(incident["services"]),
        )

    print("\n[Incident Relationships]")

    print(
        "Potential relationships:",
        report["relationship_count"],
    )

    for relationship in report["incident_relationships"]:
        print(
            "\nIncidents:",
            ", ".join(relationship["incident_ids"]),
        )

        print(
            "Relationship:",
            relationship["relationship_type"],
        )

        print(
            "Shared evidence:",
            relationship["shared_event_ids"],
        )

        print(
            "Time difference:",
            relationship["time_difference_seconds"],
            "seconds",
        )

    print("\n[Incident Investigations]")

    for investigation in report["investigations"]:
        print(
            f"\nIncident: {investigation['incident_id']}"
        )

        print(
            "Rules:",
            ", ".join(investigation["rules"]),
        )

        print(
            "Matched evidence:",
            investigation["matched_evidence_count"],
        )

        print(
            "Missing evidence:",
            len(investigation["missing_evidence_ids"]),
        )

        print(
            "Related incidents:",
            len(investigation["related_incidents"]),
        )

    print("\n[Incident Response Recommendations]")

    for response in report["responses"]:
        print(
            f"\nIncident: {response['incident_id']}"
        )
        print(
            f"Severity: {response['severity']}"
        )
        print(
            f"Risk Score: {response['risk_score']}"
        )
        print(
            f"Status: {response['status']}"
        )

        for recommendation in response["recommendations"]:
            print(
                f"  [{recommendation['rule_id']}] "
                f"{recommendation['action']}"
            )

            print(
                f"    {recommendation['description']}"
            )

            verification = recommendation["control_verification"]

            print(
                "    Control verification:",
                verification["status"],
            )

            if verification.get("source"):
                print(
                    "    Evidence:",
                    verification["source"],
                )

            if verification.get("verification_type"):
                print(
                    "    Verification type:",
                    verification["verification_type"],
                )

    print(f"\nReport saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
