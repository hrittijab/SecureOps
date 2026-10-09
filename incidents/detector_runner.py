import json
import os
from pathlib import Path

import psycopg

from detection.runner import run_detection
from detection.rules.bola import detect as detect_bola

from incidents.alert_adapter import adapt_all_alerts
from incidents.alert_correlator import correlate_alerts


REPORT_PATH = Path("results/alert_incident_report.json")


def load_authorization_events():
    database_url = os.environ["USER_DETECTION_DB_URL"]

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


def build_report():
    auth_events, auth_alerts = run_detection()

    authorization_events = load_authorization_events()

    bola_alerts = detect_bola(authorization_events)

    normalized_alerts = adapt_all_alerts(
        auth_alerts,
        bola_alerts,
        authorization_events,
    )

    incidents = correlate_alerts(normalized_alerts)

    return {
        "auth_events_analyzed": len(auth_events),
        "authorization_events_analyzed": len(
            authorization_events
        ),
        "raw_alert_count": len(auth_alerts) + len(bola_alerts),
        "normalized_alert_count": len(normalized_alerts),
        "incident_count": len(incidents),
        "incidents": incidents,
    }


def main():
    print("\n[SecureOps Alert-Driven Incident Engine]")

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
        "Authentication events analyzed:",
        report["auth_events_analyzed"],
    )
    print(
        "Authorization events analyzed:",
        report["authorization_events_analyzed"],
    )
    print("Detector alerts:", report["raw_alert_count"])
    print(
        "Normalized alert candidates:",
        report["normalized_alert_count"],
    )
    print("Incidents:", report["incident_count"])

    for incident in report["incidents"]:
        print(
            f"\n[{incident['severity']}] "
            f"Risk={incident['risk_score']} "
            f"IP={incident['source_ip']}"
        )
        print("Rules:", ", ".join(incident["rules"]))
        print("Services:", ", ".join(incident["services"]))

    print(f"\nReport saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()