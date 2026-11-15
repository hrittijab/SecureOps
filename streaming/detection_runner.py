
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from streaming.event_loader import load_kafka_auth_events

from detection.rules.brute_force import detect as brute_force
from detection.rules.slow_brute_force import detect as slow_brute_force
from detection.rules.password_spray import detect as password_spray
from detection.rules.slow_password_spray import detect as slow_password_spray
from detection.rules.distributed_password_spray import (
    detect as distributed_spray,
)

from incidents.alert_adapter import adapt_auth_alert
from incidents.alert_correlator import correlate_alerts
from incidents.persistence import save_incident


REPORT_PATH = Path("results/kafka_detection_report.json")

DETECTION_INTERVAL_SECONDS = 10

RULES = [
    brute_force,
    slow_brute_force,
    password_spray,
    slow_password_spray,
    distributed_spray,
]


def run_once():
    """Run Kafka-backed detection and persist correlated incidents."""

    # Load authentication events ingested from Kafka.
    events = load_kafka_auth_events()

    # Execute existing detection rules.
    alerts = []

    for rule in RULES:
        alerts.extend(rule(events))

    # Normalize alerts for incident correlation.
    normalized = []

    for alert in alerts:
        normalized.extend(adapt_auth_alert(alert))

    # Correlate related security alerts.
    incidents = correlate_alerts(
        normalized,
        require_related_evidence=True,
    )

    # Persist incidents in PostgreSQL.
    persisted_incidents = []

    for incident in incidents:
        persistent_id = save_incident(incident)

        persisted_incidents.append({
            **incident,
            "persistent_incident_id": str(persistent_id),
        })

    # Build detection report.
    report = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "events_analyzed": len(events),
        "alert_count": len(alerts),
        "incident_count": len(incidents),
        "alerts": alerts,
        "incidents": persisted_incidents,
    }

    # Ensure the report directory exists.
    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Write to a temporary file first.
    temporary_path = REPORT_PATH.with_suffix(".tmp")

    temporary_path.write_text(
        json.dumps(
            report,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    # Atomically replace the previous report.
    temporary_path.replace(REPORT_PATH)

    return report


def main():
    """Continuously execute Kafka-backed threat detection."""

    print(
        "[SecureOps] Kafka-backed detection started",
        flush=True,
    )

    try:
        while True:
            report = run_once()

            print(
                f"[Detection] "
                f"Events={report['events_analyzed']} "
                f"Alerts={report['alert_count']} "
                f"Incidents={report['incident_count']}",
                flush=True,
            )

            time.sleep(DETECTION_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print(
            "\n[SecureOps] Detection stopped",
            flush=True,
        )


if __name__ == "__main__":
    main()
