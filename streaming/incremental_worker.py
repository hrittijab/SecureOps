import os
from datetime import timedelta

import psycopg

from streaming.checkpoint import (
    get_checkpoint,
    save_checkpoint,
    INGESTION_LOCK_ID,
)
from streaming.event_adapter import kafka_to_auth_event
from streaming.detection_runner import RULES
from incidents.alert_adapter import adapt_auth_alert
from incidents.alert_correlator import correlate_alerts
from incidents.persistence import save_incident


WORKER_NAME = "secureops-incremental-detection-v1"
WINDOW_MINUTES = 15
BATCH_SIZE = 100


def run_incremental_once():
    """
    Process a batch of newly ingested events.

    Reconstruct a bounded event-time window, persist incidents,
    and advance the checkpoint after successful processing.
    """

    with psycopg.connect(
        os.environ["DETECTION_DB_URL"]
    ) as connection:

        with connection.transaction():

            with connection.cursor() as cursor:

                # Coordinate with cooperating Kafka ingestion writers.
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (INGESTION_LOCK_ID,),
                )

                checkpoint = get_checkpoint(
                    connection,
                    WORKER_NAME,
                )

                cursor.execute(
                    """
                    SELECT ingestion_id, payload
                    FROM kafka_ingested_events
                    WHERE ingestion_id > %s
                    ORDER BY ingestion_id
                    LIMIT %s
                    """,
                    (checkpoint, BATCH_SIZE),
                )

                new_rows = cursor.fetchall()

                if not new_rows:
                    return {
                        "new_events": 0,
                        "alerts": 0,
                        "incidents": 0,
                        "checkpoint": checkpoint,
                    }

                new_checkpoint = new_rows[-1][0]

                # Reconstruct context from recent event timestamps.
                cursor.execute(
                    """
                    SELECT MAX((payload->>'timestamp')::timestamptz)
                    FROM kafka_ingested_events
                    WHERE ingestion_id <= %s
                      AND service = 'auth-service'
                    """,
                    (new_checkpoint,),
                )

                latest = cursor.fetchone()[0]

                if latest is None:
                    save_checkpoint(
                        connection,
                        new_checkpoint,
                        WORKER_NAME,
                    )
                    return {
                        "new_events": len(new_rows),
                        "alerts": 0,
                        "incidents": 0,
                        "checkpoint": new_checkpoint,
                    }

                cutoff = latest - timedelta(
                    minutes=WINDOW_MINUTES
                )

                cursor.execute(
                    """
                    SELECT payload
                    FROM kafka_ingested_events
                    WHERE ingestion_id <= %s
                      AND service = 'auth-service'
                      AND (payload->>'timestamp')::timestamptz >= %s
                    ORDER BY (payload->>'timestamp')::timestamptz
                    """,
                    (new_checkpoint, cutoff),
                )

                rows = cursor.fetchall()

            events = [
                kafka_to_auth_event(payload)
                for (payload,) in rows
            ]

            alerts = []

            for rule in RULES:
                alerts.extend(rule(events))

            normalized = []

            for alert in alerts:
                normalized.extend(adapt_auth_alert(alert))

            incidents = correlate_alerts(
                normalized,
                require_related_evidence=True,
            )

            # Persist incidents using the same transaction.
            for incident in incidents:
                save_incident(
                    incident,
                    connection=connection,
                )

            # Advance only after successful detection and persistence.
            save_checkpoint(
                connection,
                new_checkpoint,
                WORKER_NAME,
            )

            return {
                "new_events": len(new_rows),
                "alerts": len(alerts),
                "incidents": len(incidents),
                "checkpoint": new_checkpoint,
            }


if __name__ == "__main__":
    result = run_incremental_once()

    print("\n=== INCREMENTAL DETECTION ===")

    for key, value in result.items():
        print(f"{key}: {value}")
