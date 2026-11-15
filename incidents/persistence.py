
import json
import os
from uuid import uuid4

import psycopg


def save_incident(incident, connection=None):
    """Persist an incident and its evidence atomically."""

    owns_connection = connection is None

    if owns_connection:
        connection = psycopg.connect(
            os.environ["DETECTION_DB_URL"]
        )

    try:
        with connection.transaction():
            with connection.cursor() as cursor:
                event_ids = sorted({
                    str(event_id)
                    for event_id in incident["event_ids"]
                })

                existing_id = None

                if event_ids:
                    cursor.execute(
                        """
                        SELECT si.id
                        FROM security_incidents si
                        JOIN security_incident_evidence sie
                          ON sie.incident_id = si.id
                        WHERE sie.event_id = ANY(%s::uuid[])
                          AND si.source_ip = %s
                          AND si.status != 'RESOLVED'
                        ORDER BY si.created_at, si.id
                        LIMIT 1
                        FOR UPDATE OF si
                        """,
                        (event_ids, incident["source_ip"]),
                    )

                    row = cursor.fetchone()

                    if row:
                        existing_id = row[0]

                if existing_id is None:
                    persistent_id = uuid4()

                    cursor.execute(
                        """
                        INSERT INTO security_incidents (
                            id,
                            correlation_id,
                            source_ip,
                            severity,
                            risk_score,
                            alert_count,
                            rules,
                            services,
                            timeline,
                            first_seen,
                            last_seen
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s,
                            %s::jsonb, %s::jsonb, %s::jsonb,
                            %s, %s
                        )
                        """,
                        (
                            persistent_id,
                            incident["incident_id"],
                            incident["source_ip"],
                            incident["severity"],
                            incident["risk_score"],
                            incident["alert_count"],
                            json.dumps(incident["rules"]),
                            json.dumps(incident["services"]),
                            json.dumps(incident["timeline"]),
                            incident["first_seen"],
                            incident["last_seen"],
                        ),
                    )

                else:
                    persistent_id = existing_id

                    cursor.execute(
                        """
                        UPDATE security_incidents
                        SET
                            correlation_id = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s::uuid
                                ELSE correlation_id
                            END,

                            severity = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s
                                ELSE severity
                            END,

                            risk_score = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s
                                ELSE risk_score
                            END,

                            alert_count = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s
                                ELSE alert_count
                            END,

                            rules = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s::jsonb
                                ELSE rules
                            END,

                            services = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s::jsonb
                                ELSE services
                            END,

                            timeline = CASE
                                WHEN %s::timestamptz > last_seen
                                THEN %s::jsonb
                                ELSE timeline
                            END,

                            first_seen = LEAST(first_seen, %s),
                            last_seen = GREATEST(last_seen, %s),
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (
                            incident["last_seen"],
                            incident["incident_id"],

                            incident["last_seen"],
                            incident["severity"],

                            incident["last_seen"],
                            incident["risk_score"],

                            incident["last_seen"],
                            incident["alert_count"],

                            incident["last_seen"],
                            json.dumps(incident["rules"]),

                            incident["last_seen"],
                            json.dumps(incident["services"]),

                            incident["last_seen"],
                            json.dumps(incident["timeline"]),

                            incident["first_seen"],
                            incident["last_seen"],
                            persistent_id,
                        ),
                    )

                for event_id in event_ids:
                    cursor.execute(
                        """
                        INSERT INTO security_incident_evidence (
                            incident_id,
                            event_id
                        )
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (persistent_id, event_id),
                    )

        return persistent_id

    finally:
        if owns_connection:
            connection.close()
