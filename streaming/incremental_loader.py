import json
import os

import psycopg

from streaming.event_adapter import kafka_to_auth_event


def load_event_batch(after_id=0, batch_size=100):
    """Load a bounded batch of Kafka-ingested authentication events."""

    if after_id < 0:
        raise ValueError("after_id cannot be negative")

    if not 1 <= batch_size <= 1000:
        raise ValueError("batch_size must be between 1 and 1000")

    query = """
        SELECT ingestion_id, payload
        FROM kafka_ingested_events
        WHERE ingestion_id > %s
          AND service = 'auth-service'
        ORDER BY ingestion_id ASC
        LIMIT %s
    """

    with psycopg.connect(
        os.environ["DETECTION_DB_URL"]
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (after_id, batch_size))
            rows = cursor.fetchall()

    events = []

    for ingestion_id, payload in rows:
        if isinstance(payload, str):
            payload = json.loads(payload)

        event = kafka_to_auth_event(payload)

        events.append({
            "ingestion_id": ingestion_id,
            "event": event,
        })

    return events
