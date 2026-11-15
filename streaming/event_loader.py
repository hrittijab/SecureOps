import json
import os

import psycopg

from streaming.event_adapter import kafka_to_auth_event


def load_kafka_auth_events() -> list[dict]:
    database_url = os.environ["DETECTION_DB_URL"]

    query = """
        SELECT payload
        FROM kafka_ingested_events
        WHERE service = 'auth-service'
        ORDER BY received_at, event_id
    """

    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()

    events = []

    for (payload,) in rows:
        if isinstance(payload, str):
            payload = json.loads(payload)

        events.append(kafka_to_auth_event(payload))

    return sorted(
        events,
        key=lambda event: event["occurred_at"],
    )
