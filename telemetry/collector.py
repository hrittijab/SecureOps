import os

import psycopg

from telemetry.normalize import (
    normalize_auth_event,
    normalize_authorization_event,
    normalize_timestamp,
)


def fetch_events(database_url: str, query: str, columns: list[str]):
    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()

    return [dict(zip(columns, row)) for row in rows]


def collect_auth_events() -> list[dict]:
    database_url = os.environ["DETECTION_DB_URL"]

    events = fetch_events(
        database_url,
        """
        SELECT id, event_type, user_id, email, source_ip,
               request_id, outcome, failure_reason, occurred_at
        FROM security_events
        ORDER BY occurred_at
        """,
        [
            "id",
            "event_type",
            "user_id",
            "email",
            "source_ip",
            "request_id",
            "outcome",
            "failure_reason",
            "occurred_at",
        ],
    )

    normalized = []

    for event in events:
        item = normalize_auth_event(event)
        item["timestamp"] = normalize_timestamp(item["timestamp"])
        normalized.append(item)

    return normalized


def collect_authorization_events() -> list[dict]:
    database_url = os.environ["USER_DETECTION_DB_URL"]

    events = fetch_events(
        database_url,
        """
        SELECT id, actor_user_id, target_user_id,
               action, outcome, request_id, source_ip, occurred_at
        FROM authorization_events
        ORDER BY occurred_at
        """,
        [
            "id",
            "actor_user_id",
            "target_user_id",
            "action",
            "outcome",
            "request_id",
            "source_ip",
            "occurred_at",
        ],
    )

    normalized = []

    for event in events:
        item = normalize_authorization_event(event)
        item["timestamp"] = normalize_timestamp(item["timestamp"])
        normalized.append(item)

    return normalized


def collect_all_events() -> list[dict]:
    events = collect_auth_events() + collect_authorization_events()
    return sorted(events, key=lambda event: event["timestamp"])