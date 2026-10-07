import json
import os
import sys

import psycopg

from detection.rules.brute_force import detect


def get_database_url() -> str:
    database_url = os.getenv("DETECTION_DB_URL")

    if not database_url:
        print(
            "[Configuration Error] DETECTION_DB_URL is not set.",
            file=sys.stderr
        )
        sys.exit(1)

    return database_url


def load_security_events() -> list[dict]:

    query = """
        SELECT
            event_type,
            user_id,
            email,
            source_ip,
            request_id,
            outcome,
            failure_reason,
            occurred_at
        FROM security_events
        ORDER BY occurred_at ASC
    """

    database_url = get_database_url()

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


def serialize_alert(alert: dict) -> dict:

    result = alert.copy()

    result["first_seen"] = (
        result["first_seen"].isoformat()
    )

    result["last_seen"] = (
        result["last_seen"].isoformat()
    )

    return result


def main():

    events = load_security_events()

    print(
        f"[SecureOps Detection Engine] "
        f"Loaded {len(events)} security events."
    )

    alerts = detect(events)

    if not alerts:
        print("[Detection] No alerts generated.")
        return

    print(
        f"[Detection] Generated {len(alerts)} alert(s).\n"
    )

    for alert in alerts:
        print(
            json.dumps(
                serialize_alert(alert),
                indent=2
            )
        )


if __name__ == "__main__":
    main()