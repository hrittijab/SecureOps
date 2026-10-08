import json
import os

import psycopg

from detection.rules.brute_force import (
    detect as detect_brute_force
)
from detection.rules.password_spray import (
    detect as detect_password_spray
)

from detection.rules.slow_password_spray import (
    detect as detect_slow_password_spray
)


def get_database_url() -> str:
    database_url = os.getenv("DETECTION_DB_URL")

    if not database_url:
        raise RuntimeError(
            "DETECTION_DB_URL environment variable is not set."
        )

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


def run_detection() -> tuple[list[dict], list[dict]]:
    events = load_security_events()

    alerts = []

    alerts.extend(
        detect_brute_force(events)
    )

    alerts.extend(
        detect_password_spray(events)
    )

    alerts.extend(
        detect_slow_password_spray(events)
    )

    return events, alerts


def serialize_alert(alert: dict) -> dict:
    result = alert.copy()

    if "first_seen" in result:
        result["first_seen"] = (
            result["first_seen"].isoformat()
        )

    if "last_seen" in result:
        result["last_seen"] = (
            result["last_seen"].isoformat()
        )

    return result


def main():
    try:
        events, alerts = run_detection()

    except RuntimeError as exc:
        print(f"[Configuration Error] {exc}")
        raise SystemExit(1)

    print(
        f"[SecureOps Detection Engine] "
        f"Loaded {len(events)} security events."
    )

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