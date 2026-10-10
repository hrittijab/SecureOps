
import json
import os

import psycopg

from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.password_spray import detect as detect_password_spray
from detection.rules.slow_password_spray import detect as detect_slow_password_spray
from detection.rules.jwt_abuse import detect as detect_jwt_abuse
from detection.rules.mass_assignment import detect as detect_mass_assignment

def get_database_url() -> str:
    database_url = os.getenv("DETECTION_DB_URL")

    if not database_url:
        raise RuntimeError(
            "DETECTION_DB_URL environment variable is not set."
        )

    return database_url


def get_user_database_url() -> str:
    database_url = os.getenv("DETECTION_USER_DB_URL")

    if not database_url:
        raise RuntimeError(
            "DETECTION_USER_DB_URL environment variable is not set."
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

    with psycopg.connect(get_database_url()) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [
                description.name for description in cursor.description
            ]
            return [
                dict(zip(columns, row))
                for row in cursor.fetchall()
            ]


def load_jwt_security_events() -> list[dict]:
    query = """
        SELECT
            event_type,
            failure_reason,
            source_ip,
            request_id,
            occurred_at
        FROM jwt_security_events
        ORDER BY occurred_at ASC
    """

    with psycopg.connect(get_user_database_url()) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [
                description.name for description in cursor.description
            ]
            return [
                dict(zip(columns, row))
                for row in cursor.fetchall()
            ]



def run_detection():
    auth_events = load_security_events()
    jwt_events = load_jwt_security_events()
    mass_assignment_events = load_mass_assignment_events()

    alerts = []

    alerts.extend(detect_brute_force(auth_events))
    alerts.extend(detect_password_spray(auth_events))
    alerts.extend(detect_slow_password_spray(auth_events))
    alerts.extend(detect_jwt_abuse(jwt_events))
    alerts.extend(
        detect_mass_assignment(mass_assignment_events)
    )

    all_events = (
        auth_events
        + jwt_events
        + mass_assignment_events
    )

    return all_events, alerts



def serialize_alert(alert: dict) -> dict:
    result = alert.copy()

    for field in ("first_seen", "last_seen", "occurred_at"):
        if field in result and hasattr(result[field], "isoformat"):
            result[field] = result[field].isoformat()

    return result


def main():
    try:
        events, alerts = run_detection()

    except (RuntimeError, psycopg.Error) as exc:
        print(f"[Detection Error] {exc}")
        raise SystemExit(1)

    print(
        f"[SecureOps Detection Engine] "
        f"Loaded {len(events)} security events."
    )

    if not alerts:
        print("[Detection] No alerts generated.")
        return

    print(f"[Detection] Generated {len(alerts)} alert(s).\n")

    for alert in alerts:
        print(json.dumps(serialize_alert(alert), indent=2))


    
def load_mass_assignment_events():
    query = """
        SELECT
            event_type,
            actor_user_id,
            target_user_id,
            outcome,
            attempted_fields,
            source_ip,
            request_id,
            occurred_at
        FROM mass_assignment_events
        ORDER BY occurred_at ASC
    """

    with psycopg.connect(get_user_database_url()) as connection:
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



if __name__ == "__main__":
    main()
