import json
import os
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import requests

from detection.rules.bola import detect


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"

ACTOR_ID = "11111111-1111-1111-1111-111111111111"
TARGET_ID = "22222222-2222-2222-2222-222222222222"

BASE_URL = "http://localhost:8082"

DATABASE_URL = os.environ["USER_DETECTION_DB_URL"]


def reset_events():
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE authorization_events")
        connection.commit()


def request_profile(actor_id, target_id):
    response = requests.get(
        f"{BASE_URL}/api/users/{target_id}",
        headers={"X-User-Id": actor_id},
        timeout=10,
    )

    return {
        "status_code": response.status_code,
        "data_exposed": response.status_code == 200,
    }


def load_events():
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
        ORDER BY occurred_at
    """

    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()

    return [
        {
            "actor_user_id": str(row[0]),
            "target_user_id": str(row[1]),
            "action": row[2],
            "outcome": row[3],
            "request_id": row[4],
            "source_ip": row[5],
            "occurred_at": row[6],
        }
        for row in rows
    ]


def serialize_alert(alert):
    result = dict(alert)

    if "occurred_at" in result:
        result["occurred_at"] = (
            result["occurred_at"].isoformat()
        )

    return result


def run():
    print("=" * 70)
    print("SECUREOPS BOLA REMEDIATION VALIDATION")
    print("=" * 70)

    reset_events()

    print("\n[1] Replaying Alice -> Bob attack...")
    attack = request_profile(ACTOR_ID, TARGET_ID)

    print("[2] Testing legitimate Alice -> Alice access...")
    legitimate = request_profile(ACTOR_ID, ACTOR_ID)

    print("[3] Loading authorization telemetry...")
    events = load_events()

    print("[4] Running BOLA exploit detector...")
    alerts = detect(events)

    bola_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "BOLA_001"
    ]

    denied_events = [
        event
        for event in events
        if (
            event["actor_user_id"] == ACTOR_ID
            and event["target_user_id"] == TARGET_ID
            and event["outcome"] == "DENIED"
        )
    ]

    authorized_events = [
        event
        for event in events
        if (
            event["actor_user_id"] == ACTOR_ID
            and event["target_user_id"] == ACTOR_ID
            and event["outcome"] == "AUTHORIZED"
        )
    ]

    checks = {
        "attack_blocked": attack["status_code"] == 403,
        "no_target_data_exposed": not attack["data_exposed"],
        "denied_event_recorded": len(denied_events) >= 1,
        "no_successful_bola_alert": len(bola_alerts) == 0,
        "legitimate_access_preserved": (
            legitimate["status_code"] == 200
        ),
        "authorized_event_recorded": (
            len(authorized_events) >= 1
        ),
    }

    passed = all(checks.values())

    result = {
        "scenario_id": "BOLA-PROFILE-001",
        "mode": "remediated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_http_status": attack["status_code"],
        "legitimate_http_status": legitimate["status_code"],
        "authorization_event_count": len(events),
        "bola_alert_count": len(bola_alerts),
        "checks": checks,
        "result": "PASS" if passed else "FAIL",
        "alerts": [
            serialize_alert(alert)
            for alert in bola_alerts
        ],
    }

    print()
    print("-" * 70)

    for name, value in checks.items():
        label = name.replace("_", " ").title()
        print(
            f"{label:<35} "
            f"{'PASS' if value else 'FAIL'}"
        )

    print("-" * 70)

    print(
        f"Attack HTTP status:       "
        f"{attack['status_code']}"
    )
    print(
        f"Legitimate HTTP status:   "
        f"{legitimate['status_code']}"
    )
    print(
        f"Authorization events:     "
        f"{len(events)}"
    )
    print(
        f"Successful BOLA alerts:   "
        f"{len(bola_alerts)}"
    )

    print()
    print(
        f"FINAL RESULT: "
        f"{result['result']}"
    )

    RESULTS_DIR.mkdir(exist_ok=True)

    output = (
        RESULTS_DIR
        / "bola_remediation.json"
    )

    with output.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            result,
            file,
            indent=2,
        )

    print(f"\nResults saved to: {output}")

    return passed


if __name__ == "__main__":
    raise SystemExit(
        0 if run() else 1
    )