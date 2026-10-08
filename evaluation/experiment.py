import json
import os
import sys
from pathlib import Path

import psycopg

from attacks.runner import (
    run_auth_bruteforce,
    run_benign_auth,
    run_password_spray
)
from detection.runner import run_detection


def load_scenario(path: str) -> dict:
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def get_database_url() -> str:
    database_url = os.getenv("DETECTION_DB_URL")

    if not database_url:
        raise RuntimeError(
            "DETECTION_DB_URL environment variable is required"
        )

    return database_url


def reset_lab() -> None:
    """
    Reset authentication state and telemetry before each experiment.

    This is intentionally a lab-only operation so every scenario starts
    from a clean, reproducible state.
    """
    database_url = get_database_url()

    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                UPDATE users
                SET failed_login_attempts = 0,
                    locked_until = NULL
                """
            )

            cursor.execute(
                "TRUNCATE TABLE security_events"
            )

        connection.commit()


def execute_scenario(scenario: dict) -> dict:
    scenario_id = scenario["id"]

    if scenario_id.startswith("AUTH-BRUTEFORCE"):
        return run_auth_bruteforce(scenario)

    if (
        scenario_id.startswith("AUTH-PASSWORD-SPRAY")
        or scenario_id.startswith("BENIGN-PASSWORD-SPRAY")
    ):
        return run_password_spray(scenario)

    if scenario_id.startswith("BENIGN-AUTH"):
        return run_benign_auth(scenario)

    raise ValueError(
        f"Unsupported scenario: {scenario_id}"
    )


def evaluate(
    scenario: dict,
    execution_result: dict,
    events: list[dict],
    alerts: list[dict]
) -> dict:

    expected_rule_id = (
        scenario["evaluation"]["expected_rule_id"]
    )

    expected_alert = (
        scenario["evaluation"]["expected_alert"]
    )

    matching_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == expected_rule_id
    ]

    actual_alert = bool(matching_alerts)

    passed = actual_alert == expected_alert

    result = {
        "scenario_id": scenario["id"],
        "attempt_count": execution_result["attempt_count"],
        "expected_rule_id": expected_rule_id,
        "expected_alert": expected_alert,
        "actual_alert": actual_alert,
        "event_count": len(events),
        "alert_count": len(alerts),
        "matching_alert_count": len(matching_alerts),
        "result": "PASS" if passed else "FAIL"
    }

    if matching_alerts:
        alert = matching_alerts[0]

        threshold_time = (
            alert["last_seen"] -
            alert["first_seen"]
        ).total_seconds()

        result["threshold_time_seconds"] = round(
            threshold_time,
            3
        )

    return result


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m evaluation.experiment "
            "<scenario-file>"
        )
        sys.exit(1)

    scenario = load_scenario(sys.argv[1])

    print("\n[SecureOps Experiment]")
    print(f"Scenario: {scenario['id']}")

    print("\n[1/4] Resetting lab state...")

    reset_lab()

    print("[2/4] Executing scenario...")

    execution_result = execute_scenario(scenario)

    print("\n[3/4] Running detection...")

    events, alerts = run_detection()

    print(
        f"Loaded {len(events)} events; "
        f"generated {len(alerts)} alert(s)."
    )

    print("[4/4] Evaluating ground truth...")

    result = evaluate(
        scenario,
        execution_result,
        events,
        alerts
    )

    print("\n[Experiment Result]")
    print("-" * 60)

    print(
        json.dumps(
            result,
            indent=2
        )
    )

    if result["result"] == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()