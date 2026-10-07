import json
import sys
from pathlib import Path

from detection.runner import run_detection


def load_scenario(path: str) -> dict:
    scenario_path = Path(path)

    with scenario_path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def evaluate_scenario(scenario: dict) -> dict:
    evaluation = scenario["evaluation"]

    expected_rule_id = evaluation["expected_rule_id"]
    expected_alert = evaluation["expected_alert"]

    events, alerts = run_detection()

    matching_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == expected_rule_id
    ]

    actual_alert = len(matching_alerts) > 0

    passed = actual_alert == expected_alert

    result = {
        "scenario_id": scenario["id"],
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

        threshold_time_seconds = (
            alert["last_seen"] -
            alert["first_seen"]
        ).total_seconds()

        result["threshold_time_seconds"] = round(
            threshold_time_seconds,
            3
        )

    return result


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m evaluation.runner "
            "<scenario-file>"
        )
        sys.exit(1)

    scenario = load_scenario(sys.argv[1])

    result = evaluate_scenario(scenario)

    print("\n[SecureOps Evaluation]")
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