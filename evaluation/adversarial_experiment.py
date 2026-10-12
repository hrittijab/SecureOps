
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid5, NAMESPACE_DNS

from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.password_spray import detect as detect_password_spray
from detection.rules.slow_password_spray import detect as detect_slow_spray


START = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
RESULT_PATH = Path("results/adversarial_evaluation.json")


def make_failure(email, source_ip, seconds):
    return {
        "event_type": "LOGIN_FAILURE",
        "user_id": None,
        "email": email,
        "source_ip": source_ip,
        "request_id": uuid5(
            NAMESPACE_DNS,
            f"{email}:{source_ip}:{seconds}",
        ),
        "outcome": "FAILURE",
        "failure_reason": "INVALID_CREDENTIALS",
        "occurred_at": START + timedelta(seconds=seconds),
    }


def build_scenarios():
    return [
        {
            "id": "ADV-001",
            "name": "Rapid brute force",
            "expected_detection": True,
            "events": [
                make_failure(
                    "victim@example.test",
                    "192.0.2.10",
                    i * 5,
                )
                for i in range(5)
            ],
        },
        {
            "id": "ADV-002",
            "name": "Distributed rapid brute force",
            "expected_detection": True,
            "events": [
                make_failure(
                    "victim@example.test",
                    f"192.0.2.{20 + i}",
                    i * 5,
                )
                for i in range(5)
            ],
        },
        {
            "id": "ADV-003",
            "name": "Slow single-account brute force",
            "expected_detection": False,
            "events": [
                make_failure(
                    "victim@example.test",
                    "192.0.2.30",
                    i * 90,
                )
                for i in range(5)
            ],
        },
        {
            "id": "ADV-004",
            "name": "Rapid password spray",
            "expected_detection": True,
            "events": [
                make_failure(
                    f"user{i}@example.test",
                    "192.0.2.40",
                    i * 5,
                )
                for i in range(5)
            ],
        },
        {
            "id": "ADV-005",
            "name": "Low-and-slow password spray",
            "expected_detection": True,
            "events": [
                make_failure(
                    f"user{i}@example.test",
                    "192.0.2.50",
                    i * 90,
                )
                for i in range(8)
            ],
        },
        {
            "id": "ADV-006",
            "name": "Distributed password spray",
            "expected_detection": False,
            "events": [
                make_failure(
                    f"user{i}@example.test",
                    f"192.0.2.{60 + i}",
                    i * 5,
                )
                for i in range(8)
            ],
        },
    ]


def evaluate_scenario(scenario):
    events = scenario["events"]

    alerts = (
        detect_brute_force(events)
        + detect_password_spray(events)
        + detect_slow_spray(events)
    )

    detected_rules = sorted({
        alert["rule_id"]
        for alert in alerts
    })

    detected = bool(alerts)
    expected = scenario["expected_detection"]

    return {
        "scenario_id": scenario["id"],
        "name": scenario["name"],
        "event_count": len(events),
        "expected_detection": expected,
        "detected": detected,
        "evasion_success": not detected,
        "detected_rules": detected_rules,
        "result": "PASS" if detected == expected else "FAIL",
    }


def run_experiment():
    results = [
        evaluate_scenario(scenario)
        for scenario in build_scenarios()
    ]

    detected_count = sum(
        result["detected"]
        for result in results
    )

    evaded_count = sum(
        result["evasion_success"]
        for result in results
    )

    passed_count = sum(
        result["result"] == "PASS"
        for result in results
    )

    report = {
        "experiment": "authentication_detection_robustness",
        "synthetic_data": True,
        "scenario_count": len(results),
        "detected_count": detected_count,
        "evaded_count": evaded_count,
        "detection_rate": round(
            detected_count / len(results), 4
        ) if results else 0.0,
        "checks_passed": passed_count,
        "passed": passed_count == len(results),
        "results": results,
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n[SecureOps Adversarial Detection Evaluation]")
    print("=" * 65)

    for result in results:
        status = result["result"]
        detection = "DETECTED" if result["detected"] else "EVADED"

        print(
            f"{result['scenario_id']}: "
            f"{detection:<10} "
            f"{status:<5} "
            f"{result['name']}"
        )

    print("-" * 65)
    print(f"Scenarios:       {len(results)}")
    print(f"Detected:        {detected_count}")
    print(f"Evaded:          {evaded_count}")
    print(f"Checks passed:   {passed_count}/{len(results)}")
    print(f"Report saved:   {RESULT_PATH}")

    return report


if __name__ == "__main__":
    report = run_experiment()
    raise SystemExit(0 if report["passed"] else 1)
