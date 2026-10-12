
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid5, NAMESPACE_DNS

from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.password_spray import detect as detect_password_spray
from detection.rules.slow_password_spray import detect as detect_slow_spray
from detection.rules.slow_brute_force import detect as detect_slow_brute_force
from detection.rules.distributed_password_spray import (
    detect as detect_distributed_password_spray,
)


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

    # Stage 1: Original detection rules
    baseline_alerts = (
        detect_brute_force(events)
        + detect_password_spray(events)
        + detect_slow_spray(events)
    )

    # Stage 2: Add slow brute-force detection
    improved_alerts = (
        baseline_alerts
        + detect_slow_brute_force(events)
    )

    # Stage 3: Add distributed password-spray detection
    final_alerts = (
        improved_alerts
        + detect_distributed_password_spray(events)
    )

    baseline_rules = sorted({
        alert["rule_id"] for alert in baseline_alerts
    })

    improved_rules = sorted({
        alert["rule_id"] for alert in improved_alerts
    })

    final_rules = sorted({
        alert["rule_id"] for alert in final_alerts
    })

    baseline_detected = bool(baseline_alerts)
    improved_detected = bool(improved_alerts)
    final_detected = bool(final_alerts)

    return {
        "scenario_id": scenario["id"],
        "name": scenario["name"],
        "event_count": len(events),

        # Historical expectation for baseline behavior
        "expected_detection": scenario["expected_detection"],

        # Stage 1
        "baseline_detected": baseline_detected,
        "baseline_rules": baseline_rules,

        # Stage 2
        "improved_detected": improved_detected,
        "improved_rules": improved_rules,
        "detection_improved": (
            improved_detected and not baseline_detected
        ),

        # Stage 3
        "final_detected": final_detected,
        "final_rules": final_rules,
        "final_detection_improved": (
            final_detected and not improved_detected
        ),

        # Preserve legacy baseline fields
        "detected": baseline_detected,
        "evasion_success": not baseline_detected,
        "detected_rules": baseline_rules,
        "result": (
            "PASS"
            if baseline_detected == scenario["expected_detection"]
            else "FAIL"
        ),
    }


def run_experiment():
    results = [
        evaluate_scenario(scenario)
        for scenario in build_scenarios()
    ]

    scenario_count = len(results)

    # Baseline metrics
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

    # Stage 2 metrics
    improved_detected_count = sum(
        result["improved_detected"]
        for result in results
    )

    newly_detected_count = sum(
        result["detection_improved"]
        for result in results
    )

    # Stage 3 metrics
    final_detected_count = sum(
        result["final_detected"]
        for result in results
    )

    final_newly_detected_count = sum(
        result["final_detection_improved"]
        for result in results
    )

    report = {
        "experiment": "authentication_detection_robustness",
        "synthetic_data": True,
        "scenario_count": scenario_count,

        # Original baseline
        "detected_count": detected_count,
        "evaded_count": evaded_count,
        "detection_rate": round(
            detected_count / scenario_count, 4
        ) if scenario_count else 0.0,

        # Baseline regression checks
        "checks_passed": passed_count,
        "passed": passed_count == scenario_count,

        # Stage 2
        "improved_detected_count": improved_detected_count,
        "improved_detection_rate": round(
            improved_detected_count / scenario_count, 4
        ) if scenario_count else 0.0,
        "newly_detected_count": newly_detected_count,

        # Stage 3
        "final_detected_count": final_detected_count,
        "final_detection_rate": round(
            final_detected_count / scenario_count, 4
        ) if scenario_count else 0.0,
        "final_newly_detected_count": final_newly_detected_count,

        # Scenario details
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
        baseline_status = (
            "DETECTED" if result["baseline_detected"] else "EVADED"
        )
        improved_status = (
            "DETECTED" if result["improved_detected"] else "EVADED"
        )
        final_status = (
            "DETECTED" if result["final_detected"] else "EVADED"
        )

        print(
            f"{result['scenario_id']}: "
            f"baseline={baseline_status:<8} "
            f"improved={improved_status:<8} "
            f"final={final_status:<8}"
        )

    print("-" * 65)
    print(f"Scenarios:           {scenario_count}")
    print(f"Baseline detected:   {detected_count}/{scenario_count}")
    print(
        f"Improved detected:   "
        f"{improved_detected_count}/{scenario_count}"
    )
    print(
        f"Final detected:      "
        f"{final_detected_count}/{scenario_count}"
    )
    print(f"Baseline checks:     {passed_count}/{scenario_count}")
    print(f"Report saved:        {RESULT_PATH}")

    return report


if __name__ == "__main__":
    report = run_experiment()
    raise SystemExit(0 if report["passed"] else 1)
