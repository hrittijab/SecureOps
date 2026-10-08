import json
import sys
from pathlib import Path

from detection.runner import run_detection
from evaluation.experiment import (
    evaluate,
    execute_scenario,
    load_scenario,
    reset_lab,
)


SCENARIO_DIRECTORY = Path("attacks/scenarios")
RESULTS_DIRECTORY = Path("results")
RESULTS_FILE = RESULTS_DIRECTORY / "security_benchmark.json"


def discover_scenarios() -> list[Path]:
    """
    Discover scenarios supported by the authentication
    detection benchmark.

    BOLA scenarios are evaluated separately by
    evaluation.bola_experiment because they validate
    remediation behavior rather than the auth detection
    pipeline.
    """
    return sorted(
        path
        for path in SCENARIO_DIRECTORY.glob("*.json")
        if not path.name.startswith("bola_")
    )


def run_scenario(path: Path) -> dict:
    scenario = load_scenario(str(path))

    print("\n" + "=" * 70)
    print(f"Running: {scenario['id']}")
    print("=" * 70)

    # Every authentication experiment starts from clean
    # authentication state and an empty security-event table.
    reset_lab()

    execution_result = execute_scenario(scenario)

    events, alerts = run_detection()

    return evaluate(
        scenario,
        execution_result,
        events,
        alerts,
    )


def calculate_metrics(results: list[dict]) -> dict:
    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for result in results:
        expected = result["expected_alert"]
        actual = result["actual_alert"]

        if expected and actual:
            true_positive += 1

        elif not expected and not actual:
            true_negative += 1

        elif not expected and actual:
            false_positive += 1

        elif expected and not actual:
            false_negative += 1

    attack_total = (
        true_positive + false_negative
    )

    benign_total = (
        true_negative + false_positive
    )

    detection_rate = (
        true_positive / attack_total
        if attack_total
        else 0.0
    )

    false_positive_rate = (
        false_positive / benign_total
        if benign_total
        else 0.0
    )

    return {
        "true_positives": true_positive,
        "true_negatives": true_negative,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "attack_detection_rate": round(
            detection_rate,
            4,
        ),
        "false_positive_rate": round(
            false_positive_rate,
            4,
        ),
    }


def print_results(
    results: list[dict],
    metrics: dict,
) -> None:
    print("\n")
    print("=" * 70)
    print("SECUREOPS BENCHMARK RESULTS")
    print("=" * 70)

    print(
        f"{'Scenario':<28}"
        f"{'Expected':<12}"
        f"{'Detected':<12}"
        f"{'Result':<10}"
    )

    print("-" * 70)

    for result in results:
        expected = (
            "ALERT"
            if result["expected_alert"]
            else "NONE"
        )

        detected = (
            "YES"
            if result["actual_alert"]
            else "NO"
        )

        print(
            f"{result['scenario_id']:<28}"
            f"{expected:<12}"
            f"{detected:<12}"
            f"{result['result']:<10}"
        )

    print("-" * 70)

    print(
        f"True positives:        "
        f"{metrics['true_positives']}"
    )

    print(
        f"True negatives:        "
        f"{metrics['true_negatives']}"
    )

    print(
        f"False positives:       "
        f"{metrics['false_positives']}"
    )

    print(
        f"False negatives:       "
        f"{metrics['false_negatives']}"
    )

    print(
        f"Attack detection rate: "
        f"{metrics['attack_detection_rate']:.2%}"
    )

    print(
        f"False-positive rate:   "
        f"{metrics['false_positive_rate']:.2%}"
    )

    passed = sum(
        result["result"] == "PASS"
        for result in results
    )

    print(
        f"Scenarios passed:      "
        f"{passed}/{len(results)}"
    )

    print("=" * 70)


def save_results(
    results: list[dict],
    metrics: dict,
) -> None:
    RESULTS_DIRECTORY.mkdir(
        exist_ok=True
    )

    output = {
        "scenario_count": len(results),
        "results": results,
        "metrics": metrics,
    }

    with RESULTS_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            output,
            file,
            indent=2,
        )

    print(
        f"\nResults saved to: {RESULTS_FILE}"
    )


def main():
    scenario_paths = discover_scenarios()

    if not scenario_paths:
        print(
            "[Benchmark Error] "
            "No supported authentication scenarios "
            "found in attacks/scenarios."
        )
        sys.exit(1)

    print("\n[SecureOps Security Benchmark]")

    print(
        f"Discovered "
        f"{len(scenario_paths)} scenario(s)."
    )

    results = []

    for scenario_path in scenario_paths:
        result = run_scenario(
            scenario_path
        )

        results.append(result)

    metrics = calculate_metrics(results)

    print_results(
        results,
        metrics,
    )

    save_results(
        results,
        metrics,
    )

    passed = sum(
        result["result"] == "PASS"
        for result in results
    )

    if passed != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()