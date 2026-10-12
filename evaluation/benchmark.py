
import json
import sys
from pathlib import Path

from detection.runner import load_security_events
from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.password_spray import detect as detect_password_spray
from detection.rules.slow_password_spray import (
    detect as detect_slow_password_spray,
)
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
    Discover supported authentication benchmark scenarios.

    BOLA scenarios are evaluated separately.
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

    # Reset authentication state and authentication telemetry.
    # This operation is intended only for the local test lab.
    reset_lab()

    execution_result = execute_scenario(scenario)

    # Isolate authentication benchmark events.
    # Do not include JWT or mass-assignment telemetry.
    events = load_security_events()

    alerts = (
        detect_brute_force(events)
        + detect_password_spray(events)
        + detect_slow_password_spray(events)
    )

    return evaluate(
        scenario,
        execution_result,
        events,
        alerts,
    )


def calculate_metrics(results: list[dict]) -> dict:
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for result in results:
        expected = result["expected_alert"]
        actual = result["actual_alert"]

        if expected and actual:
            tp += 1
        elif not expected and not actual:
            tn += 1
        elif not expected and actual:
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "attack_detection_rate": round(recall, 4),
        "false_positive_rate": round(
            fp / (fp + tn) if fp + tn else 0.0,
            4,
        ),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "specificity": round(specificity, 4),
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

    print(f"True positives:        {metrics['true_positives']}")
    print(f"True negatives:        {metrics['true_negatives']}")
    print(f"False positives:       {metrics['false_positives']}")
    print(f"False negatives:       {metrics['false_negatives']}")

    print(
        f"Attack detection rate: "
        f"{metrics['attack_detection_rate']:.2%}"
    )

    print(
        f"False-positive rate:   "
        f"{metrics['false_positive_rate']:.2%}"
    )

    print(f"Precision:             {metrics['precision']:.2%}")
    print(f"Recall:                {metrics['recall']:.2%}")
    print(f"F1 score:              {metrics['f1_score']:.2%}")
    print(f"Accuracy:              {metrics['accuracy']:.2%}")
    print(f"Specificity:           {metrics['specificity']:.2%}")

    passed = sum(
        result["result"] == "PASS"
        for result in results
    )

    print(f"Scenarios passed:      {passed}/{len(results)}")
    print("=" * 70)


def save_results(
    results: list[dict],
    metrics: dict,
) -> None:
    RESULTS_DIRECTORY.mkdir(exist_ok=True)

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

    print(f"\nResults saved to: {RESULTS_FILE}")


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
    print(f"Discovered {len(scenario_paths)} scenario(s).")

    results = []

    for scenario_path in scenario_paths:
        result = run_scenario(scenario_path)
        results.append(result)

    metrics = calculate_metrics(results)

    print_results(results, metrics)
    save_results(results, metrics)

    passed = sum(
        result["result"] == "PASS"
        for result in results
    )

    if passed != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
