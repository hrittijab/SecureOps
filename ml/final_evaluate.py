
import json
from pathlib import Path

from ml.benchmark_splits import build_benchmark_splits
from ml.final_test_dataset import build_final_test_dataset
from ml.features import to_feature_matrix
from ml.model import AuthenticationAnomalyDetector
from ml.calibration import predict_with_threshold
from ml.window_selection import (
    get_window_key,
    prepare_split,
    count_detected_scenarios,
)


WINDOW_SECONDS = 300
THRESHOLD = 0.03363737880038309
OUTPUT = Path("results/ml_final_evaluation.json")


def calculate_metrics(labels, predictions):
    if len(labels) != len(predictions):
        raise ValueError("Labels and predictions must match")

    tp = sum(
        actual and predicted
        for actual, predicted in zip(labels, predictions)
    )
    fp = sum(
        not actual and predicted
        for actual, predicted in zip(labels, predictions)
    )
    tn = sum(
        not actual and not predicted
        for actual, predicted in zip(labels, predictions)
    )
    fn = sum(
        actual and not predicted
        for actual, predicted in zip(labels, predictions)
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": (
            fp / (fp + tn) if fp + tn else 0.0
        ),
    }


def evaluate():
    splits = build_benchmark_splits()
    final_test = build_final_test_dataset()

    _, training_matrix, _ = prepare_split(
        splits["training"],
        WINDOW_SECONDS,
    )

    test_rows, test_matrix, test_labels = prepare_split(
        final_test,
        WINDOW_SECONDS,
    )

    model = AuthenticationAnomalyDetector()
    model.fit(training_matrix)

    scores = model.anomaly_scores(test_matrix)

    predictions = predict_with_threshold(
        scores,
        THRESHOLD,
    )

    scenario_count = count_detected_scenarios(
        final_test,
        test_rows,
        predictions,
        WINDOW_SECONDS,
    )

    detected_keys = {
        get_window_key(row["window_start"], WINDOW_SECONDS)
        for row, predicted in zip(test_rows, predictions)
        if predicted
    }

    scenario_results = []

    for scenario in final_test["scenarios"]:
        request_ids = set(scenario["request_ids"])

        attack_keys = {
            get_window_key(
                event["occurred_at"],
                WINDOW_SECONDS,
            )
            for event in final_test["events"]
            if event["request_id"] in request_ids
        }

        scenario_results.append({
            "attack_id": scenario["attack_id"],
            "attack_type": scenario["attack_type"],
            "detected": bool(attack_keys & detected_keys),
            "attack_windows": len(attack_keys),
            "flagged_attack_windows": len(
                attack_keys & detected_keys
            ),
        })

    report = {
        "experiment": "final_heldout_authentication_evaluation",
        "synthetic_data": True,
        "window_seconds": WINDOW_SECONDS,
        "threshold": THRESHOLD,
        "training_windows": len(training_matrix),
        "final_test_windows": len(test_rows),
        "metrics": calculate_metrics(
            test_labels,
            predictions,
        ),
        "detected_scenarios": scenario_count,
        "total_scenarios": len(final_test["scenarios"]),
        "scenarios": scenario_results,
        "limitations": [
            "Entirely synthetic authentication traffic",
            "Same generator family across datasets",
            "Fixed windows may obscure temporal behavior",
            "Scenario detection does not prove event attribution",
            "Configuration selected on validation data",
            "No production deployment or automated ML blocking",
        ],
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))

    return report


if __name__ == "__main__":
    evaluate()
