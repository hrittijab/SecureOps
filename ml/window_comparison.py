
import json
from pathlib import Path

from ml.benchmark_splits import build_benchmark_splits
from ml.calibration import (
    calibrate_threshold,
    predict_with_threshold,
)
from ml.features import extract_features, to_feature_matrix
from ml.heldout_evaluate import (
    attack_window_keys,
    metrics,
    scenario_detection,
    window_key,
)
from ml.model import AuthenticationAnomalyDetector


OUTPUT = Path("results/ml_window_comparison.json")
WINDOW_SIZES = (60, 300, 900)


def evaluate_window_size(splits, window_seconds):
    prepared = {}

    for name, split in splits.items():
        rows = extract_features(
            split["events"],
            window_seconds=window_seconds,
        )

        matrix = to_feature_matrix(rows)

        attack_keys = {
            int(
                __import__("datetime").datetime.fromisoformat(
                    event["occurred_at"]
                ).timestamp()
            ) // window_seconds
            for event in split["events"]
            if event["is_attack"]
        }

        labels = [
            int(
                __import__("datetime").datetime.fromisoformat(
                    row["window_start"]
                ).timestamp()
            ) // window_seconds in attack_keys
            for row in rows
        ]

        prepared[name] = (rows, matrix, labels)

    model = AuthenticationAnomalyDetector()
    model.fit(prepared["training"][1])

    validation_scores = model.anomaly_scores(
        prepared["validation"][1]
    )

    benign_scores = [
        score
        for score, label in zip(
            validation_scores,
            prepared["validation"][2],
        )
        if not label
    ]

    threshold = calibrate_threshold(
        benign_scores,
        target_false_positive_rate=0.05,
    )

    test_rows, test_matrix, test_labels = prepared["test"]

    predictions = predict_with_threshold(
        model.anomaly_scores(test_matrix),
        threshold,
    )

    detected_keys = {
        int(
            __import__("datetime").datetime.fromisoformat(
                row["window_start"]
            ).timestamp()
        ) // window_seconds
        for row, predicted in zip(test_rows, predictions)
        if predicted
    }

    scenarios = []

    for scenario in splits["test"]["scenarios"]:
        ids = set(scenario["request_ids"])

        keys = {
            int(
                __import__("datetime").datetime.fromisoformat(
                    event["occurred_at"]
                ).timestamp()
            ) // window_seconds
            for event in splits["test"]["events"]
            if event["request_id"] in ids
        }

        scenarios.append({
            "attack_type": scenario["attack_type"],
            "detected": bool(keys & detected_keys),
            "attack_windows": len(keys),
            "flagged_attack_windows": len(keys & detected_keys),
        })

    return {
        "window_seconds": window_seconds,
        "training_windows": len(prepared["training"][0]),
        "test_windows": len(test_rows),
        "threshold": float(threshold),
        "metrics": metrics(test_labels, predictions),
        "scenarios": scenarios,
    }


def compare():
    splits = build_benchmark_splits()

    results = [
        evaluate_window_size(splits, seconds)
        for seconds in WINDOW_SIZES
    ]

    report = {
        "experiment": "authentication_window_size_comparison",
        "synthetic_data": True,
        "window_sizes": list(WINDOW_SIZES),
        "results": results,
        "limitations": [
            "Exploratory comparison using held-out test scenarios",
            "Different window sizes change class prevalence",
            "Window-level metrics are not directly equivalent across sizes",
            "Synthetic traffic only",
            "Do not select a production window size using test results",
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    compare()
