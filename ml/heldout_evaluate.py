
import json
from datetime import datetime
from pathlib import Path

from ml.benchmark_splits import build_benchmark_splits
from ml.calibration import (
    calibrate_threshold,
    predict_with_threshold,
)
from ml.features import extract_features, to_feature_matrix
from ml.model import AuthenticationAnomalyDetector


OUTPUT = Path("results/ml_heldout_evaluation.json")
WINDOW_SECONDS = 60


def window_key(timestamp):
    dt = datetime.fromisoformat(timestamp)
    return int(dt.timestamp()) // WINDOW_SECONDS


def attack_window_keys(events):
    return {
        window_key(event["occurred_at"])
        for event in events
        if event["is_attack"]
    }


def prepare(split):
    rows = extract_features(
        split["events"],
        window_seconds=WINDOW_SECONDS,
    )
    matrix = to_feature_matrix(rows)
    attack_keys = attack_window_keys(split["events"])

    labels = [
        window_key(row["window_start"]) in attack_keys
        for row in rows
    ]

    return rows, matrix, labels


def metrics(labels, predictions):
    tp = fp = tn = fn = 0

    for actual, predicted in zip(labels, predictions):
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(
            tp / (tp + fp), 4
        ) if tp + fp else 0.0,
        "recall": round(
            tp / (tp + fn), 4
        ) if tp + fn else 0.0,
        "false_positive_rate": round(
            fp / (fp + tn), 4
        ) if fp + tn else 0.0,
    }


def scenario_detection(split, rows, predictions):
    detected_keys = {
        window_key(row["window_start"])
        for row, predicted in zip(rows, predictions)
        if predicted
    }

    results = []

    for scenario in split["scenarios"]:
        request_ids = set(scenario["request_ids"])

        scenario_keys = {
            window_key(event["occurred_at"])
            for event in split["events"]
            if event["request_id"] in request_ids
        }

        results.append({
            "attack_id": scenario["attack_id"],
            "attack_type": scenario["attack_type"],
            "detected": bool(
                scenario_keys & detected_keys
            ),
            "attack_windows": len(scenario_keys),
            "flagged_attack_windows": len(
                scenario_keys & detected_keys
            ),
        })

    return results


def evaluate():
    splits = build_benchmark_splits()

    _, train_matrix, _ = prepare(
        splits["training"]
    )

    validation_rows, validation_matrix, validation_labels = (
        prepare(splits["validation"])
    )

    test_rows, test_matrix, test_labels = prepare(
        splits["test"]
    )

    model = AuthenticationAnomalyDetector()
    model.fit(train_matrix)

    validation_scores = model.anomaly_scores(
        validation_matrix
    )

    # Calibrate only on benign validation windows.
    benign_validation_scores = [
        score
        for score, is_attack in zip(
            validation_scores,
            validation_labels,
        )
        if not is_attack
    ]

    threshold = calibrate_threshold(
        benign_validation_scores,
        target_false_positive_rate=0.05,
    )

    test_scores = model.anomaly_scores(test_matrix)

    predictions = predict_with_threshold(
        test_scores,
        threshold,
    )

    report = {
        "experiment": "heldout_authentication_anomaly_detection",
        "synthetic_data": True,
        "model": "IsolationForest",
        "feature_count": len(train_matrix[0]),
        "training_windows": len(train_matrix),
        "validation_windows": len(validation_rows),
        "test_windows": len(test_rows),
        "threshold": threshold,
        "target_validation_false_positive_rate": 0.05,
        "test_metrics": metrics(
            test_labels,
            predictions,
        ),
        "test_scenarios": scenario_detection(
            splits["test"],
            test_rows,
            predictions,
        ),
        "limitations": [
            "Entirely synthetic authentication traffic",
            "Training, validation and test use the same generator family",
            "60-second fixed windows can split slow attacks",
            "Attack-window labels do not establish event attribution",
            "Threshold calibrated using labeled benign validation windows",
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
