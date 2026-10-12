
from datetime import datetime

from ml.benchmark_splits import build_benchmark_splits
from ml.calibration import (
    calibrate_threshold,
    predict_with_threshold,
)
from ml.features import extract_features, to_feature_matrix
from ml.model import AuthenticationAnomalyDetector


WINDOW_SIZES = (60, 300, 900)


def get_window_key(timestamp, window_seconds):
    return int(
        datetime.fromisoformat(timestamp).timestamp()
    ) // window_seconds


def prepare_split(split, window_seconds):
    rows = extract_features(
        split["events"],
        window_seconds=window_seconds,
    )

    matrix = to_feature_matrix(rows)

    attack_keys = {
        get_window_key(event["occurred_at"], window_seconds)
        for event in split["events"]
        if event["is_attack"]
    }

    labels = [
        get_window_key(row["window_start"], window_seconds)
        in attack_keys
        for row in rows
    ]

    return rows, matrix, labels


def count_detected_scenarios(
    split,
    rows,
    predictions,
    window_seconds,
):
    flagged_keys = {
        get_window_key(row["window_start"], window_seconds)
        for row, predicted in zip(rows, predictions)
        if predicted
    }

    detected = 0

    for scenario in split["scenarios"]:
        request_ids = set(scenario["request_ids"])

        scenario_keys = {
            get_window_key(
                event["occurred_at"],
                window_seconds,
            )
            for event in split["events"]
            if event["request_id"] in request_ids
        }

        if scenario_keys & flagged_keys:
            detected += 1

    return detected


def select_window_size(
    splits=None,
    window_sizes=WINDOW_SIZES,
    max_false_positive_rate=0.05,
):
    if splits is None:
        splits = build_benchmark_splits()

    if not window_sizes:
        raise ValueError("At least one window size is required")

    if not 0 < max_false_positive_rate < 1:
        raise ValueError("Invalid false-positive rate")

    training = splits["training"]
    validation = splits["validation"]

    results = []

    for window_seconds in window_sizes:
        _, train_matrix, _ = prepare_split(
            training, window_seconds
        )

        rows, matrix, labels = prepare_split(
            validation, window_seconds
        )

        model = AuthenticationAnomalyDetector()
        model.fit(train_matrix)

        scores = model.anomaly_scores(matrix)

        benign_scores = [
            score
            for score, is_attack in zip(scores, labels)
            if not is_attack
        ]

        threshold = calibrate_threshold(
            benign_scores,
            target_false_positive_rate=max_false_positive_rate,
        )

        predictions = predict_with_threshold(
            scores, threshold
        )

        tp = sum(
            predicted and actual
            for predicted, actual in zip(predictions, labels)
        )

        fp = sum(
            predicted and not actual
            for predicted, actual in zip(predictions, labels)
        )

        fn = sum(
            not predicted and actual
            for predicted, actual in zip(predictions, labels)
        )

        benign_count = sum(not label for label in labels)

        fpr = (
            fp / benign_count
            if benign_count else 0.0
        )

        attack_window_recall = (
            tp / (tp + fn)
            if tp + fn else 0.0
        )

        precision = (
            tp / (tp + fp)
            if tp + fp else 0.0
        )

        detected = count_detected_scenarios(
            validation,
            rows,
            predictions,
            window_seconds,
        )

        results.append({
            "window_seconds": window_seconds,
            "threshold": float(threshold),
            "validation_fpr": round(fpr, 4),
            "attack_window_recall": round(
                attack_window_recall, 4
            ),
            "precision": round(precision, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "detected_scenarios": detected,
            "total_scenarios": len(validation["scenarios"]),
            "eligible": fpr <= max_false_positive_rate,
        })

    eligible = [
        result for result in results
        if result["eligible"]
    ]

    if not eligible:
        raise ValueError(
            "No window size satisfies the false-positive budget"
        )

    # Prioritize scenario detection, then attack-window recall.
    # Tie-break using lower FPR and shorter windows.
    selected = sorted(
        eligible,
        key=lambda result: (
            -result["detected_scenarios"],
            -result["attack_window_recall"],
            result["validation_fpr"],
            result["window_seconds"],
        ),
    )[0]

    return {
        "selected": selected,
        "candidates": results,
        "selection_dataset": "validation",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(
        select_window_size(),
        indent=2,
    ))
