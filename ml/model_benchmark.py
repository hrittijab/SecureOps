import json
from pathlib import Path

import pandas as pd

from ml.benchmark_splits import build_benchmark_splits
from ml.final_test_dataset import build_final_test_dataset
from ml.window_selection import prepare_split
from ml.model import AuthenticationAnomalyDetector
from ml.calibration import predict_with_threshold
from ml.statistical_baseline import FailedLoginBaseline
from ml.final_evaluate import THRESHOLD, calculate_metrics
from ml.features import FEATURE_NAMES


OUTPUT = Path("streamlit_demo/model_benchmark.json")
WINDOW_SECONDS = 300


def summarize(labels, predictions):
    metrics = calculate_metrics(labels, predictions)

    precision = metrics["precision"]
    recall = metrics["recall"]

    metrics["f1"] = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    return metrics


def run_benchmark():
    splits = build_benchmark_splits()

    _, training_matrix, _ = prepare_split(
        splits["training"], WINDOW_SECONDS
    )

    validation_rows, _, validation_labels = prepare_split(
        splits["validation"], WINDOW_SECONDS
    )

    final_test = build_final_test_dataset()

    test_rows, test_matrix, labels = prepare_split(
        final_test, WINDOW_SECONDS
    )

    model = AuthenticationAnomalyDetector()
    model.fit(training_matrix)

    ml_predictions = predict_with_threshold(
        model.anomaly_scores(test_matrix),
        THRESHOLD,
    )

    baseline = FailedLoginBaseline()
    baseline.fit(validation_rows, validation_labels)

    baseline_predictions = baseline.predict(test_rows)

    df = pd.DataFrame(test_rows)
    df["is_attack"] = labels
    df["ml_flag"] = ml_predictions
    df["baseline_flag"] = baseline_predictions

    agreement = {
        "both_flag": int(
            (df["ml_flag"] & df["baseline_flag"]).sum()
        ),
        "ml_only": int(
            (df["ml_flag"] & ~df["baseline_flag"]).sum()
        ),
        "baseline_only": int(
            (~df["ml_flag"] & df["baseline_flag"]).sum()
        ),
        "neither": int(
            (~df["ml_flag"] & ~df["baseline_flag"]).sum()
        ),
    }

    benign = df[~df["is_attack"]].copy()

    benign["group"] = "correctly_ignored"

    benign.loc[
        benign["ml_flag"] & benign["baseline_flag"],
        "group"
    ] = "both_flagged"

    benign.loc[
        benign["ml_flag"] & ~benign["baseline_flag"],
        "group"
    ] = "ml_only"

    feature_summary = {}

    for group, subset in benign.groupby("group"):
        feature_summary[group] = {
            name: {
                "mean": float(subset[name].mean()),
                "median": float(subset[name].median()),
            }
            for name in FEATURE_NAMES
        }
        feature_summary[group]["count"] = len(subset)

    missed = df[
        df["is_attack"]
        & (~df["ml_flag"] | ~df["baseline_flag"])
    ]

    missed_summary = [
        {
            "failure_count": int(row["failure_count"]),
            "failure_rate": float(row["failure_rate"]),
            "distinct_accounts": int(row["distinct_accounts"]),
            "distinct_source_ips": int(row["distinct_source_ips"]),
            "ml_detected": bool(row["ml_flag"]),
            "baseline_detected": bool(row["baseline_flag"]),
        }
        for _, row in missed.iterrows()
    ]

    report = {
        "experiment": "matched_window_model_benchmark",
        "synthetic_data": True,
        "window_seconds": WINDOW_SECONDS,
        "evaluation_windows": len(labels),
        "attack_windows": int(sum(labels)),
        "benign_windows": int(len(labels) - sum(labels)),
        "isolation_forest": summarize(
            labels, ml_predictions
        ),
        "failed_login_baseline": summarize(
            labels, baseline_predictions
        ),
        "thresholds": {
            "isolation_forest": THRESHOLD,
            "failed_login_baseline": baseline.threshold,
        },
        "prediction_agreement": agreement,
        "benign_feature_summary": feature_summary,
        "missed_attack_windows": missed_summary,
        "limitations": [
            "Entirely synthetic authentication traffic",
            "Only ten attack-positive evaluation windows",
            "Baseline threshold calibrated using benign validation labels",
            "Isolation Forest threshold previously selected on validation",
            "Model predictions are associated with windows, not individual events",
            "Feature summaries are descriptive, not causal explanations",
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("Created:", OUTPUT)
    print("Isolation Forest:", report["isolation_forest"])
    print("Baseline:", report["failed_login_baseline"])
    print("Agreement:", agreement)

    return report


if __name__ == "__main__":
    run_benchmark()
