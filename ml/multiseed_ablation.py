
import json
from pathlib import Path
from statistics import mean, stdev

from ml.benchmark_splits import build_benchmark_splits
from ml.calibration import calibrate_threshold, predict_with_threshold
from ml.feature_ablation import FEATURE_SETS, select_features, metrics
from ml.final_test_dataset import build_final_test_dataset
from ml.model import AuthenticationAnomalyDetector
from ml.statistical_baseline import FailedLoginBaseline
from ml.window_selection import prepare_split


WINDOW_SECONDS = 300
SEEDS = list(range(2030, 2040))
BASELINE_NAME = "Failed-login statistical baseline"


def run_multiseed():
    splits = build_benchmark_splits()

    training_rows, _, _ = prepare_split(
        splits["training"], WINDOW_SECONDS
    )
    validation_rows, _, validation_labels = prepare_split(
        splits["validation"], WINDOW_SECONDS
    )

    models = {}

    for name, features in FEATURE_SETS.items():
        model = AuthenticationAnomalyDetector()
        model.fit(select_features(training_rows, features))

        validation_scores = model.anomaly_scores(
            select_features(validation_rows, features)
        )

        benign_scores = [
            score
            for score, label in zip(validation_scores, validation_labels)
            if not label
        ]

        threshold = calibrate_threshold(
            benign_scores,
            target_false_positive_rate=0.05,
        )

        models[name] = (model, features, threshold)

    baseline = FailedLoginBaseline().fit(
        validation_rows,
        validation_labels,
        target_false_positive_rate=0.05,
    )

    print("Baseline threshold:", baseline.threshold)

    results = {
        name: [] for name in [*FEATURE_SETS, BASELINE_NAME]
    }

    for seed in SEEDS:
        dataset = build_final_test_dataset(seed=seed)
        test_rows, _, labels = prepare_split(
            dataset, WINDOW_SECONDS
        )

        print(
            f"Seed {seed}: {len(labels)} windows, "
            f"{sum(labels)} attack windows"
        )

        for name, (model, features, threshold) in models.items():
            scores = model.anomaly_scores(
                select_features(test_rows, features)
            )

            predictions = predict_with_threshold(
                scores, threshold
            )

            result = metrics(labels, predictions)
            results[name].append({"seed": seed, **result})

        baseline_predictions = baseline.predict(test_rows)

        baseline_result = metrics(
            labels, baseline_predictions
        )

        results[BASELINE_NAME].append({
            "seed": seed,
            **baseline_result,
        })

    print("\nMULTI-SEED MODEL COMPARISON")
    print("=" * 70)

    summary = {}

    for name, runs in results.items():
        summary[name] = {}

        print(f"\n{name}")

        for metric in (
            "precision", "recall", "f1", "fpr", "fp", "fn"
        ):
            values = [run[metric] for run in runs]

            summary[name][metric] = {
                "mean": mean(values),
                "std": stdev(values) if len(values) > 1 else 0.0,
                "min": min(values),
                "max": max(values),
            }

            value_mean = summary[name][metric]["mean"]
            value_std = summary[name][metric]["std"]

            if metric in ("fp", "fn"):
                print(
                    f"  {metric.upper()}: "
                    f"{value_mean:.2f} +/- {value_std:.2f}"
                )
            else:
                print(
                    f"  {metric.upper()}: "
                    f"{value_mean:.2%} +/- {value_std:.2%}"
                )

    output = {
        "synthetic_data": True,
        "window_seconds": WINDOW_SECONDS,
        "seeds": SEEDS,
        "baseline_threshold": baseline.threshold,
        "results": results,
        "summary": summary,
        "limitations": [
            "All test datasets are synthetic.",
            "All test seeds use the same simulator family.",
            "Training and validation datasets remain fixed.",
            "Model thresholds are calibrated on benign validation windows.",
            "Feature configurations were explored after examining an earlier test set.",
            "Results do not establish performance on real-world traffic.",
        ],
    }

    path = Path("results/multiseed_ablation.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    print(f"\nSaved: {path}")

    return output


if __name__ == "__main__":
    run_multiseed()
