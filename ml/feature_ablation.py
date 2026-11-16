from ml.benchmark_splits import build_benchmark_splits
from ml.final_test_dataset import build_final_test_dataset
from ml.window_selection import prepare_split
from ml.features import FEATURE_NAMES
from ml.model import AuthenticationAnomalyDetector
from ml.calibration import calibrate_threshold, predict_with_threshold


WINDOW_SECONDS = 300

FEATURE_SETS = {
    "Full (8 features)": list(FEATURE_NAMES),
    "No success count (7)": [
        name for name in FEATURE_NAMES
        if name != "success_count"
    ],
    "Failure-focused (6)": [
        name for name in FEATURE_NAMES
        if name not in ("success_count", "event_count")
    ],
    "Minimal (2)": [
        "failure_count",
        "failure_rate",
    ],
}


def select_features(rows, names):
    return [
        [float(row[name]) for name in names]
        for row in rows
    ]


def metrics(labels, predictions):
    tp = sum(p and y for p, y in zip(predictions, labels))
    fp = sum(p and not y for p, y in zip(predictions, labels))
    tn = sum(not p and not y for p, y in zip(predictions, labels))
    fn = sum(not p and y for p, y in zip(predictions, labels))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def run_ablation():
    splits = build_benchmark_splits()

    training_rows, _, _ = prepare_split(
        splits["training"], WINDOW_SECONDS
    )

    validation_rows, _, validation_labels = prepare_split(
        splits["validation"], WINDOW_SECONDS
    )

    test_rows, _, test_labels = prepare_split(
        build_final_test_dataset(), WINDOW_SECONDS
    )

    print("FEATURE ABLATION STUDY")
    print("=" * 65)
    print("Final-test windows:", len(test_labels))
    print("Attack windows:", sum(test_labels))

    results = {}

    for name, features in FEATURE_SETS.items():
        model = AuthenticationAnomalyDetector()

        model.fit(select_features(training_rows, features))

        validation_scores = model.anomaly_scores(
            select_features(validation_rows, features)
        )

        benign_scores = [
            score
            for score, label in zip(
                validation_scores, validation_labels
            )
            if not label
        ]

        threshold = calibrate_threshold(
            benign_scores,
            target_false_positive_rate=0.05,
        )

        test_scores = model.anomaly_scores(
            select_features(test_rows, features)
        )

        predictions = predict_with_threshold(
            test_scores, threshold
        )

        result = metrics(test_labels, predictions)

        results[name] = result

        print("\n" + name)
        print("-" * 45)
        print("Features:", ", ".join(features))
        print("Threshold:", round(threshold, 6))
        print(
            f"TP={result['tp']} FP={result['fp']} "
            f"TN={result['tn']} FN={result['fn']}"
        )
        print(f"Precision: {result['precision']:.2%}")
        print(f"Recall: {result['recall']:.2%}")
        print(f"F1: {result['f1']:.2%}")
        print(f"FPR: {result['fpr']:.2%}")

    return results


if __name__ == "__main__":
    run_ablation()
