
import json
from pathlib import Path

from ml.dataset import build_datasets
from ml.model import AuthenticationAnomalyDetector


RESULT_PATH = Path("results/ml_anomaly_evaluation.json")


def calculate_metrics(normal_predictions, attack_predictions):
    tn = int(sum(not prediction for prediction in normal_predictions))
    fp = int(sum(normal_predictions))

    tp = int(sum(attack_predictions))
    fn = int(sum(not prediction for prediction in attack_predictions))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

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
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(
            fp / (fp + tn) if fp + tn else 0.0,
            4,
        ),
        "f1_score": round(f1, 4),
    }


def run_evaluation():
    datasets = build_datasets()

    detector = AuthenticationAnomalyDetector(
        contamination=0.05,
        random_state=42,
    )

    detector.fit(datasets["training"])

    normal_predictions = detector.predict(
        datasets["normal_test"]
    )

    attack_predictions = detector.predict(
        datasets["attack_test"]
    )

    metrics = calculate_metrics(
        normal_predictions,
        attack_predictions,
    )

    report = {
        "experiment": "authentication_ml_anomaly_detection",
        "model": "IsolationForest",
        "synthetic_data": True,
        "training_windows": len(datasets["training"]),
        "normal_test_windows": len(datasets["normal_test"]),
        "attack_test_windows": len(datasets["attack_test"]),
        "metrics": metrics,
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)

    RESULT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n[SecureOps ML Anomaly Evaluation]")
    print("=" * 55)

    print(f"Training windows:    {report['training_windows']}")
    print(f"Normal test windows: {report['normal_test_windows']}")
    print(f"Attack test windows: {report['attack_test_windows']}")

    print("-" * 55)

    for name, value in metrics.items():
        print(f"{name:<25} {value}")

    print(f"\nReport saved: {RESULT_PATH}")

    return report


if __name__ == "__main__":
    run_evaluation()
