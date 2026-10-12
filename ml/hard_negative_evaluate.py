
import json
from pathlib import Path

from ml.hard_negatives import build_hard_negatives
from ml.dataset import build_datasets
from ml.features import extract_features, to_feature_matrix
from ml.model import AuthenticationAnomalyDetector
from ml.adversarial_evaluate import RULES


OUTPUT = Path("results/ml_hard_negative_evaluation.json")


def evaluate_hard_negatives():
    detector = AuthenticationAnomalyDetector()
    detector.fit(build_datasets()["training"])

    results = []

    for scenario in build_hard_negatives():
        events = scenario["events"]

        rule_alerts = []
        for rule in RULES:
            rule_alerts.extend(rule(events))

        rows = extract_features(events)
        matrix = to_feature_matrix(rows)

        predictions = detector.predict(matrix)
        scores = detector.anomaly_scores(matrix)

        results.append({
            "scenario_id": scenario["id"],
            "event_count": len(events),
            "window_count": len(rows),
            "rules_false_positive": bool(rule_alerts),
            "ml_false_positive": bool(any(predictions)),
            "ml_anomalous_windows": int(sum(predictions)),
            "max_anomaly_score": (
                round(float(max(scores)), 4)
                if scores else None
            ),
        })

    report = {
        "experiment": "authentication_ml_hard_negatives",
        "synthetic_data": True,
        "benign_scenarios": len(results),
        "rules_false_positives": int(sum(
            result["rules_false_positive"]
            for result in results
        )),
        "ml_false_positives": int(sum(
            result["ml_false_positive"]
            for result in results
        )),
        "scenarios": results,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    evaluate_hard_negatives()
