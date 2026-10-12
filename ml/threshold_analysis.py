
import json
from pathlib import Path

from ml.dataset import build_datasets
from ml.model import AuthenticationAnomalyDetector
from ml.features import extract_features, to_feature_matrix
from ml.adversarial import build_scenarios
from ml.hard_negatives import build_hard_negatives


OUTPUT = Path("results/ml_threshold_analysis.json")

THRESHOLDS = (
    0.0,
    0.05,
    0.08,
    0.10,
    0.15,
    0.18,
    0.20,
    0.25,
)


def analyze():
    model = AuthenticationAnomalyDetector()
    model.fit(build_datasets()["training"])

    scenarios = build_scenarios() + build_hard_negatives()

    scored = []

    for scenario in scenarios:
        rows = extract_features(scenario["events"])
        matrix = to_feature_matrix(rows)
        scores = model.anomaly_scores(matrix)

        scored.append({
            "id": scenario["id"],
            "attack": bool(scenario["attack"]),
            "max_score": float(max(scores)) if scores else None,
        })

    results = []

    for threshold in THRESHOLDS:
        tp = fp = tn = fn = 0

        for scenario in scored:
            detected = (
                scenario["max_score"] is not None
                and scenario["max_score"] > threshold
            )

            if scenario["attack"]:
                if detected:
                    tp += 1
                else:
                    fn += 1
            else:
                if detected:
                    fp += 1
                else:
                    tn += 1

        results.append({
            "threshold": threshold,
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
        })

    report = {
        "experiment": "ml_threshold_diagnostic",
        "synthetic_data": True,
        "scenario_count": len(scored),
        "thresholds": results,
        "scenario_scores": scored,
        "note": (
            "Exploratory diagnostic only. "
            "Do not select a deployment threshold using "
            "these test scenarios."
        ),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    analyze()
