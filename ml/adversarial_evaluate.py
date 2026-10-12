
import json
from pathlib import Path

from ml.adversarial import build_scenarios
from ml.dataset import build_datasets
from ml.features import extract_features, to_feature_matrix
from ml.model import AuthenticationAnomalyDetector

from detection.rules.brute_force import detect as brute_force
from detection.rules.slow_brute_force import detect as slow_brute_force
from detection.rules.password_spray import detect as password_spray
from detection.rules.slow_password_spray import detect as slow_password_spray
from detection.rules.distributed_password_spray import (
    detect as distributed_spray,
)


RULES = (
    brute_force,
    slow_brute_force,
    password_spray,
    slow_password_spray,
    distributed_spray,
)

OUTPUT = Path("results/ml_adversarial_evaluation.json")


def evaluate_scenarios():
    training_data = build_datasets()["training"]

    model = AuthenticationAnomalyDetector()
    model.fit(training_data)

    results = []

    for scenario in build_scenarios():
        events = scenario["events"]

        # Rules see the entire scenario, including long-term patterns.
        rule_alerts = []
        for rule in RULES:
            rule_alerts.extend(rule(events))

        feature_rows = extract_features(events)
        feature_matrix = to_feature_matrix(feature_rows)

        # An attack scenario is flagged if at least one window
        # is anomalous. Record the window count for context.
        ml_predictions = model.predict(feature_matrix)
        ml_scores = model.anomaly_scores(feature_matrix)

        result = {
            "scenario_id": scenario["id"],
            "attack": scenario["attack"],
            "event_count": len(events),
            "window_count": len(feature_rows),
            "rules_detected": bool(rule_alerts),
            "rule_ids": sorted({
                alert["rule_id"] for alert in rule_alerts
            }),
            "ml_detected": bool(any(ml_predictions)),
            "ml_anomalous_windows": int(sum(ml_predictions)),
            "ml_max_anomaly_score": (
                round(float(max(ml_scores)), 4)
                if ml_scores else None
            ),
        }

        results.append(result)

    attack_results = [r for r in results if r["attack"]]
    benign_results = [r for r in results if not r["attack"]]

    summary = {
        "scenario_count": len(results),
        "attack_count": len(attack_results),
        "benign_count": len(benign_results),
        "rules_attack_detections": sum(
            r["rules_detected"] for r in attack_results
        ),
        "ml_attack_detections": sum(
            r["ml_detected"] for r in attack_results
        ),
        "ml_only_attack_detections": sum(
            r["ml_detected"] and not r["rules_detected"]
            for r in attack_results
        ),
        "rules_benign_false_positives": sum(
            r["rules_detected"] for r in benign_results
        ),
        "ml_benign_false_positives": sum(
            r["ml_detected"] for r in benign_results
        ),
    }

    report = {
        "experiment": "authentication_adversarial_ml_evaluation",
        "synthetic_data": True,
        "summary": {key: int(value) for key, value in summary.items()},
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
    evaluate_scenarios()
