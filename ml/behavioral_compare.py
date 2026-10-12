
import json
from pathlib import Path

from ml.adversarial import build_scenarios
from ml.adversarial_evaluate import RULES
from ml.behavioral_features import (
    BEHAVIORAL_FEATURE_NAMES,
    extract_behavioral_features,
)
from ml.dataset import generate_normal_events
from ml.features import (
    FEATURE_NAMES,
    extract_features,
    to_feature_matrix,
)
from ml.hard_negatives import build_hard_negatives
from ml.model import AuthenticationAnomalyDetector


OUTPUT = Path("results/ml_behavioral_comparison.json")

ALL_FEATURE_NAMES = FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES


def behavioral_matrix(events):
    rows = extract_behavioral_features(events)
    return [
        [float(row[name]) for name in ALL_FEATURE_NAMES]
        for row in rows
    ]


def summarize(results, field):
    attacks = [r for r in results if r["attack"]]
    benign = [r for r in results if not r["attack"]]

    tp = sum(bool(r[field]) for r in attacks)
    fn = len(attacks) - tp
    fp = sum(bool(r[field]) for r in benign)
    tn = len(benign) - fp

    return {
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
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


def compare():
    training_events = generate_normal_events(
        seed=42,
        window_count=500,
    )

    baseline = AuthenticationAnomalyDetector()
    behavioral = AuthenticationAnomalyDetector()

    baseline.fit(
        to_feature_matrix(extract_features(training_events))
    )

    behavioral.fit(
        behavioral_matrix(training_events)
    )

    scenarios = build_scenarios() + build_hard_negatives()
    results = []

    for scenario in scenarios:
        events = scenario["events"]

        baseline_scores = baseline.anomaly_scores(
            to_feature_matrix(extract_features(events))
        )

        behavioral_scores = behavioral.anomaly_scores(
            behavioral_matrix(events)
        )

        rule_alerts = []
        for rule in RULES:
            rule_alerts.extend(rule(events))

        results.append({
            "scenario_id": scenario["id"],
            "attack": bool(scenario["attack"]),
            "baseline_detected": any(
                score > 0 for score in baseline_scores
            ),
            "behavioral_detected": any(
                score > 0 for score in behavioral_scores
            ),
            "rules_detected": bool(rule_alerts),
            "baseline_max_score": round(
                max(baseline_scores), 4
            ),
            "behavioral_max_score": round(
                max(behavioral_scores), 4
            ),
        })

    report = {
        "experiment": "baseline_vs_behavioral_isolation_forest",
        "synthetic_data": True,
        "training_windows": 500,
        "attack_scenarios": sum(r["attack"] for r in results),
        "benign_scenarios": sum(not r["attack"] for r in results),
        "baseline": summarize(results, "baseline_detected"),
        "behavioral": summarize(results, "behavioral_detected"),
        "rules": summarize(results, "rules_detected"),
        "scenarios": results,
        "limitations": [
            "Synthetic training and evaluation data",
            "Small scenario-level test set",
            "No independent threshold calibration",
            "Fixed 60-second ML feature windows",
            "Behavioral features do not include historical context",
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
