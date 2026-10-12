
import json
from pathlib import Path

from ml.dataset import (
    START,
    generate_normal_events,
    generate_attack_events,
)
from ml.features import extract_features, to_feature_matrix
from ml.model import AuthenticationAnomalyDetector

from detection.rules.brute_force import detect as brute_force
from detection.rules.slow_brute_force import detect as slow_brute_force
from detection.rules.password_spray import detect as password_spray
from detection.rules.slow_password_spray import detect as slow_password_spray
from detection.rules.distributed_password_spray import (
    detect as distributed_spray,
)

from datetime import timedelta


RULES = (
    brute_force,
    slow_brute_force,
    password_spray,
    slow_password_spray,
    distributed_spray,
)

RESULT_PATH = Path("results/ml_vs_rules_comparison.json")


def prepare_events(events):
    prepared = []

    for index, event in enumerate(events):
        enriched = dict(event)

        enriched.setdefault(
            "failure_reason",
            "INVALID_CREDENTIALS"
            if enriched["event_type"] == "LOGIN_FAILURE"
            else None,
        )

        enriched.setdefault("request_id", f"ML-{index:06d}")
        prepared.append(enriched)

    return prepared


def rules_detect(events):
    return any(rule(events) for rule in RULES)


def compare():
    training_events = generate_normal_events(
        seed=42,
        window_count=500,
    )

    normal_events = generate_normal_events(
        seed=123,
        window_count=100,
        start=START + timedelta(days=15),
    )

    attack_events = generate_attack_events(
        seed=99,
        window_count=100,
    )

    training_rows = extract_features(training_events)
    normal_rows = extract_features(normal_events)
    attack_rows = extract_features(attack_events)

    model = AuthenticationAnomalyDetector()
    model.fit(to_feature_matrix(training_rows))

    normal_ml = model.predict(to_feature_matrix(normal_rows))
    attack_ml = model.predict(to_feature_matrix(attack_rows))

    # Rules are evaluated independently per 60-second window.
    # This is a window-level comparison, not a complete test
    # of the rules' longer 15-minute correlation behavior.
    def group_by_window(events):
        buckets = {}

        for event in events:
            timestamp = event["occurred_at"]
            bucket = int(timestamp.timestamp() // 60)
            buckets.setdefault(bucket, []).append(event)

        return [
            buckets[key]
            for key in sorted(buckets)
        ]

    normal_rule_predictions = [
        rules_detect(prepare_events(window))
        for window in group_by_window(normal_events)
    ]

    attack_rule_predictions = [
        rules_detect(prepare_events(window))
        for window in group_by_window(attack_events)
    ]

    def metrics(normal, attack):
        tp = int(sum(attack))
        fn = len(attack) - tp
        fp = int(sum(normal))
        tn = len(normal) - fp

        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        fpr = fp / (fp + tn) if fp + tn else 0

        return {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
        }

    assert len(normal_ml) == len(normal_rule_predictions)
    assert len(attack_ml) == len(attack_rule_predictions)

    report = {
        "experiment": "ml_vs_rule_based_authentication_detection",
        "dataset": "synthetic",
        "evaluation_unit": "fixed_60_second_window",
        "ml": metrics(normal_ml, attack_ml),
        "rules": metrics(
            normal_rule_predictions,
            attack_rule_predictions,
        ),
        "additional_ml_detections": int(sum(
            ml and not rule
            for ml, rule in zip(attack_ml, attack_rule_predictions)
        )),
        "ml_only_false_positives": int(sum(
            ml and not rule
            for ml, rule in zip(normal_ml, normal_rule_predictions)
        )),
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    compare()
