
import json
from datetime import datetime
from pathlib import Path

from detection.rules.brute_force import detect as brute_force
from detection.rules.slow_brute_force import detect as slow_brute_force
from detection.rules.password_spray import detect as password_spray
from detection.rules.slow_password_spray import detect as slow_password_spray
from detection.rules.distributed_password_spray import (
    detect as distributed_password_spray,
)

from ml.final_test_dataset import build_final_test_dataset
from ml.final_evaluate import evaluate


RULES = (
    brute_force,
    slow_brute_force,
    password_spray,
    slow_password_spray,
    distributed_password_spray,
)

OUTPUT = Path("results/ml_vs_rules_final.json")


def prepare_rule_events(events):
    prepared = []

    for event in events:
        converted = dict(event)

        converted["occurred_at"] = datetime.fromisoformat(
            event["occurred_at"]
        )

        converted.setdefault("user_id", None)
        converted.setdefault("outcome", None)

        prepared.append(converted)

    return prepared


def evaluate_rules(dataset):
    events = prepare_rule_events(dataset["events"])

    alerts = []

    for rule in RULES:
        alerts.extend(rule(events))

    attack_request_ids = {
        str(event["request_id"])
        for event in dataset["events"]
        if event["is_attack"]
    }

    benign_request_ids = {
        str(event["request_id"])
        for event in dataset["events"]
        if not event["is_attack"]
    }

    scenario_results = []

    for scenario in dataset["scenarios"]:
        scenario_ids = set(scenario["request_ids"])

        matching_alerts = [
            alert
            for alert in alerts
            if scenario_ids.intersection(
                set(map(str, alert["request_ids"]))
            )
        ]

        scenario_results.append({
            "attack_id": scenario["attack_id"],
            "attack_type": scenario["attack_type"],
            "detected": bool(matching_alerts),
            "matching_alert_count": len(matching_alerts),
            "triggered_rules": sorted({
                alert["rule_id"]
                for alert in matching_alerts
            }),
        })

    attack_related_alerts = []
    benign_only_alerts = []
    mixed_alerts = []

    for alert in alerts:
        evidence = set(map(str, alert["request_ids"]))

        has_attack = bool(evidence & attack_request_ids)
        has_benign = bool(evidence & benign_request_ids)

        if has_attack and has_benign:
            mixed_alerts.append(alert)
        elif has_attack:
            attack_related_alerts.append(alert)
        else:
            benign_only_alerts.append(alert)

    return {
        "total_alerts": len(alerts),
        "attack_related_alerts": len(attack_related_alerts),
        "benign_only_alerts": len(benign_only_alerts),
        "mixed_evidence_alerts": len(mixed_alerts),
        "detected_scenarios": sum(
            scenario["detected"]
            for scenario in scenario_results
        ),
        "total_scenarios": len(dataset["scenarios"]),
        "scenarios": scenario_results,
        "alerts_by_rule": {
            rule_id: sum(
                alert["rule_id"] == rule_id
                for alert in alerts
            )
            for rule_id in sorted({
                alert["rule_id"]
                for alert in alerts
            })
        },
    }


def compare():
    dataset = build_final_test_dataset()

    ml_report = evaluate()
    rule_report = evaluate_rules(dataset)

    report = {
        "experiment": "final_ml_vs_rules_comparison",
        "dataset": "synthetic_final_test",
        "dataset_seed": dataset["seed"],
        "dataset_days": dataset["days"],
        "ml": {
            "evaluation_unit": "300_second_window",
            "metrics": ml_report["metrics"],
            "detected_scenarios": ml_report[
                "detected_scenarios"
            ],
            "total_scenarios": ml_report[
                "total_scenarios"
            ],
            "scenarios": ml_report["scenarios"],
        },
        "rules": {
            "evaluation_unit": "rule_generated_alert",
            **rule_report,
        },
        "limitations": [
            "Synthetic traffic and attack scenarios",
            "ML and rule alerts use different evaluation units",
            "Rule alerts can contain overlapping evidence",
            "Mixed-evidence alerts are reported separately",
            "Rules operate on the complete event history",
            "Offline evaluation does not measure live detection latency",
            "No production ML enforcement",
        ],
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    compare()
