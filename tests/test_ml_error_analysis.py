import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "streamlit_demo"


def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def test_error_analysis_matches_model_metrics():
    metrics = load("ml_metrics.json")["final_evaluation"]["metrics"]
    errors = load("ml_error_analysis.json")["final_300s"]

    assert errors["true_positives"] == metrics["tp"]
    assert errors["false_positives"] == metrics["fp"]
    assert errors["true_negatives"] == metrics["tn"]
    assert errors["false_negatives"] == metrics["fn"]

    assert errors["predicted_anomalies"] == metrics["tp"] + metrics["fp"]
    assert errors["actual_attack_windows"] == metrics["tp"] + metrics["fn"]

    assert abs(
        errors["false_discovery_rate"]
        - metrics["fp"] / (metrics["tp"] + metrics["fp"])
    ) < 1e-9

    assert abs(
        errors["miss_rate"]
        - metrics["fn"] / (metrics["tp"] + metrics["fn"])
    ) < 1e-9


def test_scenario_detection_counts():
    errors = load("ml_error_analysis.json")
    scenarios = errors["final_scenarios"]

    assert len(scenarios) == 4
    assert sum(s["attack_windows"] for s in scenarios) == 10
    assert sum(s["flagged_attack_windows"] for s in scenarios) == 8

    for scenario in scenarios:
        assert scenario["detected"] == (
            scenario["flagged_attack_windows"] > 0
        )


def test_rule_alert_counts():
    rules = load("ml_error_analysis.json")["rules"]

    assert sum(rules["alerts_by_rule"].values()) == rules["total_alerts"]
    assert (
        rules["attack_related_alerts"]
        + rules["benign_only_alerts"]
        + rules["mixed_evidence_alerts"]
        == rules["total_alerts"]
    )
