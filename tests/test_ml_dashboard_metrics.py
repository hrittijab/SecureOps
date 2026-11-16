import json
from pathlib import Path

DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "streamlit_demo"
    / "ml_metrics.json"
)


def test_ml_metrics_are_consistent():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))

    assert data["synthetic_data"] is True
    assert data["model"] == "IsolationForest"

    experiments = [
        data["final_evaluation"],
        data["heldout_evaluation"],
        *data["window_comparison"],
    ]

    assert len(data["window_comparison"]) == 3

    for experiment in experiments:
        m = experiment["metrics"]

        tp, fp, tn, fn = (
            m["tp"], m["fp"], m["tn"], m["fn"]
        )

        assert all(
            isinstance(value, int) and value >= 0
            for value in (tp, fp, tn, fn)
        )

        assert tp + fp + tn + fn == experiment["test_windows"]

        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        fpr = fp / (fp + tn) if fp + tn else 0

        assert abs(m["precision"] - precision) < 0.0001
        assert abs(m["recall"] - recall) < 0.0001
        assert abs(m["false_positive_rate"] - fpr) < 0.0001


def test_scenario_counts_are_valid():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))

    final = data["final_evaluation"]
    assert 0 <= final["detected_scenarios"] <= final["total_scenarios"]

    for experiment in data["window_comparison"]:
        for scenario in experiment["scenarios"]:
            assert isinstance(scenario["detected"], bool)
            assert scenario["attack_windows"] >= 0
            assert 0 <= scenario["flagged_attack_windows"] <= scenario["attack_windows"]
