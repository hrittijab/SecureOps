
import json

import ml.behavioral_compare as comparison


def test_comparison_report(tmp_path, monkeypatch):
    output = tmp_path / "comparison.json"
    monkeypatch.setattr(comparison, "OUTPUT", output)

    report = comparison.compare()

    assert output.exists()
    assert report["synthetic_data"] is True
    assert report["training_windows"] == 500
    assert report["attack_scenarios"] == 4
    assert report["benign_scenarios"] == 7

    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved == report


def test_comparison_metrics_consistent(tmp_path, monkeypatch):
    monkeypatch.setattr(
        comparison,
        "OUTPUT",
        tmp_path / "comparison.json",
    )

    report = comparison.compare()

    for detector in ("baseline", "behavioral", "rules"):
        metrics = report[detector]

        assert metrics["tp"] + metrics["fn"] == 4
        assert metrics["tn"] + metrics["fp"] == 7

        assert 0 <= metrics["precision"] <= 1
        assert 0 <= metrics["recall"] <= 1
        assert 0 <= metrics["false_positive_rate"] <= 1
