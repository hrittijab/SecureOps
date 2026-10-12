
from ml.hard_negatives import build_hard_negatives
from ml.hard_negative_evaluate import evaluate_hard_negatives


def test_hard_negative_catalog():
    scenarios = build_hard_negatives()

    assert len(scenarios) == 5
    assert len({s["id"] for s in scenarios}) == 5
    assert all(s["attack"] is False for s in scenarios)


def test_hard_negative_events():
    for scenario in build_hard_negatives():
        assert scenario["events"]

        for event in scenario["events"]:
            assert event["request_id"]
            assert event["occurred_at"].tzinfo is not None


def test_hard_negative_report(tmp_path, monkeypatch):
    import ml.hard_negative_evaluate as evaluator

    monkeypatch.setattr(
        evaluator,
        "OUTPUT",
        tmp_path / "hard_negative_report.json",
    )

    report = evaluate_hard_negatives()

    assert report["benign_scenarios"] == 5
    assert len(report["scenarios"]) == 5
    assert evaluator.OUTPUT.exists()
