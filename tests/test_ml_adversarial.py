
from ml.adversarial import build_scenarios
from ml.adversarial_evaluate import evaluate_scenarios


def test_scenario_catalog():
    scenarios = build_scenarios()

    assert len(scenarios) == 6
    assert sum(s["attack"] for s in scenarios) == 4
    assert sum(not s["attack"] for s in scenarios) == 2

    assert len({s["id"] for s in scenarios}) == 6


def test_all_scenarios_have_valid_events():
    for scenario in build_scenarios():
        assert scenario["events"]

        for event in scenario["events"]:
            assert event["event_type"] in {
                "LOGIN_SUCCESS",
                "LOGIN_FAILURE",
            }
            assert event["occurred_at"].tzinfo is not None
            assert event["request_id"]


def test_evaluation_report_structure(tmp_path, monkeypatch):
    import ml.adversarial_evaluate as evaluator

    monkeypatch.setattr(
        evaluator,
        "OUTPUT",
        tmp_path / "evaluation.json",
    )

    report = evaluate_scenarios()

    assert report["synthetic_data"] is True
    assert report["summary"]["scenario_count"] == 6
    assert len(report["scenarios"]) == 6

    assert evaluator.OUTPUT.exists()
