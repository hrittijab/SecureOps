
import json

from evaluation import adversarial_experiment as experiment


def test_six_unique_scenarios():
    scenarios = experiment.build_scenarios()

    assert len(scenarios) == 6
    assert len({s["id"] for s in scenarios}) == 6


def test_all_scenarios_match_expected_behavior():
    results = [
        experiment.evaluate_scenario(s)
        for s in experiment.build_scenarios()
    ]

    assert all(r["result"] == "PASS" for r in results)


def test_detected_and_evaded_counts():
    results = [
        experiment.evaluate_scenario(s)
        for s in experiment.build_scenarios()
    ]

    assert sum(r["detected"] for r in results) == 4
    assert sum(r["evasion_success"] for r in results) == 2


def test_evasion_gaps_are_explicit():
    results = {
        r["scenario_id"]: r
        for r in (
            experiment.evaluate_scenario(s)
            for s in experiment.build_scenarios()
        )
    }

    for scenario_id in ("ADV-003", "ADV-006"):
        assert results[scenario_id]["detected"] is False
        assert results[scenario_id]["detected_rules"] == []


def test_expected_detection_rules():
    results = {
        r["scenario_id"]: r
        for r in (
            experiment.evaluate_scenario(s)
            for s in experiment.build_scenarios()
        )
    }

    assert results["ADV-001"]["detected_rules"] == [
        "BRUTE_FORCE_001"
    ]
    assert results["ADV-002"]["detected_rules"] == [
        "BRUTE_FORCE_001"
    ]
    assert results["ADV-004"]["detected_rules"] == [
        "PASSWORD_SPRAY_001"
    ]
    assert results["ADV-005"]["detected_rules"] == [
        "SLOW_PASSWORD_SPRAY_001"
    ]


def test_report_is_saved(tmp_path, monkeypatch):
    output = tmp_path / "adversarial_evaluation.json"
    monkeypatch.setattr(experiment, "RESULT_PATH", output)

    report = experiment.run_experiment()

    assert output.exists()

    saved = json.loads(output.read_text(encoding="utf-8"))

    assert saved == report
    assert saved["scenario_count"] == 6
    assert saved["detected_count"] == 4
    assert saved["evaded_count"] == 2
    assert saved["passed"] is True
