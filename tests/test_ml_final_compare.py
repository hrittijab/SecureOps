
from datetime import datetime

from ml.final_compare import (
    prepare_rule_events,
    evaluate_rules,
)
from ml.final_test_dataset import build_final_test_dataset


def test_prepare_rule_events_converts_timestamps():
    events = [{
        "event_type": "LOGIN_FAILURE",
        "email": "test@example.test",
        "source_ip": "203.0.113.10",
        "occurred_at": "2027-01-01T12:00:00+00:00",
        "request_id": "TEST-001",
        "failure_reason": "INVALID_CREDENTIALS",
    }]

    prepared = prepare_rule_events(events)

    assert isinstance(
        prepared[0]["occurred_at"],
        datetime,
    )


def test_prepare_rule_events_does_not_mutate_input():
    events = [{
        "event_type": "LOGIN_SUCCESS",
        "email": "test@example.test",
        "source_ip": "198.51.100.10",
        "occurred_at": "2027-01-01T12:00:00+00:00",
        "request_id": "TEST-002",
        "failure_reason": None,
    }]

    prepare_rule_events(events)

    assert isinstance(events[0]["occurred_at"], str)


def test_rule_evaluation_has_four_scenarios():
    dataset = build_final_test_dataset()
    result = evaluate_rules(dataset)

    assert result["total_scenarios"] == 4
    assert len(result["scenarios"]) == 4


def test_rule_alert_categories_account_for_all_alerts():
    dataset = build_final_test_dataset()
    result = evaluate_rules(dataset)

    assert result["total_alerts"] == (
        result["attack_related_alerts"]
        + result["benign_only_alerts"]
        + result["mixed_evidence_alerts"]
    )


def test_scenario_detection_count_is_consistent():
    dataset = build_final_test_dataset()
    result = evaluate_rules(dataset)

    assert result["detected_scenarios"] == sum(
        scenario["detected"]
        for scenario in result["scenarios"]
    )
