
import pytest

from evaluation.benchmark import calculate_metrics


def make_result(expected, actual):
    return {
        "expected_alert": expected,
        "actual_alert": actual,
    }


def test_perfect_detection():
    results = [
        make_result(True, True),
        make_result(True, True),
        make_result(False, False),
        make_result(False, False),
    ]

    metrics = calculate_metrics(results)

    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["accuracy"] == 1.0
    assert metrics["false_positive_rate"] == 0.0


def test_mixed_detection_results():
    results = [
        make_result(True, True),
        make_result(False, False),
        make_result(False, True),
        make_result(True, False),
    ]

    metrics = calculate_metrics(results)

    assert metrics["true_positives"] == 1
    assert metrics["true_negatives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1

    for key in (
        "precision",
        "recall",
        "f1_score",
        "accuracy",
        "specificity",
        "false_positive_rate",
    ):
        assert metrics[key] == 0.5


def test_all_benign_without_alerts():
    results = [
        make_result(False, False),
        make_result(False, False),
    ]

    metrics = calculate_metrics(results)

    assert metrics["true_negatives"] == 2
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0


def test_all_attacks_missed():
    results = [
        make_result(True, False),
        make_result(True, False),
    ]

    metrics = calculate_metrics(results)

    assert metrics["false_negatives"] == 2
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0


def test_empty_benchmark():
    metrics = calculate_metrics([])

    assert metrics["true_positives"] == 0
    assert metrics["true_negatives"] == 0
    assert metrics["accuracy"] == 0.0
    assert metrics["f1_score"] == 0.0


def test_precision_recall_tradeoff():
    results = [
        make_result(True, True),
        make_result(True, True),
        make_result(True, False),
        make_result(False, True),
        make_result(False, False),
        make_result(False, False),
    ]

    metrics = calculate_metrics(results)

    assert metrics["precision"] == pytest.approx(0.6667, abs=0.0001)
    assert metrics["recall"] == pytest.approx(0.6667, abs=0.0001)
    assert metrics["f1_score"] == pytest.approx(0.6667, abs=0.0001)
    assert metrics["accuracy"] == pytest.approx(0.6667, abs=0.0001)
