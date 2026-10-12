
import pytest

from ml.benchmark_splits import build_benchmark_splits
from ml.window_selection import (
    get_window_key,
    prepare_split,
    count_detected_scenarios,
    select_window_size,
)


def test_window_alignment():
    timestamp = "2027-01-01T12:04:59+00:00"

    assert get_window_key(
        timestamp, 300
    ) == get_window_key(
        "2027-01-01T12:00:00+00:00", 300
    )


def test_attack_labels_present():
    splits = build_benchmark_splits()

    _, _, labels = prepare_split(
        splits["validation"], 60
    )

    assert sum(labels) == 15


def test_no_attack_labels_in_training():
    splits = build_benchmark_splits()

    _, _, labels = prepare_split(
        splits["training"], 60
    )

    assert not any(labels)


def test_scenario_detection_with_no_alerts():
    splits = build_benchmark_splits()

    rows, _, _ = prepare_split(
        splits["validation"], 60
    )

    predictions = [False] * len(rows)

    assert count_detected_scenarios(
        splits["validation"],
        rows,
        predictions,
        60,
    ) == 0

def test_selection_reports_attack_window_metrics():
    result = select_window_size()

    for candidate in result["candidates"]:
        assert 0 <= candidate["attack_window_recall"] <= 1
        assert 0 <= candidate["precision"] <= 1
        assert 0 <= candidate["validation_fpr"] <= 1


def test_invalid_window_configuration():
    with pytest.raises(ValueError):
        select_window_size(window_sizes=())


def test_invalid_false_positive_budget():
    with pytest.raises(ValueError):
        select_window_size(
            max_false_positive_rate=0,
        )
