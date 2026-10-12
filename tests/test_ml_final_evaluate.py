
import pytest

from ml.final_evaluate import (
    WINDOW_SECONDS,
    THRESHOLD,
    calculate_metrics,
)


def test_frozen_configuration():
    assert WINDOW_SECONDS == 300
    assert THRESHOLD == pytest.approx(
        0.03363737880038309
    )


def test_perfect_predictions():
    result = calculate_metrics(
        [True, False, True, False],
        [True, False, True, False],
    )

    assert result["tp"] == 2
    assert result["tn"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0


def test_false_positive_and_false_negative():
    result = calculate_metrics(
        [True, False, True, False],
        [False, True, True, False],
    )

    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["tn"] == 1
    assert result["fn"] == 1


def test_mismatched_lengths_rejected():
    with pytest.raises(ValueError):
        calculate_metrics(
            [True, False],
            [True],
        )


def test_empty_metrics():
    result = calculate_metrics([], [])

    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["false_positive_rate"] == 0.0
