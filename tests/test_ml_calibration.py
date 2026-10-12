
import pytest

from ml.calibration import (
    calibrate_threshold,
    predict_with_threshold,
)


def test_calibration_respects_false_positive_budget():
    scores = [0.01, 0.02, 0.03, 0.04, 0.05]

    threshold = calibrate_threshold(
        scores,
        target_false_positive_rate=0.20,
    )

    predictions = predict_with_threshold(
        scores,
        threshold,
    )

    assert sum(predictions) <= 1


def test_empty_scores_rejected():
    with pytest.raises(ValueError):
        calibrate_threshold([])


def test_invalid_target_rejected():
    with pytest.raises(ValueError):
        calibrate_threshold(
            [0.1, 0.2],
            target_false_positive_rate=0,
        )


def test_threshold_predictions():
    predictions = predict_with_threshold(
        [0.1, 0.2, 0.3],
        threshold=0.2,
    )

    assert predictions == [False, False, True]
