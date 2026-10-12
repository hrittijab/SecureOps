
import numpy as np


def calibrate_threshold(
    scores,
    target_false_positive_rate=0.05,
):
    if not 0 < target_false_positive_rate < 1:
        raise ValueError(
            "target_false_positive_rate must be between 0 and 1"
        )

    scores = np.asarray(scores, dtype=float)

    if scores.size == 0:
        raise ValueError("Cannot calibrate on empty scores")

    if not np.all(np.isfinite(scores)):
        raise ValueError("Scores must be finite")

    # Strict '>' detection means a threshold equal to the
    # largest benign score yields zero calibration alerts.
    # Choose the lowest observed cutoff satisfying the
    # empirical false-positive budget.
    candidates = np.unique(scores)

    for threshold in candidates:
        false_positive_rate = np.mean(scores > threshold)

        if false_positive_rate <= target_false_positive_rate:
            return float(threshold)

    return float(candidates[-1])


def predict_with_threshold(scores, threshold):
    return [
        bool(score > threshold)
        for score in scores
    ]
