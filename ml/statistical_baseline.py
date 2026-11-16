from ml.calibration import (
    calibrate_threshold,
    predict_with_threshold,
)


class FailedLoginBaseline:
    """
    Single-feature anomaly detector using failed-login counts.

    Threshold selection must use validation data only.
    """

    def __init__(self):
        self.threshold = None

    def fit(self, validation_rows, validation_labels,
            target_false_positive_rate=0.05):

        if len(validation_rows) != len(validation_labels):
            raise ValueError("Rows and labels must match")

        benign_scores = [
            float(row["failure_count"])
            for row, is_attack in zip(
                validation_rows, validation_labels
            )
            if not is_attack
        ]

        self.threshold = calibrate_threshold(
            benign_scores,
            target_false_positive_rate,
        )

        return self

    def predict(self, rows):
        if self.threshold is None:
            raise RuntimeError("Baseline must be calibrated first")

        scores = [
            float(row["failure_count"])
            for row in rows
        ]

        return predict_with_threshold(
            scores,
            self.threshold,
        )
