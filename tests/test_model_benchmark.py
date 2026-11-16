import unittest

from ml.model_benchmark import run_benchmark


class TestModelBenchmark(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = run_benchmark()

    def test_dataset_counts(self):
        report = self.report

        self.assertEqual(report["evaluation_windows"], 2829)
        self.assertEqual(report["attack_windows"], 10)
        self.assertEqual(report["benign_windows"], 2819)

    def test_confusion_matrices(self):
        ml = self.report["isolation_forest"]
        baseline = self.report["failed_login_baseline"]

        self.assertEqual(
            (ml["tp"], ml["fp"], ml["tn"], ml["fn"]),
            (8, 102, 2717, 2),
        )

        self.assertEqual(
            (
                baseline["tp"],
                baseline["fp"],
                baseline["tn"],
                baseline["fn"],
            ),
            (8, 77, 2742, 2),
        )

    def test_prediction_agreement(self):
        agreement = self.report["prediction_agreement"]

        self.assertEqual(agreement["both_flag"], 85)
        self.assertEqual(agreement["ml_only"], 25)
        self.assertEqual(agreement["baseline_only"], 0)
        self.assertEqual(agreement["neither"], 2719)

        self.assertEqual(
            sum(agreement.values()),
            self.report["evaluation_windows"],
        )

    def test_feature_summary(self):
        summary = self.report["benign_feature_summary"]

        self.assertEqual(summary["ml_only"]["count"], 25)
        self.assertEqual(summary["both_flagged"]["count"], 77)
        self.assertEqual(
            summary["correctly_ignored"]["count"], 2717
        )

        ml_only = summary["ml_only"]

        self.assertGreater(
            ml_only["success_count"]["mean"],
            summary["correctly_ignored"]["success_count"]["mean"],
        )

    def test_missed_attack_windows(self):
        missed = self.report["missed_attack_windows"]

        self.assertEqual(len(missed), 2)

        for window in missed:
            self.assertEqual(window["failure_count"], 1)
            self.assertFalse(window["ml_detected"])
            self.assertFalse(window["baseline_detected"])


if __name__ == "__main__":
    unittest.main()
