
import json
from pathlib import Path

import pytest


DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "streamlit_demo"
    / "multiseed_ablation.json"
)

EXPECTED_MODELS = {
    "Full (8 features)",
    "No success count (7)",
    "Failure-focused (6)",
    "Minimal (2)",
    "Failed-login statistical baseline",
}


@pytest.fixture(scope="module")
def data():
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def test_results_file_exists():
    assert DATA_PATH.is_file()


def test_synthetic_data_is_declared(data):
    assert data["synthetic_data"] is True
    assert data["window_seconds"] == 300


def test_all_five_models_present(data):
    assert set(data["results"]) == EXPECTED_MODELS


def test_all_models_use_same_seeds(data):
    seeds = data["seeds"]

    assert len(seeds) == 10
    assert len(set(seeds)) == 10

    for runs in data["results"].values():
        assert [run["seed"] for run in runs] == seeds


def test_confusion_matrix_metrics(data):
    for runs in data["results"].values():
        for run in runs:
            tp = run["tp"]
            fp = run["fp"]
            tn = run["tn"]
            fn = run["fn"]

            assert all(
                isinstance(value, int) and value >= 0
                for value in (tp, fp, tn, fn)
            )

            precision = tp / (tp + fp) if tp + fp else 0
            recall = tp / (tp + fn) if tp + fn else 0
            fpr = fp / (fp + tn) if fp + tn else 0

            f1 = (
                2 * precision * recall / (precision + recall)
                if precision + recall else 0
            )

            assert run["precision"] == pytest.approx(precision)
            assert run["recall"] == pytest.approx(recall)
            assert run["fpr"] == pytest.approx(fpr)
            assert run["f1"] == pytest.approx(f1)


def test_summary_matches_individual_runs(data):
    for name, runs in data["results"].items():
        for metric in ("precision", "recall", "f1", "fpr", "fp", "fn"):
            calculated_mean = sum(
                run[metric] for run in runs
            ) / len(runs)

            reported_mean = data["summary"][name][metric]["mean"]

            assert reported_mean == pytest.approx(calculated_mean)


def test_limitations_are_documented(data):
    assert data["limitations"]
    assert any(
        "synthetic" in limitation.lower()
        for limitation in data["limitations"]
    )
