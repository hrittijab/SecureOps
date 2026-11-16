import csv
from collections import Counter
from pathlib import Path

from ml.features import FEATURE_NAMES
from ml.final_test_dataset import build_final_test_dataset
from ml.window_selection import prepare_split


DATA_PATH = Path(__file__).resolve().parents[1] / "streamlit_demo" / "eda_windows.csv"


def load_rows():
    with DATA_PATH.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def test_dataset_matches_final_evaluation():
    rows = load_rows()
    labels = Counter(row["is_attack"] for row in rows)

    assert len(rows) == 2829
    assert labels == {"0": 2819, "1": 10}
    assert all(int(row["window_seconds"]) == 300 for row in rows)


def test_features_are_consistent():
    rows = load_rows()

    assert rows
    assert len(FEATURE_NAMES) == 8

    for row in rows:
        assert all(row[name] != "" for name in FEATURE_NAMES)

        total = float(row["event_count"])
        failures = float(row["failure_count"])
        successes = float(row["success_count"])

        assert total > 0
        assert total == failures + successes
        assert abs(
            float(row["failure_rate"]) - failures / total
        ) < 1e-9


def test_no_duplicate_windows_or_raw_identifiers():
    rows = load_rows()

    timestamps = [row["window_start"] for row in rows]
    assert len(timestamps) == len(set(timestamps))

    expected_columns = {
        "window_start",
        "window_seconds",
        *FEATURE_NAMES,
        "is_attack",
    }

    assert set(rows[0]) == expected_columns


def test_csv_matches_reproducible_generator():
    rows = load_rows()

    dataset = build_final_test_dataset()
    generated_rows, _, labels = prepare_split(dataset, 300)

    assert len(rows) == len(generated_rows)

    for saved, generated, label in zip(
        rows, generated_rows, labels
    ):
        assert saved["window_start"] == generated["window_start"]
        assert int(saved["is_attack"]) == int(label)

        for name in FEATURE_NAMES:
            assert abs(
                float(saved[name]) - float(generated[name])
            ) < 1e-9
