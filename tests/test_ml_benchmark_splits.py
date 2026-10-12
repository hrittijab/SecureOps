
from datetime import datetime

from ml.benchmark_splits import build_benchmark_splits


def test_split_structure():
    splits = build_benchmark_splits()

    assert set(splits) == {
        "training",
        "validation",
        "test",
    }

    assert len(splits["training"]["scenarios"]) == 0
    assert len(splits["validation"]["scenarios"]) == 4
    assert len(splits["test"]["scenarios"]) == 4


def test_training_has_no_attacks():
    splits = build_benchmark_splits()

    assert all(
        not event["is_attack"]
        for event in splits["training"]["events"]
    )


def test_validation_and_test_have_attacks():
    splits = build_benchmark_splits()

    for name in ("validation", "test"):
        assert sum(
            event["is_attack"]
            for event in splits[name]["events"]
        ) == 48


def test_time_periods_do_not_overlap():
    splits = build_benchmark_splits()

    bounds = {}

    for name, split in splits.items():
        timestamps = [
            datetime.fromisoformat(event["occurred_at"])
            for event in split["events"]
        ]

        bounds[name] = (min(timestamps), max(timestamps))

    assert bounds["training"][1] < bounds["validation"][0]
    assert bounds["validation"][1] < bounds["test"][0]


def test_request_ids_are_unique_within_each_split():
    splits = build_benchmark_splits()

    for split in splits.values():
        request_ids = [
            event["request_id"]
            for event in split["events"]
        ]

        assert len(request_ids) == len(set(request_ids))
