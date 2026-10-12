
from datetime import datetime

from ml.final_test_dataset import build_final_test_dataset
from ml.benchmark_splits import build_benchmark_splits


def test_final_dataset_is_deterministic():
    assert build_final_test_dataset() == build_final_test_dataset()


def test_final_dataset_contains_four_attacks():
    dataset = build_final_test_dataset()

    assert len(dataset["scenarios"]) == 4
    assert sum(event["is_attack"] for event in dataset["events"]) == 48


def test_final_dataset_does_not_overlap_existing_splits():
    splits = build_benchmark_splits()
    final = build_final_test_dataset()

    existing_end = max(
        datetime.fromisoformat(event["occurred_at"])
        for event in splits["test"]["events"]
    )

    final_start = min(
        datetime.fromisoformat(event["occurred_at"])
        for event in final["events"]
    )

    assert existing_end < final_start


def test_final_dataset_request_ids_are_unique():
    dataset = build_final_test_dataset()

    ids = [event["request_id"] for event in dataset["events"]]

    assert len(ids) == len(set(ids))


def test_final_dataset_events_are_chronological():
    dataset = build_final_test_dataset()

    timestamps = [
        event["occurred_at"]
        for event in dataset["events"]
    ]

    assert timestamps == sorted(timestamps)
