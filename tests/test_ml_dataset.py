
from ml.dataset import build_datasets


def test_dataset_sizes():
    datasets = build_datasets()

    assert len(datasets["training"]) == 500
    assert len(datasets["normal_test"]) == 100
    assert len(datasets["attack_test"]) == 100


def test_dataset_reproducibility():
    first = build_datasets()
    second = build_datasets()

    assert first == second


def test_training_contains_normal_activity():
    datasets = build_datasets()

    # Index 2 corresponds to success_count.
    assert any(
        row[2] > 0
        for row in datasets["training"]
    )


def test_attack_windows_contain_failures():
    datasets = build_datasets()

    # Index 1 corresponds to failure_count.
    assert all(
        row[1] > 0
        for row in datasets["attack_test"]
    )
