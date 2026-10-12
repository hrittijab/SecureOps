
import random
from datetime import datetime, timedelta, timezone

from ml.features import extract_features, to_feature_matrix


START = datetime(2026, 10, 12, tzinfo=timezone.utc)


def generate_normal_events(
    seed=42,
    window_count=500,
    start=START,
):
    rng = random.Random(seed)
    events = []

    for window_index in range(window_count):
        window_start = start + timedelta(
            minutes=window_index
        )

        event_count = rng.randint(3, 20)

        for _ in range(event_count):
            user_id = rng.randint(1, 100)
            ip_id = rng.randint(1, 60)

            success = rng.random() < 0.92

            events.append({
                "event_type": (
                    "LOGIN_SUCCESS"
                    if success
                    else "LOGIN_FAILURE"
                ),
                "email": f"user{user_id}@example.test",
                "source_ip": f"192.0.2.{ip_id}",
                "occurred_at": window_start + timedelta(
                    seconds=rng.randint(0, 59)
                ),
            })

    return events


def generate_attack_events(
    seed=99,
    window_count=100,
    start=START + timedelta(days=30),
):
    rng = random.Random(seed)
    events = []

    for window_index in range(window_count):
        window_start = start + timedelta(
            minutes=window_index
        )

        attack_type = window_index % 3

        if attack_type == 0:
            # Repeated failures against one account
            for i in range(20):
                events.append({
                    "event_type": "LOGIN_FAILURE",
                    "email": "victim@example.test",
                    "source_ip": "192.0.2.200",
                    "occurred_at": window_start + timedelta(
                        seconds=i * 2
                    ),
                })

        elif attack_type == 1:
            # Password spraying from one source
            for i in range(20):
                events.append({
                    "event_type": "LOGIN_FAILURE",
                    "email": f"target{i}@example.test",
                    "source_ip": "192.0.2.201",
                    "occurred_at": window_start + timedelta(
                        seconds=i * 2
                    ),
                })

        else:
            # Distributed authentication failures
            for i in range(20):
                events.append({
                    "event_type": "LOGIN_FAILURE",
                    "email": f"target{i}@example.test",
                    "source_ip": f"198.51.100.{i + 1}",
                    "occurred_at": window_start + timedelta(
                        seconds=i * 2
                    ),
                })

    rng.shuffle(events)
    return events


def build_datasets():
    training_events = generate_normal_events(
        seed=42,
        window_count=500,
    )

    normal_test_events = generate_normal_events(
        seed=123,
        window_count=100,
        start=START + timedelta(days=15),
    )

    attack_test_events = generate_attack_events(
        seed=99,
        window_count=100,
    )

    training_rows = extract_features(training_events)
    normal_test_rows = extract_features(normal_test_events)
    attack_test_rows = extract_features(attack_test_events)

    return {
        "training": to_feature_matrix(training_rows),
        "normal_test": to_feature_matrix(normal_test_rows),
        "attack_test": to_feature_matrix(attack_test_rows),
    }


if __name__ == "__main__":
    datasets = build_datasets()

    for name, rows in datasets.items():
        print(f"{name}: {len(rows)} windows")
