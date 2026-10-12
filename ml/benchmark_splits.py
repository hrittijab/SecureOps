
from datetime import datetime, timedelta, timezone

from ml.auth_sessions import generate_authentication_sessions
from ml.attack_injection import (
    ATTACK_TYPES,
    generate_attack_events,
)


BASE = datetime(2027, 1, 1, tzinfo=timezone.utc)


def shift_events(events, day_offset):
    shifted = []

    for event in events:
        timestamp = datetime.fromisoformat(
            event["occurred_at"]
        )

        shifted.append({
            **event,
            "occurred_at": (
                timestamp + timedelta(days=day_offset)
            ).isoformat(),
        })

    return shifted


def make_split(
    name,
    seed,
    days,
    day_offset,
    include_attacks,
):
    normal = generate_authentication_sessions(
        seed=seed,
        days=days,
        users=100,
        recovery_sessions=30,
    )

    normal = shift_events(normal, day_offset)

    # Preserve event-level ground truth.
    events = [
        {**event, "is_attack": False}
        for event in normal
    ]

    scenarios = []

    if include_attacks:
        for index, attack_type in enumerate(ATTACK_TYPES):
            attack_id = f"{name.upper()}-ATTACK-{index + 1}"

            start = (
                BASE
                + timedelta(days=day_offset + index)
                + timedelta(hours=12)
            )

            attack_events = generate_attack_events(
                attack_type=attack_type,
                start_time=start,
                attack_id=attack_id,
                seed=seed + index,
            )

            events.extend(
                {**event, "is_attack": True}
                for event in attack_events
            )

            scenarios.append({
                "attack_id": attack_id,
                "attack_type": attack_type,
                "request_ids": [
                    event["request_id"]
                    for event in attack_events
                ],
            })

    events.sort(key=lambda event: event["occurred_at"])

    return {
        "name": name,
        "seed": seed,
        "days": days,
        "events": events,
        "scenarios": scenarios,
    }


def build_benchmark_splits():
    training = make_split(
        name="training",
        seed=42,
        days=14,
        day_offset=0,
        include_attacks=False,
    )

    validation = make_split(
        name="validation",
        seed=123,
        days=7,
        day_offset=14,
        include_attacks=True,
    )

    test = make_split(
        name="test",
        seed=999,
        days=7,
        day_offset=21,
        include_attacks=True,
    )

    return {
        "training": training,
        "validation": validation,
        "test": test,
    }


if __name__ == "__main__":
    splits = build_benchmark_splits()

    for name, split in splits.items():
        attack_count = sum(
            event["is_attack"]
            for event in split["events"]
        )

        print(
            name,
            "events=", len(split["events"]),
            "attack_events=", attack_count,
            "scenarios=", len(split["scenarios"]),
        )
