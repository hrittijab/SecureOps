
from datetime import datetime, timedelta, timezone

from ml.attack_injection import ATTACK_TYPES, generate_attack_events
from ml.benchmark_splits import shift_events
from ml.auth_sessions import generate_authentication_sessions


FINAL_TEST_SEED = 2028
FINAL_TEST_DAY_OFFSET = 35
FINAL_TEST_DAYS = 14


def build_final_test_dataset():
    normal_events = generate_authentication_sessions(
        seed=FINAL_TEST_SEED,
        days=FINAL_TEST_DAYS,
        users=100,
        recovery_sessions=60,
    )

    normal_events = shift_events(
        normal_events,
        FINAL_TEST_DAY_OFFSET,
    )

    events = [
        {**event, "is_attack": False}
        for event in normal_events
    ]

    scenarios = []

    base = datetime(2027, 1, 1, tzinfo=timezone.utc)

    for index, attack_type in enumerate(ATTACK_TYPES):
        attack_id = f"FINAL-ATTACK-{index + 1:03d}"

        start_time = (
            base
            + timedelta(days=FINAL_TEST_DAY_OFFSET + index * 3)
            + timedelta(hours=14)
        )

        attack_events = generate_attack_events(
            attack_type=attack_type,
            start_time=start_time,
            attack_id=attack_id,
            seed=FINAL_TEST_SEED + index,
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
        "name": "final_test",
        "seed": FINAL_TEST_SEED,
        "days": FINAL_TEST_DAYS,
        "events": events,
        "scenarios": scenarios,
        "synthetic_data": True,
    }


if __name__ == "__main__":
    dataset = build_final_test_dataset()

    print("Total events:", len(dataset["events"]))
    print(
        "Attack events:",
        sum(event["is_attack"] for event in dataset["events"]),
    )
    print("Attack scenarios:", len(dataset["scenarios"]))
    print("First event:", dataset["events"][0]["occurred_at"])
    print("Last event:", dataset["events"][-1]["occurred_at"])
