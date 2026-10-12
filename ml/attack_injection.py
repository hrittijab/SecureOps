
import random
from datetime import datetime, timedelta, timezone

from ml.auth_sessions import generate_authentication_sessions
from ml.realistic_traffic import make_login_event


ATTACK_TYPES = (
    "brute_force",
    "password_spray",
    "distributed_spray",
    "slow_brute_force",
)


def generate_attack_events(
    attack_type,
    start_time,
    attack_id,
    seed=42,
):
    if attack_type not in ATTACK_TYPES:
        raise ValueError(f"Unknown attack type: {attack_type}")

    if start_time.tzinfo is None:
        raise ValueError("start_time must be timezone-aware")

    rng = random.Random(seed)
    events = []

    for index in range(12):
        if attack_type == "brute_force":
            email = "victim@example.test"
            ip = "203.0.113.10"
            offset = index * 3

        elif attack_type == "password_spray":
            email = f"victim{index}@example.test"
            ip = "203.0.113.20"
            offset = index * 3

        elif attack_type == "distributed_spray":
            email = f"victim{index}@example.test"
            ip = f"203.0.113.{30 + index}"
            offset = index * 3

        else:
            email = "slowvictim@example.test"
            ip = "203.0.113.50"
            offset = index * 180

        timestamp = start_time + timedelta(
            seconds=offset,
            milliseconds=rng.randint(0, 500),
        )

        events.append(
            make_login_event(
                email=email,
                source_ip=ip,
                timestamp=timestamp,
                success=False,
                request_id=f"{attack_id}-{index:03d}",
            )
        )

    return events


def build_attack_traffic(
    seed=42,
    days=7,
    users=100,
):
    if days < 2:
        raise ValueError("days must be at least 2")

    events = generate_authentication_sessions(
        seed=seed,
        days=days,
        users=users,
    )

    start = datetime(
        2027, 1, 1, tzinfo=timezone.utc
    )

    scenarios = []

    for index, attack_type in enumerate(ATTACK_TYPES):
        attack_id = f"ATTACK-{index + 1:03d}"

        # Place attacks on separate days.
        # All scenarios fit within the observation period.
        attack_start = start + timedelta(
            days=index % days,
            hours=12,
        )

        attack_events = generate_attack_events(
            attack_type=attack_type,
            start_time=attack_start,
            attack_id=attack_id,
            seed=seed + index,
        )

        events.extend(attack_events)

        scenarios.append({
            "attack_id": attack_id,
            "attack_type": attack_type,
            "event_count": len(attack_events),
            "start_time": attack_events[0]["occurred_at"],
            "end_time": attack_events[-1]["occurred_at"],
            "request_ids": [
                event["request_id"]
                for event in attack_events
            ],
        })

    events.sort(key=lambda event: event["occurred_at"])

    return {
        "events": events,
        "scenarios": scenarios,
        "synthetic_data": True,
    }


if __name__ == "__main__":
    dataset = build_attack_traffic()

    print("Total events:", len(dataset["events"]))
    print("Attack scenarios:", len(dataset["scenarios"]))

    for scenario in dataset["scenarios"]:
        print(
            scenario["attack_id"],
            scenario["attack_type"],
            scenario["event_count"],
        )
