
import random
from datetime import timedelta

from ml.realistic_traffic import (
    generate_realistic_normal_traffic,
    make_login_event,
)


def generate_authentication_sessions(
    seed=42,
    days=7,
    users=100,
    recovery_sessions=30,
):
    if recovery_sessions < 0:
        raise ValueError(
            "recovery_sessions must be non-negative"
        )

    rng = random.Random(seed)

    events = generate_realistic_normal_traffic(
        seed=seed,
        days=days,
        users=users,
    )

    # Use existing timestamps to place recovery sessions
    # within the generated observation period.
    candidate_events = [
        event for event in events
        if event["event_type"] == "LOGIN_SUCCESS"
    ]

    if recovery_sessions > len(candidate_events):
        raise ValueError(
            "Not enough successful events for sessions"
        )

    selected = rng.sample(
        candidate_events,
        recovery_sessions,
    )

    for index, success_event in enumerate(selected):
        from datetime import datetime

        success_time = datetime.fromisoformat(
            success_event["occurred_at"]
        )

        # Add failed attempts before the existing success.
        failure_count = rng.randint(1, 3)

        for attempt in range(failure_count):
            timestamp = (
                success_time
                - timedelta(
                    seconds=10 * (failure_count - attempt)
                )
            )

            events.append(
                make_login_event(
                    email=success_event["email"],
                    source_ip=success_event["source_ip"],
                    timestamp=timestamp,
                    success=False,
                    request_id=(
                        f"RECOVERY-{index:05d}-{attempt}"
                    ),
                )
            )

    events.sort(key=lambda e: e["occurred_at"])

    return events


if __name__ == "__main__":
    events = generate_authentication_sessions()

    failures = sum(
        event["event_type"] == "LOGIN_FAILURE"
        for event in events
    )

    successes = sum(
        event["event_type"] == "LOGIN_SUCCESS"
        for event in events
    )

    recovery_failures = sum(
        event["request_id"].startswith("RECOVERY-")
        for event in events
    )

    print("Total events:", len(events))
    print("Successful logins:", successes)
    print("Failed logins:", failures)
    print("Recovery failure events:", recovery_failures)
