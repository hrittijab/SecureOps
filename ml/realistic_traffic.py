
import random
from datetime import datetime, timedelta, timezone


BASE_TIME = datetime(
    2027, 1, 1, tzinfo=timezone.utc
)


def make_login_event(
    email,
    source_ip,
    timestamp,
    success=True,
    request_id=None,
):
    return {
        "event_type": (
            "LOGIN_SUCCESS" if success
            else "LOGIN_FAILURE"
        ),
        "email": email,
        "source_ip": source_ip,
        "occurred_at": timestamp.isoformat(),
        "request_id": request_id,
        "failure_reason": (
            None if success
            else "INVALID_CREDENTIALS"
        ),
    }


def generate_realistic_normal_traffic(
    seed=42,
    days=7,
    users=100,
):
    if days < 1 or users < 1:
        raise ValueError(
            "days and users must be positive"
        )

    rng = random.Random(seed)
    events = []
    request_counter = 0

    accounts = [
        f"user{i}@example.test"
        for i in range(1, users + 1)
    ]

    for day in range(days):
        day_start = BASE_TIME + timedelta(days=day)

        for hour in range(24):
            # Higher login volume during working hours.
            if 8 <= hour <= 18:
                login_count = rng.randint(30, 60)
            else:
                login_count = rng.randint(3, 12)

            for _ in range(login_count):
                request_counter += 1

                email = rng.choice(accounts)

                # Shared office networks are normal.
                if rng.random() < 0.30:
                    ip = "192.0.2.10"
                else:
                    ip = (
                        f"198.51.100."
                        f"{rng.randint(1, 200)}"
                    )

                timestamp = (
                    day_start
                    + timedelta(
                        hours=hour,
                        seconds=rng.randint(0, 3599),
                    )
                )

                # Approximately 5% login failures.
                success = rng.random() >= 0.05

                events.append(
                    make_login_event(
                        email=email,
                        source_ip=ip,
                        timestamp=timestamp,
                        success=success,
                        request_id=(
                            f"NORMAL-{request_counter:07d}"
                        ),
                    )
                )

    events.sort(key=lambda e: e["occurred_at"])
    return events


if __name__ == "__main__":
    events = generate_realistic_normal_traffic()

    print("Generated events:", len(events))
    print(
        "Successful logins:",
        sum(
            e["event_type"] == "LOGIN_SUCCESS"
            for e in events
        ),
    )
    print(
        "Failed logins:",
        sum(
            e["event_type"] == "LOGIN_FAILURE"
            for e in events
        ),
    )
    print("First event:", events[0]["occurred_at"])
    print("Last event:", events[-1]["occurred_at"])
