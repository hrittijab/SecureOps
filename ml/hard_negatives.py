
from datetime import datetime, timedelta, timezone

from ml.adversarial import make_event


BASE = datetime(2026, 12, 1, 12, 0, tzinfo=timezone.utc)


def build_hard_negatives():
    scenarios = []

    def create_event(index, email, ip, seconds, success=False):
        event = make_event(index, email, ip, seconds, success)
        event["occurred_at"] = BASE + timedelta(seconds=seconds)
        return event

    # A user mistypes their password four times,
    # then successfully authenticates.
    scenarios.append({
        "id": "benign_password_recovery",
        "attack": False,
        "events": [
            create_event(
                i, "employee@example.test", "192.0.2.50", i * 8
            )
            for i in range(4)
        ] + [
            create_event(
                4, "employee@example.test",
                "192.0.2.50", 40, success=True
            )
        ],
    })

    # Several employees log in from one office network.
    scenarios.append({
        "id": "benign_shared_office_ip",
        "attack": False,
        "events": [
            create_event(
                i, f"employee{i}@example.test",
                "192.0.2.60", i * 3, success=True
            )
            for i in range(25)
        ],
    })

    # One isolated incorrect password.
    scenarios.append({
        "id": "benign_single_failure",
        "attack": False,
        "events": [
            create_event(
                0, "employee@example.test",
                "192.0.2.70", 0
            )
        ],
    })

    # A temporary wave of successful logins.
    scenarios.append({
        "id": "benign_shift_change",
        "attack": False,
        "events": [
            create_event(
                i, f"worker{i}@example.test",
                f"198.51.100.{i + 1}",
                i % 60, success=True
            )
            for i in range(50)
        ],
    })

    # Different legitimate users independently
    # enter incorrect passwords.
    scenarios.append({
        "id": "benign_independent_mistakes",
        "attack": False,
        "events": [
            create_event(
                i, f"user{i}@example.test",
                f"203.0.113.{i + 1}", i * 5
            )
            for i in range(7)
        ],
    })

    return scenarios
