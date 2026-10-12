
from datetime import datetime, timedelta, timezone

from ml.dataset import generate_normal_events


BASE = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


def make_event(index, email, ip, seconds, success=False):
    return {
        "event_type": "LOGIN_SUCCESS" if success else "LOGIN_FAILURE",
        "failure_reason": None if success else "INVALID_CREDENTIALS",
        "email": email,
        "source_ip": ip,
        "request_id": f"ADV-{index:05d}",
        "occurred_at": BASE + timedelta(seconds=seconds),
    }


def build_scenarios():
    scenarios = []

    # Below the existing brute-force threshold.
    scenarios.append({
        "id": "subthreshold_brute_force",
        "attack": True,
        "events": [
            make_event(i, "victim@example.test", "192.0.2.200", i * 10)
            for i in range(4)
        ],
    })

    # Below the password-spray threshold.
    scenarios.append({
        "id": "subthreshold_password_spray",
        "attack": True,
        "events": [
            make_event(
                i,
                f"target{i}@example.test",
                "192.0.2.201",
                i * 10,
            )
            for i in range(4)
        ],
    })

    # Below the distributed-spray threshold.
    scenarios.append({
        "id": "subthreshold_distributed_spray",
        "attack": True,
        "events": [
            make_event(
                i,
                f"target{i}@example.test",
                f"198.51.100.{i + 1}",
                i * 5,
            )
            for i in range(7)
        ],
    })

    # Five failures spread over 20 minutes.
    # This is outside the existing 15-minute slow brute-force window.
    scenarios.append({
        "id": "very_slow_brute_force",
        "attack": True,
        "events": [
            make_event(
                i,
                "slowvictim@example.test",
                "192.0.2.202",
                i * 300,
            )
            for i in range(5)
        ],
    })

    # Legitimate high-volume authentication.
    benign_spike = [
        make_event(
            i,
            f"employee{i}@example.test",
            f"203.0.113.{i + 1}",
            i % 60,
            success=True,
        )
        for i in range(40)
    ]

    scenarios.append({
        "id": "benign_login_spike",
        "attack": False,
        "events": benign_spike,
    })

    # Normal login activity with occasional mistakes.
    benign_mistakes = generate_normal_events(
        seed=456,
        window_count=5,
        start=BASE + timedelta(days=1),
    )

    for i, event in enumerate(benign_mistakes):
        event["failure_reason"] = (
            "INVALID_CREDENTIALS"
            if event["event_type"] == "LOGIN_FAILURE"
            else None
        )
        event["request_id"] = f"BENIGN-{i:05d}"

    scenarios.append({
        "id": "benign_password_mistakes",
        "attack": False,
        "events": benign_mistakes,
    })

    return scenarios
