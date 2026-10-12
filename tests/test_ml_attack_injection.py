
from datetime import datetime, timezone

import pytest

from ml.attack_injection import (
    ATTACK_TYPES,
    build_attack_traffic,
    generate_attack_events,
)


START = datetime(2027, 1, 1, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("attack_type", ATTACK_TYPES)
def test_attack_generation(attack_type):
    events = generate_attack_events(
        attack_type,
        START,
        "TEST-001",
    )

    assert len(events) == 12

    assert all(
        event["event_type"] == "LOGIN_FAILURE"
        for event in events
    )

    assert all(
        event["failure_reason"] == "INVALID_CREDENTIALS"
        for event in events
    )


def test_attack_generation_is_deterministic():
    first = generate_attack_events(
        "brute_force", START, "TEST-001"
    )
    second = generate_attack_events(
        "brute_force", START, "TEST-001"
    )

    assert first == second


def test_attack_types_have_distinct_patterns():
    brute = generate_attack_events(
        "brute_force", START, "BRUTE"
    )
    spray = generate_attack_events(
        "password_spray", START, "SPRAY"
    )
    distributed = generate_attack_events(
        "distributed_spray", START, "DIST"
    )

    assert len({e["email"] for e in brute}) == 1
    assert len({e["email"] for e in spray}) == 12
    assert len({e["source_ip"] for e in spray}) == 1
    assert len({e["source_ip"] for e in distributed}) == 12


def test_dataset_contains_four_scenarios():
    dataset = build_attack_traffic()

    assert len(dataset["scenarios"]) == 4
    assert len(dataset["events"]) > 4000


def test_invalid_attack_type():
    with pytest.raises(ValueError):
        generate_attack_events(
            "unknown", START, "TEST"
        )


def test_naive_datetime_rejected():
    with pytest.raises(ValueError):
        generate_attack_events(
            "brute_force",
            datetime(2027, 1, 1),
            "TEST",
        )
