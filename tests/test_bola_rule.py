from datetime import datetime, timezone
from uuid import uuid4

from detection.rules.bola import detect


ALICE = "11111111-1111-1111-1111-111111111111"
BOB = "22222222-2222-2222-2222-222222222222"


def make_event(actor, target, outcome):
    return {
        "actor_user_id": actor,
        "target_user_id": target,
        "action": "READ_PROFILE",
        "outcome": outcome,
        "request_id": uuid4(),
        "source_ip": "192.0.2.50",
        "occurred_at": datetime.now(timezone.utc),
    }


def test_cross_user_profile_access_alerts():
    events = [
        make_event(ALICE, BOB, "CROSS_USER_ACCESS")
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "BOLA_001"
    assert alerts[0]["entity"] == ALICE
    assert alerts[0]["target_user_id"] == BOB


def test_own_profile_access_does_not_alert():
    events = [
        make_event(ALICE, ALICE, "AUTHORIZED")
    ]

    assert detect(events) == []


def test_authorized_cross_user_operation_does_not_alert():
    events = [
        make_event(ALICE, BOB, "AUTHORIZED")
    ]

    assert detect(events) == []