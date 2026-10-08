RULE_ID = "BOLA_001"
RULE_NAME = "Broken Object Level Authorization"


def detect(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        actor = event.get("actor_user_id")
        target = event.get("target_user_id")

        if (
            event.get("action") == "READ_PROFILE"
            and event.get("outcome") == "CROSS_USER_ACCESS"
            and actor
            and target
            and actor != target
        ):
            alerts.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": "HIGH",
                "entity": str(actor),
                "target_user_id": str(target),
                "request_id": str(event["request_id"]),
                "occurred_at": event["occurred_at"],
            })

    return alerts