from datetime import datetime, timezone


def to_timestamp(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if parsed.tzinfo is None:
        raise ValueError("Alert timestamp must include timezone")

    return parsed.astimezone(timezone.utc).isoformat()


def adapt_auth_alert(alert):
    rule_id = alert["rule_id"]

    if rule_id in {
        "BRUTE_FORCE_001",
        "SLOW_BRUTE_FORCE_001",
        "DISTRIBUTED_PASSWORD_SPRAY_001",
        }:
        source_ips = alert.get("source_ips", [])

    elif rule_id in {
        "PASSWORD_SPRAY_001",
        "SLOW_PASSWORD_SPRAY_001",
        }:
        source_ips = [alert["entity"]]
    else:
        raise ValueError(f"Unsupported auth rule: {rule_id}")

    # A brute-force alert can involve multiple IPs.
    # Preserve the original alert but create one correlation
    # candidate for each observed source IP.
    normalized = []

    for source_ip in sorted(set(filter(None, source_ips))):
        normalized.append({
            "rule_id": rule_id,
            "timestamp": to_timestamp(alert["last_seen"]),
            "source_ip": source_ip,
            "service": "auth-service",
            "actor": alert.get("entity"),
            "target": (
                alert.get("entity")
                if rule_id in {"BRUTE_FORCE_001", "SLOW_BRUTE_FORCE_001"}                else alert.get("targeted_accounts")
            ),
            # These are request IDs, not database event IDs.
            # They are retained as evidence references.
            "event_ids": alert.get("request_ids", []),
        })

    return normalized


def adapt_bola_alert(alert, authorization_events):
    request_id = str(alert["request_id"])

    matches = [
        event
        for event in authorization_events
        if str(event.get("request_id")) == request_id
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected one authorization event for {request_id}; "
            f"found {len(matches)}"
        )

    event = matches[0]

    source_ip = event.get("source_ip")

    if not source_ip:
        raise ValueError(
            f"BOLA event {request_id} has no source IP"
        )

    return {
        "rule_id": alert["rule_id"],
        "timestamp": to_timestamp(alert["occurred_at"]),
        "source_ip": source_ip,
        "service": "user-service",
        "actor": str(event["actor_user_id"]),
        "target": str(event["target_user_id"]),
        "event_ids": [request_id],
    }


def adapt_all_alerts(
    auth_alerts,
    bola_alerts,
    authorization_events,
):
    normalized = []

    for alert in auth_alerts:
        normalized.extend(adapt_auth_alert(alert))

    for alert in bola_alerts:
        normalized.append(
            adapt_bola_alert(alert, authorization_events)
        )

    return normalized

def adapt_jwt_alert(alert):
    """Convert a JWT abuse alert into normalized correlation records."""
    source_ips = alert.get("source_ips") or [alert.get("entity")]

    return [
        {
            "rule_id": alert["rule_id"],
            "timestamp": to_timestamp(alert["last_seen"]),
            "source_ip": str(source_ip),
            "service": "user-service",
            "actor": None,
            "target": None,
            "event_ids": [
                str(value)
                for value in alert.get("request_ids", [])
            ],
        }
        for source_ip in sorted(set(filter(None, source_ips)))
    ]


def adapt_mass_assignment_alert(alert, mass_assignment_events):
    """Resolve an actor-based alert to its original request source IPs."""
    request_ids = {
        str(value) for value in alert.get("request_ids", [])
    }

    matches = [
        event
        for event in mass_assignment_events
        if str(event.get("request_id")) in request_ids
        and event.get("event_type") == "MASS_ASSIGNMENT_ATTEMPT"
        and event.get("outcome") == "BLOCKED"
        and str(event.get("actor_user_id")) == str(alert["entity"])
    ]

    grouped = {}

    for event in matches:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        grouped.setdefault(str(source_ip), []).append(
            str(event["request_id"])
        )

    return [
        {
            "rule_id": alert["rule_id"],
            "timestamp": to_timestamp(alert["last_seen"]),
            "source_ip": source_ip,
            "service": "user-service",
            "actor": str(alert["entity"]),
            "target": None,
            "event_ids": sorted(set(ids)),
        }
        for source_ip, ids in sorted(grouped.items())
    ]
