from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5


SEVERITY_SCORES = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90,
}

RULE_SCORES = {
    "BRUTE_FORCE_001": 45,
    "PASSWORD_SPRAY_001": 65,
    "SLOW_PASSWORD_SPRAY_001": 65,
    "BOLA_001": 80,
}


def parse_time(value):
    if isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if result.tzinfo is None:
        raise ValueError("Alert timestamps must be timezone-aware")

    return result.astimezone(timezone.utc)


def normalize_alert(alert):
    required = ("rule_id", "timestamp", "source_ip")

    for field in required:
        if not alert.get(field):
            raise ValueError(f"Missing alert field: {field}")

    return {
        "rule_id": str(alert["rule_id"]),
        "timestamp": parse_time(alert["timestamp"]).isoformat(),
        "source_ip": str(alert["source_ip"]),
        "service": str(alert.get("service", "unknown")),
        "actor": alert.get("actor"),
        "target": alert.get("target"),
        "event_ids": sorted({
            str(value) for value in alert.get("event_ids", [])
        }),
    }


def score_incident(alerts):
    rule_ids = {alert["rule_id"] for alert in alerts}

    score = max(
        RULE_SCORES.get(rule_id, 20)
        for rule_id in rule_ids
    )

    # Multiple independent detection types increase confidence.
    score += min(15, 5 * (len(rule_ids) - 1))

    # Cross-service activity receives additional investigative priority.
    services = {alert["service"] for alert in alerts}

    if len(services) > 1:
        score += 10

    return min(score, 100)


def severity_from_score(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def build_incident(source_ip, alerts):
    alerts = sorted(
        alerts,
        key=lambda alert: (
            alert["timestamp"],
            alert["rule_id"],
        ),
    )

    score = score_incident(alerts)

    identity = "|".join(
        [
            source_ip,
            *[
                (
                    f"{alert['rule_id']}:"
                    f"{alert['timestamp']}:"
                    f"{','.join(alert['event_ids'])}"
                )
                for alert in alerts
            ],
        ]
    )

    return {
        "incident_id": str(uuid5(NAMESPACE_URL, identity)),
        "source_ip": source_ip,
        "severity": severity_from_score(score),
        "risk_score": score,
        "alert_count": len(alerts),
        "rules": sorted({a["rule_id"] for a in alerts}),
        "services": sorted({a["service"] for a in alerts}),
        "first_seen": alerts[0]["timestamp"],
        "last_seen": alerts[-1]["timestamp"],
        "event_ids": sorted({
            event_id
            for alert in alerts
            for event_id in alert["event_ids"]
        }),
        "timeline": alerts,
    }


def correlate_alerts(alerts, window_minutes=15):
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    normalized = [normalize_alert(a) for a in alerts]
    grouped = defaultdict(list)

    for alert in normalized:
        grouped[alert["source_ip"]].append(alert)

    incidents = []
    window = timedelta(minutes=window_minutes)

    for source_ip, group in grouped.items():
        group.sort(key=lambda a: a["timestamp"])

        current = []

        for alert in group:
            if not current:
                current = [alert]
                continue

            elapsed = (
                parse_time(alert["timestamp"])
                - parse_time(current[0]["timestamp"])
            )

            if elapsed <= window:
                current.append(alert)
            else:
                incidents.append(build_incident(source_ip, current))
                current = [alert]

        if current:
            incidents.append(build_incident(source_ip, current))

    return sorted(
        incidents,
        key=lambda incident: (
            incident["first_seen"],
            incident["source_ip"],
        ),
    )