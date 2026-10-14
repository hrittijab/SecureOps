
from datetime import datetime, timezone
from itertools import combinations


def _parse_utc(timestamp):
    """
    Parse an ISO timestamp and normalize it to UTC.
    """
    if isinstance(timestamp, datetime):
        parsed = timestamp
    else:
        parsed = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    if parsed.tzinfo is None:
        raise ValueError(
            "Timestamp must be timezone-aware"
        )

    return parsed.astimezone(timezone.utc)


def build_timeline(events):
    """
    Build a chronological timeline from security events.

    - Preserve distinct events sharing a request ID.
    - Remove duplicate event records.
    - Sort events chronologically.
    - Avoid modifying input events.
    """
    unique_events = {}

    for event in events:
        event_id = str(event["event_id"])

        identity = (
            event_id,
            event.get("service"),
            event.get("event_type"),
            _parse_utc(event["timestamp"]),
        )

        if identity not in unique_events:
            unique_events[identity] = dict(event)

    return sorted(
        unique_events.values(),
        key=lambda event: (
            _parse_utc(event["timestamp"]),
            str(event["event_id"]),
            str(event.get("service", "")),
            str(event.get("event_type", "")),
        ),
    )


def build_incident_timeline(incident, events):
    """
    Reconstruct an incident timeline using explicit evidence IDs.

    Events are included only when their IDs appear in the incident.
    Missing evidence is reported rather than silently ignored.
    """
    evidence_ids = {
        str(event_id)
        for event_id in incident.get("event_ids", [])
    }

    matching_events = [
        event
        for event in events
        if str(event.get("event_id")) in evidence_ids
    ]

    timeline = build_timeline(matching_events)

    matched_ids = {
        str(event["event_id"])
        for event in timeline
    }

    missing_ids = sorted(
        evidence_ids - matched_ids
    )

    return {
        "incident_id": incident["incident_id"],
        "timeline": timeline,
        "matched_evidence_count": len(matched_ids),
        "missing_evidence_ids": missing_ids,
    }


def find_incident_relationships(
    incidents,
    window_minutes=15,
):
    """
    Identify potential relationships between separate incidents.

    SHARED_EVIDENCE:
        Incidents reference at least one common evidence ID.

    POSSIBLE_RELATED_ACTIVITY:
        Incidents share a source IP within the time window
        but have no shared evidence.

    Relationships do not merge incidents or modify severity.
    """
    if window_minutes < 0:
        raise ValueError(
            "window_minutes cannot be negative"
        )

    ordered = sorted(
        incidents,
        key=lambda incident: str(incident["incident_id"]),
    )

    relationships = []

    for first, second in combinations(ordered, 2):
        if first["incident_id"] == second["incident_id"]:
            continue

        first_timestamp = first.get(
            "first_seen",
            first.get("start_time"),
        )
        second_timestamp = second.get(
            "first_seen",
            second.get("start_time"),
        )

        if first_timestamp is None or second_timestamp is None:
            raise ValueError(
                "Incident is missing first_seen/start_time"
            )

        first_time = _parse_utc(first_timestamp)
        second_time = _parse_utc(second_timestamp)

        elapsed = abs(
            (second_time - first_time).total_seconds()
        )

        if elapsed > window_minutes * 60:
            continue

        first_ids = {
            str(event_id)
            for event_id in first.get("event_ids", [])
        }
        second_ids = {
            str(event_id)
            for event_id in second.get("event_ids", [])
        }

        shared_ids = sorted(
            first_ids & second_ids
        )

        first_ip = first.get("source_ip")
        second_ip = second.get("source_ip")

        shared_ip = (
            first_ip
            if first_ip is not None
            and first_ip == second_ip
            else None
        )

        if shared_ids:
            relationship_type = "SHARED_EVIDENCE"

        elif shared_ip is not None:
            relationship_type = "POSSIBLE_RELATED_ACTIVITY"

        else:
            continue

        relationships.append({
            "incident_ids": [
                first["incident_id"],
                second["incident_id"],
            ],
            "relationship_type": relationship_type,
            "shared_event_ids": shared_ids,
            "shared_source_ip": shared_ip,
            "time_difference_seconds": elapsed,
        })

    return relationships


def build_investigation_report(
    incidents,
    events,
    relationships=None,
):
    """
    Build evidence-linked investigation records.

    Preserve incident metadata, reconstruct matched evidence,
    report missing evidence, and attach relationships.
    """
    relationships = relationships or []
    investigations = []

    for incident in incidents:
        evidence = build_incident_timeline(
            incident,
            events,
        )

        related = [
            dict(relationship)
            for relationship in relationships
            if incident["incident_id"]
            in relationship["incident_ids"]
        ]

        investigation = {
            "incident_id": incident["incident_id"],
            "source_ip": incident.get("source_ip"),
            "severity": incident.get("severity"),
            "risk_score": incident.get("risk_score"),
            "rules": list(incident.get("rules", [])),
            "timeline": evidence["timeline"],
            "matched_evidence_count": evidence[
                "matched_evidence_count"
            ],
            "missing_evidence_ids": evidence[
                "missing_evidence_ids"
            ],
            "related_incidents": related,
        }

        investigations.append(investigation)

    investigations.sort(
        key=lambda item: str(item["incident_id"])
    )

    return {
        "investigation_count": len(investigations),
        "investigations": investigations,
    }
