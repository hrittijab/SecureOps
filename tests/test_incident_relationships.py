
from incidents.investigation import find_incident_relationships


def make_incident(incident_id, timestamp, ip, event_ids, actor=None):
    return {
        "incident_id": incident_id,
        "source_ip": ip,
        "start_time": timestamp,
        "event_ids": event_ids,
        "actor": actor,
    }


def test_shared_evidence_creates_relationship():
    incidents = [
        make_incident("inc-1", "2026-10-10T12:00:00+00:00",
                      "10.0.0.5", ["event-1"]),
        make_incident("inc-2", "2026-10-10T12:04:00+00:00",
                      "10.0.0.5", ["event-1", "event-2"]),
    ]

    relationships = find_incident_relationships(incidents)

    assert len(relationships) == 1
    assert relationships[0]["relationship_type"] == "SHARED_EVIDENCE"
    assert relationships[0]["shared_event_ids"] == ["event-1"]


def test_same_ip_creates_only_possible_relationship():
    incidents = [
        make_incident("inc-1", "2026-10-10T12:00:00+00:00",
                      "10.0.0.5", ["event-1"]),
        make_incident("inc-2", "2026-10-10T12:04:00+00:00",
                      "10.0.0.5", ["event-2"]),
    ]

    relationships = find_incident_relationships(incidents)

    assert len(relationships) == 1
    assert relationships[0]["relationship_type"] == "POSSIBLE_RELATED_ACTIVITY"
    assert relationships[0]["shared_event_ids"] == []


def test_different_ips_without_shared_evidence_are_unrelated():
    incidents = [
        make_incident("inc-1", "2026-10-10T12:00:00+00:00",
                      "10.0.0.5", ["event-1"]),
        make_incident("inc-2", "2026-10-10T12:04:00+00:00",
                      "10.0.0.6", ["event-2"]),
    ]

    assert find_incident_relationships(incidents) == []


def test_relationship_outside_time_window_is_excluded():
    incidents = [
        make_incident("inc-1", "2026-10-10T12:00:00+00:00",
                      "10.0.0.5", ["event-1"]),
        make_incident("inc-2", "2026-10-10T13:00:00+00:00",
                      "10.0.0.5", ["event-2"]),
    ]

    assert find_incident_relationships(
        incidents, window_minutes=15
    ) == []


def test_relationships_are_deterministic():
    incidents = [
        make_incident("inc-2", "2026-10-10T12:04:00+00:00",
                      "10.0.0.5", ["event-2"]),
        make_incident("inc-1", "2026-10-10T12:00:00+00:00",
                      "10.0.0.5", ["event-1"]),
    ]

    assert find_incident_relationships(incidents) == (
        find_incident_relationships(list(reversed(incidents)))
    )

def test_relationships_support_real_correlator_incidents():
    from incidents.alert_correlator import correlate_alerts

    alerts = [
        {
            "rule_id": "PASSWORD_SPRAY_001",
            "timestamp": "2026-10-10T12:00:00+00:00",
            "source_ip": "10.0.0.5",
            "service": "auth-service",
            "event_ids": ["auth-1"],
        },
        {
            "rule_id": "JWT_ABUSE_001",
            "timestamp": "2026-10-10T12:04:00+00:00",
            "source_ip": "10.0.0.5",
            "service": "user-service",
            "event_ids": ["jwt-1"],
        },
    ]

    incidents = correlate_alerts(
        alerts,
        require_related_evidence=True,
    )

    assert len(incidents) == 2

    relationships = find_incident_relationships(incidents)

    assert len(relationships) == 1
    assert relationships[0]["relationship_type"] == (
        "POSSIBLE_RELATED_ACTIVITY"
    )
