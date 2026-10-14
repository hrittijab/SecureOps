
from incidents.investigation import build_timeline


def test_build_timeline_sorts_events_chronologically():
    events = [
        {
            "event_id": "event-2",
            "timestamp": "2026-10-10T12:03:00+00:00",
            "service": "user-service",
            "event_type": "JWT_REJECTED",
        },
        {
            "event_id": "event-1",
            "timestamp": "2026-10-10T12:01:00+00:00",
            "service": "auth-service",
            "event_type": "LOGIN_FAILED",
        },
    ]

    timeline = build_timeline(events)

    assert len(timeline) == 2
    assert timeline[0]["event_id"] == "event-1"
    assert timeline[1]["event_id"] == "event-2"


def test_build_timeline_removes_duplicate_events():
    event = {
        "event_id": "event-1",
        "timestamp": "2026-10-10T12:01:00+00:00",
        "service": "auth-service",
        "event_type": "LOGIN_FAILED",
    }

    timeline = build_timeline([event, event])

    assert len(timeline) == 1


def test_build_timeline_preserves_event_evidence():
    event = {
        "event_id": "event-1",
        "timestamp": "2026-10-10T12:01:00+00:00",
        "service": "auth-service",
        "event_type": "LOGIN_FAILED",
        "source_ip": "127.0.0.1",
        "username": "test-user",
    }

    timeline = build_timeline([event])

    assert timeline[0]["source_ip"] == "127.0.0.1"
    assert timeline[0]["username"] == "test-user"

from incidents.investigation import build_incident_timeline


def test_incident_timeline_links_matching_evidence():
    incident = {
        "incident_id": "incident-001",
        "event_ids": ["auth-1", "jwt-1"],
    }

    events = [
        {
            "event_id": "jwt-1",
            "timestamp": "2026-10-10T12:03:00+00:00",
            "service": "user-service",
            "event_type": "JWT_REJECTED",
        },
        {
            "event_id": "auth-1",
            "timestamp": "2026-10-10T12:01:00+00:00",
            "service": "auth-service",
            "event_type": "LOGIN_FAILED",
        },
        {
            "event_id": "unrelated-1",
            "timestamp": "2026-10-10T12:02:00+00:00",
            "service": "auth-service",
            "event_type": "LOGIN_SUCCESS",
        },
    ]

    result = build_incident_timeline(incident, events)

    assert result["incident_id"] == "incident-001"
    assert [e["event_id"] for e in result["timeline"]] == [
        "auth-1",
        "jwt-1",
    ]
    assert result["matched_evidence_count"] == 2
    assert result["missing_evidence_ids"] == []


def test_incident_timeline_reports_missing_evidence():
    incident = {
        "incident_id": "incident-002",
        "event_ids": ["auth-1", "missing-1"],
    }

    events = [
        {
            "event_id": "auth-1",
            "timestamp": "2026-10-10T12:01:00+00:00",
            "service": "auth-service",
            "event_type": "LOGIN_FAILED",
        },
    ]

    result = build_incident_timeline(incident, events)

    assert result["matched_evidence_count"] == 1
    assert result["missing_evidence_ids"] == ["missing-1"]


def test_incident_timeline_does_not_infer_evidence_from_ip():
    incident = {
        "incident_id": "incident-003",
        "event_ids": ["auth-1"],
    }

    events = [
        {
            "event_id": "other-1",
            "timestamp": "2026-10-10T12:01:00+00:00",
            "source_ip": "127.0.0.1",
            "service": "auth-service",
            "event_type": "LOGIN_FAILED",
        },
    ]

    result = build_incident_timeline(incident, events)

    assert result["timeline"] == []
    assert result["missing_evidence_ids"] == ["auth-1"]

def test_timeline_preserves_distinct_events_with_same_request_id():
    from incidents.investigation import build_timeline

    events = [
        {
            "event_id": "request-123",
            "service": "auth-service",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": "2026-10-10T12:00:00+00:00",
        },
        {
            "event_id": "request-123",
            "service": "user-service",
            "event_type": "ACCESS_GRANTED",
            "timestamp": "2026-10-10T12:00:01+00:00",
        },
    ]

    timeline = build_timeline(events)

    assert len(timeline) == 2
    assert timeline[0]["event_type"] == "LOGIN_SUCCESS"
    assert timeline[1]["event_type"] == "ACCESS_GRANTED"

def test_build_timeline_handles_empty_input():
    assert build_timeline([]) == []
