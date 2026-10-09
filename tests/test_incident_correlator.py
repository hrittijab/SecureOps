from incidents.correlator import correlate_events


def event(
    event_id,
    timestamp,
    source_ip="127.0.0.1",
    service="auth-service",
    event_type="LOGIN_FAILED",
    outcome=None,
):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "service": service,
        "event_type": event_type,
        "actor": "test@secureops.local",
        "target": "test@secureops.local",
        "outcome": outcome,
    }


def test_groups_events_from_same_source():
    events = [
        event("1", "2026-10-08T10:00:00+00:00"),
        event("2", "2026-10-08T10:01:00+00:00"),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1
    assert incidents[0]["event_count"] == 2


def test_separates_different_sources():
    events = [
        event("1", "2026-10-08T10:00:00+00:00", source_ip="10.0.0.1"),
        event("2", "2026-10-08T10:01:00+00:00", source_ip="10.0.0.2"),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 2


def test_separates_events_outside_window():
    events = [
        event("1", "2026-10-08T10:00:00+00:00"),
        event("2", "2026-10-08T10:30:00+00:00"),
    ]

    incidents = correlate_events(events, window_minutes=15)

    assert len(incidents) == 2


def test_cross_user_access_is_high_severity():
    events = [
        event(
            "1",
            "2026-10-08T10:00:00+00:00",
            service="user-service",
            event_type="READ_PROFILE",
            outcome="CROSS_USER_ACCESS",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "HIGH"


def test_normal_activity_is_ignored():
    events = [
        event(
            "1",
            "2026-10-08T10:00:00+00:00",
            event_type="LOGIN_SUCCESS",
            outcome="AUTHORIZED",
        ),
    ]

    assert correlate_events(events) == []


def test_incident_ids_are_stable():
    events = [
        event("1", "2026-10-08T10:00:00+00:00"),
        event("2", "2026-10-08T10:01:00+00:00"),
    ]

    first = correlate_events(events)
    second = correlate_events(events)

    assert first[0]["incident_id"] == second[0]["incident_id"]