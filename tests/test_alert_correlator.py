from incidents.alert_correlator import correlate_alerts


def alert(
    rule_id,
    timestamp="2026-10-08T10:00:00+00:00",
    source_ip="10.0.0.5",
    service="auth-service",
    event_ids=None,
):
    return {
        "rule_id": rule_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "service": service,
        "event_ids": event_ids or ["event-1"],
    }


def test_single_detector_alert_creates_incident():
    incidents = correlate_alerts([
        alert("BRUTE_FORCE_001")
    ])

    assert len(incidents) == 1
    assert incidents[0]["risk_score"] == 45
    assert incidents[0]["severity"] == "MEDIUM"


def test_multiple_rules_increase_score():
    incidents = correlate_alerts([
        alert("BRUTE_FORCE_001"),
        alert("PASSWORD_SPRAY_001"),
    ])

    assert len(incidents) == 1
    assert incidents[0]["risk_score"] == 70
    assert incidents[0]["severity"] == "HIGH"


def test_cross_service_alerts_are_correlated():
    incidents = correlate_alerts([
        alert("PASSWORD_SPRAY_001"),
        alert(
            "BOLA_001",
            timestamp="2026-10-08T10:03:00+00:00",
            service="user-service",
        ),
    ])

    assert len(incidents) == 1
    assert incidents[0]["services"] == [
        "auth-service",
        "user-service",
    ]
    assert incidents[0]["risk_score"] == 95
    assert incidents[0]["severity"] == "CRITICAL"


def test_different_ips_do_not_merge():
    incidents = correlate_alerts([
        alert("BRUTE_FORCE_001", source_ip="10.0.0.1"),
        alert("BRUTE_FORCE_001", source_ip="10.0.0.2"),
    ])

    assert len(incidents) == 2


def test_outside_window_does_not_merge():
    incidents = correlate_alerts([
        alert("BRUTE_FORCE_001"),
        alert(
            "PASSWORD_SPRAY_001",
            timestamp="2026-10-08T10:30:00+00:00",
        ),
    ], window_minutes=15)

    assert len(incidents) == 2


def test_empty_alerts_produce_no_incidents():
    assert correlate_alerts([]) == []

def test_overlapping_password_spray_rules_create_one_incident():
    alerts = [
        alert(
            "PASSWORD_SPRAY_001",
            timestamp="2026-10-08T10:00:00+00:00",
            event_ids=["req-1", "req-2", "req-3"],
        ),
        alert(
            "SLOW_PASSWORD_SPRAY_001",
            timestamp="2026-10-08T10:04:00+00:00",
            event_ids=["req-2", "req-3", "req-4"],
        ),
    ]

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["alert_count"] == 2
    assert incident["rules"] == [
        "PASSWORD_SPRAY_001",
        "SLOW_PASSWORD_SPRAY_001",
    ]
    assert incident["event_ids"] == [
        "req-1",
        "req-2",
        "req-3",
        "req-4",
    ]
    assert len(incident["timeline"]) == 2
    assert incident["first_seen"] == "2026-10-08T10:00:00+00:00"
    assert incident["last_seen"] == "2026-10-08T10:04:00+00:00"



def test_unrelated_attacks_same_ip_remain_separate():
    alerts = [
        alert(
            "PASSWORD_SPRAY_001",
            timestamp="2026-10-08T10:00:00+00:00",
            event_ids=["spray-1", "spray-2"],
        ),
        alert(
            "BOLA_001",
            timestamp="2026-10-08T10:03:00+00:00",
            service="user-service",
            event_ids=["bola-1"],
        ),
    ]

    incidents = correlate_alerts(
        alerts,
        require_related_evidence=True,
    )

    assert len(incidents) == 2

    assert {
        tuple(incident["rules"])
        for incident in incidents
    } == {
        ("PASSWORD_SPRAY_001",),
        ("BOLA_001",),
    }


def test_identical_alerts_are_deduplicated():
    duplicate = alert(
        "PASSWORD_SPRAY_001",
        event_ids=["request-1", "request-2"],
    )

    incidents = correlate_alerts([
        duplicate,
        dict(duplicate),
    ])

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["alert_count"] == 1
    assert incident["rules"] == ["PASSWORD_SPRAY_001"]
    assert incident["event_ids"] == [
        "request-1",
        "request-2",
    ]
    assert len(incident["timeline"]) == 1


def test_incident_id_is_deterministic():
    alerts = [
        alert("BRUTE_FORCE_001"),
        alert("PASSWORD_SPRAY_001"),
    ]

    first = correlate_alerts(alerts)
    second = correlate_alerts(alerts)

    assert first[0]["incident_id"] == second[0]["incident_id"]


def test_invalid_alert_rejected():
    try:
        correlate_alerts([{
            "rule_id": "BOLA_001",
            "timestamp": "2026-10-08T10:00:00+00:00",
        }])
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_same_service_unrelated_evidence_stays_separate():
    alerts = [
        alert(
            "BRUTE_FORCE_001",
            event_ids=["attack-a"],
        ),
        alert(
            "PASSWORD_SPRAY_001",
            timestamp="2026-10-08T10:02:00+00:00",
            event_ids=["attack-b"],
        ),
    ]

    incidents = correlate_alerts(
        alerts,
        require_related_evidence=True,
    )

    assert len(incidents) == 2