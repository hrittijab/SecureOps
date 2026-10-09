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