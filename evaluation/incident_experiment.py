import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.password_spray import detect as detect_password_spray
from detection.rules.slow_password_spray import detect as detect_slow_spray
from detection.rules.bola import detect as detect_bola

from incidents.alert_adapter import adapt_all_alerts
from incidents.alert_correlator import correlate_alerts


START = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
SOURCE_IP = "192.0.2.25"  # Reserved documentation IP


def auth_event(email, seconds, source_ip=SOURCE_IP):
    return {
        "event_type": "LOGIN_FAILURE",
        "user_id": None,
        "email": email,
        "source_ip": source_ip,
        "request_id": uuid4(),
        "outcome": "FAILURE",
        "failure_reason": "INVALID_CREDENTIALS",
        "occurred_at": START + timedelta(seconds=seconds),
    }


def generate_attack_events():
    events = []

    # Five rapid failures against one account.
    for i in range(5):
        events.append(
            auth_event("victim@example.test", i * 5)
        )

    # Eight distinct accounts over several minutes.
    # The first five also satisfy the rapid spray rule.
    for i in range(8):
        events.append(
            auth_event(
                f"target{i}@example.test",
                30 + i * 5 if i < 5 else 120 + i * 30,
            )
        )

    return events


def generate_bola_events():
    return [{
        "actor_user_id": "alice",
        "target_user_id": "bob",
        "action": "READ_PROFILE",
        "outcome": "CROSS_USER_ACCESS",
        "request_id": uuid4(),
        "source_ip": SOURCE_IP,
        "occurred_at": START + timedelta(minutes=6),
    }]


def run_experiment():
    auth_events = generate_attack_events()
    authorization_events = generate_bola_events()

    auth_alerts = (
        detect_brute_force(auth_events)
        + detect_password_spray(auth_events)
        + detect_slow_spray(auth_events)
    )

    bola_alerts = detect_bola(authorization_events)

    normalized = adapt_all_alerts(
        auth_alerts,
        bola_alerts,
        authorization_events,
    )

    incidents = correlate_alerts(normalized)

    detected_rules = {
        alert["rule_id"]
        for alert in normalized
    }

    expected_rules = {
        "BRUTE_FORCE_001",
        "PASSWORD_SPRAY_001",
        "SLOW_PASSWORD_SPRAY_001",
        "BOLA_001",
    }

    checks = {
        "all_attack_types_detected": (
            expected_rules.issubset(detected_rules)
        ),
        "single_correlated_incident": len(incidents) == 1,
        "cross_service_correlation": (
            len(incidents) == 1
            and set(incidents[0]["services"])
            == {"auth-service", "user-service"}
        ),
        "critical_severity": (
            len(incidents) == 1
            and incidents[0]["severity"] == "CRITICAL"
        ),
    }

    report = {
        "experiment": "multi_stage_attack_correlation",
        "synthetic_data": True,
        "auth_events": len(auth_events),
        "authorization_events": len(authorization_events),
        "detected_rules": sorted(detected_rules),
        "checks": checks,
        "passed": all(checks.values()),
        "incidents": incidents,
    }

    path = Path("results/multi_stage_incident_experiment.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    print("\n[SecureOps Multi-Stage Attack Experiment]")

    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")

    print(f"\nReport saved to: {path}")

    return report


if __name__ == "__main__":
    result = run_experiment()
    raise SystemExit(0 if result["passed"] else 1)