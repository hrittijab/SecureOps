import json
import uuid
from pathlib import Path

import requests

from detection.runner import load_security_events
from detection.rules.brute_force import detect as detect_brute_force
from detection.rules.password_spray import detect as detect_password_spray
from detection.rules.slow_password_spray import detect as detect_slow_spray

from incidents.alert_adapter import adapt_all_alerts
from incidents.alert_correlator import correlate_alerts


BASE_URL = "http://localhost:8081"
OUTPUT = Path("results/live_auth_replay.json")


def send_failed_login(email):
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={
            "email": email,
            "password": "secureops-intentionally-wrong",
        },
        timeout=10,
    )

    return response.status_code


def run():
    # Unique run ID prevents old benchmark events
    # from contaminating this experiment.
    run_id = uuid.uuid4().hex[:12]
    domain = "example.test"

    victim = f"victim-{run_id}@{domain}"

    accounts = [
        f"target{i}-{run_id}@{domain}"
        for i in range(8)
    ]

    print("\n[SecureOps Live Authentication Replay]")
    print("Run ID:", run_id)

    health = requests.get(
        f"{BASE_URL}/actuator/health",
        timeout=10,
    )
    health.raise_for_status()

    statuses = []

    # Brute-force pattern:
    # Five failures against the same synthetic account.
    print("\nRunning brute-force scenario...")

    for _ in range(5):
        statuses.append(send_failed_login(victim))

    # Password-spray pattern:
    # Eight distinct synthetic accounts.
    print("Running password-spray scenario...")

    for email in accounts:
        statuses.append(send_failed_login(email))

    # Retrieve actual events written by Spring Boot.
    all_events = load_security_events()

    # Only analyze this experiment's synthetic accounts.
    experiment_events = [
        event
        for event in all_events
        if event.get("email")
        and run_id in event["email"]
    ]

    auth_alerts = (
        detect_brute_force(experiment_events)
        + detect_password_spray(experiment_events)
        + detect_slow_spray(experiment_events)
    )

    normalized = adapt_all_alerts(
        auth_alerts,
        [],
        [],
    )

    incidents = correlate_alerts(normalized)

    detected_rules = {
        alert["rule_id"]
        for alert in auth_alerts
    }

    expected_rules = {
        "BRUTE_FORCE_001",
        "PASSWORD_SPRAY_001",
        "SLOW_PASSWORD_SPRAY_001",
    }

    checks = {
        "requests_rejected": all(
            400 <= status < 500
            for status in statuses
        ),
        "telemetry_recorded": len([
            event
            for event in experiment_events
            if event.get("event_type") == "LOGIN_FAILURE"
            and event.get("failure_reason") == "INVALID_CREDENTIALS"
        ]) == 13,
        "brute_force_detected": (
            "BRUTE_FORCE_001" in detected_rules
        ),
        "password_spray_detected": (
            "PASSWORD_SPRAY_001" in detected_rules
        ),
        "slow_spray_detected": (
            "SLOW_PASSWORD_SPRAY_001" in detected_rules
        ),
        "incident_generated": len(incidents) >= 1,
    }

    report = {
        "experiment": "live_authentication_detection",
        "run_id": run_id,
        "target": BASE_URL,
        "requests_sent": len(statuses),
        "http_statuses": statuses,
        "telemetry_events": len(experiment_events),
        "detected_rules": sorted(detected_rules),
        "incident_count": len(incidents),
        "checks": checks,
        "passed": all(checks.values()),
        "incidents": incidents,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    print("\n[Evaluation Results]")

    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")

    print("\nDetected rules:", sorted(detected_rules))
    print("Incidents generated:", len(incidents))
    print("Report saved to:", OUTPUT)

    return report


if __name__ == "__main__":
    result = run()
    raise SystemExit(0 if result["passed"] else 1)