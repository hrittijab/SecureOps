
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def load_report(filename):
    path = RESULTS / filename

    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def verify_mass_assignment(report):
    if report is None:
        return {
            "rule_id": "MASS_ASSIGNMENT_001",
            "status": "INCONCLUSIVE",
            "reason": "Replay evidence unavailable",
        }

    results = report.get("results", {})
    vulnerable = results.get("vulnerable_mass_assignment", {})
    defended = results.get("defended_mass_assignment", {})
    restored = results.get("original_tier_restored", {})

    exploited = (
        vulnerable.get("passed") is True
        and vulnerable.get("attack_succeeded") is True
        and vulnerable.get("http_status") == 200
    )

    blocked = (
        defended.get("passed") is True
        and defended.get("attack_blocked") is True
        and defended.get("http_status") == 400
    )

    restored_ok = restored.get("passed") is True

    if exploited and blocked and restored_ok:
        status = "VERIFIED"
    elif exploited and defended.get("attack_blocked") is False:
        status = "FAILED"
    else:
        status = "INCONCLUSIVE"

    return {
        "rule_id": "MASS_ASSIGNMENT_001",
        "control": "WRITABLE_FIELD_RESTRICTION",
        "verification_type": "COMPARATIVE_CONTROL_TEST",
        "status": status,
        "vulnerable_attack_succeeded": exploited,
        "defended_attack_blocked": blocked,
        "state_restored": restored_ok,
        "source": "mass_assignment_replay.json",
    }


def verify_bola(report):
    if report is None:
        return {
            "rule_id": "BOLA_001",
            "status": "INCONCLUSIVE",
            "reason": "Replay evidence unavailable",
        }

    checks = report.get("checks", {})

    required = (
        "legitimate_access_allowed",
        "cross_user_access_blocked",
        "spoofed_identity_blocked",
        "cross_user_data_not_returned",
    )

    if any(name not in checks for name in required):
        status = "INCONCLUSIVE"
    elif all(checks[name] is True for name in required):
        status = "VERIFIED"
    else:
        status = "FAILED"

    return {
        "rule_id": "BOLA_001",
        "control": "OBJECT_LEVEL_AUTHORIZATION",
        "verification_type": "DEFENSE_ONLY_TEST",
        "status": status,
        "source": "live_bola_replay.json",
    }


def build_report():
    verifications = [
        verify_mass_assignment(
            load_report("mass_assignment_replay.json")
        ),
        verify_bola(
            load_report("live_bola_replay.json")
        ),
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verification_count": len(verifications),
        "verifications": verifications,
    }


def main():
    report = build_report()

    RESULTS.mkdir(parents=True, exist_ok=True)
    output = RESULTS / "remediation_verification.json"

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n[SecureOps Remediation Verification]")

    for item in report["verifications"]:
        print(
            f"{item['rule_id']}: "
            f"{item['status']} "
            f"({item.get('verification_type', 'UNKNOWN')})"
        )

    print(f"\nReport saved to: {output}")


if __name__ == "__main__":
    main()
