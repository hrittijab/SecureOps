import json
from pathlib import Path

import requests


BASE_URL = "http://localhost:8082"

ALICE_ID = "11111111-1111-1111-1111-111111111111"
BOB_ID = "22222222-2222-2222-2222-222222222222"


def request_profile(actor_id, profile_id):
    return requests.get(
        f"{BASE_URL}/api/users/{profile_id}",
        headers={"X-User-Id": actor_id},
        timeout=10,
    )


def run():
    health = requests.get(
        f"{BASE_URL}/actuator/health",
        timeout=10,
    )
    health.raise_for_status()

    print("\n[SecureOps Live BOLA Replay]")

    # Legitimate request: Alice accesses her own profile.
    legitimate = request_profile(ALICE_ID, ALICE_ID)

    # Unauthorized request: Alice attempts to access Bob.
    unauthorized = request_profile(ALICE_ID, BOB_ID)

    checks = {
        "legitimate_access_allowed": legitimate.status_code == 200,
        "cross_user_access_blocked": unauthorized.status_code == 403,
        "cross_user_data_not_returned": (
            BOB_ID not in unauthorized.text
        ),
    }

    report = {
        "experiment": "live_bola_prevention",
        "target": BASE_URL,
        "legitimate_status": legitimate.status_code,
        "unauthorized_status": unauthorized.status_code,
        "checks": checks,
        "passed": all(checks.values()),
    }

    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")

    output = Path("results/live_bola_replay.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nReport saved to: {output}")

    return report


if __name__ == "__main__":
    result = run()
    raise SystemExit(0 if result["passed"] else 1)