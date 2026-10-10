
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
AUTH_URL = "http://localhost:8081"
USER_URL = "http://localhost:8082"
TIMEOUT = 10

BOB_ID = "22222222-2222-2222-2222-222222222222"


def request(method, url, **kwargs):
    return requests.request(
        method, url, timeout=TIMEOUT, **kwargs
    )


def login():
    email = os.environ["SECUREOPS_TEST_EMAIL"]
    password = os.environ["SECUREOPS_TEST_PASSWORD"]

    response = request(
        "POST",
        f"{AUTH_URL}/api/auth/login",
        json={"email": email, "password": password},
    )
    response.raise_for_status()

    data = response.json()
    return data["accessToken"], data["userId"]


def get_profile(user_id, headers):
    response = request(
        "GET",
        f"{USER_URL}/api/users/{user_id}",
        headers=headers,
    )
    response.raise_for_status()
    return response.json()


def check(name, condition, details, results):
    passed = bool(condition)
    results[name] = {
        "passed": passed,
        **details,
    }
    print(f"{'PASS' if passed else 'FAIL'} {name}")
    return passed


def run():
    print("\n[SecureOps Mass Assignment Replay]")

    token, user_id = login()
    headers = {"Authorization": f"Bearer {token}"}

    original = get_profile(user_id, headers)
    original_tier = original["accountTier"]

    # Use a different tier so the experiment proves
    # that the vulnerable endpoint changed state.
    attack_tier = (
        "PREMIUM" if original_tier != "PREMIUM"
        else "STANDARD"
    )

    results = {}
    restore_error = None

    try:
        vulnerable = request(
            "PATCH",
            f"{USER_URL}/api/lab/users/{user_id}/vulnerable",
            headers=headers,
            json={"accountTier": attack_tier},
        )

        after_vulnerable = get_profile(user_id, headers)

        check(
            "vulnerable_mass_assignment",
            vulnerable.status_code == 200
            and after_vulnerable["accountTier"] == attack_tier,
            {
                "http_status": vulnerable.status_code,
                "original_tier": original_tier,
                "tier_after_attack": after_vulnerable["accountTier"],
                "attack_succeeded": (
                    after_vulnerable["accountTier"] == attack_tier
                ),
            },
            results,
        )

        defended = request(
            "PATCH",
            f"{USER_URL}/api/users/{user_id}",
            headers=headers,
            json={"accountTier": original_tier},
        )

        after_defended = get_profile(user_id, headers)

        check(
            "defended_mass_assignment",
            defended.status_code == 400
            and after_defended["accountTier"] == attack_tier,
            {
                "http_status": defended.status_code,
                "tier_after_attempt": after_defended["accountTier"],
                "attack_blocked": (
                    after_defended["accountTier"] == attack_tier
                ),
            },
            results,
        )

        cross_user = request(
            "PATCH",
            f"{USER_URL}/api/lab/users/{BOB_ID}/vulnerable",
            headers=headers,
            json={"accountTier": "STANDARD"},
        )

        check(
            "cross_user_update_blocked",
            cross_user.status_code == 403,
            {"http_status": cross_user.status_code},
            results,
        )

    finally:
        # The lab endpoint is intentionally used to restore
        # the test account's original state.
        try:
            restore = request(
                "PATCH",
                f"{USER_URL}/api/lab/users/{user_id}/vulnerable",
                headers=headers,
                json={"accountTier": original_tier},
            )

            restored = get_profile(user_id, headers)

            restored_ok = (
                restore.status_code == 200
                and restored["accountTier"] == original_tier
            )

            check(
                "original_tier_restored",
                restored_ok,
                {
                    "http_status": restore.status_code,
                    "restored_tier": restored["accountTier"],
                },
                results,
            )

            if not restored_ok:
                restore_error = "Profile restoration verification failed"

        except requests.RequestException as exc:
            restore_error = str(exc)
            check(
                "original_tier_restored",
                False,
                {"error": restore_error},
                results,
            )

    passed = all(
        item["passed"] for item in results.values()
    )

    report = {
        "experiment": "mass_assignment_replay",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "restoration_error": restore_error,
        "passed": passed,
    }

    output = ROOT / "results" / "mass_assignment_replay.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nOverall: {'PASS' if passed else 'FAIL'}")
    print(f"Report: {output.relative_to(ROOT)}")

    return passed


if __name__ == "__main__":
    try:
        success = run()
        sys.exit(0 if success else 1)
    except (requests.RequestException, KeyError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        sys.exit(1)
