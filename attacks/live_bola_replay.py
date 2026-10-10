
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


AUTH_URL = os.getenv(
    "SECUREOPS_AUTH_URL",
    "http://localhost:8081",
)

USER_URL = os.getenv(
    "SECUREOPS_USER_URL",
    "http://localhost:8082",
)

BOB_ID = "22222222-2222-2222-2222-222222222222"

TIMEOUT = 10


def request_profile(profile_id, token=None, extra_headers=None):
    headers = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    if extra_headers:
        headers.update(extra_headers)

    return requests.get(
        f"{USER_URL}/api/users/{profile_id}",
        headers=headers,
        timeout=TIMEOUT,
    )


def get_token(email, password):
    response = requests.post(
        f"{AUTH_URL}/api/auth/login",
        json={
            "email": email,
            "password": password,
        },
        timeout=TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()

    token = data["accessToken"]
    user_id = data["userId"]

    if not token or not user_id:
        raise ValueError("Login response missing JWT or user ID")

    return token, user_id


def run():
    email = os.getenv("SECUREOPS_TEST_EMAIL")
    password = os.getenv("SECUREOPS_TEST_PASSWORD")

    if not email or not password:
        raise ValueError(
            "Set SECUREOPS_TEST_EMAIL and "
            "SECUREOPS_TEST_PASSWORD before running."
        )

    for url in (AUTH_URL, USER_URL):
        health = requests.get(
            f"{url}/actuator/health",
            timeout=TIMEOUT,
        )
        health.raise_for_status()

    print("\n[SecureOps JWT-Based BOLA Replay]")

    token, user_id = get_token(email, password)

    # 1. No JWT
    no_token = request_profile(user_id)

    # 2. Invalid JWT
    fake_token = request_profile(
        user_id,
        token="fake.invalid.token",
    )

    # 3. Legitimate profile access
    legitimate = request_profile(
        user_id,
        token=token,
    )

    # 4. Cross-user access attempt
    unauthorized = request_profile(
        BOB_ID,
        token=token,
    )

    # 5. Identity spoofing attempt
    spoofed = request_profile(
        BOB_ID,
        token=token,
        extra_headers={
            "X-User-Id": BOB_ID,
        },
    )

    checks = {
        "missing_jwt_rejected": no_token.status_code == 401,
        "invalid_jwt_rejected": fake_token.status_code == 401,
        "legitimate_access_allowed": legitimate.status_code == 200,
        "cross_user_access_blocked": unauthorized.status_code == 403,
        "spoofed_identity_blocked": spoofed.status_code == 403,
        "cross_user_data_not_returned": (
            unauthorized.status_code == 403
            and spoofed.status_code == 403
            and "bob@example.test" not in unauthorized.text.lower()
            and "bob@example.test" not in spoofed.text.lower()
        ),
    }

    report = {
        "experiment": "jwt_bola_prevention",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auth_service": AUTH_URL,
        "user_service": USER_URL,
        "authenticated_user_id": user_id,
        "target_profile_id": BOB_ID,
        "http_statuses": {
            "missing_jwt": no_token.status_code,
            "invalid_jwt": fake_token.status_code,
            "legitimate": legitimate.status_code,
            "cross_user": unauthorized.status_code,
            "spoofed_identity": spoofed.status_code,
        },
        "checks": checks,
        "passed": all(checks.values()),
    }

    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{status} {name}")

    output = Path("results/live_bola_replay.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nReport saved to: {output}")
    print(f"Overall result: {'PASS' if report['passed'] else 'FAIL'}")

    return report


if __name__ == "__main__":
    try:
        result = run()
        sys.exit(0 if result["passed"] else 1)
    except (requests.RequestException, ValueError, KeyError) as error:
        print(f"Replay failed: {error}", file=sys.stderr)
        sys.exit(1)
