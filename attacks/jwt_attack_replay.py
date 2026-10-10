
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


AUTH_URL = "http://localhost:8081"
USER_URL = "http://localhost:8082"
TIMEOUT = 10


def login():
    email = os.environ["SECUREOPS_TEST_EMAIL"]
    password = os.environ["SECUREOPS_TEST_PASSWORD"]

    response = requests.post(
        f"{AUTH_URL}/api/auth/login",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    response.raise_for_status()

    data = response.json()
    return data["accessToken"], data["userId"]


def change_segment(token, index):
    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError("Expected three JWT segments")

    if index not in (0, 1, 2):
        raise IndexError("JWT segment index must be 0, 1, or 2")

    segment = parts[index]

    if not segment:
        raise ValueError("JWT segment cannot be empty")

    position = len(segment) // 2

    replacement = "A" if segment[position] != "A" else "B"

    parts[index] = (
        segment[:position]
        + replacement
        + segment[position + 1:]
    )

    return ".".join(parts)


def request_profile(user_id, token):
    return requests.get(
        f"{USER_URL}/api/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT,
    )


def run():
    print("\n[SecureOps JWT Attack Replay]")

    token, user_id = login()

    cases = {
        "valid_jwt": (token, 200),
        "modified_payload": (change_segment(token, 1), 401),
        "modified_signature": (change_segment(token, 2), 401),
        "malformed_jwt": ("not.a.valid.jwt", 401),
    }

    results = {}
    for name, (test_token, expected) in cases.items():
        response = request_profile(user_id, test_token)
        passed = response.status_code == expected

        results[name] = {
            "expected_status": expected,
            "actual_status": response.status_code,
            "passed": passed,
        }

        print(
            f"{'PASS' if passed else 'FAIL'} "
            f"{name}: HTTP {response.status_code}"
        )

    report = {
        "experiment": "jwt_attack_replay",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "passed": all(item["passed"] for item in results.values()),
    }

    output = Path("results/jwt_attack_replay.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nOverall: {'PASS' if report['passed'] else 'FAIL'}")
    print(f"Saved: {output}")

    return report


if __name__ == "__main__":
    try:
        result = run()
        sys.exit(0 if result["passed"] else 1)
    except (requests.RequestException, KeyError, ValueError) as error:
        print(f"Replay error: {error}", file=sys.stderr)
        sys.exit(1)
