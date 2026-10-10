
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import requests


AUTH_URL = "http://localhost:8081"
USER_URL = "http://localhost:8082"
TIMEOUT = 10


def login():
    response = requests.post(
        f"{AUTH_URL}/api/auth/login",
        json={
            "email": os.environ["SECUREOPS_TEST_EMAIL"],
            "password": os.environ["SECUREOPS_TEST_PASSWORD"],
        },
        timeout=TIMEOUT,
    )
    response.raise_for_status()

    data = response.json()
    return data["accessToken"], data["userId"]


def create_token(private_key, user_id, **overrides):
    now = datetime.now(timezone.utc)

    claims = {
        "iss": "secureops-auth",
        "sub": user_id,
        "aud": "secureops-user-service",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "role": "USER",
    }

    claims.update(overrides)

    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
    )


def run():
    print("\n[SecureOps JWT Claims Replay]")

    private_key_path = Path(
        os.getenv(
            "SECUREOPS_JWT_PRIVATE_KEY",
            "secrets/jwt-private.pem",
        )
    )

    private_key = private_key_path.read_bytes()

    valid_token, user_id = login()
    now = datetime.now(timezone.utc)

    cases = {
        "valid_auth_service_jwt": (valid_token, 200),
        "expired_jwt": (
            create_token(
                private_key,
                user_id,
                iat=now - timedelta(minutes=30),
                exp=now - timedelta(minutes=20),
            ),
            401,
        ),
        "incorrect_issuer": (
            create_token(
                private_key,
                user_id,
                iss="untrusted-issuer",
            ),
            401,
        ),
        "incorrect_audience": (
            create_token(
                private_key,
                user_id,
                aud="untrusted-service",
            ),
            401,
        ),
    }

    results = {}

    for name, (token, expected) in cases.items():
        response = requests.get(
            f"{USER_URL}/api/users/{user_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=TIMEOUT,
        )

        passed = response.status_code == expected

        results[name] = {
            "expected": expected,
            "actual": response.status_code,
            "passed": passed,
        }

        print(
            f"{'PASS' if passed else 'FAIL'} "
            f"{name}: HTTP {response.status_code}"
        )

    report = {
        "experiment": "jwt_claim_validation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "passed": all(r["passed"] for r in results.values()),
    }

    output = Path("results/jwt_claims_replay.json")
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
        report = run()
        sys.exit(0 if report["passed"] else 1)
    except (
        requests.RequestException,
        KeyError,
        OSError,
        jwt.PyJWTError,
    ) as error:
        print(f"Replay error: {error}", file=sys.stderr)
        sys.exit(1)
