import json
import sys
import time
from pathlib import Path

import requests


BASE_URL = "http://localhost:8081"


def load_scenario(path: str) -> dict:
    scenario_path = Path(path)

    with scenario_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def run_auth_bruteforce(scenario: dict) -> dict:
    scenario_id = scenario["id"]
    endpoint = scenario["target"]["endpoint"]
    email = scenario["target"]["email"]
    passwords = scenario["attack"]["passwords"]

    url = f"{BASE_URL}{endpoint}"

    print("\n[SecureOps Attack Runner]")
    print(f"Scenario: {scenario_id}")
    print(f"Target:   {url}")
    print(f"Account:  {email}")
    print("-" * 60)

    attempts = []

    for number, password in enumerate(passwords, start=1):
        started_at = time.time()

        try:
            response = requests.post(
                url,
                json={
                    "email": email,
                    "password": password
                },
                timeout=5
            )

            elapsed_ms = round(
                (time.time() - started_at) * 1000,
                2
            )

            attempts.append({
                "attempt": number,
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms
            })

            print(
                f"[Attempt {number}] "
                f"HTTP {response.status_code} "
                f"({elapsed_ms} ms)"
            )

        except requests.RequestException as exc:
            attempts.append({
                "attempt": number,
                "error": str(exc)
            })

            print(
                f"[Attempt {number}] "
                f"Request failed: {exc}"
            )

        time.sleep(0.2)

    return {
        "scenario_id": scenario_id,
        "attempt_count": len(attempts),
        "attempts": attempts
    }


def run_benign_auth(scenario: dict) -> dict:
    scenario_id = scenario["id"]
    endpoint = scenario["target"]["endpoint"]
    email = scenario["target"]["email"]

    incorrect_passwords = (
        scenario["traffic"]["incorrect_passwords"]
    )

    correct_password = (
        scenario["traffic"]["correct_password"]
    )

    url = f"{BASE_URL}{endpoint}"

    print("\n[SecureOps Benign Traffic Runner]")
    print(f"Scenario: {scenario_id}")
    print(f"Target:   {url}")
    print(f"Account:  {email}")
    print("-" * 60)

    attempts = []

    passwords = incorrect_passwords + [correct_password]

    for number, password in enumerate(passwords, start=1):
        started_at = time.time()

        try:
            response = requests.post(
                url,
                json={
                    "email": email,
                    "password": password
                },
                timeout=5
            )

            elapsed_ms = round(
                (time.time() - started_at) * 1000,
                2
            )

            attempts.append({
                "attempt": number,
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms
            })

            print(
                f"[Attempt {number}] "
                f"HTTP {response.status_code} "
                f"({elapsed_ms} ms)"
            )

        except requests.RequestException as exc:
            attempts.append({
                "attempt": number,
                "error": str(exc)
            })

            print(
                f"[Attempt {number}] "
                f"Request failed: {exc}"
            )

        time.sleep(0.2)

    return {
        "scenario_id": scenario_id,
        "attempt_count": len(attempts),
        "attempts": attempts
    }


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m attacks.runner "
            "<scenario-file>"
        )
        sys.exit(1)

    scenario = load_scenario(sys.argv[1])

    if scenario["id"].startswith("AUTH-BRUTEFORCE"):
        result = run_auth_bruteforce(scenario)

    elif scenario["id"].startswith("BENIGN-AUTH"):
        result = run_benign_auth(scenario)

    else:
        raise ValueError(
            f"Unsupported scenario: {scenario['id']}"
        )

    print("-" * 60)

    print(
        json.dumps(
            result,
            indent=2
        )
    )


if __name__ == "__main__":
    main()