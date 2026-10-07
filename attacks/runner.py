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
    attack_id = scenario["id"]
    endpoint = scenario["target"]["endpoint"]
    email = scenario["target"]["email"]
    passwords = scenario["attack"]["passwords"]

    url = f"{BASE_URL}{endpoint}"

    print(f"\n[SecureOps Attack Runner]")
    print(f"Scenario: {attack_id}")
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

            result = {
                "attempt": number,
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms
            }

            attempts.append(result)

            print(
                f"[Attempt {number}] "
                f"HTTP {response.status_code} "
                f"({elapsed_ms} ms)"
            )

        except requests.RequestException as exc:
            print(
                f"[Attempt {number}] Request failed: {exc}"
            )

            attempts.append({
                "attempt": number,
                "error": str(exc)
            })

        time.sleep(0.2)

    return {
        "scenario_id": attack_id,
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