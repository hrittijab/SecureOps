import os

import psycopg
import requests


BASE_URL = "http://localhost:8081"

LAB_USERS = [
    {
        "email": "spray01@secureops.local",
        "password": "SecureOpsPass123!"
    },
    {
        "email": "spray02@secureops.local",
        "password": "SecureOpsPass123!"
    },
    {
        "email": "spray03@secureops.local",
        "password": "SecureOpsPass123!"
    },
    {
        "email": "spray04@secureops.local",
        "password": "SecureOpsPass123!"
    },
    {
        "email": "spray05@secureops.local",
        "password": "SecureOpsPass123!"
    }
]


def get_database_url() -> str:
    database_url = os.getenv("DETECTION_DB_URL")

    if not database_url:
        raise RuntimeError(
            "DETECTION_DB_URL environment variable is required"
        )

    return database_url


def user_exists(email: str) -> bool:
    database_url = get_database_url()

    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS(
                    SELECT 1
                    FROM users
                    WHERE email = %s
                )
                """,
                (email,)
            )

            return cursor.fetchone()[0]


def ensure_lab_users() -> None:
    print("[Lab Setup] Ensuring spray-test users exist...")

    for user in LAB_USERS:
        email = user["email"]

        if user_exists(email):
            print(f"  Exists  {email}")
            continue

        response = requests.post(
            f"{BASE_URL}/api/auth/register",
            json=user,
            timeout=5
        )

        if response.status_code == 201:
            print(f"  Created {email}")
            continue

        raise RuntimeError(
            f"Could not prepare {email}: "
            f"HTTP {response.status_code} "
            f"{response.text}"
        )


def main():
    ensure_lab_users()


if __name__ == "__main__":
    main()