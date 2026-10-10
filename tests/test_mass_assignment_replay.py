
import importlib.util
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "mass_assignment_replay",
    ROOT / "attacks" / "mass_assignment_replay.py",
)
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


def response(status, data=None):
    result = Mock()
    result.status_code = status
    result.json.return_value = data or {}
    return result


def test_login_returns_token_and_user_id():
    with patch.dict(
        replay.os.environ,
        {
            "SECUREOPS_TEST_EMAIL": "test@example.test",
            "SECUREOPS_TEST_PASSWORD": "dummy-password",
        },
    ):
        with patch.object(replay, "request") as mocked:
            mocked.return_value = response(
                200,
                {
                    "accessToken": "test-token",
                    "userId": "test-user",
                },
            )

            token, user_id = replay.login()

    assert token == "test-token"
    assert user_id == "test-user"


def test_profile_fetch():
    with patch.object(replay, "request") as mocked:
        mocked.return_value = response(
            200, {"accountTier": "STANDARD"}
        )

        profile = replay.get_profile(
            "test-user",
            {"Authorization": "Bearer test-token"},
        )

    assert profile["accountTier"] == "STANDARD"


def test_check_records_pass():
    results = {}

    assert replay.check(
        "example",
        True,
        {"http_status": 200},
        results,
    )

    assert results["example"]["passed"] is True


def test_check_records_failure():
    results = {}

    assert not replay.check(
        "example",
        False,
        {"http_status": 400},
        results,
    )

    assert results["example"]["passed"] is False
