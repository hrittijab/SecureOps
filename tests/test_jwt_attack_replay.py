
import importlib.util
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "attacks"
    / "jwt_attack_replay.py"
)

spec = importlib.util.spec_from_file_location(
    "jwt_attack_replay",
    SCRIPT_PATH,
)

replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


@pytest.fixture
def sample_token():
    return "header.payload.signature"


@pytest.mark.parametrize("segment_index", [1, 2])
def test_modified_jwt_is_different(sample_token, segment_index):
    modified = replay.change_segment(
        sample_token,
        segment_index,
    )

    assert modified != sample_token
    assert len(modified.split(".")) == 3


def test_original_token_is_not_modified(sample_token):
    original = sample_token

    replay.change_segment(sample_token, 1)

    assert sample_token == original


def test_login_returns_token_and_user_id():
    response = Mock()
    response.json.return_value = {
        "accessToken": "test.jwt.signature",
        "userId": "test-user-id",
    }

    with patch.dict(
        "os.environ",
        {
            "SECUREOPS_TEST_EMAIL": "test@example.test",
            "SECUREOPS_TEST_PASSWORD": "test-password",
        },
    ):
        with patch.object(
            replay.requests,
            "post",
            return_value=response,
        ) as mock_post:
            token, user_id = replay.login()

    assert token == "test.jwt.signature"
    assert user_id == "test-user-id"

    mock_post.assert_called_once()


def test_profile_request_sends_bearer_token():
    response = Mock()
    response.status_code = 200

    with patch.object(
        replay.requests,
        "get",
        return_value=response,
    ) as mock_get:
        result = replay.request_profile(
            "test-user-id",
            "test.jwt.signature",
        )

    assert result.status_code == 200

    _, kwargs = mock_get.call_args

    assert kwargs["headers"]["Authorization"] == (
        "Bearer test.jwt.signature"
    )


@pytest.mark.parametrize(
    "index",
    [-1, 3],
)
def test_invalid_segment_index(index):
    with pytest.raises(IndexError):
        replay.change_segment(
            "header.payload.signature",
            index,
        )
