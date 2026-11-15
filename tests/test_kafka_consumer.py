import json
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from streaming.kafka_consumer import validate_event, store_event


def make_payload():
    return {
        "event_id": str(uuid4()),
        "service": "auth-service",
        "event_type": "LOGIN_FAILURE",
        "timestamp": "2026-11-15T15:00:00Z",
        "actor": "consumer-test@example.com",
    }


def make_message(payload):
    message = MagicMock()
    message.value.return_value = json.dumps(payload).encode("utf-8")
    message.topic.return_value = "secureops.security-events.v1"
    message.partition.return_value = 0
    message.offset.return_value = 10
    return message


def make_connection(rowcount):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.rowcount = rowcount
    return connection


def test_valid_event():
    payload = make_payload()
    event = validate_event(payload)

    assert str(event["event_id"]) == payload["event_id"]
    assert event["service"] == "auth-service"
    assert event["event_type"] == "LOGIN_FAILURE"


def test_invalid_uuid_rejected():
    payload = make_payload()
    payload["event_id"] = "invalid-uuid"

    with pytest.raises(ValueError):
        validate_event(payload)


def test_missing_required_field_rejected():
    payload = make_payload()
    del payload["service"]

    with pytest.raises(ValueError):
        validate_event(payload)


def test_new_event_inserted():
    payload = make_payload()
    connection = make_connection(rowcount=1)

    inserted, event_id = store_event(
        connection,
        make_message(payload),
    )

    assert inserted is True
    assert str(event_id) == payload["event_id"]

    connection.transaction.assert_called_once()


def test_duplicate_event_not_inserted():
    payload = make_payload()
    connection = make_connection(rowcount=0)

    inserted, event_id = store_event(
        connection,
        make_message(payload),
    )

    assert inserted is False
    assert str(event_id) == payload["event_id"]


def test_database_failure_propagates():
    payload = make_payload()
    connection = make_connection(rowcount=1)

    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.execute.side_effect = RuntimeError("Database unavailable")

    with pytest.raises(RuntimeError, match="Database unavailable"):
        store_event(connection, make_message(payload))
