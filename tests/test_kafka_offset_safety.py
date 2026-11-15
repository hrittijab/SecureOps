from unittest.mock import MagicMock, patch, call
from uuid import uuid4

import pytest

from streaming import kafka_consumer


def make_message():
    message = MagicMock()
    message.error.return_value = None
    message.partition.return_value = 0
    message.offset.return_value = 10
    return message


def run_consumer_test(store_result=None, store_error=None):
    message = make_message()
    consumer = MagicMock()

    consumer.poll.side_effect = [
        message,
        KeyboardInterrupt(),
    ]

    connection = MagicMock()
    connection_context = MagicMock()
    connection_context.__enter__.return_value = connection
    connection_context.__exit__.return_value = False

    events = []

    def store_side_effect(conn, msg):
        events.append("database")
        if store_error:
            raise store_error
        return store_result

    def commit_side_effect(**kwargs):
        events.append("kafka_commit")

    consumer.commit.side_effect = commit_side_effect

    with (
        patch.dict(
            "os.environ",
            {"DETECTION_DB_URL": "postgresql://test"},
        ),
        patch.object(
            kafka_consumer,
            "Consumer",
            return_value=consumer,
        ),
        patch.object(
            kafka_consumer.psycopg,
            "connect",
            return_value=connection_context,
        ),
        patch.object(
            kafka_consumer,
            "store_event",
            side_effect=store_side_effect,
        ),
    ):
        if store_error:
            with pytest.raises(type(store_error)):
                kafka_consumer.main()
        else:
            kafka_consumer.main()

    return consumer, message, events


def test_successful_write_commits_kafka_offset():
    consumer, message, events = run_consumer_test(
        store_result=(True, uuid4()),
    )

    assert events == ["database", "kafka_commit"]

    consumer.commit.assert_called_once_with(
        message=message,
        asynchronous=False,
    )

    consumer.close.assert_called_once()


def test_database_failure_does_not_commit_offset():
    consumer, message, events = run_consumer_test(
        store_error=RuntimeError("Database unavailable"),
    )

    assert events == ["database"]

    consumer.commit.assert_not_called()
    consumer.close.assert_called_once()


def test_duplicate_event_commits_offset():
    consumer, message, events = run_consumer_test(
        store_result=(False, uuid4()),
    )

    assert events == ["database", "kafka_commit"]

    consumer.commit.assert_called_once_with(
        message=message,
        asynchronous=False,
    )
