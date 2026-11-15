import os

import psycopg


CONSUMER_NAME = "secureops-threat-detection-v1"
INGESTION_LOCK_ID = 62001


def get_checkpoint(connection, consumer_name=CONSUMER_NAME):
    """Read the last successfully processed ingestion ID."""

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT last_processed_id
            FROM detection_checkpoints
            WHERE consumer_name = %s
            """,
            (consumer_name,),
        )
        row = cursor.fetchone()

    return int(row[0]) if row else 0


def save_checkpoint(
    connection,
    last_processed_id,
    consumer_name=CONSUMER_NAME,
):
    """Save a checkpoint without allowing it to move backwards."""

    if last_processed_id < 0:
        raise ValueError("Checkpoint cannot be negative")

    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO detection_checkpoints (
                consumer_name,
                last_processed_id,
                updated_at
            )
            VALUES (%s, %s, NOW())
            ON CONFLICT (consumer_name)
            DO UPDATE SET
                last_processed_id = GREATEST(
                    detection_checkpoints.last_processed_id,
                    EXCLUDED.last_processed_id
                ),
                updated_at = NOW()
            """,
            (consumer_name, last_processed_id),
        )


def advance_checkpoint_safely(
    last_processed_id,
    consumer_name=CONSUMER_NAME,
):
    """
    Advance the checkpoint while coordinating with Kafka ingestion.

    Call only after the corresponding events have been processed
    successfully and all required results have been persisted.
    """

    with psycopg.connect(
        os.environ["DETECTION_DB_URL"]
    ) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (INGESTION_LOCK_ID,),
                )

            save_checkpoint(
                connection,
                last_processed_id,
                consumer_name,
            )
