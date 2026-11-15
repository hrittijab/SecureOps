import json
import os
from uuid import UUID

import psycopg
from confluent_kafka import Consumer, KafkaException


TOPIC = "secureops.security-events.v1"


def validate_event(payload):
    if not isinstance(payload, dict):
        raise ValueError("Event payload must be a JSON object")

    required = ("event_id", "service", "event_type", "timestamp")

    for field in required:
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise ValueError(f"Missing or invalid field: {field}")

    event_id = UUID(payload["event_id"])

    return {
        "event_id": event_id,
        "service": payload["service"],
        "event_type": payload["event_type"],
    }



def store_event(connection, message):
    payload = json.loads(message.value().decode("utf-8"))
    event = validate_event(payload)

    with connection.transaction():
        with connection.cursor() as cursor:

            # Serialize ingestion transactions before allocating IDs.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (62001,),
            )

            cursor.execute(
                """
                INSERT INTO kafka_ingested_events (
                    service,
                    event_id,
                    event_type,
                    payload,
                    topic,
                    partition_id,
                    kafka_offset
                )
                VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    event["service"],
                    event["event_id"],
                    event["event_type"],
                    json.dumps(payload),
                    message.topic(),
                    message.partition(),
                    message.offset(),
                ),
            )

            inserted = cursor.rowcount == 1

    return inserted, event["event_id"]



def main():
    database_url = os.environ["DETECTION_DB_URL"]

    consumer = Consumer({
        "bootstrap.servers": os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
        ),
        "group.id": os.getenv("KAFKA_CONSUMER_GROUP", "secureops-threat-detection-v1"),
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        "enable.auto.offset.store": False,
    })

    try:
        with psycopg.connect(database_url, autocommit=True) as connection:
            consumer.subscribe([TOPIC])

            print("[SecureOps Kafka] Consumer started", flush=True)

            while True:
                message = consumer.poll(1.0)

                if message is None:
                    continue

                if message.error():
                    raise KafkaException(message.error())

                try:
                    inserted, event_id = store_event(
                        connection, message
                    )

                    consumer.commit(
                        message=message,
                        asynchronous=False,
                    )

                    status = "INGESTED" if inserted else "DUPLICATE"

                    print(
                        f"[{status}] event_id={event_id} "
                        f"partition={message.partition()} "
                        f"offset={message.offset()}",
                        flush=True,
                    )

                except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                    print(
                        f"[INVALID EVENT] {exc}. "
                        "Stopping without committing offset.",
                        flush=True,
                    )
                    raise

    except KeyboardInterrupt:
        print("\n[SecureOps Kafka] Consumer stopped")

    finally:
        consumer.close()


if __name__ == "__main__":
    main()
