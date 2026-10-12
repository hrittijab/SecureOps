
from datetime import datetime, timedelta, timezone


FEATURE_NAMES = (
    "event_count",
    "failure_count",
    "success_count",
    "failure_rate",
    "distinct_accounts",
    "distinct_source_ips",
    "failures_per_account",
    "failures_per_ip",
)


def parse_timestamp(value):
    if isinstance(value, datetime):
        timestamp = value
    else:
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if timestamp.tzinfo is None:
        raise ValueError("Event timestamp must include timezone")

    return timestamp.astimezone(timezone.utc)


def extract_features(events, window_seconds=60):
    """
    Extract numerical authentication features from fixed time windows.

    Returns a list of dictionaries, one per non-empty window.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    auth_events = []

    for event in events:
        if event.get("event_type") not in {
            "LOGIN_FAILURE",
            "LOGIN_SUCCESS",
        }:
            continue

        if not event.get("occurred_at"):
            continue

        auth_events.append({
            **event,
            "occurred_at": parse_timestamp(event["occurred_at"]),
        })

    if not auth_events:
        return []

    auth_events.sort(key=lambda event: event["occurred_at"])

    # Anchor windows to UTC boundaries, rather than to the
    # first event. This makes feature extraction deterministic.
    buckets = {}

    for event in auth_events:
        timestamp = event["occurred_at"]
        bucket_number = int(
            timestamp.timestamp() // window_seconds
        )

        buckets.setdefault(bucket_number, []).append(event)

    feature_rows = []

    for bucket_number, window in sorted(buckets.items()):
        failures = [
            event
            for event in window
            if event["event_type"] == "LOGIN_FAILURE"
        ]

        successes = [
            event
            for event in window
            if event["event_type"] == "LOGIN_SUCCESS"
        ]

        accounts = {
            event["email"]
            for event in failures
            if event.get("email")
        }

        source_ips = {
            event["source_ip"]
            for event in failures
            if event.get("source_ip")
        }

        event_count = len(window)
        failure_count = len(failures)
        success_count = len(successes)

        start = datetime.fromtimestamp(
            bucket_number * window_seconds,
            tz=timezone.utc,
        )

        feature_rows.append({
            "window_start": start.isoformat(),
            "window_seconds": window_seconds,
            "event_count": event_count,
            "failure_count": failure_count,
            "success_count": success_count,
            "failure_rate": failure_count / event_count,
            "distinct_accounts": len(accounts),
            "distinct_source_ips": len(source_ips),
            "failures_per_account": (
                failure_count / len(accounts)
                if accounts else 0.0
            ),
            "failures_per_ip": (
                failure_count / len(source_ips)
                if source_ips else 0.0
            ),
        })

    return feature_rows


def to_feature_matrix(feature_rows):
    """
    Convert feature dictionaries into a numerical matrix.

    The column order is defined by FEATURE_NAMES.
    """
    return [
        [float(row[name]) for name in FEATURE_NAMES]
        for row in feature_rows
    ]
