
from collections import defaultdict

from ml.features import extract_features, parse_timestamp


BEHAVIORAL_FEATURE_NAMES = (
    "recovered_accounts",
    "failure_only_accounts",
    "max_consecutive_failures",
    "unique_account_ip_pairs",
    "successful_login_rate",
)


def extract_behavioral_features(events, window_seconds=60):
    base_rows = extract_features(events, window_seconds)

    if not base_rows:
        return []

    buckets = defaultdict(list)

    for event in events:
        if event.get("event_type") not in {
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE",
        }:
            continue

        if not event.get("occurred_at"):
            continue

        timestamp = parse_timestamp(event["occurred_at"])
        bucket = int(timestamp.timestamp() // window_seconds)

        buckets[bucket].append({
            **event,
            "occurred_at": timestamp,
        })

    results = []

    for row in base_rows:
        start = parse_timestamp(row["window_start"])
        bucket = int(start.timestamp() // window_seconds)

        window_events = sorted(
            buckets[bucket],
            key=lambda event: event["occurred_at"],
        )

        account_events = defaultdict(list)
        account_ip_pairs = set()

        for event in window_events:
            email = event.get("email")
            ip = event.get("source_ip")

            if email:
                account_events[email].append(event["event_type"])

            if email and ip:
                account_ip_pairs.add((email, ip))

        recovered_accounts = 0
        failure_only_accounts = 0
        max_consecutive_failures = 0

        for sequence in account_events.values():
            seen_failure = False
            recovered = False
            consecutive = 0

            for event_type in sequence:
                if event_type == "LOGIN_FAILURE":
                    seen_failure = True
                    consecutive += 1
                    max_consecutive_failures = max(
                        max_consecutive_failures,
                        consecutive,
                    )
                else:
                    if seen_failure:
                        recovered = True
                    consecutive = 0

            if recovered:
                recovered_accounts += 1

            if seen_failure and "LOGIN_SUCCESS" not in sequence:
                failure_only_accounts += 1

        results.append({
            **row,
            "recovered_accounts": recovered_accounts,
            "failure_only_accounts": failure_only_accounts,
            "max_consecutive_failures": max_consecutive_failures,
            "unique_account_ip_pairs": len(account_ip_pairs),
            "successful_login_rate": (
                row["success_count"] / row["event_count"]
                if row["event_count"] else 0.0
            ),
        })

    return results
