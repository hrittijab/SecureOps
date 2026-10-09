import json
from pathlib import Path

from telemetry.collector import collect_all_events
from incidents.correlator import correlate_events


RESULTS_FILE = Path("results/incident_report.json")


def main():
    print("\n[SecureOps Incident Correlation]")

    events = collect_all_events()
    incidents = correlate_events(events)

    RESULTS_FILE.parent.mkdir(exist_ok=True)

    report = {
        "event_count": len(events),
        "incident_count": len(incidents),
        "incidents": incidents,
    }

    RESULTS_FILE.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"Events collected: {len(events)}")
    print(f"Incidents generated: {len(incidents)}")

    for incident in incidents:
        print(
            f"[{incident['severity']}] "
            f"{incident['incident_id']} "
            f"IP={incident['source_ip']} "
            f"Events={incident['event_count']} "
            f"Services={','.join(incident['services'])}"
        )

    print(f"\nReport saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()