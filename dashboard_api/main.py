
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException


REPORT_PATH = (
    Path(__file__).resolve().parent.parent
    / "results"
    / "alert_incident_report.json"
)

app = FastAPI(
    title="SecureOps Security Investigation API",
    description=(
        "Read-only API for security incidents, "
        "investigations, and remediation findings."
    ),
    version="0.1.0",
)


def load_report():
    if not REPORT_PATH.is_file():
        raise HTTPException(
            status_code=503,
            detail="Security report is not available",
        )

    try:
        with REPORT_PATH.open(encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, json.JSONDecodeError):
        raise HTTPException(
            status_code=503,
            detail="Security report could not be loaded",
        ) from None

    if not isinstance(report, dict):
        raise HTTPException(
            status_code=503,
            detail="Invalid security report",
        )

    return report


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/overview")
def overview():
    report = load_report()

    return {
        "generated_at": report.get("generated_at"),
        "incident_count": report.get("incident_count", 0),
        "investigation_count": report.get(
            "investigation_count", 0
        ),
        "relationship_count": report.get(
            "relationship_count", 0
        ),
        "response_count": report.get("response_count", 0),
        "raw_alert_count": report.get("raw_alert_count", 0),
    }


@app.get("/api/incidents")
def incidents():
    return load_report().get("incidents", [])


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str):
    report = load_report()

    incident = next(
        (
            item
            for item in report.get("incidents", [])
            if item["incident_id"] == incident_id
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    investigation = next(
        (
            item
            for item in report.get("investigations", [])
            if item["incident_id"] == incident_id
        ),
        None,
    )

    response = next(
        (
            item
            for item in report.get("responses", [])
            if item["incident_id"] == incident_id
        ),
        None,
    )

    return {
        "incident": incident,
        "investigation": investigation,
        "response": response,
    }


@app.get("/api/investigations")
def investigations():
    return load_report().get("investigations", [])


@app.get("/api/relationships")
def relationships():
    return load_report().get("incident_relationships", [])


@app.get("/api/responses")
def responses():
    return load_report().get("responses", [])
