import json
from pathlib import Path

import streamlit as st

st.set_page_config(
    page_title="SecureOps | Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
)

REPORT_PATH = Path(__file__).resolve().parent / "demo_report.json"

st.title("🛡️ SecureOps")
st.caption("Security Threat Detection & Incident Investigation Platform")
st.info("Portfolio demonstration using a static security investigation report. No live systems are connected.")

if not REPORT_PATH.is_file():
    st.error("Investigation report unavailable.")
    st.stop()

try:
    with REPORT_PATH.open(encoding="utf-8") as f:
        report = json.load(f)
except (OSError, json.JSONDecodeError):
    st.error("Could not load investigation report.")
    st.stop()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Security Incidents", report.get("incident_count", 0))
col2.metric("Raw Alerts", report.get("raw_alert_count", 0))
col3.metric("Investigations", report.get("investigation_count", 0))
col4.metric("Responses", report.get("response_count", 0))

st.divider()
st.subheader("Security Incidents")

incidents = report.get("incidents", [])

if incidents:
    st.dataframe(
        [
            {
                "Incident ID": item.get("incident_id"),
                "Severity": item.get("severity"),
                "Risk Score": item.get("risk_score"),
                "Alert Count": item.get("alert_count"),
                "Rules": ", ".join(map(str, item.get("rules", []))),
            }
            for item in incidents
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Incident Investigation")

    selected_id = st.selectbox(
        "Select an incident",
        [item.get("incident_id") for item in incidents],
    )

    incident = next(
        (item for item in incidents if item.get("incident_id") == selected_id),
        None,
    )

    investigation = next(
        (
            item for item in report.get("investigations", [])
            if item.get("incident_id") == selected_id
        ),
        None,
    )

    response = next(
        (
            item for item in report.get("responses", [])
            if item.get("incident_id") == selected_id
        ),
        None,
    )

    tab1, tab2, tab3 = st.tabs(
        ["Incident Details", "Investigation", "Recommended Response"]
    )

    with tab1:
        st.json(incident)

    with tab2:
        if investigation:
            st.json(investigation)
        else:
            st.info("No investigation available.")

    with tab3:
        if response:
            st.json(response)
        else:
            st.info("No response available.")
else:
    st.info("No security incidents found.")

st.divider()
st.caption("SecureOps | Java • Spring Boot • Kafka • PostgreSQL • Python • Docker")


