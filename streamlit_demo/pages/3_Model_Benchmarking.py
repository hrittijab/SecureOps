import json
from pathlib import Path

import pandas as pd
import streamlit as st


DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "model_benchmark.json"
)

st.set_page_config(
    page_title="SecureOps | Model Benchmarking",
    layout="wide",
)

st.title("Model Benchmarking & Error Investigation")

st.caption(
    "Matched-window evaluation on synthetic authentication "
    "traffic. Results are reproducible, not production telemetry."
)

with DATA_PATH.open(encoding="utf-8") as file:
    report = json.load(file)

ml = report["isolation_forest"]
baseline = report["failed_login_baseline"]

st.subheader("Evaluation Overview")

a, b, c, d = st.columns(4)

a.metric("Evaluation Windows", report["evaluation_windows"])
b.metric("Attack Windows", report["attack_windows"])
c.metric("Isolation Forest F1", f"{ml['f1']:.2%}")
d.metric("Baseline F1", f"{baseline['f1']:.2%}")

st.subheader("Matched-Window Model Comparison")

comparison = pd.DataFrame(
    {
        "Isolation Forest": {
            "Precision": ml["precision"],
            "Recall": ml["recall"],
            "F1 Score": ml["f1"],
            "False Positive Rate": ml["false_positive_rate"],
        },
        "Failed-Login Baseline": {
            "Precision": baseline["precision"],
            "Recall": baseline["recall"],
            "F1 Score": baseline["f1"],
            "False Positive Rate": baseline["false_positive_rate"],
        },
    }
)

st.dataframe(
    comparison.style.format("{:.2%}"),
    use_container_width=True,
)

st.bar_chart(comparison.T)

st.subheader("Confusion Matrix Comparison")

confusion = pd.DataFrame(
    {
        "Isolation Forest": {
            "True Positives": ml["tp"],
            "False Positives": ml["fp"],
            "True Negatives": ml["tn"],
            "False Negatives": ml["fn"],
        },
        "Failed-Login Baseline": {
            "True Positives": baseline["tp"],
            "False Positives": baseline["fp"],
            "True Negatives": baseline["tn"],
            "False Negatives": baseline["fn"],
        },
    }
)

st.dataframe(confusion, use_container_width=True)

st.bar_chart(
    confusion.loc[
        ["True Positives", "False Positives", "False Negatives"]
    ].T
)

st.subheader("Prediction Agreement")

agreement = report["prediction_agreement"]

agreement_df = pd.DataFrame(
    {
        "Prediction Group": [
            "Both Flagged",
            "Isolation Forest Only",
            "Baseline Only",
            "Neither Flagged",
        ],
        "Windows": [
            agreement["both_flag"],
            agreement["ml_only"],
            agreement["baseline_only"],
            agreement["neither"],
        ],
    }
)

st.dataframe(agreement_df, hide_index=True)

st.bar_chart(
    agreement_df.set_index("Prediction Group")
)

st.info(
    f"Isolation Forest flagged {agreement['ml_only']} "
    "additional windows that the baseline did not. "
    "All were benign in this evaluation."
)

st.subheader("False-Positive Feature Investigation")

feature_summary = report["benign_feature_summary"]

feature_names = [
    "event_count",
    "success_count",
    "failure_count",
    "failure_rate",
    "distinct_accounts",
    "distinct_source_ips",
    "failures_per_account",
    "failures_per_ip",
]

selected_feature = st.selectbox(
    "Feature to investigate",
    feature_names,
)

feature_rows = []

for group, values in feature_summary.items():
    feature_rows.append(
        {
            "Group": group.replace("_", " ").title(),
            "Mean": values[selected_feature]["mean"],
            "Median": values[selected_feature]["median"],
            "Windows": values["count"],
        }
    )

feature_df = pd.DataFrame(feature_rows)

st.dataframe(feature_df, hide_index=True)

st.bar_chart(
    feature_df.set_index("Group")[["Mean", "Median"]]
)

st.markdown(
    "**Interpretation:** Isolation Forest-only false positives "
    "show unusually high successful-login volume, even with "
    "few failed logins. These are descriptive associations, "
    "not proof of individual feature causality."
)

st.subheader("Missed Attack Windows")

missed_df = pd.DataFrame(
    report["missed_attack_windows"]
)

st.dataframe(
    missed_df,
    hide_index=True,
    use_container_width=True,
)

st.warning(
    "Both models missed two low-volume attack windows. "
    "Each contained only one failed login. "
    "Longer-term temporal features may help distinguish "
    "slow attacks from normal behavior."
)

with st.expander("Methodology and Limitations"):
    st.markdown(
        """
        **Methodology**
        - Same 300-second labeled final-test windows for both models.
        - Isolation Forest trained on the training split.
        - Isolation Forest threshold selected previously on validation.
        - Failed-login baseline calibrated using benign validation windows.
        - Final-test labels used only for evaluation and analysis.
        """
    )

    for limitation in report["limitations"]:
        st.write(f"- {limitation}")

st.caption(
    "SecureOps — reproducible synthetic security analytics "
    "and applied data science evaluation."
)
