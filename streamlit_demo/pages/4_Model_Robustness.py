
import json
from pathlib import Path

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Model Robustness | SecureOps",
    page_icon="📊",
    layout="wide",
)

st.title("Model Robustness & Feature Ablation")
st.caption(
    "Isolation Forest feature ablation and statistical baseline "
    "across 10 seeded synthetic authentication datasets."
)

DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "multiseed_ablation.json"
)

if not DATA_PATH.exists():
    st.error("Multi-seed evaluation data is missing.")
    st.stop()

with DATA_PATH.open(encoding="utf-8") as file:
    data = json.load(file)

records = []

for model_name, runs in data["results"].items():
    for run in runs:
        records.append({
            "Model": model_name,
            "Seed": run["seed"],
            "Precision": run["precision"],
            "Recall": run["recall"],
            "F1": run["f1"],
            "False-positive rate": run["fpr"],
            "False positives": run["fp"],
            "False negatives": run["fn"],
        })

df = pd.DataFrame(records)

summary = (
    df.groupby("Model", as_index=False)
    .agg(
        precision=("Precision", "mean"),
        recall=("Recall", "mean"),
        f1=("F1", "mean"),
        f1_std=("F1", "std"),
        fpr=("False-positive rate", "mean"),
        false_positives=("False positives", "mean"),
    )
)

st.subheader("Experiment overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Test datasets", len(data["seeds"]))
col2.metric("Models compared", df["Model"].nunique())
col3.metric("Window size", f"{data['window_seconds']}s")
col4.metric("Data source", "Synthetic")

st.divider()

st.subheader("Model performance comparison")

display_summary = summary.copy()

for column in ("precision", "recall", "f1", "f1_std", "fpr"):
    display_summary[column] = (
        display_summary[column] * 100
    ).round(2)

display_summary = display_summary.rename(columns={
    "precision": "Precision (%)",
    "recall": "Recall (%)",
    "f1": "F1 (%)",
    "f1_std": "F1 std. dev. (pp)",
    "fpr": "FPR (%)",
    "false_positives": "Mean false positives",
})

st.dataframe(
    display_summary.round(2),
    use_container_width=True,
    hide_index=True,
)

st.subheader("Mean F1 score by model")

f1_chart = summary.set_index("Model")[["f1"]] * 100

st.bar_chart(f1_chart)

st.subheader("False positives by model")

fp_chart = summary.set_index("Model")[["false_positives"]]

st.bar_chart(fp_chart)

st.divider()

st.subheader("Performance variation across test seeds")

selected_metric = st.selectbox(
    "Choose metric",
    [
        "F1",
        "Precision",
        "Recall",
        "False-positive rate",
        "False positives",
        "False negatives",
    ],
)

variation = df.pivot(
    index="Seed",
    columns="Model",
    values=selected_metric,
).sort_index()

if selected_metric in (
    "F1",
    "Precision",
    "Recall",
    "False-positive rate",
):
    variation = variation * 100
    st.caption("Values shown as percentages.")

st.line_chart(variation)

st.divider()

st.subheader("Key findings")

full = summary.loc[
    summary["Model"] == "Full (8 features)"
].iloc[0]

focused = summary.loc[
    summary["Model"] == "Failure-focused (6)"
].iloc[0]

baseline = summary.loc[
    summary["Model"] == "Failed-login statistical baseline"
].iloc[0]

fp_reduction = (
    (full["false_positives"] - focused["false_positives"])
    / full["false_positives"]
    * 100
)

f1_improvement = (
    (focused["f1"] - full["f1"])
    / full["f1"]
    * 100
)

st.markdown(
    f"""
- Removing overall login-volume features reduced mean false
  positives by **{fp_reduction:.1f}%**.
- The failure-focused model improved mean F1 by
  **{f1_improvement:.1f}%** relative to the full model.
- Both models achieved **{focused['recall']:.0%} mean recall**.
- The statistical baseline achieved the same aggregate mean
  F1 (**{baseline['f1']:.2%}**) as the failure-focused model.
"""
)

st.info(
    "Identical aggregate metrics do not necessarily mean "
    "the models flagged identical authentication windows."
)

st.subheader("Experimental limitations")

for limitation in data["limitations"]:
    st.write(f"• {limitation}")

st.caption(
    "Exploratory synthetic evaluation. These results do not "
    "establish real-world detection performance."
)
