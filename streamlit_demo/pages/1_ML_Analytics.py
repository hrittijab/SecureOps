import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SecureOps | ML Analytics",
    page_icon="📊",
    layout="wide",
)

DATA_PATH = Path(__file__).resolve().parents[1] / "ml_metrics.json"

@st.cache_data
def load_data():
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))

data = load_data()

st.title("Machine Learning Analytics")
st.caption("SecureOps | Isolation Forest | Synthetic authentication data")
st.info(
    "These results come from controlled experiments using synthetic data. "
    "They do not represent production detection performance."
)

st.header("1. Final Model Evaluation")

final = data["final_evaluation"]
metrics = final["metrics"]

tp = metrics["tp"]
fp = metrics["fp"]
tn = metrics["tn"]
fn = metrics["fn"]

precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
fpr = fp / (fp + tn) if fp + tn else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Precision", f"{precision:.2%}")
c2.metric("Recall", f"{recall:.2%}")
c3.metric("F1-score", f"{f1:.2%}")
c4.metric("False-positive rate", f"{fpr:.2%}")

st.write(
    f"**Training windows:** {final['training_windows']:,} | "
    f"**Test windows:** {final['test_windows']:,} | "
    f"**Window size:** {final['window_seconds']} seconds"
)

st.subheader("Confusion Matrix")

matrix = pd.DataFrame(
    [
        [tn, fp],
        [fn, tp],
    ],
    index=["Actual: Benign", "Actual: Attack"],
    columns=["Predicted: Benign", "Predicted: Anomaly"],
)

st.dataframe(matrix, use_container_width=True)

st.caption(
    "TP = attack windows flagged as anomalous; "
    "FP = benign windows flagged as anomalous; "
    "TN = benign windows not flagged; "
    "FN = attack windows missed."
)

st.header("2. Detection Window Comparison")

rows = []

for experiment in data["window_comparison"]:
    m = experiment["metrics"]

    p = m["tp"] / (m["tp"] + m["fp"]) if m["tp"] + m["fp"] else 0
    r = m["tp"] / (m["tp"] + m["fn"]) if m["tp"] + m["fn"] else 0
    score = 2 * p * r / (p + r) if p + r else 0
    false_positive_rate = (
        m["fp"] / (m["fp"] + m["tn"])
        if m["fp"] + m["tn"]
        else 0
    )

    rows.append({
        "Window": f"{experiment['window_seconds']}s",
        "Precision": p,
        "Recall": r,
        "F1-score": score,
        "False-positive rate": false_positive_rate,
        "Test windows": experiment["test_windows"],
    })

df = pd.DataFrame(rows).set_index("Window")

st.subheader("Model Performance by Window Size")

metric_choice = st.selectbox(
    "Choose a metric",
    ["Precision", "Recall", "F1-score", "False-positive rate"],
)

st.bar_chart(df[[metric_choice]])

st.subheader("Full Experiment Comparison")

st.dataframe(
    df.style.format({
        "Precision": "{:.2%}",
        "Recall": "{:.2%}",
        "F1-score": "{:.2%}",
        "False-positive rate": "{:.2%}",
        "Test windows": "{:,.0f}",
    }),
    use_container_width=True,
)

st.warning(
    "Window sizes change the number and composition of evaluation units. "
    "The metrics therefore illustrate experimental tradeoffs, "
    "not a perfectly controlled comparison of identical predictions."
)

st.header("3. ML vs. Rule-Based Detection")

rules = data["rules_comparison"]

c1, c2, c3 = st.columns(3)

c1.metric(
    "ML scenarios detected",
    f"{final['detected_scenarios']}/{final['total_scenarios']}",
)
c2.metric(
    "Rule-based scenarios detected",
    f"{rules['rules_detected_scenarios']}/{rules['rules_total_scenarios']}",
)
c3.metric("Rule-generated alerts", rules["rules_total_alerts"])

st.info(
    "ML evaluation uses 300-second windows, while rule-based detection "
    "produces alerts. Their precision and recall cannot be compared "
    "directly without a shared evaluation unit."
)

st.header("4. Key Findings")

st.markdown("""
- **Short windows:** The 60-second experiment achieved 20% recall and missed the slow brute-force scenario.
- **Medium windows:** The 300-second experiment achieved 80% recall and detected all four attack scenarios.
- **Long windows:** The 900-second experiment achieved 100% recall, but had the highest false-positive rate.
- **Operational tradeoff:** Increasing the window size may improve attack coverage while introducing more false alarms.
- **Limitations:** Results are based on synthetic datasets, and performance may change with real-world traffic and different attack distributions.
""")


# ------------------------------------------------------------
# 5. Model Error Analysis
# ------------------------------------------------------------

st.header("5. Model Error Analysis")

ERROR_PATH = Path(__file__).resolve().parents[1] / "ml_error_analysis.json"

@st.cache_data
def load_error_analysis():
    return json.loads(ERROR_PATH.read_text(encoding="utf-8"))

errors = load_error_analysis()
final_errors = errors["final_300s"]

st.subheader("False Positives and Missed Attacks")

c1, c2, c3, c4 = st.columns(4)

c1.metric(
    "False Discovery Rate",
    f"{final_errors['false_discovery_rate']:.2%}"
)
c2.metric(
    "Miss Rate",
    f"{final_errors['miss_rate']:.2%}"
)
c3.metric(
    "False Positives",
    final_errors["false_positives"]
)
c4.metric(
    "False Negatives",
    final_errors["false_negatives"]
)

st.subheader("Predicted Anomalies: Correct vs. Incorrect")

prediction_df = pd.DataFrame({
    "Outcome": ["True Positive", "False Positive"],
    "Windows": [
        final_errors["true_positives"],
        final_errors["false_positives"],
    ],
}).set_index("Outcome")

st.bar_chart(prediction_df)

st.caption(
    "A false positive is a benign window incorrectly flagged as anomalous. "
    "The false discovery rate is the proportion of flagged windows that "
    "were actually benign."
)

st.subheader("Attack Scenario Detection")

scenario_rows = []

for scenario in errors["final_scenarios"]:
    scenario_rows.append({
        "Attack Type": scenario["attack_type"].replace("_", " ").title(),
        "Attack Windows": scenario["attack_windows"],
        "Detected Windows": scenario["flagged_attack_windows"],
        "Missed Windows": (
            scenario["attack_windows"]
            - scenario["flagged_attack_windows"]
        ),
    })

scenario_df = pd.DataFrame(scenario_rows).set_index("Attack Type")

st.bar_chart(
    scenario_df[["Detected Windows", "Missed Windows"]]
)

st.dataframe(scenario_df, use_container_width=True)

st.subheader("Rule-Based Detection")

rule_data = errors["rules"]

rule_df = pd.DataFrame(
    [
        {"Rule": name, "Alerts": count}
        for name, count in rule_data["alerts_by_rule"].items()
    ]
).set_index("Rule")

st.bar_chart(rule_df)

st.info(
    f"The rule engine generated {rule_data['total_alerts']} alerts, "
    f"including {rule_data['attack_related_alerts']} attack-related alerts. "
    "Rule alerts and ML detection windows are different evaluation units, "
    "so their counts should not be treated as equivalent."
)

st.subheader("Experimental Interpretation")

st.markdown("""
**Finding 1 — High false discovery rate**

The final model detected 8 attack windows but also flagged 102 benign
windows. This indicates that most flagged windows were false positives
in the synthetic test dataset.

**Finding 2 — Slow attack detection**

The 300-second model detected 5 of 7 slow brute-force attack windows,
whereas the earlier 60-second experiment detected 0 of 12.

**Finding 3 — Complementary detection approaches**

Rule-based detection covered all four evaluated attack scenarios.
The ML detector also covered all four scenarios, but generated many
false-positive windows.

**Finding 4 — Limitations**

These experiments use synthetic authentication traffic. Differences
in window size and evaluation datasets limit direct comparisons.
Neither the ML metrics nor the rule alert counts establish production
detection accuracy.
""")
