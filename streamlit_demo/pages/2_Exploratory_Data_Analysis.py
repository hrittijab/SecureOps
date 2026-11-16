import pandas as pd
import streamlit as st

from pathlib import Path

st.set_page_config(
    page_title="SecureOps | Exploratory Data Analysis",
    page_icon="📊",
    layout="wide",
)

DATA_PATH = Path(__file__).resolve().parents[1] / "eda_windows.csv"

FEATURES = [
    "event_count",
    "failure_count",
    "success_count",
    "failure_rate",
    "distinct_accounts",
    "distinct_source_ips",
    "failures_per_account",
    "failures_per_ip",
]


@st.cache_data
def load_data():
    df = pd.read_csv(DATA_PATH)
    df["window_start"] = pd.to_datetime(
        df["window_start"],
        utc=True,
    )
    df["activity_type"] = df["is_attack"].map({
        0: "Benign",
        1: "Attack",
    })
    return df


df = load_data()

st.title("Exploratory Data Analysis")
st.caption(
    "SecureOps | Synthetic authentication traffic | "
    "300-second non-empty windows"
)

st.info(
    "This analysis uses a reproducible synthetic evaluation dataset. "
    "An attack window contains at least one injected attack event; "
    "it may also contain benign activity."
)

total_windows = len(df)
attack_windows = int(df["is_attack"].sum())
benign_windows = total_windows - attack_windows

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Windows", f"{total_windows:,}")
c2.metric("Attack Windows", f"{attack_windows:,}")
c3.metric("Benign Windows", f"{benign_windows:,}")
c4.metric(
    "Attack Prevalence",
    f"{attack_windows / total_windows:.2%}",
)

st.divider()

st.header("1. Authentication Activity Over Time")

daily = (
    df.set_index("window_start")
    .resample("D")[["failure_count", "success_count"]]
    .sum()
)

st.line_chart(daily)

st.caption(
    "Daily authentication totals are aggregated from non-empty "
    "five-minute windows. Dates are displayed in UTC."
)

st.header("2. Benign vs. Attack Behavior")

feature = st.selectbox(
    "Choose a feature",
    FEATURES,
    index=3,
)

summary = (
    df.groupby("activity_type")[feature]
    .agg(["count", "mean", "median", "std", "min", "max"])
    .round(3)
)

st.dataframe(summary, use_container_width=True)

st.bar_chart(
    df.groupby("activity_type")[feature].mean(),
)

st.caption(
    "Group means are descriptive, not evidence of statistical "
    "significance. Only 10 attack windows are available."
)

st.header("3. Feature Distributions")

distribution_feature = st.selectbox(
    "Select a feature to inspect",
    FEATURES,
    key="distribution_feature",
)

bins = st.slider(
    "Histogram bins",
    min_value=5,
    max_value=60,
    value=20,
)

import numpy as np

values = df[distribution_feature].to_numpy(dtype=float)
counts, edges = np.histogram(values, bins=bins)

histogram = pd.DataFrame({
    "Bin": [
        f"{edges[i]:.2f}–{edges[i + 1]:.2f}"
        for i in range(len(counts))
    ],
    "Window Count": counts,
})

st.bar_chart(
    histogram.set_index("Bin"),
)

st.caption(
    "This histogram shows the overall distribution, including "
    "both benign and attack windows."
)

st.header("4. Feature Correlation Analysis")

correlations = df[FEATURES].corr()

st.dataframe(
    correlations.style.format("{:.2f}").background_gradient(
        cmap="coolwarm",
        vmin=-1,
        vmax=1,
    ),
    use_container_width=True,
)

st.caption(
    "Pearson correlation measures linear relationships between "
    "numerical features. Correlation does not imply causation."
)

st.header("5. Dataset Limitations")

st.markdown(
    """
    - All authentication activity is synthetically generated.
    - Only non-empty 300-second windows are included.
    - Attack windows may contain a mixture of benign and malicious events.
    - The dataset is highly imbalanced: 10 attack windows versus
      2,819 benign windows.
    - Features describing accounts and IP addresses are calculated
      from failed logins, not all authentication events.
    - Results do not establish real-world detection performance.
    """
)
