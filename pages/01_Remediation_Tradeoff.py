import json
import os
import sys

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st


# =====================================================
# PATH SETUP
# =====================================================

S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)

if P_DIR not in sys.path:
    sys.path.insert(0, P_DIR)

from app_utils.config_manager import (
    load_active_dataset,
    get_active_dataset_path,
)


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Remediation Trade-off Analysis",
    layout="wide",
)

st.title("Remediation Trade-off Analysis")


# =====================================================
# REMEDIATION WEIGHTS
# =====================================================

R_CONF = os.path.join(
    P_DIR,
    "engines",
    "remediation_weights.json",
)

DEFAULT_COMPLEXITY_ORDER = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Very High": 3,
}

DEFAULT_EFFORT_WEIGHTS = {
    "1-4 hours": 0.5,
    "1-2 days": 0.8,
    "3-5 days": 1.0,
    "1-3 weeks": 3.0,
    "1 month+": 5.0,
}

DEFAULT_COMPLEXITY_DESCRIPTIONS = {
    "Low": "Routine patch / simple rollback",
    "Medium": "Coordinated maintenance",
    "High": "Compatibility or clustered-service testing",
    "Very High": "Major upgrade, legacy dependency, or high outage risk",
}


def load_remediation_weights() -> tuple[dict, dict, dict]:
    """Load remediation complexity order, effort weights, and descriptions."""
    try:
        with open(R_CONF, "r", encoding="utf-8") as remediation_file:
            remediation_config = json.load(remediation_file)
    except FileNotFoundError:
        remediation_config = {}
    except (OSError, json.JSONDecodeError) as error:
        st.error(f"Could not load remediation weights: {error}")
        st.stop()

    complexity_order = remediation_config.get(
        "complexity_order",
        DEFAULT_COMPLEXITY_ORDER,
    )

    effort_weights = remediation_config.get(
        "effort_weights",
        DEFAULT_EFFORT_WEIGHTS,
    )

    complexity_descriptions = remediation_config.get(
        "patch_complexity_descriptions",
        DEFAULT_COMPLEXITY_DESCRIPTIONS,
    )

    return complexity_order, effort_weights, complexity_descriptions


complexity_order, effort_weights, complexity_descriptions = (
    load_remediation_weights()
)


# =====================================================
# LOAD DATA
# =====================================================

try:
    dataset_path = get_active_dataset_path()
    df = load_active_dataset(validate=True).copy()
except Exception as error:
    st.error(f"Dataset load failed: {error}")
    st.stop()


# =====================================================
# FILTER FINDINGS
# =====================================================

if "Finding ID" in df.columns:
    df = df[
        df["Finding ID"]
        .astype(str)
        .str.startswith("VULN-")
    ].copy()

if df.empty:
    st.warning("No vulnerability findings available.")
    st.stop()


# =====================================================
# NUMERIC CONVERSION
# =====================================================

numeric_columns = [
    "Critical assets",
    "High-criticality assets",
    "Internet-facing assets",
    "CVSS base score",
]

for column in numeric_columns:
    if column in df.columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        ).fillna(0)


# =====================================================
# ASSET CRITICALITY INDEX
# =====================================================

df["Asset Criticality Index"] = (
    df["Critical assets"]
    + df["High-criticality assets"] * 0.75
    + df["Internet-facing assets"] * 0.25
)


# =====================================================
# PATCH DIFFICULTY INDEX
# =====================================================

complexity_score = (
    df["Patch complexity"]
    .astype(str)
    .str.strip()
    .map(complexity_order)
    .fillna(0)
)

effort_score = (
    df["Estimated remediation effort"]
    .astype(str)
    .str.strip()
    .str.replace("–", "-", regex=False)
    .map(effort_weights)
    .fillna(1.0)
)

df["Patch Difficulty Index"] = (
    complexity_score * effort_score
)


# =====================================================
# LOAD RAW DATASET FOR ALL-ROW KPI
# =====================================================

try:
    all_df = load_active_dataset(validate=True).copy()
except Exception as error:
    st.error(f"Dataset reload failed: {error}")
    st.stop()


# =====================================================
# VERY HIGH COMPLEXITY COUNTS
# =====================================================

very_high_all_count = int(
    (
        all_df["Patch complexity"]
        .astype(str)
        .str.strip()
        .str.lower()
        == "very high"
    ).sum()
)

very_high_vuln_count = int(
    (
        df["Patch complexity"]
        .astype(str)
        .str.strip()
        == "Very High"
    ).sum()
)


# =====================================================
# ACTIVE DATASET STATUS
# =====================================================

st.caption(
    f"Active dataset: `{os.path.basename(dataset_path)}`"
)

# st.code(
#     dataset_path,
#     language="text",
# )

# =====================================================
# KPI SECTION
# =====================================================

st.subheader("Executive Overview")

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric(
    "VULN Findings",
    len(df),
)

c2.metric(
    "Avg Asset Criticality",
    round(df["Asset Criticality Index"].mean(), 2),
)

c3.metric(
    "Avg Patch Difficulty",
    round(df["Patch Difficulty Index"].mean(), 2),
)

c4.metric(
    "Very High Complexity (VULN)",
    very_high_vuln_count,
)

c5.metric(
    "Very High Complexity (All)",
    very_high_all_count,
)


# =====================================================
# MATRIX THRESHOLDS
# =====================================================

asset_threshold = df["Asset Criticality Index"].median()
patch_threshold = df["Patch Difficulty Index"].median()


# =====================================================
# REMEDIATION DECISION MATRIX
# =====================================================

conditions = [
    (
        (df["Asset Criticality Index"] >= asset_threshold)
        & (df["Patch Difficulty Index"] >= patch_threshold)
    ),
    (
        (df["Asset Criticality Index"] >= asset_threshold)
        & (df["Patch Difficulty Index"] < patch_threshold)
    ),
    (
        (df["Asset Criticality Index"] < asset_threshold)
        & (df["Patch Difficulty Index"] >= patch_threshold)
    ),
]

choices = [
    "Strategic Remediation",
    "Quick Win",
    "Low Impact / High Effort",
]

df["Remediation Decision Matrix"] = np.select(
    conditions,
    choices,
    default="Routine Remediation",
)


# =====================================================
# SCATTER CHART
# =====================================================

st.subheader("Remediation Decision Matrix")

# Add subtle deterministic horizontal jitter so overlapping points spread out visibly
rng = np.random.default_rng(42)
plot_df = df.copy()
plot_df["Patch Difficulty (Jittered)"] = (
    plot_df["Patch Difficulty Index"] + rng.uniform(-0.22, 0.22, size=len(plot_df))
)

fig = px.scatter(
    plot_df,
    x="Patch Difficulty (Jittered)",
    y="Asset Criticality Index",
    color="Remediation Decision Matrix",
    size="CVSS base score",
    opacity=0.72,
    hover_name="Finding ID",
    hover_data={
        "Patch Difficulty (Jittered)": False,   # Hide jittered value in tooltip
        "Patch Difficulty Index": ":.2f",       # Show exact original index in tooltip
        "CVE ID": True,
        "Affected product": True,
        "Asset group": True,
        "Patch complexity": True,
        "Estimated remediation effort": True,
    },
    height=420,
)

fig.update_traces(marker=dict(line=dict(width=0.6, color="white")))

fig.add_vline(
    x=patch_threshold,
    line_dash="dash",
    line_color="gray",
)

fig.add_hline(
    y=asset_threshold,
    line_dash="dash",
    line_color="gray",
)

fig.update_layout(
    xaxis_title="Patch Difficulty Index",
    margin=dict(l=10, r=10, t=45, b=10),
    legend=dict(
        orientation="h",
        yanchor="bottom",
        y=1.02,
        xanchor="left",
        x=0,
        title="",
    ),
)

st.plotly_chart(
    fig,
    width='stretch',
)



# =====================================================
# SUMMARY SECTION
# =====================================================

st.subheader("Decision Matrix Distribution")
left, right = st.columns((38, 62), vertical_alignment="center")

matrix_summary = (
    df["Remediation Decision Matrix"]
    .value_counts()
    .reset_index()
)
matrix_summary.columns = ["Category", "Count"]
matrix_summary["Share (%)"] = (matrix_summary["Count"] / len(df) * 100).round(1).astype(str) + "%"

with left:
    st.dataframe(
        matrix_summary,
        hide_index=True,
        width='stretch',
        height=178,  # Exact height for header + 4 rows (no empty trailing rows)
    )

with right:
    fig2 = px.bar(
        matrix_summary,
        x="Category",
        y="Count",
        color="Category",
        text_auto=True,
        height=230,
    )
    fig2.update_layout(
        margin=dict(l=10, r=10, t=20, b=10),
        showlegend=False,
        xaxis_title="",
    )

    st.plotly_chart(
        fig2,
        width='stretch',
    )



# =====================================================
# STRATEGIC REMEDIATION
# =====================================================

st.subheader("Strategic Remediation Candidates")

strategic = df[
    df["Remediation Decision Matrix"] == "Strategic Remediation"
].sort_values(
    [
        "Asset Criticality Index",
        "Patch Difficulty Index",
        "CVSS base score",
    ],
    ascending=False,
)

strategic_columns = [
    "Finding ID",
    "CVE ID",
    "Vulnerability title",
    "Affected product",
    "Asset group",
    "Critical assets",
    "Internet-facing assets",
    "Patch complexity",
    "Estimated remediation effort",
    "CVSS base score",
    "Asset Criticality Index",
    "Patch Difficulty Index",
]

strategic_columns = [
    column
    for column in strategic_columns
    if column in strategic.columns
]

st.dataframe(
    strategic[strategic_columns],
    hide_index=True,
    width='stretch',
    height=450,
)


# =====================================================
# FULL PRIORITIZATION QUEUE
# =====================================================

st.subheader("Full Remediation Queue")

queue = df.sort_values(
    [
        "Asset Criticality Index",
        "Patch Difficulty Index",
        "CVSS base score",
    ],
    ascending=False,
)

queue_columns = [
    "Finding ID",
    "CVE ID",
    "Vulnerability title",
    "Remediation Decision Matrix",
    "Asset Criticality Index",
    "Patch Difficulty Index",
    "CVSS base score",
    "Exposure classification",
    "Asset group",
    "Critical assets",
    "Patch complexity",
    "Estimated remediation effort",
]

queue_columns = [
    column
    for column in queue_columns
    if column in queue.columns
]

st.dataframe(
    queue[queue_columns],
    hide_index=True,
    width='stretch',
    height=700,
)


# =====================================================
# DEBUG SECTION
# =====================================================

with st.expander("Debug Metrics"):
    st.write("Active Dataset:", dataset_path)

    st.write("Asset Threshold:", round(asset_threshold, 2))
    st.write("Patch Threshold:", round(patch_threshold, 2))

    st.write("Complexity Order:", complexity_order)
    st.write("Effort Weights:", effort_weights)

    st.dataframe(
        df[
            [
                "Asset Criticality Index",
                "Patch Difficulty Index",
            ]
        ].describe()
    )