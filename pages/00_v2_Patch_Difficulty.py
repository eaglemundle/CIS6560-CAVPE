import os
import json
import pandas as pd
import streamlit as st
import numpy as np

EXCEL_FILE_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
COORDINATED_LEDGER_PATH = "reference_data/vulnerability_coordinated_ledger.xlsx"
REMEDIATION_JSON_PATH = "engines/remediation_weights.json"
WEIGHT_CONFIG_JSON_PATH = "engines/weight_config.json"

# --- Load remediation mapping data directly from JSON ---
with open(REMEDIATION_JSON_PATH, "r", encoding="utf-8") as f:
    rem_data = json.load(f)

effort_weight_map = rem_data["effort_weights"]
complexity_order = rem_data["complexity_order"]
patch_complexity_descriptions = rem_data["patch_complexity_descriptions"]

# --- Load risk scoring configuration directly from JSON ---
with open(WEIGHT_CONFIG_JSON_PATH, "r", encoding="utf-8") as f:
    risk_data = json.load(f)

raw_risk_data = risk_data
weights_config = risk_data["weights"]
selected_preset = risk_data["selected_preset"]


# --- Load Excel datasets ---
if st.session_state.get("df_sample_excel") is None and os.path.exists(EXCEL_FILE_PATH):
    try:
        st.session_state.df_sample_excel = pd.read_excel(EXCEL_FILE_PATH)
    except Exception as e:
        st.error(f"Error reading sample excel dataset: {e}")

if st.session_state.get("df_coordinated_excel") is not None:
    pass
elif os.path.exists(COORDINATED_LEDGER_PATH):
    try:
        st.session_state.df_coordinated_excel = pd.read_excel(COORDINATED_LEDGER_PATH)
    except Exception as e:
        st.error(f"Error reading coordinated ledger dataset: {e}")

# --- Streamlit UI and Dashboard Rendering ---
st.title("Patch Difficulty Metrics Dashboard")

with st.container(border=True):
    st.markdown("### Metrics & Engine Status")
    
    st.latex(r"\text{Patch Difficulty} = \text{Complexity Order} \times \text{Effort Weight}")
    
    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.markdown("**Core Metrics**")
        st.markdown(
            "- **Complexity Order:** Low = 0, Medium = 1, High = 2, Very High = 3\n"
            "- **Effort Weight:** 0.5 to 5.0 (Mapped based on estimated remediation duration)"
        )
    with info_col2:
        st.markdown("**Engine Sync**")
        st.markdown(
            f"- **Weight Config:** `engines/weight_config.json` \n"
            f"- **Remediation Weight:** `reference_data/remediation_weights.json` \n"
            f"- **Preset Name:** `{selected_preset}` \n"
            f"- **Weight Effect:** Impacting **{weights_config.get('patch_difficulty', 0.10)*100:.1f}%** of final Integrated Risk Score"
        )
    
    st.divider()
    
    col_cfg1, col_cfg2 = st.columns(2)
    with col_cfg1:
        with st.expander("View Active Risk Scoring Weights (weight_config.json)"):
            st.json(raw_risk_data)
    with col_cfg2:
        with st.expander("View Active Remediation Maps (remediation_weights.json)"):
            st.json({
                "effort_weights": effort_weight_map,
                "complexity_order": complexity_order,
                "patch_complexity_descriptions": patch_complexity_descriptions
            })

if st.session_state.get("df_coordinated_excel") is not None:
    df_mapped = st.session_state.df_coordinated_excel.copy()
    
    if "Patch complexity" in df_mapped.columns:
        df_mapped["Complexity description"] = df_mapped["Patch complexity"].map(patch_complexity_descriptions).fillna("")
        df_mapped["Complexity Order"] = df_mapped["Patch complexity"].map(complexity_order)

    if "Estimated remediation effort" in df_mapped.columns:
        df_mapped["Effort Weight"] = (
            df_mapped["Estimated remediation effort"]
            .astype(str)
            .str.strip()
            .str.replace("–", "-")
            .map(effort_weight_map)
            .fillna(1.0)
        )

    if "Complexity Order" in df_mapped.columns and "Effort Weight" in df_mapped.columns:
        df_mapped["Patch Difficulty"] = df_mapped["Complexity Order"] * df_mapped["Effort Weight"]

    w_severity = weights_config.get("severity", 0.40)
    w_difficulty = weights_config.get("patch_difficulty", 0.10)
    
    if "CVSS base score" in df_mapped.columns and "Patch Difficulty" in df_mapped.columns:
        df_mapped["Integrated Risk Score"] = (df_mapped["CVSS base score"] * w_severity) + (df_mapped["Patch Difficulty"] * w_difficulty)
    else:
        df_mapped["Integrated Risk Score"] = df_mapped["Contextual risk score"]

    df_sorted = df_mapped.sort_values(by="Integrated Risk Score", ascending=False)

    with st.container(border=True):
        st.markdown("**Weighted Remediation Queue**")
        
        visible_cols = [
            "CVE ID",
            "Integrated Risk Score",
            "Patch Difficulty",
            "Complexity Order",
            "Effort Weight",
            "Contextual risk score",
            "CVSS base score"
        ]

        display_cols = [c for c in visible_cols if c in df_sorted.columns]
        df_sorted = df_sorted[display_cols]

        display_config = {
            col: st.column_config.NumberColumn(format="%.2f")
            for col in df_sorted.select_dtypes(include=["float"]).columns
        }
        
        if "Complexity Order" in df_sorted.columns:
            display_config["Complexity Order"] = st.column_config.NumberColumn(
                "Complexity Order", format="%d", width="small"
            )
        if "Effort Weight" in df_sorted.columns:
            display_config["Effort Weight"] = st.column_config.NumberColumn(
                "Effort Weight", format="%.1f", width="small"
            )
        if "Patch Difficulty" in df_sorted.columns:
            display_config["Patch Difficulty"] = st.column_config.NumberColumn(
                "Patch Difficulty", format="%.2f", width="small"
            )
        if "Integrated Risk Score" in df_sorted.columns:
            display_config["Integrated Risk Score"] = st.column_config.NumberColumn(
                "Integrated Risk Score", format="%.2f", width="medium"
            )

        st.dataframe(
            df_sorted,
            use_container_width=True,
            hide_index=True,
            height=450,
            column_config=display_config
        )

        st.markdown("---")
        st.markdown("### Patch Difficulty Drivers (Complexity vs Effort)")
        st.markdown("Analyzes whether remediation friction is driven by technical complexity (color) or time duration (X-axis).")
        
        if "Effort Weight" in df_mapped.columns and "Complexity Order" in df_mapped.columns:
            df_chart_copy = df_mapped.copy()
            
            df_chart_copy["Effort Weight (Jittered)"] = df_chart_copy["Effort Weight"] + np.random.uniform(-0.08, 0.08, size=len(df_chart_copy))
            df_chart_copy["Complexity Order (Jittered)"] = df_chart_copy["Complexity Order"] + np.random.uniform(-0.08, 0.08, size=len(df_chart_copy))
            df_chart_copy["Bubble Size"] = df_chart_copy["Patch Difficulty"] * 10
            
            st.scatter_chart(
                data=df_chart_copy,
                x="Effort Weight (Jittered)",
                y="Complexity Order (Jittered)",
                color="Patch complexity" if "Patch complexity" in df_chart_copy.columns else None,
                size="Bubble Size",
                use_container_width=True
            )

        st.markdown("---")
        st.markdown("### Remediation Density Heatmap (Complexity vs Effort)")
        st.markdown("Quantified instance counts aligned precisely with dashboard execution mapping rules.")

        if "Patch complexity" in df_mapped.columns and "Estimated remediation effort" in df_mapped.columns:
            df_heatmap_sync = df_mapped.copy()
            
            df_heatmap_sync["Cleaned Effort"] = (
                df_heatmap_sync["Estimated remediation effort"]
                .astype(str)
                .str.strip()
                .str.replace("–", "-")
            )
            
            complexity_axis = ["Low", "Medium", "High", "Very High"]
            effort_axis = ["1-4 hours", "1-2 days", "3-5 days", "1-3 weeks", "1 month+"]
            
            density_matrix = pd.crosstab(
                df_heatmap_sync["Patch complexity"], 
                df_heatmap_sync["Cleaned Effort"]
            ).reindex(
                index=complexity_axis,
                columns=effort_axis,
                fill_value=0
            )
            
            styled_matrix = density_matrix.style.background_gradient(
                cmap="Reds", 
                axis=None
            )
            
            st.dataframe(
                styled_matrix,
                use_container_width=True
            )

        st.markdown("---")
        st.markdown("#### TEMP - Operational Workload Triage Summary")

        st.error(
            "**Critical Bottleneck:** 22 Very High items require roughly **44 man-weeks** of complex engineering effort "
            "($22 \\text{ CVEs} \\times 2 \\text{ weeks median effort} = 44 \\text{ man-weeks}$) and carry steep service outage risks."
        )

        st.markdown("---")
        st.markdown("##### High-Friction Bottleneck Inspection Queue (Very High Items)")
        # st.markdown("##### Under Construction: Nov 12")
        st.markdown("Direct tracking list for the 22 vulnerabilities causing the engineering bottleneck.")

        df_bottleneck = df_heatmap_sync[
            (df_heatmap_sync["Patch complexity"] == "Very High") & 
            (df_heatmap_sync["Cleaned Effort"] == "1-3 weeks")
        ]

        target_cols = [
            "CVE ID",
            "Affected product",
            "Chartered Risk Score",
            "Patch Difficulty",
            "CVSS base score",
            "Estimated remediation effort"
        ]

        display_bottleneck_cols = [c for c in target_cols if c in df_bottleneck.columns]
        df_bottleneck_display = df_bottleneck[display_bottleneck_cols].sort_values(
            by="Patch Difficulty",
            ascending=False
        )

        # Dynamic table display configuration for bottleneck queue
        bottleneck_config = {
            col: st.column_config.NumberColumn(format="%.2f")
            for col in df_bottleneck_display.select_dtypes(include=["float"]).columns
        }

        if "CVE ID" in df_bottleneck_display.columns:
            bottleneck_config["CVE ID"] = st.column_config.TextColumn("CVE ID", width="medium")

        st.dataframe(
            df_bottleneck_display,
            use_container_width=True,
            hide_index=True,
            column_config=bottleneck_config
        )
