import os
import sys
import json
import pandas as pd
import streamlit as st
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR) if os.path.basename(CURRENT_DIR) == "pages" else CURRENT_DIR
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app_utils.config_manager import (
    get_active_dataset_path,
    get_config_version,
    load_active_dataset,
)

# --- File Paths (Synced with System Configuration) ---
EXCEL_FILE_PATH = get_active_dataset_path()
TAXONOMY_REGISTRY_PATH = os.path.join(PROJECT_ROOT, "engines", "taxonomy_registry.json")
ASSET_CRITICALITY_JSON_PATH = os.path.join(PROJECT_ROOT, "engines", "asset_criticality_weights.json")
WEIGHT_CONFIG_JSON_PATH = os.path.join(PROJECT_ROOT, "engines", "weight_config.json")
NVD_VALIDATED_JSON_PATH = os.path.join(PROJECT_ROOT, "outputs", "nvd_validated_scores.json")
ENGINES_DIR = os.path.join(PROJECT_ROOT, "engines")

# --- 1. Load Active Taxonomy ---
with open(TAXONOMY_REGISTRY_PATH, "r", encoding="utf-8") as f:
    registry_data = json.load(f)

active_key = registry_data.get("active_default_taxonomy", "Option B")
active_tax_info = next(
    (item for item in registry_data["registered_taxonomies"] if item["system_key"] == active_key),
    registry_data["registered_taxonomies"][0],
)
active_tax_filename = active_tax_info["filename"]
active_tax_path = os.path.join(ENGINES_DIR, active_tax_filename)

with open(active_tax_path, "r", encoding="utf-8") as f:
    taxonomy_data = json.load(f)

exposure_mapping = {
    str(k).strip().lower(): v
    for k, v in taxonomy_data.get("exposure_classification_mapping", {}).items()
}
option_display_name = taxonomy_data.get("option_name", active_key)

# --- 2. Load Asset Criticality & Weight Configs ---
with open(ASSET_CRITICALITY_JSON_PATH, "r", encoding="utf-8") as f:
    crit_weight_data = json.load(f)

asset_group_mapping = taxonomy_data.get("asset_group_mapping", crit_weight_data.get("asset_group_bonus", {}))
volume_rules = crit_weight_data.get("volume_bonus_rules", {})

with open(WEIGHT_CONFIG_JSON_PATH, "r", encoding="utf-8") as f:
    risk_data = json.load(f)

weights_config = risk_data["weights"]
selected_preset = risk_data["selected_preset"]

# --- 3. Load NVD Validated CVSS Scores ---
nvd_validated_map = {}
nvd_last_validated = "N/A"
if os.path.exists(NVD_VALIDATED_JSON_PATH):
    with open(NVD_VALIDATED_JSON_PATH, "r", encoding="utf-8") as f:
        raw_nvd_data = json.load(f)
        if isinstance(raw_nvd_data, dict):
            nvd_last_validated = raw_nvd_data.get("last_validated", "N/A")
            scores_dict = raw_nvd_data.get("scores", raw_nvd_data)
            for cve_id, val in scores_dict.items():
                if isinstance(val, (int, float)):
                    nvd_validated_map[str(cve_id).strip()] = float(val)

# --- 4. Load Active Dataset Dynamically ---
df_active = None
try:
    df_active = load_active_dataset(validate=True).copy()
except Exception as e:
    st.error(f"Error loading active dataset (`{os.path.basename(EXCEL_FILE_PATH)}`): {e}")
# --- 5. Top Status Card UI ---
st.title("Asset Criticality & Validation Metrics Dashboard")
st.warning("**Under Construction (Nov 12):** Asset Criticality scoring rules and categories are still being fine-tuned.")

w_severity = weights_config.get("severity", 0.10)
w_criticality = weights_config.get("asset_criticality", 0.10)

with st.container(border=True):
    st.markdown("### Metrics & Engine Status")
    st.latex(r"\text{Asset Criticality (1.5–10)} = \text{Exposure Weight (1–4)} + \text{Asset Group Bonus (0.5–3)} + \text{Volume Bonus (0–3)}")

    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.markdown("**Core Mapping Fields**")
        st.markdown(
            "- **Exposure Classification (1–4 pts):** Mapped from the active taxonomy file\n"
            "- **Asset Group Bonus (0.5–3 pts):** Mapped from `asset_criticality_weights.json`:\n"
            "  - **3.0 (Critical):** Identity, payment, safety, core business, and crown-jewel data\n"
            "  - **2.0 (High):** Important production infrastructure\n"
            "  - **1.0 (Medium):** Standard production apps and servers\n"
            "  - **0.5 (Low):** Dev, test, and non-critical productivity tools\n"
            "- **Asset Volume Bonus (0–3 pts):** Adds up to +2.0 for `Critical assets` and +1.0 for `Internet-facing assets`\n"
            "- **Validation Diff:** Tracks the variance between **Provided CVSS Base Score** and **NVD Validated CVSS**"
        )
    with info_col2:
        st.markdown("**Engine Sync**")
        st.markdown(
            f"- **Active Dataset ({get_config_version()}):** `{os.path.basename(EXCEL_FILE_PATH)}` \n"
            f"- **Weight Config:** `engines/weight_config.json` (`{selected_preset}`) \n"
            f"- **Taxonomy Registry:** `engines/taxonomy_registry.json` (`{active_tax_filename}`) \n"
            f"- **Asset Criticality Config:** `engines/asset_criticality_weights.json` \n"
            f"- **Active Taxonomy:** `{option_display_name}` \n"
            f"- **NVD Validated Scores:** `outputs/nvd_validated_scores.json` (**{len(nvd_validated_map)} CVEs**, updated `{nvd_last_validated}`) \n"
            f"- **Weight Effect:** Impacting **{w_criticality*100:.1f}%** of final Integrated Risk Score"
        )

    st.divider()
    col_cfg1, col_cfg2, col_cfg3 = st.columns(3)
    with col_cfg1:
        with st.expander("Weight Config (weight_config.json)"):
            st.json(risk_data)
    with col_cfg2:
        with st.expander(f"Taxonomy ({active_tax_filename})"):
            st.json(taxonomy_data)
    with col_cfg3:
        with st.expander("Asset Weights (asset_criticality_weights.json)"):
            st.json(crit_weight_data)

# --- 6. Data Processing & Scoring ---
if df_active is not None and not df_active.empty:
    df_mapped = df_active.copy()

    if "Exposure classification" in df_mapped.columns:
        df_mapped["Cleaned Exposure"] = df_mapped["Exposure classification"].astype(str).str.strip().str.lower()
        df_mapped["Exposure Weight"] = df_mapped["Cleaned Exposure"].map(exposure_mapping).fillna(1.0)
    else:
        df_mapped["Cleaned Exposure"] = "other / unmapped"
        df_mapped["Exposure Weight"] = 1.0

    if "Asset group" in df_mapped.columns:
        df_mapped["Asset Group Bonus"] = (
            df_mapped["Asset group"].astype(str).str.strip().str.lower().map(asset_group_mapping).fillna(1.0)
        )
    else:
        df_mapped["Asset Group Bonus"] = 1.0

    crit_assets = df_mapped["Critical assets"].fillna(0) if "Critical assets" in df_mapped.columns else pd.Series(0, index=df_mapped.index)
    inet_assets = df_mapped["Internet-facing assets"].fillna(0) if "Internet-facing assets" in df_mapped.columns else pd.Series(0, index=df_mapped.index)

    crit_bonus = np.where(
        crit_assets >= volume_rules.get("critical_assets_high_threshold", 5),
        volume_rules.get("critical_assets_high_bonus", 2.0),
        np.where(crit_assets > 0, volume_rules.get("critical_assets_base_bonus", 1.5), 0.0)
    )
    inet_bonus = np.where(
        inet_assets >= volume_rules.get("internet_facing_high_threshold", 5),
        volume_rules.get("internet_facing_high_bonus", 1.0),
        np.where(inet_assets > 0, volume_rules.get("internet_facing_base_bonus", 0.5), 0.0)
    )
    df_mapped["Asset Volume Bonus"] = crit_bonus + inet_bonus

    df_mapped["Asset Criticality"] = (
        df_mapped["Exposure Weight"] + df_mapped["Asset Group Bonus"] + df_mapped["Asset Volume Bonus"]
    )

    df_mapped["Provided CVSS"] = df_mapped.get("CVSS base score", 0.0).fillna(0.0)
    if "CVE ID" in df_mapped.columns and nvd_validated_map:
        cleaned_cve = df_mapped["CVE ID"].astype(str).str.strip()
        mapped_nvd = cleaned_cve.map(nvd_validated_map)
        df_mapped["Validation Status"] = np.where(mapped_nvd.notna(), "Validated", "Unvalidated (Provided)")
        df_mapped["Validated CVSS"] = mapped_nvd.fillna(df_mapped["Provided CVSS"])
    else:
        df_mapped["Validation Status"] = "Unvalidated (Provided)"
        df_mapped["Validated CVSS"] = df_mapped["Provided CVSS"]

    df_mapped["CVSS Diff"] = df_mapped["Validated CVSS"] - df_mapped["Provided CVSS"]
    df_mapped["Baseline Risk Score"] = (df_mapped["Provided CVSS"] * w_severity) + (df_mapped["Asset Criticality"] * w_criticality)
    df_mapped["Validated Risk Score"] = (df_mapped["Validated CVSS"] * w_severity) + (df_mapped["Asset Criticality"] * w_criticality)
    df_mapped["Risk Score Diff"] = df_mapped["Validated Risk Score"] - df_mapped["Baseline Risk Score"]
    # --- 7. KPI Summary & Priority Queue Table ---
    with st.container(border=True):
        st.markdown("**Validation Impact Summary & Weighted Criticality Queue**")

        val_count = (df_mapped["Validation Status"] == "Validated").sum()
        unval_count = (df_mapped["Validation Status"] != "Validated").sum()
        changed_count = (df_mapped["CVSS Diff"].abs() > 0.01).sum()

        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        kpi1.metric("Validated CVEs", f"{val_count} / {len(df_mapped)}")
        kpi2.metric("Unvalidated (Provided Fallback)", f"{unval_count}")
        kpi3.metric("Scores Adjusted by NVD", f"{changed_count}")
        kpi4.metric("Avg Risk Score Diff", f"{df_mapped['Risk Score Diff'].mean():+.2f}")

        st.divider()

        df_sorted = df_mapped.sort_values(by="Validated Risk Score", ascending=False)
        visible_cols = [
            "CVE ID", "Validation Status", "Validated Risk Score", "Baseline Risk Score",
            "Risk Score Diff", "Validated CVSS", "Provided CVSS", "CVSS Diff",
            "Asset Criticality", "Exposure Weight", "Asset Group Bonus", "Asset group"
        ]
        df_display = df_sorted[[c for c in visible_cols if c in df_sorted.columns]]

        col_cfg = {
            col: st.column_config.NumberColumn(format="%.2f")
            for col in df_display.select_dtypes(include=["float"]).columns
        }
        for col_name, label, fmt in [
            ("Exposure Weight", "Exposure Weight", "%.1f"),
            ("Asset Group Bonus", "Group Bonus", "%.1f"),
            ("Provided CVSS", "Provided CVSS", "%.1f"),
            ("Validated CVSS", "Validated CVSS", "%.1f"),
            ("CVSS Diff", "CVSS Diff", "%+.1f"),
            ("Risk Score Diff", "Risk Diff", "%+.2f"),
        ]:
            if col_name in df_display.columns:
                col_cfg[col_name] = st.column_config.NumberColumn(label, format=fmt, width="small")

        st.dataframe(df_display, use_container_width=True, hide_index=True, height=400, column_config=col_cfg)

        # --- 8. Scatter Chart ---
        st.markdown("---")
        st.markdown("### Asset Criticality Drivers (Exposure Weight vs Group & Volume Bonus)")
        st.markdown("Shows whether criticality is driven more by exposure level (Y-axis) or asset importance and volume (X-axis).")

        df_chart = df_mapped.copy()
        df_chart["Combined Bonus"] = df_chart["Asset Group Bonus"] + df_chart["Asset Volume Bonus"]
        df_chart["Asset Bonus (Jittered)"] = df_chart["Combined Bonus"] + np.random.uniform(-0.12, 0.12, size=len(df_chart))
        df_chart["Exposure Weight (Jittered)"] = df_chart["Exposure Weight"] + np.random.uniform(-0.10, 0.10, size=len(df_chart))
        df_chart["Bubble Size"] = df_chart["Asset Criticality"] * 12

        st.scatter_chart(
            data=df_chart,
            x="Asset Bonus (Jittered)",
            y="Exposure Weight (Jittered)",
            color="Validation Status",
            size="Bubble Size",
            use_container_width=True
        )

        # --- 9. Density Heatmap ---
        st.markdown("---")
        st.markdown("### Criticality Density Heatmap (Exposure vs Asset Profile)")
        st.markdown("Counts how many vulnerabilities fall into each exposure level and asset profile.")

        has_crit = df_mapped["Critical assets"].fillna(0) > 0 if "Critical assets" in df_mapped.columns else pd.Series(False, index=df_mapped.index)
        has_inet = df_mapped["Internet-facing assets"].fillna(0) > 0 if "Internet-facing assets" in df_mapped.columns else pd.Series(False, index=df_mapped.index)

        df_mapped["Asset Exposure Profile"] = np.select(
            [has_crit & has_inet, has_crit & ~has_inet, ~has_crit & has_inet, ~has_crit & ~has_inet],
            ["Critical + Internet-Facing", "Critical Only", "Internet-Facing Only", "Standard / Internal"],
            default="Standard / Internal"
        )
        df_mapped["Mapped Exposure Axis"] = np.where(
            df_mapped["Cleaned Exposure"].isin(["internet-facing", "restricted / segmented", "internal"]),
            df_mapped["Cleaned Exposure"],
            "other / unmapped"
        )

        crit_matrix = pd.crosstab(df_mapped["Mapped Exposure Axis"], df_mapped["Asset Exposure Profile"]).reindex(
            index=["internet-facing", "restricted / segmented", "internal", "other / unmapped"],
            columns=["Standard / Internal", "Internet-Facing Only", "Critical Only", "Critical + Internet-Facing"],
            fill_value=0
        )
        st.dataframe(crit_matrix.style.background_gradient(cmap="Reds", axis=None), use_container_width=True)

        # --- 10. High-Criticality Triage Queue ---
        st.markdown("---")
        st.markdown("#### High-Criticality Exposure Triage Summary")

        hotspot_exposure, hotspot_profile = crit_matrix.stack().idxmax()
        hotspot_count = int(crit_matrix.loc[hotspot_exposure, hotspot_profile])

        df_crit_queue = df_mapped[
            (df_mapped["Mapped Exposure Axis"] == hotspot_exposure) &
            (df_mapped["Asset Exposure Profile"] == hotspot_profile)
        ]

        st.error(
            f"**Primary Criticality Bottleneck ({option_display_name}):** **{hotspot_count} vulnerabilities** are concentrated in "
            f"**`{hotspot_exposure}`** exposure affecting **`{hotspot_profile}`** assets, forming the largest risk cluster in the heatmap."
        )

        st.markdown("---")
        st.markdown(f"##### Bottleneck Inspection Queue ({hotspot_exposure.title()} & {hotspot_profile})")
        st.markdown("Direct tracking list for the vulnerabilities in the highest-density cluster.")

        queue_cols = [
            "CVE ID", "Validation Status", "Affected product", "Asset group",
            "Asset Criticality", "Validated Risk Score", "Baseline Risk Score", "Risk Score Diff", "Validated CVSS", "Provided CVSS"
        ]
        df_q_display = df_crit_queue[[c for c in queue_cols if c in df_crit_queue.columns]].sort_values(by="Validated Risk Score", ascending=False)
        st.dataframe(df_q_display, use_container_width=True, hide_index=True, column_config=col_cfg)
