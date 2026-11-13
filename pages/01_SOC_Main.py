import json
import os
import sys
import datetime
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from app_utils.config_manager import get_config_version

# Add PROJECT_ROOT to sys.path at index 0 to ensure app_utils is resolved first
S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)
if P_DIR not in sys.path:
    sys.path.insert(0, P_DIR)

from app_utils.config_manager import (
    get_active_dataset_path,
    load_active_dataset,
)
from engines.kev_validation import catalog_warning, load_kev
from engines.asset_criticality import (
    compare_asset_criticality_modes,
    write_asset_criticality_comparison,
)
from engines.scoring_pipeline import score_dataset
from engines.risk_bands import build_band_distribution
from engines.reporting import write_scoring_export
from engines.run_info import build_run_info

# Force light theme mode regardless of system or browser dark mode settings
st.markdown(
    """
    <style>
    :root {
        --color-background: #ffffff;
        --color-text: #31333F;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# 2. Native Multipage Directory Scanning Enforcer
# This explicit declaration prevents the left sidebar menu from disappearing due to numeric file naming layout conflicts
with st.sidebar:
    st.markdown("### Navigation Controls")
    st.markdown("---")

# Synced path to look inside the 'engines' subfolder for absolute consistency
W_CONF = os.path.join(P_DIR, "engines", "weight_config.json")
S_CONF = os.path.join(P_DIR, "engines", "scoring_config.json")
TAX_FILES = {k: os.path.join(P_DIR, "engines", f"taxonomy_option_{k.lower()}.json") for k in ["A", "B", "C"]}
OUTPUT_EXCEL_PATH = os.path.join(P_DIR, "outputs", "multi_taxonomy_weighted_risk_model.xlsx")


# 3. Mathematical Risk Engine
def get_matrix_config(opt_letter):
    with open(W_CONF, "r", encoding="utf-8") as weight_file:
        weights = json.load(weight_file).get("weights", {})
    with open(TAX_FILES[opt_letter], "r", encoding="utf-8") as taxonomy_file:
        mapping = {
            str(key).strip().lower(): value
            for key, value in json.load(taxonomy_file)
            .get("exposure_classification_mapping", {})
            .items()
        }
    return weights, mapping


# 4. Dynamic Data Ingestion synced with System Configuration
def load_data():
    tgt = get_active_dataset_path()
    if not tgt or not os.path.exists(tgt):
        return pd.DataFrame(), tgt, 0

    try:
        # Automatically loads the active dataset and invalidates cache when file/mtime changes
        df = load_active_dataset(validate=True).copy()
    except (FileNotFoundError, ValueError) as err:
        st.error(f"Active dataset load error: {err}")
        return pd.DataFrame(), tgt, 0

    if "CISA KEV Status" not in df.columns:
        df["CISA KEV Status"] = np.where(
            df.get("Exploitation context", "")
            .astype(str)
            .str.lower()
            .str.contains("known exploited"),
            "Confirmed - Active Exploitation",
            "Standard Monitored",
        )
    input_rows = len(df)
    scored_data = df[df["Finding ID"].astype(str).str.startswith("VULN-", na=False)].head(300)
    return scored_data, tgt, input_rows


# Load compiled model from scoring.py if available
def load_compiled_model_data():
    if os.path.exists(OUTPUT_EXCEL_PATH):
        try:
            return pd.read_excel(OUTPUT_EXCEL_PATH, engine="openpyxl")
        except (OSError, ValueError, KeyError) as error:
            st.error(f"Could not read the latest scoring export: {error}")
            return None
    return None


@st.cache_data(show_spinner=False)
def cached_score_data(data, weights, mappings, scoring_config, kev_catalog):
    return score_dataset(data, weights, mappings, scoring_config, kev_catalog)


if "active_taxonomy" not in st.session_state:
    st.session_state.active_taxonomy = "Option B"


# 5. Main Dashboard Header View Layout
st.title("SOC Main Dashboard")


# 6. Engine Processing
v_data, input_path, input_rows = load_data()
kev_catalog = load_kev()
kev_notice = catalog_warning(kev_catalog)

# Load and apply NVD API validated CVSS scores if available
nvd_json_path = os.path.join(P_DIR, "outputs", "nvd_validated_scores.json")
nvd_meta = None
nvd_applied_count = 0

if os.path.exists(nvd_json_path) and not v_data.empty:
    try:
        with open(nvd_json_path, "r", encoding="utf-8") as nvd_file:
            nvd_meta = json.load(nvd_file)

        score_map = nvd_meta.get("scores", {})
        if score_map and "CVE ID" in v_data.columns:
            use_nvd_scores = st.toggle(
                "Use NVD API Validated CVSS Scores",
                value=True,
                help=(
                    "Replaces scanner CVSS base scores with verified NVD API scores"
                    " before risk scoring."
                ),
            )
            if use_nvd_scores:
                normalized_cves = v_data["CVE ID"].astype(str).str.strip().str.upper()
                mapped_scores = normalized_cves.map(score_map)
                nvd_applied_count = int(mapped_scores.notna().sum())
                v_data["CVSS base score"] = mapped_scores.fillna(
                    v_data["CVSS base score"]
                )
    except (OSError, json.JSONDecodeError):
        nvd_meta = None


if not v_data.empty:
    with open(S_CONF, "r", encoding="utf-8") as scoring_config_file:
        scoring_config = json.load(scoring_config_file)
    with open(W_CONF, "r", encoding="utf-8") as weight_file:
        weight_config = json.load(weight_file)
    weight_dict = weight_config["weights"]
    taxonomy_mappings = {
        option: get_matrix_config(option)[1] for option in "ABC"
    }
    v_data, scoring_quality, option_a_exposure = cached_score_data(
        v_data, weight_dict, taxonomy_mappings, scoring_config, kev_catalog
    )
    dimension_quality = scoring_quality["dimension"]
    exposure_quality = scoring_quality["exposure"]
    if dimension_quality["controls_unmatched_count"]:
        st.warning(
            f"{dimension_quality['controls_unmatched_count']} findings have "
            "control text that matched no configured category."
        )
    if dimension_quality["unknown_count"]:
        st.warning(
            f"{dimension_quality['unknown_count']} patch-complexity value(s) "
            "used the configured default."
        )
    asset_mode_comparison = compare_asset_criticality_modes(
        v_data,
        option_a_exposure,
        scoring_config["asset_criticality"],
        weight_dict,
        scoring_config,
    )
    write_asset_criticality_comparison(asset_mode_comparison)
    band_distribution = build_band_distribution(v_data, scoring_config)
    band_output_path = os.path.join(P_DIR, "outputs", "band_distribution.csv")
    os.makedirs(os.path.dirname(band_output_path), exist_ok=True)
    band_distribution.to_csv(band_output_path, index=False)

is_dyn = not v_data.empty and "Exposure classification" in v_data.columns and st.session_state.active_taxonomy != "None"
if is_dyn:
    active_opt = st.session_state.active_taxonomy[-1]
    v_data["Normalized Score"] = v_data[
        f"Unrounded_Risk_Score_Option_{active_opt}"
    ]
    active_quality = exposure_quality[active_opt]
    if active_quality["blank_count"] or active_quality["unmapped_count"]:
        st.warning(
            "Exposure data quality: "
            f"{active_quality['blank_count']} blank value(s), "
            f"{active_quality['unmapped_count']} unmapped value(s). "
            "Configured defaults were applied."
        )
        exposure = v_data["Exposure classification"]
        missing = exposure.isna() | exposure.astype(str).str.strip().eq("")
        unknown = (
            exposure.astype(str)
            .str.strip()
            .str.lower()
            .map(get_matrix_config(active_opt)[1])
            .isna()
            & ~missing
        )
        st.dataframe(
            v_data.loc[missing | unknown, ["Finding ID", "Exposure classification"]]
        )
# 7. UI Metrics & Charts (Compact Layout)
tot = len(v_data)
s_col = "Normalized Score" if is_dyn else "CVSS base score"

count_2026_unique = (
    v_data[v_data["CVE ID"].astype(str).str.startswith("CVE-2026")][
        "CVE ID"
    ].nunique()
    if tot > 0
    else 0
)

active_filename = os.path.basename(input_path) if input_path else "None"

# Top summary with ctive Dataset filename
st.markdown(
    f"**Total Active Detections:** {tot:,} &nbsp;|&nbsp; "
    f"**Unique 2026 CVEs:** {count_2026_unique:,} &nbsp;|&nbsp; "
    f"**Active Dataset:** <span style='font-size: 1.15rem; font-weight: 700; color: #09AB3B;'>{active_filename}</span>",
    unsafe_allow_html=True,
)


base_crit = len(v_data[v_data["CVSS base score"] >= 9.0]) if tot > 0 else 0
base_high_crit = len(v_data[v_data["CVSS base score"] >= 7.0]) if tot > 0 else 0

metric_perspectives = [
    ("CVSS Only", "None", None),
    ("Exposure-Centric", "Option A", "Risk_Level_Option_A"),
    ("Impact-Centric", "Option B", "Risk_Level_Option_B"),
    ("Balanced", "Option C", "Risk_Level_Option_C"),
]

m_cols = st.columns(4)

for col, (label, opt_key, level_col) in zip(m_cols, metric_perspectives):
    with col:
        with st.container(border=True):
            active_tag = (
                " · :orange[**Active**]"
                if st.session_state.active_taxonomy == opt_key
                else ""
            )
            st.markdown(f"**{label}**{active_tag}")

            if level_col is None:
                crit_cnt = base_crit
                high_cnt = base_high_crit
                crit_diff = "Baseline"
                high_diff = "Baseline"
            else:
                if tot > 0 and level_col in v_data.columns:
                    crit_cnt = int(v_data[level_col].eq("Critical").sum())
                    high_cnt = int(v_data[level_col].isin(["High", "Critical"]).sum())
                else:
                    crit_cnt = 0
                    high_cnt = 0

                crit_diff = f"{crit_cnt - base_crit:+d} vs CVSS"
                high_diff = f"{high_cnt - base_high_crit:+d} vs CVSS"

            # Side-by-side compact HTML metrics inside each card to prevent vertical scrolling
            st.markdown(
                f"""
                <div style="display: flex; justify-content: space-between; margin-top: 6px;">
                    <div>
                        <div style="font-size: 0.75rem; color: #666;">Critical</div>
                        <div style="font-size: 1.35rem; font-weight: 700; line-height: 1.2;">{crit_cnt:,}</div>
                        <div style="font-size: 0.7rem; color: #FF8C00;">{crit_diff}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: #666;">High + Critical</div>
                        <div style="font-size: 1.35rem; font-weight: 700; line-height: 1.2;">{high_cnt:,}</div>
                        <div style="font-size: 0.7rem; color: #FF8C00;">{high_diff}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


col1, col2, col3 = st.columns(3)

# Column 1: Asset Group
with col1:
    if tot > 0 and "Asset group" in v_data.columns:
        st.plotly_chart(
            px.pie(
                v_data["Asset group"].value_counts().reset_index(name="Count"),
                values="Count",
                names="Asset group",
                hole=0.4,
                title="Detections by Asset Group",
            ),
            width="stretch",
        )

# Column 2: Exposure Classification
with col2:
    if tot > 0 and "Exposure classification" in v_data.columns:
        counts = v_data["Exposure classification"].value_counts().reset_index(name="Count")
        counts.columns = ["Classification", "Count"]

        fig = px.pie(counts, values="Count", names="Classification", title="Count by Exposure Classification", hole=0.4)
        fig.update_traces(textinfo="value", textposition="inside")
        st.plotly_chart(fig, width="stretch")
    else:
        st.warning("No exposure classification data.")

# Column 3: Dynamic Risk Level Distribution based on Active Perspective
with col3:
    if tot > 0:
        # Map internal session keys to user-facing perspective labels
        perspective_labels = {
            "None": "CVSS Only",
            "Option A": "Exposure-Centric",
            "Option B": "Impact-Centric",
            "Option C": "Balanced",
        }
        active_label = perspective_labels.get(
            st.session_state.active_taxonomy, "CVSS Only"
        )

        if is_dyn:
            active_opt = st.session_state.active_taxonomy[-1]
            level_col = f"Risk_Level_Option_{active_opt}"
        else:
            # Derive standard CVSS severity bands when CVSS Only is active
            v_data["CVSS_Severity_Band"] = pd.cut(
                v_data["CVSS base score"],
                bins=[-0.1, 3.9, 6.9, 8.9, 10.0],
                labels=["Low", "Medium", "High", "Critical"],
            )
            level_col = "CVSS_Severity_Band"

        chart_title = f"Count by Risk Level ({active_label})"

        if level_col in v_data.columns:
            r_counts = v_data[level_col].value_counts().reset_index(name="Count")
            r_counts.columns = ["Risk Level", "Count"]

            # Consistent color mapping across severity levels
            color_map = {
                "Critical": "#D9534F",
                "High": "#F0AD4E",
                "Medium": "#5BC0DE",
                "Low": "#5CB85C",
            }
            fig = px.pie(
                r_counts,
                values="Count",
                names="Risk Level",
                title=chart_title,
                hole=0.4,
                color="Risk Level",
                color_discrete_map=color_map,
            )
            fig.update_traces(textinfo="value", textposition="inside")
            st.plotly_chart(fig, width="stretch")
        else:
            st.warning("Risk level calculation column is missing.")
    else:
        st.warning("No risk level data available.")
st.markdown(
    """
<style>
div[data-testid="stExpander"] details:not([open]) > summary {
    background-color: rgba(255, 140, 0, 0.18) !important;
    border-radius: 0.5rem;
}
div[data-testid="stExpander"] details:not([open]) > summary:hover {
    background-color: rgba(255, 140, 0, 0.28) !important;
}
div[data-testid="stExpander"] details {
    border-color: rgba(255, 140, 0, 0.4) !important;
}
</style>
""",
    unsafe_allow_html=True,
)

with st.expander("**How do these perspectives differ?**", expanded=False):
    st.markdown("""
* **CVSS Only (Baseline)**  
  Uses raw severity without network exposure weighting.

* **Exposure-Centric**  
  Prioritizes external attack surface.  
  `internet-facing: 4` > `internal: 2` > `restricted: 1`

* **Impact-Centric**  
  Prioritizes high-value "crown jewel" assets isolated in segmented zones.  
  `restricted: 4` > `internal: 2` > `internet-facing: 1`

* **Balanced**  
  Balances immediate external exposure with high-impact segmented assets.  
  `internet-facing: 4` > `restricted: 3` > `internal: 2`
""")

btn_none, btn_a, btn_b, btn_c = st.columns(4)

with btn_none:
    if st.button("CVSS Only", width="stretch", type="secondary" if st.session_state.active_taxonomy != "None" else "primary"):
        st.session_state.active_taxonomy = "None"
        st.rerun()
with btn_a:
    if st.button("Exposure-Centric", width="stretch", type="secondary" if st.session_state.active_taxonomy != "Option A" else "primary"):
        st.session_state.active_taxonomy = "Option A"
        st.rerun()
with btn_b:
    if st.button("Impact-Centric", width="stretch", type="secondary" if st.session_state.active_taxonomy != "Option B" else "primary"):
        st.session_state.active_taxonomy = "Option B"
        st.rerun()
with btn_c:
    if st.button("Balanced", width="stretch", type="secondary" if st.session_state.active_taxonomy != "Option C" else "primary"):
        st.session_state.active_taxonomy = "Option C"
        st.rerun()

st.markdown("---")

# 9. Actionable Mitigation Directives (Top N Prioritized by Perspective)
header_col, select_col = st.columns((6, 1), vertical_alignment="center")

with select_col:
    top_n = st.selectbox(
        "Items to display",
        options=(3, 5, 10, 15),
        index=1,
        label_visibility="collapsed",
    )

with header_col:
    st.markdown(
        f"### **Top {top_n} Risk Rankings by Exposure Classification Mapping**"
    )

if not v_data.empty:
    perspectives = (
        ("CVSS Only", "CVSS base score", False),
        ("Exposure-Centric", "Unrounded_Risk_Score_Option_A", True),
        ("Impact-Centric", "Unrounded_Risk_Score_Option_B", True),
        ("Balanced", "Unrounded_Risk_Score_Option_C", True),
    )

    cols = st.columns(4)

    for col, (label, score_col, is_weighted) in zip(cols, perspectives):
        with col:
            with st.container(border=True):
                st.markdown(f"**{label}**")

                if score_col in v_data.columns:
                    top_n_df = v_data.sort_values(by=score_col, ascending=False).head(
                        top_n
                    )

                    for rank, (_, r) in enumerate(top_n_df.iterrows(), start=1):
                        score_val = r.get(score_col, 0)
                        formatted_score = (
                            f"{score_val:.2f}" if is_weighted else f"{score_val:.1f}"
                        )
                        cve_id = str(r.get("CVE ID", "No CVE"))
                        title = str(r.get("Vulnerability title", "Untitled Finding"))
                        exposure = str(r.get("Exposure classification", "Unknown"))

                        short_title = title if len(title) <= 38 else title[:35] + "..."

                        st.caption(
                            f"**#{rank} {cve_id}** · :orange[**{formatted_score}**]  \n"
                            f"{short_title}  \n"
                            f"Exposure: **{exposure}**"
                        )
else:
    st.warning("No tracking data available to analyze mitigation directives.")


# 10. Footer: Data Provenance & Active Weight Configuration
_w_cfg = {}
if os.path.exists("engines/weight_config.json"):
    with open("engines/weight_config.json", "r", encoding="utf-8") as _wf:
        _w_cfg = json.load(_wf)

_preset = _w_cfg.get("selected_preset", "Default")
_w_updated = _w_cfg.get("last_updated", "N/A")

st.caption(
    f"Active Scoring Weights: **{_preset}** (Last updated: {_w_updated})  |  "
    f"Config Version: **{get_config_version()}**"
)
with st.expander("View Active Weight Configuration (JSON)", expanded=False):
    st.json(_w_cfg.get("weights", _w_cfg))

# Summarized Engine & Data Sync Status
summary_items = []
_mismatch = next((v for k, v in locals().items() if "mismatch" in k and isinstance(v, (int, float))), 0)
if _mismatch > 0:
    summary_items.append(f"**CVSS Auto-Corrected:** {int(_mismatch)} mismatched labels")

if "kev_catalog" in locals() and kev_catalog:
    summary_items.append(f"**CISA KEV:** v{kev_catalog.version} (Synced)")
else:
    summary_items.append("**CISA KEV:** Missing (Provisional)")

# Read NVD sync count & timestamp directly from JSON
_nvd_cnt, _nvd_ts = 0, ""
if os.path.exists("outputs/nvd_validated_scores.json"):
    with open("outputs/nvd_validated_scores.json", "r", encoding="utf-8") as _nf:
        _nvd_json = json.load(_nf)
        _nvd_cnt = _nvd_json.get("total_validated_cves", len(_nvd_json.get("scores", {})))
        _nvd_ts = _nvd_json.get("last_validated", "")

if _nvd_cnt > 0:
    ts_label = f" ({_nvd_ts})" if _nvd_ts else ""
    summary_items.append(f"**NVD Sync:** {int(_nvd_cnt)} CVEs{ts_label}")

if summary_items:
    st.caption("  •  ".join(summary_items))
