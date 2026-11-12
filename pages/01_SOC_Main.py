import json
import os
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
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
    unsafe_allow_html=True
)

# 2. Native Multipage Directory Scanning Enforcer
# This explicit declaration prevents the left sidebar menu from disappearing due to numeric file naming layout conflicts
with st.sidebar:
    st.markdown("### Navigation Controls")
    st.markdown("---")

S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)

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

# 4. Data Ingestion
@st.cache_data(show_spinner=False)
def read_input_data(path, modified_ns, size):
    return pd.read_excel(path, engine="openpyxl") if path.endswith(".xlsx") else pd.read_csv(path)

def load_data():
    candidates = [
        os.path.join(
            P_DIR, "reference_data", "vulnerability_cisa_kev_enriched.xlsx"
        ),
        os.path.join(
            P_DIR,
            "reference_data",
            "vulnerability_contextualization_scanner_sample_updated.xlsx",
        ),
    ]
    tgt = next((path for path in candidates if os.path.exists(path)), None)
    if not tgt:
        return pd.DataFrame(), None, 0
    stats = os.stat(tgt)
    df = read_input_data(tgt, stats.st_mtime_ns, stats.st_size)
    if "CISA KEV Status" not in df.columns:
        df["CISA KEV Status"] = np.where(df.get("Exploitation context", "").astype(str).str.lower().str.contains("known exploited"), "Confirmed - Active Exploitation", "Standard Monitored")
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

if "active_taxonomy" not in st.session_state: st.session_state.active_taxonomy = "Option B"


# 5. Main Dashboard Header View Layout
st.title("SOC Main Dashboard")
# st.subheader("Select Active Taxonomy Perspective")

# st.caption(
#     "Choose how asset network exposure weights are applied to prioritize vulnerabilities alongside CVSS."
# )

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

# 6. Engine Processing
v_data, input_path, input_rows = load_data()
kev_catalog = load_kev()
kev_notice = catalog_warning(kev_catalog)
if kev_notice:
    st.warning(kev_notice)
elif kev_catalog:
    st.caption(
        f"CISA KEV snapshot {kev_catalog.version}, released "
        f"{kev_catalog.date_released.date()}."
    )
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
    if scoring_quality["severity_mismatches_before"]:
        st.warning(
            f"{scoring_quality['severity_mismatches_before']} source CVSS "
            "severity label(s) disagree with the numeric score; recomputed labels "
            "are displayed."
        )
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
    st.caption(
        "Option A comparison uses synthetic asset-tier counts and control descriptions."
    )
    band_distribution = build_band_distribution(v_data, scoring_config)
    band_output_path = os.path.join(P_DIR, "outputs", "band_distribution.csv")
    os.makedirs(os.path.dirname(band_output_path), exist_ok=True)
    band_distribution.to_csv(band_output_path, index=False)
    st.caption(
        f"Risk bands use {scoring_config['risk_bands']['mode']}; distributions "
        "for both scales are saved under outputs/."
    )

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

# 7. UI Metrics & Charts
tot = len(v_data)
s_col = "Normalized Score" if is_dyn else "CVSS base score"

# Calculate Contextual Priority metrics dynamically based on configuration threshold rules
if is_dyn:
    active_opt = st.session_state.active_taxonomy[-1]
    risk_level_column = f"Risk_Level_Option_{active_opt}"
    priority_count = int(v_data[risk_level_column].eq("Critical").sum())
    high_count = int(v_data[risk_level_column].isin(["High", "Critical"]).sum())
    priority_label = "Contextual Priority (Critical band)"
else:
    priority_count = len(v_data[v_data["CVSS base score"] >= 9.0]) if tot > 0 else 0
    priority_label = "Contextual Priority (CVSS >= 9.0)"
    high_count = len(v_data[v_data["CVSS base score"] >= 7.0])

c2, c3, c4, c1 = st.columns(4)
c2.metric(priority_label, f"{priority_count:,}")
c3.metric("High or Critical Risk Band" if is_dyn else "High Risk (CVSS >= 7.0)", high_count)

count_2026 = v_data['CVE ID'].astype(str).str.startswith('CVE-2026').sum()
count_2026_unique = v_data[v_data['CVE ID'].astype(str).str.startswith('CVE-2026')]['CVE ID'].nunique()
if 'df' not in locals() and 'df' not in globals():
    # Example fallback so the app doesn't crash if df is genuinely missing
    df = pd.DataFrame({'CVE ID': ['CVE-2026-0001', 'CVE-2025-1234', 'CVE-2026-0002']})
    
c4.metric(label="Unique 2026 CVEs", value=f"{count_2026_unique:,}")

c1.metric("Total Active Detections", f"{tot:,}")

col1, col2, col3 = st.columns(3)

col1, col2, col3 = st.columns(3)

# Column 1: Asset Group
with col1:
    if tot > 0 and "Asset group" in v_data.columns:
        st.plotly_chart(px.pie(v_data["Asset group"].value_counts().reset_index(name="Count"), values="Count", names="Asset group", hole=0.4, title="Detections by Asset Group"), width="stretch")

# Column 2: Exposure Classification
with col2:
    if tot > 0 and "Exposure classification" in v_data.columns:
        counts = v_data['Exposure classification'].value_counts().reset_index(name="Count")
        counts.columns = ['Classification', 'Count']
        
        fig = px.pie(counts, values='Count', names='Classification', title='Count by Exposure Classification', hole=0.4)
        fig.update_traces(textinfo='value', textposition='inside')
        st.plotly_chart(fig, width="stretch")
    else:
        st.warning("No exposure classification data.")

# Column 3: Contextual Priority (Raw Clumn Value - Recalculate!!!)
with col3:
    if tot > 0 and 'Contextual priority' in v_data.columns:
        p_counts = v_data['Contextual priority'].value_counts().reset_index(name="Count")
        p_counts.columns = ['Priority', 'Count']
        
        fig = px.pie(p_counts, values='Count', names='Priority', title='Count by Contextual Priority', hole=0.4)
        fig.update_traces(textinfo='value', textposition='inside')
        st.plotly_chart(fig, width="stretch")
    else:
        st.warning("No contextual priority data available.")

# 4. Actionable Mitigation Directives (Top 5 Prioritized per Top 5 Affected Asset Groups)
st.markdown("### **Actionable Mitigation Directives (Top 5 Prioritized for Top 5 Affected Asset Groups):**")

compiled_df = load_compiled_model_data()

# 1. Determine active sorting column based on active taxonomy view
if is_dyn:
    if st.session_state.active_taxonomy == "Option A":
        model_sort_col = "Final_Risk_Score_Option_A"
    elif st.session_state.active_taxonomy == "Option C":
        model_sort_col = "Final_Risk_Score_Option_C"
    else:
        model_sort_col = "Final_Risk_Score_Option_B"
else:
    model_sort_col = "CVSS base score"

# 2. Select data source (compiled model file takes precedence over memory cache)
source_df = compiled_df if (compiled_df is not None and not compiled_df.empty and model_sort_col in compiled_df.columns) else v_data

if not source_df.empty and "Asset group" in source_df.columns:
    # 3. Find the top 5 asset groups based on total detection count (affected assets count)
    top_5_asset_counts = source_df["Asset group"].value_counts().head(5)
    top_5_assets = top_5_asset_counts.index.tolist()
    
    if top_5_assets:
        # 4. Dynamically generate tab components with total affected count in the label
        asset_tabs = st.tabs([f"🌐 {asset} ({top_5_asset_counts[asset]})" for asset in top_5_assets])
        
        # 5. Populate each tab with its respective top 5 prioritized findings
        for tab, asset in zip(asset_tabs, top_5_assets):
            with tab:
                asset_top_5 = source_df[source_df["Asset group"] == asset].sort_values(by=model_sort_col, ascending=False).head(5)
                
                if not asset_top_5.empty:
                    for _, r in asset_top_5.iterrows():
                        score_val = r.get(model_sort_col, r.get(s_col, 0))
                        st.info(f"**{str(r.get('CVE ID', 'No CVE'))}**: {r.get('Vulnerability title', 'Untitled Finding')} (Risk Score: {score_val})")
                else:
                    st.write("No findings detected for this asset group.")
else:
    st.warning("No tracking data available to analyze asset categories.")

