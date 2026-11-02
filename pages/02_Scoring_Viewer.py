"""
Title: Automated Multi-Taxonomy Risk Scoring Engine
Author: Myunghee Jung
Date: 2026-10-26
Description: 
"""

import json
import os
import sys
import pandas as pd
import streamlit as st  
from engines.kev_validation import (
    DEFAULT_KEV_PATH,
    catalog_warning,
    cve_level_kev_summary,
    load_kev,
    validate_exploitation,
)

# Absolute path resolution logic
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

WEIGHT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "../engines/weight_config.json")
TAXONOMY_FILES = {
    "A": os.path.join(SCRIPT_DIR, "../engines/taxonomy_option_a.json"),
    "B": os.path.join(SCRIPT_DIR, "../engines/taxonomy_option_b.json"),
    "C": os.path.join(SCRIPT_DIR, "../engines/taxonomy_option_c.json")
}
INPUT_EXCEL_PATH = os.path.join(SCRIPT_DIR, "../reference_data", "vulnerability_contextualization_scanner_sample_updated.xlsx")
OUTPUT_EXCEL_PATH = os.path.join(SCRIPT_DIR, "multi_taxonomy_weighted_risk_model.xlsx")

def load_weights():
    """Loads weight settings dynamically from disk and validates mathematical total sum bounds."""
    if not os.path.exists(WEIGHT_CONFIG_PATH) or os.path.getsize(WEIGHT_CONFIG_PATH) == 0:
        st.error("CRITICAL ERROR: Weight configuration file is missing or empty.")
        return None
    with open(WEIGHT_CONFIG_PATH, "r", encoding="utf-8") as f:
        try:
            weight_data = json.load(f)
        except json.JSONDecodeError:
            st.error("CRITICAL ERROR: Weight file contains invalid JSON.")
            return None
    return weight_data.get("weights", {})

def load_taxonomies():
    """Parses mappings dynamically out of the external JSON files."""
    maps = {}
    for opt, filename in TAXONOMY_FILES.items():
        if not os.path.exists(filename) or os.path.getsize(filename) == 0:
            st.error(f"CRITICAL ERROR: Taxonomy file {opt} is missing or empty.")
            return None
        with open(filename, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                maps[opt] = data.get("exposure_classification_mapping", {})
            except json.JSONDecodeError:
                st.error(f"CRITICAL ERROR: Taxonomy file {opt} contains invalid JSON.")
                return None
    return maps

def calculate_risk_score(row, asset_crit_column, weight_dict):
  
    v_severity = (row["CVSS base score"] / 10.0) if pd.notna(row["CVSS base score"]) else 0.0
    if "Exploited_score" in row:
        v_exploited = row["Exploited_score"] / 2.0
    else:
        v_exploited = 1.0 if str(row.get("Exploitation context", "")).strip().lower() == "active" else 0.0
    v_poc, v_patch, v_controls, v_transfer = 0.5, 0.5, 0.3, 0.0
    v_criticality = (row[asset_crit_column] / 4.0)
    
    final_score = (
        (v_severity * weight_dict.get("severity", 0.0)) +
        (v_exploited * weight_dict.get("exploited_in_the_wild", 0.0)) +
        (v_poc * weight_dict.get("poc_exploit_availability", 0.0)) +
        (v_patch * weight_dict.get("patch_difficulty", 0.0)) +
        (v_controls * weight_dict.get("compensating_controls", 0.0)) +
        (v_criticality * weight_dict.get("asset_criticality", 0.0)) +
        (v_transfer * weight_dict.get("risk_acceptance_transfer", 0.0))
    ) * 100.0
    return round(final_score, 2)

def main():

    st.title("Automated Multi-Taxonomy Risk Scoring Engine")
    st.caption("Version 1.0 (Development)")
    st.divider()

    # Core background backend operations
    weights = load_weights()
    maps = load_taxonomies()
    
    if weights is None or maps is None:
        st.stop()

    if not os.path.exists(INPUT_EXCEL_PATH):
        st.error(f"ERROR: Master Excel tracking sheet not found at {INPUT_EXCEL_PATH}")
        st.stop()
        
    df = pd.read_excel(INPUT_EXCEL_PATH)
    df["Exposure classification"] = df["Exposure classification"].fillna("internal").astype(str).str.strip().str.lower()

    kev_catalog = load_kev(DEFAULT_KEV_PATH)
    kev_notice = catalog_warning(kev_catalog)
    if kev_notice:
        st.warning(kev_notice)
    if kev_catalog:
        st.caption(
            f"CISA KEV snapshot {kev_catalog.version}, released "
            f"{kev_catalog.date_released.date()}."
        )
    df = validate_exploitation(df, kev_catalog)
    
    # Structural framework mappings
    df["Asset_Crit_A"] = df["Exposure classification"].map(maps["A"]).fillna(1).astype(int)
    df["Asset_Crit_B"] = df["Exposure classification"].map(maps["B"]).fillna(1).astype(int)
    df["Asset_Crit_C"] = df["Exposure classification"].map(maps["C"]).fillna(1).astype(int)
    
    # Background algorithmic risk calculations
    df["Final_Risk_Score_Option_A"] = df.apply(lambda r: calculate_risk_score(r, "Asset_Crit_A", weights), axis=1)
    df["Final_Risk_Score_Option_B"] = df.apply(lambda r: calculate_risk_score(r, "Asset_Crit_B", weights), axis=1)
    df["Final_Risk_Score_Option_C"] = df.apply(lambda r: calculate_risk_score(r, "Asset_Crit_C", weights), axis=1)
    
    # Default sorting configuration 
    df_sorted = df.sort_values(by="Final_Risk_Score_Option_B", ascending=False)
    
    st.subheader("Risk Calculation Summary Matrix")
    output_columns = [
        "CVE ID", 
        "Exposure classification", 
        "CVSS base score", 
        "Final_Risk_Score_Option_A", 
        "Final_Risk_Score_Option_B", 
        "Final_Risk_Score_Option_C"
    ]
    st.dataframe(df_sorted[output_columns], use_container_width=True)
    
    # Save scores, KEV discrepancies, and a CVE-deduplicated KEV summary.
    try:
        kev_review = df_sorted[
            df_sorted["KEV_status"].isin(
                ["flagged in dataset, not in KEV", "in KEV, not flagged in dataset"]
            )
        ]
        data_quality = cve_level_kev_summary(df_sorted, kev_catalog)
        with pd.ExcelWriter(OUTPUT_EXCEL_PATH, engine="openpyxl") as writer:
            df_sorted.to_excel(writer, sheet_name="Scores", index=False)
            kev_review.to_excel(writer, sheet_name="KEV_Review", index=False)
            data_quality.to_excel(writer, sheet_name="Data_Quality", index=False)
        st.success(f"Excel sheet exported successfully to: {OUTPUT_EXCEL_PATH}")
    except Exception as e:
        st.error(f"EXPORT ERROR: Failed to save final Excel sheet to disk: {e}")

if __name__ == "__main__":
    main()
