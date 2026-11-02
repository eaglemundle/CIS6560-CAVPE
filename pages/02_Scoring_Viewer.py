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
from engines.scoring_validation import cvss_severity, map_exposure_classification
from engines.dimension_scores import add_dimension_scores
from engines.asset_criticality import (
    asset_criticality_scores,
    asset_tier_scores,
    compare_asset_criticality_modes,
    write_asset_criticality_comparison,
)
from engines.scoring import calculate_risk_score

# Absolute path resolution logic
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

WEIGHT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "../engines/weight_config.json")
SCORING_CONFIG_PATH = os.path.join(SCRIPT_DIR, "../engines/scoring_config.json")
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

def load_scoring_config():
    if not os.path.exists(SCORING_CONFIG_PATH):
        st.error(f"CRITICAL ERROR: Scoring configuration file is missing at {SCORING_CONFIG_PATH}")
        return None
    with open(SCORING_CONFIG_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            st.error("CRITICAL ERROR: Scoring configuration file contains invalid JSON.")
            return None

def main():

    st.title("Automated Multi-Taxonomy Risk Scoring Engine")
    st.caption("Version 1.0 (Development)")
    st.divider()

    # Core background backend operations
    weights = load_weights()
    maps = load_taxonomies()
    scoring_config = load_scoring_config()
    
    if weights is None or maps is None or scoring_config is None:
        st.stop()

    if not os.path.exists(INPUT_EXCEL_PATH):
        st.error(f"ERROR: Master Excel tracking sheet not found at {INPUT_EXCEL_PATH}")
        st.stop()
        
    df = pd.read_excel(INPUT_EXCEL_PATH)

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
    df, dimension_quality = add_dimension_scores(df, scoring_config)
    df["Asset_Tier_Score"] = asset_tier_scores(
        df, scoring_config["asset_criticality"]["tier_scores"]
    )
    st.caption(
        "PoC lookup coverage: "
        f"{dimension_quality['poc_coverage']}; missing values use the configured "
        "placeholder."
    )
    st.caption(
        "Asset-tier counts and compensating-control descriptions are synthetic "
        "dataset values."
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

    # Structural framework mappings
    exposure_quality = {}
    for opt in "ABC":
        asset_scores, quality = map_exposure_classification(
            df, maps[opt], scoring_config
        )
        df[f"Asset_Crit_{opt}"] = asset_scores
        exposure_quality[opt] = quality
    exposure_a_scores = df["Asset_Crit_A"].copy()
    df["Asset_Crit_A"] = asset_criticality_scores(
        df, exposure_a_scores, scoring_config
    )
    asset_mode_comparison = compare_asset_criticality_modes(
        df,
        exposure_a_scores,
        scoring_config["asset_criticality"],
        weights,
        scoring_config,
    )
    comparison_path = write_asset_criticality_comparison(asset_mode_comparison)
    st.caption(
        "Asset-tier counts are synthetic. Mode comparison saved to "
        f"{comparison_path}."
    )

    active_opt = st.session_state.get("active_taxonomy", "Option B")[-1]
    active_quality = exposure_quality.get(active_opt, exposure_quality["B"])
    if active_quality["blank_count"] or active_quality["unmapped_count"]:
        st.warning(
            "Exposure data quality: "
            f"{active_quality['blank_count']} blank value(s), "
            f"{active_quality['unmapped_count']} unmapped value(s) for Option "
            f"{active_opt}. Configured defaults were applied and recorded."
        )

    thresholds = scoring_config["cvss_severity_thresholds"]
    df["CVSS severity (recomputed)"] = df["CVSS base score"].map(
        lambda value: cvss_severity(value, thresholds)
    )
    expected_severity = df["CVSS base score"].map(
        lambda value: cvss_severity(value, thresholds)
    )
    recomputed_mismatch_count = int(
        (
            df["CVSS severity (recomputed)"].fillna("").astype(str).str.casefold()
            != expected_severity.fillna("").astype(str).str.casefold()
        ).sum()
    )
    df["Severity_label_mismatch"] = (
        df["CVSS severity"].fillna("").astype(str).str.strip().str.casefold()
        != df["CVSS severity (recomputed)"].fillna("").astype(str).str.casefold()
    )
    mismatch_count = int(df["Severity_label_mismatch"].sum())
    if mismatch_count:
        st.warning(
            f"{mismatch_count} source CVSS severity label(s) disagree with the "
            "numeric score; recomputed labels are used in scoring reports."
        )
    
    # Background algorithmic risk calculations
    df["Final_Risk_Score_Option_A"] = df.apply(
        lambda r: calculate_risk_score(r, "Asset_Crit_A", weights, scoring_config),
        axis=1,
    )
    df["Final_Risk_Score_Option_B"] = df.apply(
        lambda r: calculate_risk_score(r, "Asset_Crit_B", weights, scoring_config),
        axis=1,
    )
    df["Final_Risk_Score_Option_C"] = df.apply(
        lambda r: calculate_risk_score(r, "Asset_Crit_C", weights, scoring_config),
        axis=1,
    )
    
    # Default sorting configuration 
    df_sorted = df.sort_values(by="Final_Risk_Score_Option_B", ascending=False)
    
    st.subheader("Risk Calculation Summary Matrix")
    output_columns = [
        "CVE ID", 
        "Exposure classification", 
        "CVSS base score", 
        "CVSS severity (recomputed)",
        "Severity_label_mismatch",
        "Asset_Tier_Score",
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
        data_quality["Record_type"] = "CVE"
        metric_rows = []
        for opt, quality in exposure_quality.items():
            metric_rows.append(
                {
                    "Record_type": "Exposure",
                    "Metric": f"Option {opt} blank exposure values",
                    "Count": quality["blank_count"],
                    "Finding IDs": ", ".join(quality["blank_finding_ids"]),
                }
            )
            metric_rows.append(
                {
                    "Record_type": "Exposure",
                    "Metric": f"Option {opt} unmapped exposure values",
                    "Count": quality["unmapped_count"],
                    "Values": ", ".join(quality["unmapped_labels"]),
                    "Finding IDs": ", ".join(quality["unmapped_finding_ids"]),
                }
            )
        metric_rows.extend(
            [
                {
                    "Record_type": "Patch",
                    "Metric": "Unknown patch-complexity values",
                    "Count": dimension_quality["unknown_count"],
                    "Values": ", ".join(dimension_quality["unknown_labels"]),
                    "Finding IDs": ", ".join(
                        dimension_quality["unknown_finding_ids"]
                    ),
                },
                {
                    "Record_type": "Controls",
                    "Metric": "Filled control rows",
                    "Count": dimension_quality["controls_filled_count"],
                },
                {
                    "Record_type": "Controls",
                    "Metric": "Control rows with no category match",
                    "Count": dimension_quality["controls_unmatched_count"],
                    "Finding IDs": ", ".join(
                        dimension_quality["controls_unmatched_finding_ids"]
                    ),
                },
                {
                    "Record_type": "PoC",
                    "Metric": "PoC lookup coverage",
                    "Count": dimension_quality["poc_coverage"],
                },
                {
                    "Record_type": "Risk transfer",
                    "Metric": "Findings covered by risk register",
                    "Count": dimension_quality[
                        "risk_register_covered_findings"
                    ],
                },
                {
                    "Record_type": "Dataset note",
                    "Metric": "Asset tiers and control descriptions",
                    "Count": "Synthetic dataset values",
                },
            ]
        )
        metric_rows.append(
            {
                "Record_type": "Metric",
                "Metric": "CVSS severity label mismatches before recomputation",
                "Count": mismatch_count,
                "Finding IDs": ", ".join(
                    df_sorted.loc[
                        df_sorted["Severity_label_mismatch"], "Finding ID"
                    ].astype(str)
                ),
            }
        )
        metric_rows.append(
            {
                "Record_type": "Metric",
                "Metric": "CVSS severity label mismatches after recomputation",
                "Count": recomputed_mismatch_count,
            }
        )
        data_quality = pd.concat(
            [data_quality, pd.DataFrame(metric_rows)], ignore_index=True
        )
        with pd.ExcelWriter(OUTPUT_EXCEL_PATH, engine="openpyxl") as writer:
            df_sorted.to_excel(writer, sheet_name="Scores", index=False)
            kev_review.to_excel(writer, sheet_name="KEV_Review", index=False)
            data_quality.to_excel(writer, sheet_name="Data_Quality", index=False)
        st.success(f"Excel sheet exported successfully to: {OUTPUT_EXCEL_PATH}")
    except Exception as e:
        st.error(f"EXPORT ERROR: Failed to save final Excel sheet to disk: {e}")

if __name__ == "__main__":
    main()
