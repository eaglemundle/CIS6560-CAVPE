"""Automated multi-taxonomy vulnerability risk scoring viewer."""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from engines.asset_criticality import (
    compare_asset_criticality_modes,
    write_asset_criticality_comparison,
)
from engines.kev_validation import (
    DEFAULT_KEV_PATH,
    catalog_warning,
    load_kev,
)
from engines.risk_bands import build_band_distribution
from engines.run_info import build_run_info
from engines.reporting import write_scoring_export
from engines.scoring import calculate_risk_score
from engines.scoring_pipeline import score_dataset


ROOT_DIR = Path(__file__).resolve().parents[1]
ENGINE_DIR = ROOT_DIR / "engines"
WEIGHT_CONFIG_PATH = ENGINE_DIR / "weight_config.json"
SCORING_CONFIG_PATH = ENGINE_DIR / "scoring_config.json"
TAXONOMY_FILES = {
    option: ENGINE_DIR / f"taxonomy_option_{option.lower()}.json"
    for option in "ABC"
}
INPUT_EXCEL_PATH = (
    ROOT_DIR
    / "reference_data"
    / "vulnerability_contextualization_scanner_sample_updated.xlsx"
)
OUTPUT_DIR = ROOT_DIR / "outputs"
OUTPUT_EXCEL_PATH = OUTPUT_DIR / "multi_taxonomy_weighted_risk_model.xlsx"


def load_weights():
    if not WEIGHT_CONFIG_PATH.is_file() or WEIGHT_CONFIG_PATH.stat().st_size == 0:
        st.error(f"Weight configuration file is missing or empty: {WEIGHT_CONFIG_PATH}")
        return None
    with WEIGHT_CONFIG_PATH.open(encoding="utf-8") as weight_file:
        try:
            return json.load(weight_file)
        except json.JSONDecodeError:
            st.error(f"Weight configuration contains invalid JSON: {WEIGHT_CONFIG_PATH}")
            return None


def load_taxonomies():
    mappings = {}
    for option, path in TAXONOMY_FILES.items():
        if not path.is_file() or path.stat().st_size == 0:
            st.error(f"Taxonomy file {option} is missing or empty: {path}")
            return None
        with path.open(encoding="utf-8") as taxonomy_file:
            try:
                mappings[option] = json.load(taxonomy_file)[
                    "exposure_classification_mapping"
                ]
            except json.JSONDecodeError:
                st.error(f"Taxonomy file {option} contains invalid JSON: {path}")
                return None
    return mappings


def load_scoring_config():
    if not SCORING_CONFIG_PATH.is_file():
        st.error(f"Scoring configuration file is missing: {SCORING_CONFIG_PATH}")
        return None
    with SCORING_CONFIG_PATH.open(encoding="utf-8") as config_file:
        try:
            return json.load(config_file)
        except json.JSONDecodeError:
            st.error(
                f"Scoring configuration contains invalid JSON: {SCORING_CONFIG_PATH}"
            )
            return None


@st.cache_data(show_spinner=False)
def load_input_data(path: str, modified_ns: int, size: int) -> pd.DataFrame:
    return pd.read_excel(path, engine="openpyxl")


@st.cache_data(show_spinner=False)
def cached_score_data(data, weights, mappings, scoring_config, kev_catalog):
    return score_dataset(data, weights, mappings, scoring_config, kev_catalog)


def main():
    st.title("Automated Multi-Taxonomy Risk Scoring Engine")
    st.caption("Version 2.0")

    weight_config = load_weights()
    taxonomies = load_taxonomies()
    scoring_config = load_scoring_config()
    if weight_config is None or taxonomies is None or scoring_config is None:
        st.stop()

    if not INPUT_EXCEL_PATH.is_file():
        st.error(f"Master input workbook not found: {INPUT_EXCEL_PATH}")
        st.stop()
    input_stat = INPUT_EXCEL_PATH.stat()
    raw_data = load_input_data(
        str(INPUT_EXCEL_PATH), input_stat.st_mtime_ns, input_stat.st_size
    )
    kev_catalog = load_kev(DEFAULT_KEV_PATH)
    kev_notice = catalog_warning(kev_catalog)
    if kev_notice:
        st.warning(kev_notice)
    elif kev_catalog:
        st.caption(
            f"CISA KEV snapshot {kev_catalog.version}, "
            f"released {kev_catalog.date_released.date()}."
        )

    data, quality, exposure_a = cached_score_data(
        raw_data,
        weight_config["weights"],
        taxonomies,
        scoring_config,
        kev_catalog,
    )
    dimension = quality["dimension"]
    active_option = st.session_state.get("active_taxonomy", "Option B")[-1]
    exposure_quality = quality["exposure"][active_option]
    if exposure_quality["blank_count"] or exposure_quality["unmapped_count"]:
        st.warning(
            f"Option {active_option} exposure quality: "
            f"{exposure_quality['blank_count']} blank and "
            f"{exposure_quality['unmapped_count']} unmapped values. "
            "Configured defaults were applied and recorded."
        )
    if dimension["controls_unmatched_count"]:
        st.warning(
            f"{dimension['controls_unmatched_count']} findings have control text "
            "that matched no configured category."
        )
    if dimension["unknown_count"]:
        st.warning(
            f"{dimension['unknown_count']} patch-complexity value(s) used the "
            "configured default."
        )
    if quality["severity_mismatches_before"]:
        st.warning(
            f"{quality['severity_mismatches_before']} source CVSS severity "
            "label(s) disagree with the numeric score; recomputed labels are used."
        )
    st.caption(
        f"PoC lookup coverage: {dimension['poc_coverage']}; missing values use "
        "the configured placeholder. Asset-tier counts and control descriptions "
        "are synthetic dataset values."
    )

    asset_comparison = compare_asset_criticality_modes(
        data,
        exposure_a,
        scoring_config["asset_criticality"],
        weight_config["weights"],
        scoring_config,
    )
    comparison_path = write_asset_criticality_comparison(asset_comparison)
    st.caption(f"Asset criticality comparison saved to {comparison_path}.")

    band_distribution = build_band_distribution(data, scoring_config)
    band_output_path = OUTPUT_DIR / "band_distribution.csv"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    band_distribution.to_csv(band_output_path, index=False)
    st.caption(
        f"Risk bands use {scoring_config['risk_bands']['mode']}; distributions "
        f"for both scales are saved to {band_output_path}."
    )

    data = data.sort_values("Rank_Option_B", ascending=True)
    st.subheader("Risk Calculation Summary Matrix")
    output_columns = [
        "Finding ID",
        "CVE ID",
        "Exposure classification",
        "CVSS base score",
        "CVSS severity (recomputed)",
        "Severity_label_mismatch",
        "Asset_Tier_Score",
        "Score_Rescaled_Option_A",
        "Risk_Level_Option_A",
        "Final_Risk_Score_Option_A",
        "Rank_Option_A",
        "Score_Rescaled_Option_B",
        "Risk_Level_Option_B",
        "Final_Risk_Score_Option_B",
        "Rank_Option_B",
        "Score_Rescaled_Option_C",
        "Risk_Level_Option_C",
        "Final_Risk_Score_Option_C",
        "Rank_Option_C",
    ]
    st.dataframe(data[output_columns], width="stretch", hide_index=True)

    if st.button("Export scoring results", type="primary"):
        run_info = build_run_info(
            ROOT_DIR,
            INPUT_EXCEL_PATH,
            len(raw_data),
            WEIGHT_CONFIG_PATH,
            weight_config,
            SCORING_CONFIG_PATH,
            scoring_config,
            TAXONOMY_FILES,
            kev_catalog,
        )
        write_scoring_export(
            data, quality, kev_catalog, run_info, OUTPUT_EXCEL_PATH
        )
        st.success(f"Scoring export created: {OUTPUT_EXCEL_PATH}")

    if OUTPUT_EXCEL_PATH.is_file():
        st.download_button(
            "Download latest scoring export",
            data=OUTPUT_EXCEL_PATH.read_bytes(),
            file_name=OUTPUT_EXCEL_PATH.name,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )


if __name__ == "__main__":
    main()
