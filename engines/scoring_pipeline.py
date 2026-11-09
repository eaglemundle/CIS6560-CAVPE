"""Pure data preparation and scoring pipeline shared by project surfaces."""

from typing import Any

import numpy as np
import pandas as pd

from engines.asset_criticality import asset_tier_scores
from engines.dimension_scores import add_dimension_scores
from engines.kev_validation import KevCatalog, validate_exploitation
from engines.risk_bands import add_risk_band_columns
from engines.scoring import calculate_risk_scores, rank_findings
from engines.scoring_validation import cvss_severity, map_exposure_classification


def score_dataset(
    input_data: pd.DataFrame,
    weights: dict[str, float],
    taxonomy_mappings: dict[str, dict[str, int]],
    scoring_config: dict[str, Any],
    kev_catalog: KevCatalog | None,
) -> tuple[pd.DataFrame, dict[str, Any], pd.Series]:
    """Return fully scored findings, quality metrics, and Option A exposure scores."""
    required_options = {"A", "B"}
    missing_options = required_options - taxonomy_mappings.keys()
    unknown_options = taxonomy_mappings.keys() - required_options
    if missing_options or unknown_options:
        details = []
        if missing_options:
            details.append(f"missing options: {', '.join(sorted(missing_options))}")
        if unknown_options:
            details.append(f"unknown options: {', '.join(sorted(unknown_options))}")
        raise ValueError("Invalid taxonomy mappings (" + "; ".join(details) + ")")

    data = validate_exploitation(input_data, kev_catalog)
    data, dimension_quality = add_dimension_scores(data, scoring_config)
    data["Asset_Tier_Score"] = asset_tier_scores(
        data, scoring_config["asset_criticality"]["tier_scores"]
    )
    data["CISA KEV Status"] = np.where(
        data["Exploited_score"] == 2,
        "Confirmed - Active Exploitation",
        "Standard Monitored",
    )

    severity_thresholds = scoring_config["cvss_severity_thresholds"]
    data["CVSS severity (recomputed)"] = data["CVSS base score"].map(
        lambda value: cvss_severity(value, severity_thresholds)
    )
    data["Severity_label_mismatch"] = (
        data["CVSS severity"].fillna("").astype(str).str.strip().str.casefold()
        != data["CVSS severity (recomputed)"]
        .fillna("")
        .astype(str)
        .str.casefold()
    )
    severity_mismatches = int(data["Severity_label_mismatch"].sum())
    expected_severity = data["CVSS base score"].map(
        lambda value: cvss_severity(value, severity_thresholds)
    )
    recomputed_mismatches = int(
        (
            data["CVSS severity (recomputed)"].fillna("").astype(str).str.casefold()
            != expected_severity.fillna("").astype(str).str.casefold()
        ).sum()
    )

    result = data.copy()
    exposure_quality = {}
    option_a_exposure_scores = None
    for option in "AB":
        option_data = data.copy()
        exposure_scores, quality = map_exposure_classification(
            option_data, taxonomy_mappings[option], scoring_config
        )
        exposure_quality[option] = quality
        if option == "A":
            option_a_exposure_scores = exposure_scores.copy()
        criticality = exposure_scores

        option_data[f"Asset_Crit_{option}"] = criticality
        raw_column = f"Unrounded_Risk_Score_Option_{option}"
        option_data[raw_column] = calculate_risk_scores(
            option_data, f"Asset_Crit_{option}", weights, scoring_config
        )
        option_data[f"Final_Risk_Score_Option_{option}"] = option_data[
            raw_column
        ].round(2)
        option_data[f"Rank_Option_{option}"] = rank_findings(option_data, raw_column)

        for column in (
            f"Asset_Crit_{option}",
            raw_column,
            f"Final_Risk_Score_Option_{option}",
            f"Rank_Option_{option}",
        ):
            result[column] = option_data[column]

    result = add_risk_band_columns(result, scoring_config)
    quality = {
        "dimension": dimension_quality,
        "exposure": exposure_quality,
        "severity_mismatches_before": severity_mismatches,
        "severity_mismatches_after": recomputed_mismatches,
    }
    if option_a_exposure_scores is None:
        raise ValueError("Taxonomy Option A mapping is required")
    return result, quality, option_a_exposure_scores
