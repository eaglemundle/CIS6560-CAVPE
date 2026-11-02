"""Pure data preparation and scoring pipeline shared by project surfaces."""

from typing import Any

import numpy as np
import pandas as pd

from engines.asset_criticality import asset_criticality_scores, asset_tier_scores
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

    exposure_quality = {}
    option_a_exposure_scores = None
    for option in "ABC":
        exposure_scores, quality = map_exposure_classification(
            data, taxonomy_mappings[option], scoring_config
        )
        exposure_quality[option] = quality
        if option == "A":
            option_a_exposure_scores = exposure_scores.copy()
            criticality = asset_criticality_scores(
                data, exposure_scores, scoring_config
            )
        else:
            criticality = exposure_scores

        data[f"Asset_Crit_{option}"] = criticality
        raw_column = f"Unrounded_Risk_Score_Option_{option}"
        data[raw_column] = calculate_risk_scores(
            data, f"Asset_Crit_{option}", weights, scoring_config
        )
        data[f"Final_Risk_Score_Option_{option}"] = data[raw_column].round(2)
        data[f"Rank_Option_{option}"] = rank_findings(data, raw_column)

    data = add_risk_band_columns(data, scoring_config)
    quality = {
        "dimension": dimension_quality,
        "exposure": exposure_quality,
        "severity_mismatches_before": severity_mismatches,
        "severity_mismatches_after": recomputed_mismatches,
    }
    if option_a_exposure_scores is None:
        raise ValueError("Taxonomy Option A mapping is required")
    return data, quality, option_a_exposure_scores
