"""Input normalization and data-quality helpers for the scoring engine."""

from collections.abc import Mapping

import pandas as pd


def map_exposure_classification(
    data: pd.DataFrame,
    exposure_mapping: Mapping[str, int],
    config: Mapping[str, object],
    exposure_column: str = "Exposure classification",
) -> tuple[pd.Series, dict[str, object]]:
    """Map exposure values while explicitly reporting configured fallbacks."""
    default_label = str(config["exposure_default_label"]).strip().lower()
    default_score = int(config["exposure_default_score"])
    if not 1 <= default_score <= 4:
        raise ValueError("exposure_default_score must be between 1 and 4")

    normalized_mapping = {
        str(label).strip().lower(): score for label, score in exposure_mapping.items()
    }
    if any(
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not float(score).is_integer()
        or not 1 <= int(score) <= 4
        for score in normalized_mapping.values()
    ):
        raise ValueError("Exposure mappings must use integer scores from 1 through 4")
    if default_label not in normalized_mapping:
        raise ValueError(
            f"exposure_default_label {default_label!r} is not in the taxonomy mapping"
        )

    raw = data[exposure_column]
    blank = raw.isna() | raw.astype(str).str.strip().eq("")
    normalized = raw.astype(str).str.strip().str.lower().mask(blank, default_label)
    scores = normalized.map(normalized_mapping)
    unmapped = ~blank & scores.isna()
    scores = scores.mask(unmapped, default_score)
    if scores.isna().any():
        raise ValueError("Exposure mapping left one or more scores unresolved")

    quality = {
        "blank_count": int(blank.sum()),
        "blank_finding_ids": data.loc[blank, "Finding ID"].astype(str).tolist(),
        "unmapped_count": int(unmapped.sum()),
        "unmapped_labels": sorted(
            raw.loc[unmapped].astype(str).str.strip().unique().tolist()
        ),
        "unmapped_finding_ids": data.loc[unmapped, "Finding ID"].astype(str).tolist(),
    }
    return scores.astype(int), quality


def cvss_severity(score: object, thresholds: Mapping[str, object]) -> str | None:
    """Return the standard CVSS severity band derived from its base score."""
    if pd.isna(score):
        return None
    numeric_score = float(score)
    if numeric_score <= 0:
        return "None"
    if numeric_score >= float(thresholds["critical_min"]):
        return "Critical"
    if numeric_score >= float(thresholds["high_min"]):
        return "High"
    if numeric_score >= float(thresholds["medium_min"]):
        return "Medium"
    if numeric_score >= float(thresholds["low_min"]):
        return "Low"
    return "None"
