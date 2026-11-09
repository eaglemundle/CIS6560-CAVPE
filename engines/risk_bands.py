"""Score-scale conversion and configurable risk-band assignment."""

import math
from typing import Any

import pandas as pd


CONTEXTUAL_PRIORITY_LABELS = {
    "Critical": "P1 - Urgent",
    "High": "P2 - High",
    "Medium": "P3 - Planned",
    "Low": "P4 - Low",
}


def rescale_score(score: float, scale_config: dict[str, float]) -> float:
    native_min = float(scale_config["native_min"])
    native_max = float(scale_config["native_max"])
    rescaled_min = float(scale_config["rescaled_min"])
    rescaled_max = float(scale_config["rescaled_max"])
    if native_max <= native_min or rescaled_max <= rescaled_min:
        raise ValueError("Score-scale ranges must be increasing")
    bounded_score = min(native_max, max(native_min, float(score)))
    ratio = (bounded_score - native_min) / (native_max - native_min)
    rescaled_score = rescaled_min + ratio * (rescaled_max - rescaled_min)
    if scale_config["rounding"] == "nearest_integer":
        return float(math.floor(rescaled_score + 0.5))
    raise ValueError(f"Unsupported score rescaling mode: {scale_config['rounding']}")


def risk_level(score: float, bands: list[dict[str, Any]]) -> str:
    numeric_score = float(score)
    for band in bands:
        if float(band["min"]) <= numeric_score <= float(band["max"]):
            return str(band["name"])
    raise ValueError(f"Score {numeric_score:g} does not fit a configured risk band")


def add_risk_band_columns(
    data: pd.DataFrame, scoring_config: dict[str, Any]
) -> pd.DataFrame:
    result = data.copy()
    scale = scoring_config["score_scale"]
    mode = scoring_config["risk_bands"]["mode"]
    if mode not in {"rescaled_24", "native_100"}:
        raise ValueError(f"Unsupported risk band mode: {mode}")

    for option in "AB":
        score_column = f"Final_Risk_Score_Option_{option}"
        raw_column = f"Unrounded_Risk_Score_Option_{option}"
        score_values = result[raw_column] if raw_column in result else result[score_column]
        rescaled = score_values.map(lambda score: rescale_score(score, scale))
        result[f"Score_Rescaled_Option_{option}"] = rescaled.round(2)
        band_values = (
            rescaled
            if mode == "rescaled_24"
            else score_values
        )
        result[f"Risk_Level_Option_{option}"] = band_values.map(
            lambda score: risk_level(
                score, scoring_config["risk_bands"][mode]
            )
        )
        result[f"Contextual_Priority_Option_{option}"] = result[
            f"Risk_Level_Option_{option}"
        ].map(CONTEXTUAL_PRIORITY_LABELS)
    return result


def build_band_distribution(
    data: pd.DataFrame, scoring_config: dict[str, Any]
) -> pd.DataFrame:
    records = []
    for option in "AB":
        score_column = f"Unrounded_Risk_Score_Option_{option}"
        if score_column not in data:
            score_column = f"Final_Risk_Score_Option_{option}"
        scores = data[score_column]
        rescaled_scores = scores.map(
            lambda score: rescale_score(score, scoring_config["score_scale"])
        )
        for mode in ("rescaled_24", "native_100"):
            bands = scoring_config["risk_bands"][mode]
            values = rescaled_scores if mode == "rescaled_24" else scores
            counts = values.map(lambda score: risk_level(score, bands)).value_counts()
            for band in bands:
                count = int(counts.get(band["name"], 0))
                records.append(
                    {
                        "Taxonomy": f"Option {option}",
                        "Score_mode": mode,
                        "Risk_level": band["name"],
                        "Count": count,
                        "Percent": count / len(data) * 100 if len(data) else 0.0,
                    }
                )
    return pd.DataFrame(records)
