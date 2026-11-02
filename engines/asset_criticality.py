"""Option A asset-tier alternatives and ranking comparison."""

from pathlib import Path
from typing import Any

import pandas as pd
from scipy.stats import kendalltau

from engines.scoring import calculate_risk_score


ROOT_DIR = Path(__file__).resolve().parents[1]
ASSET_MODE_OUTPUT = ROOT_DIR / "outputs" / "asset_criticality_modes.csv"


def asset_tier_scores(
    data: pd.DataFrame, tier_scores: dict[str, int]
) -> pd.Series:
    missing_columns = set(tier_scores) - set(data.columns)
    if missing_columns:
        raise ValueError(
            "Missing asset-tier columns: " + ", ".join(sorted(missing_columns))
        )

    counts = data[list(tier_scores)].apply(pd.to_numeric, errors="raise")
    if counts.isna().any().any() or (counts < 0).any().any():
        raise ValueError("Asset-tier counts must be present and nonnegative")

    tier_score = pd.Series(0, index=data.index, dtype=float)
    for column, score in sorted(
        tier_scores.items(), key=lambda item: item[1], reverse=True
    ):
        if not 1 <= int(score) <= 4:
            raise ValueError(f"Asset tier score for {column!r} must be 1 through 4")
        tier_score = tier_score.mask((tier_score == 0) & counts[column].gt(0), score)

    if tier_score.eq(0).any():
        raise ValueError("One or more findings have no assets assigned to a tier")
    return tier_score


def asset_criticality_scores(
    data: pd.DataFrame,
    exposure_scores: pd.Series,
    config: dict[str, Any],
    mode: str | None = None,
) -> pd.Series:
    asset_config = config.get("asset_criticality", config)
    selected_mode = mode or asset_config["mode"]
    if selected_mode == "exposure_only":
        return exposure_scores.astype(float)
    if selected_mode not in {"tier_only", "blend"}:
        raise ValueError(f"Unsupported asset criticality mode: {selected_mode}")

    tiers = asset_tier_scores(data, asset_config["tier_scores"])
    if selected_mode == "tier_only":
        return tiers

    combine = asset_config["combine"]
    if combine == "max":
        return pd.concat([exposure_scores, tiers], axis=1).max(axis=1)
    if combine == "mean":
        return (exposure_scores + tiers) / 2.0
    raise ValueError(f"Unsupported asset criticality combine mode: {combine}")


def _rank_scores(scores: pd.Series, data: pd.DataFrame) -> pd.Series:
    order = data.assign(_score=scores).sort_values(
        by=["_score", "Exploited_score", "CVSS base score", "Finding ID"],
        ascending=[False, False, False, True],
        kind="mergesort",
    )
    ranks = pd.Series(range(1, len(order) + 1), index=order.index)
    return ranks.reindex(data.index)


def compare_asset_criticality_modes(
    data: pd.DataFrame,
    exposure_scores: pd.Series,
    config: dict[str, Any],
    weight_dict: dict[str, float],
    scoring_config: dict[str, Any],
    top_n: int = 30,
) -> pd.DataFrame:
    modes = ("exposure_only", "tier_only", "blend")
    rank_by_mode = {}
    top_by_mode = {}

    for mode in modes:
        criticality = asset_criticality_scores(data, exposure_scores, config, mode)
        rows = data.copy()
        rows["Asset_Criticality_Mode"] = criticality
        scores = rows.apply(
            lambda row: calculate_risk_score(
                row, "Asset_Criticality_Mode", weight_dict, scoring_config
            ),
            axis=1,
        )
        ranks = _rank_scores(scores, rows)
        rank_by_mode[mode] = ranks
        top_by_mode[mode] = set(
            rows.loc[ranks.nsmallest(top_n).index, "Finding ID"]
        )

    results = []
    for first_index, first_mode in enumerate(modes):
        for second_mode in modes[first_index + 1 :]:
            tau = kendalltau(
                rank_by_mode[first_mode].to_numpy(),
                rank_by_mode[second_mode].to_numpy(),
            ).statistic
            overlap = len(top_by_mode[first_mode] & top_by_mode[second_mode])
            denominator = min(
                len(top_by_mode[first_mode]), len(top_by_mode[second_mode])
            )
            results.append(
                {
                    "Mode_A": first_mode,
                    "Mode_B": second_mode,
                    "Kendall_tau": float(tau),
                    f"Top_{top_n}_overlap_count": overlap,
                    f"Top_{top_n}_overlap": overlap / denominator if denominator else 1.0,
                    "Data_note": (
                        "Asset-tier counts and control descriptions are synthetic."
                    ),
                }
            )
    return pd.DataFrame(results)


def write_asset_criticality_comparison(
    comparison: pd.DataFrame, output_path: str | Path = ASSET_MODE_OUTPUT
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    comparison.to_csv(path, index=False)
    return path
