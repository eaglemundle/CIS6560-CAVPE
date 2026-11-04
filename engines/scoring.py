"""Risk scoring shared by the dashboards and analysis tools."""

import pandas as pd


def calculate_risk_scores(
    data: pd.DataFrame,
    asset_crit_column: str,
    weight_dict: dict[str, float],
    scoring_config: dict[str, object] | None = None,
) -> pd.Series:
    severity = (
        pd.to_numeric(data["CVSS base score"], errors="raise").fillna(0) / 10.0
    )
    if "Exploited_score" in data:
        exploited = pd.to_numeric(
            data["Exploited_score"], errors="raise"
        ) / 2.0
    else:
        exploited = (
            data.get("Exploitation context", pd.Series("", index=data.index))
            .astype(str)
            .str.strip()
            .str.lower()
            .eq("active")
            .astype(float)
        )
    criticality = pd.to_numeric(data[asset_crit_column], errors="raise") / 4.0

    if scoring_config is None:
        poc = pd.Series(0.5, index=data.index)
        patch = pd.Series(0.5, index=data.index)
        controls = pd.Series(0.3, index=data.index)
        transfer = pd.Series(0.0, index=data.index)
        transfer_mode = "additive"
        minimum_score = 0.0
    else:
        required_dimensions = (
            "PoC_norm",
            "Patch_norm",
            "Controls_norm",
            "Transfer_norm",
        )
        missing = [column for column in required_dimensions if column not in data]
        if missing:
            raise ValueError(
                f"Missing prepared scoring dimensions: {', '.join(missing)}"
            )
        poc = pd.to_numeric(data["PoC_norm"], errors="raise")
        patch = pd.to_numeric(data["Patch_norm"], errors="raise")
        controls = pd.to_numeric(data["Controls_norm"], errors="raise")
        transfer = pd.to_numeric(data["Transfer_norm"], errors="raise")
        transfer_mode = scoring_config["risk_transfer_mode"]
        minimum_score = float(scoring_config["risk_transfer_min_score"])
        if transfer_mode not in {"reducer", "additive"}:
            raise ValueError(f"Unsupported risk transfer mode: {transfer_mode}")

    weighted_score = (
        severity * weight_dict.get("severity", 0.0)
        + exploited * weight_dict.get("exploited_in_the_wild", 0.0)
        + poc * weight_dict.get("poc_exploit_availability", 0.0)
        + patch * weight_dict.get("patch_difficulty", 0.0)
        + controls * weight_dict.get("compensating_controls", 0.0)
        + criticality * weight_dict.get("asset_criticality", 0.0)
    ) * 100.0
    transfer_adjustment = (
        weight_dict.get("risk_acceptance_transfer", 0.0) * transfer * 100.0
    )
    if transfer_mode == "reducer":
        weighted_score -= transfer_adjustment
    else:
        weighted_score += transfer_adjustment

    if scoring_config is None:
        return weighted_score.clip(lower=minimum_score).round(2)
    return weighted_score.clip(lower=minimum_score)


def calculate_risk_score(
    row: pd.Series,
    asset_crit_column: str,
    weight_dict: dict[str, float],
    scoring_config: dict[str, object] | None = None,
) -> float:
    """Row-wise wrapper retained for tests and small callers."""
    result = calculate_risk_scores(
        pd.DataFrame([row]), asset_crit_column, weight_dict, scoring_config
    )
    return float(result.iloc[0])


def rank_findings(data: pd.DataFrame, score_column: str) -> pd.Series:
    """Assign deterministic one-based ranks without rounding scores."""
    order = data.sort_values(
        by=[score_column, "Exploited_score", "CVSS base score", "Finding ID"],
        ascending=[False, False, False, True],
        kind="mergesort",
    )
    ranks = pd.Series(range(1, len(order) + 1), index=order.index)
    return ranks.reindex(data.index)
