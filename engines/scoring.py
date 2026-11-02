"""Risk scoring shared by the dashboards and analysis tools."""

import pandas as pd


def calculate_risk_score(
    row: pd.Series,
    asset_crit_column: str,
    weight_dict: dict[str, float],
    scoring_config: dict[str, object] | None = None,
) -> float:
    severity = (
        row["CVSS base score"] / 10.0
        if pd.notna(row.get("CVSS base score"))
        else 0.0
    )
    exploited = (
        row["Exploited_score"] / 2.0
        if "Exploited_score" in row
        else (
            1.0
            if str(row.get("Exploitation context", "")).strip().lower() == "active"
            else 0.0
        )
    )
    criticality = row[asset_crit_column] / 4.0

    if scoring_config is None:
        poc, patch, controls, transfer = 0.5, 0.5, 0.3, 0.0
        transfer_mode = "additive"
        minimum_score = 0.0
    else:
        required_dimensions = (
            "PoC_norm",
            "Patch_norm",
            "Controls_norm",
            "Transfer_norm",
        )
        missing = [column for column in required_dimensions if column not in row]
        if missing:
            raise ValueError(
                f"Missing prepared scoring dimensions: {', '.join(missing)}"
            )
        poc = row["PoC_norm"]
        patch = row["Patch_norm"]
        controls = row["Controls_norm"]
        transfer = row["Transfer_norm"]
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
        return round(max(minimum_score, weighted_score), 2)
    return max(minimum_score, weighted_score)


def rank_findings(data: pd.DataFrame, score_column: str) -> pd.Series:
    """Assign deterministic one-based ranks without rounding scores."""
    order = data.sort_values(
        by=[score_column, "Exploited_score", "CVSS base score", "Finding ID"],
        ascending=[False, False, False, True],
        kind="mergesort",
    )
    ranks = pd.Series(range(1, len(order) + 1), index=order.index)
    return ranks.reindex(data.index)
