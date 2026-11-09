"""Risk scoring shared by the dashboards and analysis tools."""

import math

import pandas as pd


REQUIRED_WEIGHT_KEYS = frozenset(
    {
        "severity",
        "exploited_in_the_wild",
        "poc_exploit_availability",
        "patch_difficulty",
        "compensating_controls",
        "asset_criticality",
        "risk_transfer",
    }
)


def validate_weights(weight_dict: dict[str, float]) -> None:
    missing = REQUIRED_WEIGHT_KEYS - weight_dict.keys()
    unknown = weight_dict.keys() - REQUIRED_WEIGHT_KEYS
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing required keys: {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown keys: {', '.join(sorted(unknown))}")
        raise ValueError("Invalid scoring weights (" + "; ".join(details) + ")")

    try:
        values = [float(weight_dict[key]) for key in REQUIRED_WEIGHT_KEYS]
    except (TypeError, ValueError) as error:
        raise ValueError("Scoring weights must be numeric") from error
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("Scoring weights must be finite and nonnegative")
    if not math.isclose(sum(values), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(
            f"Scoring weights must sum to 1.0; received {sum(values):.12g}"
        )


def calculate_risk_scores(
    data: pd.DataFrame,
    asset_crit_column: str,
    weight_dict: dict[str, float],
    scoring_config: dict[str, object] | None = None,
) -> pd.Series:
    validate_weights(weight_dict)
    severity_values = pd.to_numeric(data["CVSS base score"], errors="raise").fillna(0)
    if not severity_values.between(0, 10).all():
        raise ValueError("CVSS base scores must be between 0 and 10")
    severity = severity_values / 10.0
    if "Exploited_score" in data:
        exploited_values = pd.to_numeric(data["Exploited_score"], errors="raise")
        if not exploited_values.between(0, 2).all():
            raise ValueError("Exploited scores must be between 0 and 2")
        exploited = exploited_values / 2.0
    else:
        exploited = (
            data.get("Exploitation context", pd.Series("", index=data.index))
            .astype(str)
            .str.strip()
            .str.lower()
            .eq("active")
            .astype(float)
        )
    criticality_values = pd.to_numeric(data[asset_crit_column], errors="raise")
    if not criticality_values.between(1, 4).all():
        raise ValueError("Asset criticality scores must be between 1 and 4")
    criticality = criticality_values / 4.0

    if scoring_config is None:
        poc = pd.Series(0.5, index=data.index)
        patch = pd.Series(0.5, index=data.index)
        controls = pd.Series(0.3, index=data.index)
        transfer = pd.Series(0.0, index=data.index)
        transfer_mode = "reducer"
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
        if transfer_mode != "reducer":
            raise ValueError(f"Unsupported risk transfer mode: {transfer_mode}")
        for name, values in (
            ("PoC", poc),
            ("patch", patch),
            ("compensating controls", controls),
            ("risk transfer", transfer),
        ):
            if not values.between(0, 1).all():
                raise ValueError(f"Normalized {name} scores must be between 0 and 1")

    weighted_score = (
        severity * weight_dict["severity"]
        + exploited * weight_dict["exploited_in_the_wild"]
        + poc * weight_dict["poc_exploit_availability"]
        + patch * weight_dict["patch_difficulty"]
        + controls * weight_dict["compensating_controls"]
        + criticality * weight_dict["asset_criticality"]
    ) * 100.0
    transfer_adjustment = weight_dict["risk_transfer"] * transfer * 100.0
    weighted_score -= transfer_adjustment

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
