"""Dimension scoring and optional lookup ingestion for vulnerability findings."""

import re
from pathlib import Path
from typing import Any

import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_POC_PATH = ROOT_DIR / "reference_data" / "poc_lookup.csv"
DEFAULT_RISK_REGISTER_PATH = ROOT_DIR / "reference_data" / "risk_register.csv"


def score_patch(label: object, patch_config: dict[str, Any]) -> float:
    labels = {
        str(key).strip().casefold(): float(value)
        for key, value in patch_config["scores"].items()
    }
    if label is None or pd.isna(label) or not str(label).strip():
        score = float(patch_config["default_score"])
    else:
        score = labels.get(
            str(label).strip().casefold(), float(patch_config["default_score"])
        )

    scale_max = float(patch_config["scale_max"])
    if not 1 <= score <= scale_max:
        raise ValueError(f"Patch score must be between 1 and {scale_max:g}")

    direction = patch_config["direction"]
    if direction == "harder_is_higher":
        return score
    if direction == "harder_is_lower":
        return scale_max + 1 - score
    raise ValueError(f"Unsupported patch scoring direction: {direction}")


def map_patch_complexity(
    data: pd.DataFrame,
    patch_config: dict[str, Any],
    label_column: str = "Patch complexity",
) -> tuple[pd.Series, dict[str, object]]:
    scores = data[label_column].map(lambda value: score_patch(value, patch_config))
    known_labels = {
        str(label).strip().casefold() for label in patch_config["scores"]
    }
    raw = data[label_column]
    blank = raw.isna() | raw.astype(str).str.strip().eq("")
    unknown = ~blank & ~raw.astype(str).str.strip().str.casefold().isin(known_labels)
    quality = {
        "blank_count": int(blank.sum()),
        "unknown_count": int(unknown.sum()),
        "unknown_labels": sorted(
            raw.loc[unknown].astype(str).str.strip().unique().tolist()
        ),
        "unknown_finding_ids": data.loc[unknown, "Finding ID"].astype(str).tolist(),
    }
    return scores, quality


def control_types(
    control_text: object, categories: dict[str, Any]
) -> list[str]:
    if control_text is None or pd.isna(control_text):
        return []
    text = str(control_text)
    matched = []
    for name, category in categories.items():
        pattern = category if isinstance(category, str) else category["pattern"]
        if re.search(pattern, text, flags=re.IGNORECASE):
            matched.append(name)
    return matched


def score_controls(
    control_text: object,
    controls_config: dict[str, Any],
    profile: str = "equal",
    effectiveness_profile: dict[str, float] | None = None,
) -> float:
    scale_max = float(controls_config["scale_max"])
    weight_cap = float(controls_config["max_counted_weight"])
    if scale_max <= 0 or weight_cap < 0 or weight_cap > scale_max:
        raise ValueError("Control score scale and cap are inconsistent")
    if profile not in {"equal", "effectiveness"}:
        raise ValueError(f"Unsupported controls profile: {profile}")

    matched_types = control_types(control_text, controls_config["categories"])
    total_weight = 0.0
    for name in matched_types:
        category = controls_config["categories"][name]
        if isinstance(category, str):
            weight = 1.0
            category_type = "preventive"
        else:
            weight = float(category.get("weight", 1.0))
            category_type = str(category.get("type", "preventive"))
        if profile == "effectiveness" and effectiveness_profile is not None:
            weight = float(effectiveness_profile.get(category_type, weight))
        if weight < 0:
            raise ValueError(f"Control category {name!r} has a negative weight")
        total_weight += weight
    return scale_max - min(total_weight, weight_cap)


def load_poc_lookup(path: str | Path = DEFAULT_POC_PATH) -> dict[str, int]:
    lookup_path = Path(path)
    if not lookup_path.is_file():
        return {}
    data = pd.read_csv(lookup_path, dtype={"cve_id": str})
    required = {"cve_id", "poc_level", "source", "date_checked"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(
            f"PoC lookup is missing required columns: {', '.join(sorted(missing))}"
        )
    data["cve_id"] = data["cve_id"].str.strip().str.upper()
    if data["cve_id"].eq("").any() or data["cve_id"].duplicated().any():
        raise ValueError("PoC lookup CVE IDs must be nonblank and unique")
    levels = pd.to_numeric(data["poc_level"], errors="raise")
    if levels.isna().any() or not levels.isin([0, 1, 2]).all():
        raise ValueError("PoC levels must be integers from 0 through 2")
    data["poc_level"] = levels.astype(int)
    return dict(zip(data["cve_id"], data["poc_level"]))


def load_risk_register(path: str | Path = DEFAULT_RISK_REGISTER_PATH) -> dict[str, int]:
    register_path = Path(path)
    if not register_path.is_file():
        return {}
    data = pd.read_csv(register_path, dtype={"finding_id": str})
    required = {"finding_id", "status"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(
            f"Risk register is missing required columns: {', '.join(sorted(missing))}"
        )
    data["finding_id"] = data["finding_id"].str.strip()
    if data["finding_id"].eq("").any() or data["finding_id"].duplicated().any():
        raise ValueError("Risk register finding IDs must be nonblank and unique")
    statuses = pd.to_numeric(data["status"], errors="raise")
    if statuses.isna().any() or not statuses.isin([0, 1, 2]).all():
        raise ValueError("Risk register statuses must be 0, 1, or 2")
    data["status"] = statuses.astype(int)
    return dict(zip(data["finding_id"], data["status"]))


def add_dimension_scores(
    data: pd.DataFrame,
    scoring_config: dict[str, Any],
    poc_path: str | Path = DEFAULT_POC_PATH,
    risk_register_path: str | Path = DEFAULT_RISK_REGISTER_PATH,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Add patch, controls, PoC, and risk-transfer dimensions to a copy."""
    result = data.copy()
    patch_scores, patch_quality = map_patch_complexity(
        result, scoring_config["patch_complexity"]
    )
    result["Patch_score"] = patch_scores
    patch_scale = float(scoring_config["patch_complexity"]["scale_max"])
    result["Patch_norm"] = result["Patch_score"] / patch_scale

    controls_config = scoring_config["compensating_controls"]
    profile = scoring_config["controls_profile"]
    effectiveness = scoring_config["controls_profile_effectiveness"]
    result["Controls_types"] = result["Compensating controls"].map(
        lambda value: ", ".join(
            control_types(value, controls_config["categories"])
        )
    )
    result["Controls_score"] = result["Compensating controls"].map(
        lambda value: score_controls(
            value, controls_config, profile, effectiveness
        )
    )
    result["Controls_norm"] = (
        result["Controls_score"] / float(controls_config["scale_max"])
    )
    controls_text_present = (
        result["Compensating controls"].notna()
        & result["Compensating controls"].astype(str).str.strip().ne("")
    )
    controls_unmatched = controls_text_present & result["Controls_types"].eq("")

    poc_lookup = load_poc_lookup(poc_path)
    placeholder_level = int(scoring_config["poc_placeholder_level"])
    if placeholder_level not in [0, 1, 2]:
        raise ValueError("poc_placeholder_level must be 0, 1, or 2")
    normalized_cves = result["CVE ID"].astype(str).str.strip().str.upper()
    result["PoC_level"] = normalized_cves.map(poc_lookup).fillna(placeholder_level)
    result["PoC_norm"] = result["PoC_level"] / 2.0
    unique_cves = set(normalized_cves[normalized_cves.ne("")])
    poc_covered_cves = unique_cves.intersection(poc_lookup)

    risk_register = load_risk_register(risk_register_path)
    result["Risk_transfer_status"] = (
        result["Finding ID"].astype(str).str.strip().map(risk_register).fillna(0)
    )
    transfer_scale = int(scoring_config["risk_transfer_status_scale_max"])
    if transfer_scale < 2:
        raise ValueError("risk_transfer_status_scale_max must be at least 2")
    result["Transfer_norm"] = result["Risk_transfer_status"] / transfer_scale

    quality = {
        **patch_quality,
        "controls_filled_count": int(controls_text_present.sum()),
        "controls_unmatched_count": int(controls_unmatched.sum()),
        "controls_unmatched_finding_ids": result.loc[
            controls_unmatched, "Finding ID"
        ].astype(str).tolist(),
        "poc_covered_cves": len(poc_covered_cves),
        "unique_cves": len(unique_cves),
        "poc_coverage": f"{len(poc_covered_cves)} of {len(unique_cves)} CVEs",
        "risk_register_covered_findings": int(
            result["Finding ID"].astype(str).str.strip().isin(risk_register).sum()
        ),
    }
    return result, quality
