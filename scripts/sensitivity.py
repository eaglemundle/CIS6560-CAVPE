"""Generate reproducible weight, taxonomy, and rule sensitivity reports."""

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
from scipy.stats import kendalltau


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engines.kev_validation import DEFAULT_KEV_PATH, load_kev
from engines.scoring import rank_findings
from engines.scoring_pipeline import score_dataset


INPUT_PATH = (
    ROOT_DIR
    / "reference_data"
    / "vulnerability_contextualization_scanner_sample_updated.xlsx"
)
WEIGHT_CONFIG_PATH = ROOT_DIR / "engines" / "weight_config.json"
SCORING_CONFIG_PATH = ROOT_DIR / "engines" / "scoring_config.json"
TAXONOMY_PATHS = {
    option: ROOT_DIR / "engines" / f"taxonomy_option_{option.lower()}.json"
    for option in "ABC"
}
OUTPUT_DIR = ROOT_DIR / "outputs"
WEIGHT_FACTORS = (0.9, 1.1)
RECORD_LEVELS = ("finding", "cve")


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def _load_taxonomy_mappings() -> dict[str, dict[str, int]]:
    return {
        option: _read_json(path)["exposure_classification_mapping"]
        for option, path in TAXONOMY_PATHS.items()
    }


def _perturb_weight(
    weights: dict[str, float], name: str, factor: float
) -> dict[str, float]:
    if name not in weights:
        raise ValueError(f"Unknown scoring weight: {name}")
    total = sum(weights.values())
    original = weights[name]
    other_total = total - original
    adjusted_value = original * factor
    if other_total <= 0 or adjusted_value < 0 or adjusted_value >= total:
        raise ValueError(f"Cannot preserve total weight while perturbing {name!r}")

    adjusted = dict(weights)
    remaining_scale = (total - adjusted_value) / other_total
    adjusted[name] = adjusted_value
    for other_name in weights.keys() - {name}:
        adjusted[other_name] = weights[other_name] * remaining_scale
    return adjusted


def _build_scenarios(
    weights: dict[str, float],
    mappings: dict[str, dict[str, int]],
    scoring_config: dict[str, Any],
) -> list[
    tuple[
        str,
        str,
        dict[str, float],
        dict[str, dict[str, int]],
        dict[str, Any],
        str,
        str,
    ]
]:
    scenarios = [
        (
            "baseline_option_a",
            "baseline",
            weights,
            mappings,
            scoring_config,
            "A",
            "Current configured Option A scoring.",
        )
    ]

    for weight_name in weights:
        for factor, suffix in zip(WEIGHT_FACTORS, ("minus_10pct", "plus_10pct")):
            scenarios.append(
                (
                    f"weight_{weight_name}_{suffix}",
                    "weight",
                    _perturb_weight(weights, weight_name, factor),
                    mappings,
                    scoring_config,
                    "A",
                    (
                        f"{weight_name} adjusted by {(factor - 1) * 100:+.0f}%; "
                        "remaining weights proportionally rescaled to preserve "
                        "the total."
                    ),
                )
            )

    for option in "ABC":
        scenarios.append(
            (
                f"taxonomy_option_{option.lower()}",
                "taxonomy",
                weights,
                mappings,
                scoring_config,
                option,
                f"Uses taxonomy Option {option} with all other settings unchanged.",
            )
        )

    rule_variants = [
        (
            "rule_asset_criticality_tier_only",
            "Asset criticality mode set to tier_only.",
            lambda config: config["asset_criticality"].update(mode="tier_only"),
        ),
        (
            "rule_asset_criticality_blend",
            "Asset criticality mode set to blend.",
            lambda config: config["asset_criticality"].update(mode="blend"),
        ),
        (
            "rule_patch_direction_harder_is_lower",
            "Patch complexity direction set to harder_is_lower.",
            lambda config: config["patch_complexity"].update(
                direction="harder_is_lower"
            ),
        ),
        (
            "rule_controls_profile_effectiveness",
            "Controls profile set to effectiveness.",
            lambda config: config.update(controls_profile="effectiveness"),
        ),
        (
            "rule_risk_transfer_mode_additive",
            "Risk transfer mode set to additive.",
            lambda config: config.update(risk_transfer_mode="additive"),
        ),
    ]
    for level in (0, 2):
        rule_variants.append(
            (
                f"rule_poc_placeholder_level_{level}",
                f"Missing PoC lookup entries use placeholder level {level}.",
                lambda config, level=level: config.update(
                    poc_placeholder_level=level
                ),
            )
        )

    for name, note, change in rule_variants:
        variant_config = copy.deepcopy(scoring_config)
        change(variant_config)
        scenarios.append((name, "rule", weights, mappings, variant_config, "A", note))
    return scenarios


def _rank_entities(
    data: pd.DataFrame, scores: pd.Series, record_level: str
) -> pd.DataFrame:
    rows = data[
        ["Finding ID", "CVE ID", "Exploited_score", "CVSS base score"]
    ].copy()
    rows["Score"] = scores.to_numpy()

    if record_level == "finding":
        if rows["Finding ID"].astype(str).duplicated().any():
            raise ValueError("Finding IDs must be unique for finding-level ranking")
        entities = rows.copy()
        entities["Entity_ID"] = entities["Finding ID"].astype(str)
    elif record_level == "cve":
        entities = (
            rows.groupby("CVE ID", dropna=False, as_index=False)
            .agg(
                Score=("Score", "max"),
                Exploited_score=("Exploited_score", "max"),
                **{"CVSS base score": ("CVSS base score", "max")},
            )
        )
        entities["Entity_ID"] = entities["CVE ID"].fillna("<missing>").astype(str)
        entities["Finding ID"] = "CVE:" + entities["Entity_ID"]
    else:
        raise ValueError(f"Unsupported record level: {record_level}")

    entities["Rank"] = rank_findings(entities, "Score")
    return entities[["Entity_ID", "Score", "Rank"]].sort_values(
        "Entity_ID", kind="mergesort"
    )


def _compare_ranks(
    baseline: pd.DataFrame,
    scenario: pd.DataFrame,
    record_level: str,
    top_n: int,
) -> tuple[dict[str, Any], pd.DataFrame]:
    comparison = baseline.merge(
        scenario,
        on="Entity_ID",
        how="inner",
        suffixes=("_baseline", "_scenario"),
        validate="one_to_one",
    )
    rank_delta = comparison["Rank_scenario"] - comparison["Rank_baseline"]
    score_delta = comparison["Score_scenario"] - comparison["Score_baseline"]
    baseline_top = set(baseline.nsmallest(top_n, "Rank")["Entity_ID"])
    scenario_top = set(scenario.nsmallest(top_n, "Rank")["Entity_ID"])
    overlap = len(baseline_top & scenario_top)
    overlap_denominator = min(len(baseline_top), len(scenario_top))

    metric = {
        "Record_level": record_level,
        "Entity_count": len(comparison),
        "Kendall_tau": float(
            kendalltau(
                comparison["Rank_baseline"], comparison["Rank_scenario"]
            ).statistic
        ),
        "Top_n": top_n,
        "Top_n_overlap_count": overlap,
        "Top_n_overlap_rate": (
            overlap / overlap_denominator if overlap_denominator else 1.0
        ),
        "Mean_absolute_rank_change": float(rank_delta.abs().mean()),
        "Maximum_absolute_rank_change": int(rank_delta.abs().max()),
        "Mean_absolute_score_change": float(score_delta.abs().mean()),
        "Maximum_absolute_score_change": float(score_delta.abs().max()),
    }
    movers = comparison.loc[rank_delta.ne(0)].copy()
    movers["Record_level"] = record_level
    movers["Rank_delta"] = rank_delta.loc[movers.index]
    return metric, movers


def run_sensitivity(
    input_path: str | Path = INPUT_PATH,
    output_dir: str | Path = OUTPUT_DIR,
    top_n: int = 30,
) -> tuple[Path, Path, Path]:
    if top_n < 1:
        raise ValueError("top_n must be a positive integer")

    input_file = Path(input_path)
    output_path = Path(output_dir)
    raw_data = pd.read_excel(input_file, engine="openpyxl")
    weight_config = _read_json(WEIGHT_CONFIG_PATH)
    scoring_config = _read_json(SCORING_CONFIG_PATH)
    mappings = _load_taxonomy_mappings()
    kev_catalog = load_kev(DEFAULT_KEV_PATH)
    weights = weight_config["weights"]
    scenarios = _build_scenarios(weights, mappings, scoring_config)

    baseline_data, baseline_quality, _ = score_dataset(
        raw_data, weights, mappings, scoring_config, kev_catalog
    )
    baseline_scores = baseline_data["Unrounded_Risk_Score_Option_A"]
    baseline_ranks = {
        level: _rank_entities(baseline_data, baseline_scores, level)
        for level in RECORD_LEVELS
    }

    scenario_results: list[
        tuple[str, str, str, pd.DataFrame, pd.Series, str]
    ] = []
    for name, scenario_type, variant_weights, variant_mappings, config, option, note in scenarios:
        if name == "baseline_option_a":
            scenario_data = baseline_data
            scores = baseline_scores
        else:
            scenario_data, _, _ = score_dataset(
                raw_data, variant_weights, variant_mappings, config, kev_catalog
            )
            scores = scenario_data[f"Unrounded_Risk_Score_Option_{option}"]
        scenario_results.append(
            (name, scenario_type, option, scenario_data, scores, note)
        )

    cvss_only_scores = (
        pd.to_numeric(baseline_data["CVSS base score"], errors="raise")
        .fillna(0)
        .mul(10)
    )
    scenario_results.append(
        (
            "cvss_only",
            "benchmark",
            "CVSS",
            baseline_data,
            cvss_only_scores,
            "CVSS base score scaled to 0-100; other scoring dimensions excluded.",
        )
    )

    summary_records: list[dict[str, Any]] = []
    mover_frames: list[pd.DataFrame] = []
    for name, scenario_type, option, scenario_data, scores, note in scenario_results:
        if name == "rule_risk_transfer_mode_additive" and not baseline_quality[
            "dimension"
        ]["risk_register_covered_findings"]:
            note += " No risk-register findings are present, so this rule has no effect."
        if name.startswith("rule_poc_placeholder_level_"):
            coverage = baseline_quality["dimension"]["poc_coverage"]
            if not coverage:
                note += " No manual PoC lookup entries are present."

        for level in RECORD_LEVELS:
            scenario_ranks = _rank_entities(scenario_data, scores, level)
            metric, movers = _compare_ranks(
                baseline_ranks[level], scenario_ranks, level, top_n
            )
            summary_records.append(
                {
                    "Scenario": name,
                    "Scenario_type": scenario_type,
                    "Taxonomy": option,
                    "Scenario_note": note,
                    **metric,
                }
            )
            if not movers.empty:
                movers.insert(0, "Scenario", name)
                movers.insert(1, "Scenario_type", scenario_type)
                movers.insert(2, "Taxonomy", option)
                mover_frames.append(movers)

    summary = pd.DataFrame(summary_records)
    rank_movers = (
        pd.concat(mover_frames, ignore_index=True)
        if mover_frames
        else pd.DataFrame(
            columns=[
                "Scenario",
                "Scenario_type",
                "Taxonomy",
                "Record_level",
                "Entity_ID",
                "Score_baseline",
                "Rank_baseline",
                "Score_scenario",
                "Rank_scenario",
                "Rank_delta",
            ]
        )
    )
    output_path.mkdir(parents=True, exist_ok=True)
    summary_path = output_path / "sensitivity_summary.csv"
    movers_path = output_path / "sensitivity_rank_movers.csv"
    chart_path = output_path / "sensitivity_kendall_tau.html"
    summary.to_csv(summary_path, index=False)
    rank_movers.to_csv(movers_path, index=False)

    chart = px.bar(
        summary,
        x="Scenario",
        y="Kendall_tau",
        color="Record_level",
        barmode="group",
        title="Sensitivity scenario rank correlation against Option A baseline",
        labels={"Kendall_tau": "Kendall's tau", "Record_level": "Ranking unit"},
        hover_data=["Scenario_type", "Taxonomy", "Top_n_overlap_rate"],
    )
    chart.update_xaxes(tickangle=-60)
    chart.write_html(chart_path, include_plotlyjs="cdn", auto_open=False)
    return summary_path, movers_path, chart_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=INPUT_PATH)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--top-n", type=int, default=30)
    arguments = parser.parse_args()

    summary_path, movers_path, chart_path = run_sensitivity(
        arguments.input, arguments.output_dir, arguments.top_n
    )
    print(f"Sensitivity summary: {summary_path}")
    print(f"Rank movers: {movers_path}")
    print(f"Rank-correlation chart: {chart_path}")


if __name__ == "__main__":
    main()
