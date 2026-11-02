import json
from pathlib import Path

import pandas as pd
import pytest

from engines.dimension_scores import (
    add_dimension_scores,
    control_types,
    load_poc_lookup,
    load_risk_register,
    map_patch_complexity,
    score_controls,
    score_patch,
)
from engines.kev_validation import load_kev, validate_exploitation
from engines.scoring_validation import map_exposure_classification
from engines.scoring import calculate_risk_score


ROOT = Path(__file__).resolve().parents[1]


def scoring_config():
    return json.loads(
        (ROOT / "engines" / "scoring_config.json").read_text(encoding="utf-8")
    )


def test_score_patch_maps_every_current_label_and_flips_direction():
    config = scoring_config()["patch_complexity"]

    assert [score_patch(label, config) for label in ["Low", "Medium", "High", "Very High"]] == [
        1,
        2,
        3,
        3,
    ]
    flipped = {**config, "direction": "harder_is_lower"}
    assert [score_patch(label, flipped) for label in ["Low", "Medium", "High", "Very High"]] == [
        3,
        2,
        1,
        1,
    ]


def test_unknown_patch_labels_use_and_report_configured_default():
    data = pd.DataFrame(
        {
            "Finding ID": ["VULN-1", "VULN-2"],
            "Patch complexity": ["Novel", "Low"],
        }
    )

    scores, quality = map_patch_complexity(data, scoring_config()["patch_complexity"])

    assert scores.tolist() == [2.0, 1.0]
    assert quality["unknown_count"] == 1
    assert quality["unknown_labels"] == ["Novel"]
    assert quality["unknown_finding_ids"] == ["VULN-1"]


def test_control_patterns_and_legacy_string_categories_are_supported():
    categories = {
        "waf": {"pattern": r"\bWAF\b", "weight": 1.0, "type": "preventive"},
        "monitoring": "SIEM|alert",
    }
    assert control_types("WAF blocks traffic; SIEM sends an alert", categories) == [
        "waf",
        "monitoring",
    ]
    assert score_controls(
        "WAF; SIEM",
        {"scale_max": 3, "max_counted_weight": 3, "categories": categories},
    ) == 1


def test_controls_profile_effectiveness_changes_only_detective_or_recovery_types():
    config = scoring_config()
    controls_config = config["compensating_controls"]
    effectiveness = config["controls_profile_effectiveness"]
    samples = {
        "preventive": "WAF policy",
        "detective": "SIEM alert",
        "recovery": "daily backup snapshot",
    }
    equal_scores = {
        kind: score_controls(text, controls_config, "equal", effectiveness)
        for kind, text in samples.items()
    }
    alternative_scores = {
        kind: score_controls(text, controls_config, "effectiveness", effectiveness)
        for kind, text in samples.items()
    }

    assert equal_scores["preventive"] == alternative_scores["preventive"]
    assert equal_scores["detective"] != alternative_scores["detective"]
    assert equal_scores["recovery"] != alternative_scores["recovery"]


def test_every_filled_current_control_description_matches_a_category(tmp_path):
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )
    prepared, quality = add_dimension_scores(
        data,
        scoring_config(),
        poc_path=tmp_path / "missing-poc.csv",
        risk_register_path=tmp_path / "missing-register.csv",
    )

    assert quality["controls_filled_count"] == 120
    assert quality["controls_unmatched_count"] == 0
    assert prepared.loc[
        prepared["Compensating controls"].notna(), "Controls_types"
    ].ne("").all()


def test_current_patch_labels_have_no_unknowns(tmp_path):
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )
    _, quality = add_dimension_scores(
        data,
        scoring_config(),
        poc_path=tmp_path / "missing-poc.csv",
        risk_register_path=tmp_path / "missing-register.csv",
    )

    assert quality["unknown_count"] == 0


def test_poc_lookup_loads_values_and_validates_levels(tmp_path):
    path = tmp_path / "poc_lookup.csv"
    path.write_text(
        "cve_id,poc_level,source,date_checked\nCVE-2024-0001,2,manual,2026-10-30\n",
        encoding="utf-8",
    )
    assert load_poc_lookup(path) == {"CVE-2024-0001": 2}
    assert load_poc_lookup(tmp_path / "missing.csv") == {}

    path.write_text(
        "cve_id,poc_level,source,date_checked\nCVE-2024-0001,3,manual,2026-10-30\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="0 through 2"):
        load_poc_lookup(path)


def test_risk_register_loads_status_and_validates_range(tmp_path):
    path = tmp_path / "risk_register.csv"
    path.write_text("finding_id,status\nVULN-1,2\n", encoding="utf-8")
    assert load_risk_register(path) == {"VULN-1": 2}
    assert load_risk_register(tmp_path / "missing.csv") == {}

    path.write_text("finding_id,status\nVULN-1,3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="0, 1, or 2"):
        load_risk_register(path)


def test_missing_optional_files_use_documented_poc_placeholder_and_no_transfer(tmp_path):
    data = pd.DataFrame(
        {
            "Finding ID": ["VULN-1"],
            "CVE ID": ["CVE-2024-0001"],
            "Patch complexity": ["Medium"],
            "Compensating controls": [None],
        }
    )

    prepared, quality = add_dimension_scores(
        data,
        scoring_config(),
        poc_path=tmp_path / "missing-poc.csv",
        risk_register_path=tmp_path / "missing-register.csv",
    )

    assert prepared.loc[0, "PoC_level"] == 1
    assert prepared.loc[0, "PoC_norm"] == 0.5
    assert prepared.loc[0, "Transfer_norm"] == 0
    assert quality["poc_coverage"] == "0 of 1 CVEs"
    assert quality["risk_register_covered_findings"] == 0


def test_risk_transfer_is_a_reducer_and_respects_the_floor():
    config = scoring_config()
    weights = json.loads(
        (ROOT / "engines" / "weight_config.json").read_text(encoding="utf-8")
    )["weights"]
    row = pd.Series(
        {
            "CVSS base score": 10.0,
            "Exploited_score": 2,
            "PoC_norm": 0.5,
            "Patch_norm": 1.0,
            "Controls_norm": 1.0,
            "Transfer_norm": 1.0,
            "Asset_Crit_A": 4,
        }
    )

    assert calculate_risk_score(row, "Asset_Crit_A", weights, config) == 85.0
    floor_config = {**config, "risk_transfer_min_score": 90.0}
    assert calculate_risk_score(row, "Asset_Crit_A", weights, floor_config) == 90.0
    additive_config = {**config, "risk_transfer_mode": "additive"}
    assert calculate_risk_score(row, "Asset_Crit_A", weights, additive_config) == 95.0


def test_integrated_option_a_scores_match_phase4_snapshot():
    config = scoring_config()
    weights = json.loads(
        (ROOT / "engines" / "weight_config.json").read_text(encoding="utf-8")
    )["weights"]
    taxonomy = json.loads(
        (ROOT / "engines" / "taxonomy_option_a.json").read_text(encoding="utf-8")
    )["exposure_classification_mapping"]
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )
    data = validate_exploitation(data, load_kev())
    data, _ = add_dimension_scores(data, config)
    data["Asset_Crit_A"], _ = map_exposure_classification(data, taxonomy, config)
    data["Final_Risk_Score_Option_A"] = data.apply(
        lambda row: calculate_risk_score(
            row, "Asset_Crit_A", weights, config
        ),
        axis=1,
    )
    data["rank"] = data["Final_Risk_Score_Option_A"].rank(
        method="min", ascending=False
    ).astype(int)
    actual = data[["Finding ID", "Final_Risk_Score_Option_A", "rank"]]
    expected = pd.read_csv(ROOT / "tests" / "golden" / "option_a_phase4.csv")

    pd.testing.assert_frame_equal(actual, expected, check_dtype=False)
