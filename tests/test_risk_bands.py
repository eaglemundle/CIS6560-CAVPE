import json
from pathlib import Path

import numpy as np
import pandas as pd

from engines.risk_bands import (
    add_risk_band_columns,
    build_band_distribution,
    rescale_score,
    risk_level,
)
from engines.scoring import rank_findings


ROOT = Path(__file__).resolve().parents[1]


def scoring_config():
    return json.loads(
        (ROOT / "engines" / "scoring_config.json").read_text(encoding="utf-8")
    )


def test_score_scale_maps_to_charter_range_and_rounds_for_bands():
    scale = scoring_config()["score_scale"]

    assert rescale_score(0, scale) == 1
    assert rescale_score(100, scale) == 24
    assert rescale_score(50, scale) == 13


def test_rescaled_and_native_risk_band_boundaries():
    bands = scoring_config()["risk_bands"]

    assert [
        risk_level(value, bands["rescaled_24"])
        for value in [1, 6, 7, 12, 13, 18, 19, 24]
    ] == ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]
    assert [
        risk_level(value, bands["native_100"])
        for value in [0, 25, 50, 75, 100]
    ] == ["Low", "Low", "Medium", "High", "Critical"]


def test_rank_ties_are_broken_deterministically_without_rounding():
    rows = pd.DataFrame(
        {
            "Finding ID": ["VULN-3", "VULN-2", "VULN-1", "VULN-4"],
            "Unrounded": [9.001, 9.001, 9.001, 9.000],
            "Exploited_score": [2, 2, 2, 1],
            "CVSS base score": [10.0, 9.0, 9.0, 10.0],
        }
    )
    ranks = rank_findings(rows, "Unrounded")
    actual = dict(zip(rows["Finding ID"], ranks))
    repeated = dict(
        zip(
            rows.iloc[::-1]["Finding ID"],
            rank_findings(rows.iloc[::-1], "Unrounded"),
        )
    )

    assert actual == {
        "VULN-3": 1,
        "VULN-1": 2,
        "VULN-2": 3,
        "VULN-4": 4,
    }
    assert repeated == actual


def test_band_columns_and_distribution_cover_both_taxonomies_and_modes():
    config = scoring_config()
    data = pd.DataFrame(
        {
            f"Final_Risk_Score_Option_{option}": [0.0, 50.0, 100.0]
            for option in "AB"
        }
    )

    result = add_risk_band_columns(data, config)
    distribution = build_band_distribution(result, config)

    assert result["Score_Rescaled_Option_A"].tolist() == [1, 13, 24]
    assert result["Risk_Level_Option_A"].tolist() == ["Low", "High", "Critical"]
    assert result["Contextual_Priority_Option_A"].tolist() == [
        "P4 - Low",
        "P2 - High",
        "P1 - Urgent",
    ]
    assert len(distribution) == 16
    assert distribution.groupby(["Taxonomy", "Score_mode"])["Count"].sum().eq(3).all()
    assert np.isclose(
        distribution.groupby(["Taxonomy", "Score_mode"])["Percent"].sum(),
        100,
    ).all()
