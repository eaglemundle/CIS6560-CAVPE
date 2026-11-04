import json
from pathlib import Path

import pandas as pd
import pytest

from engines.asset_criticality import (
    asset_criticality_scores,
    asset_tier_scores,
    compare_asset_criticality_modes,
    write_asset_criticality_comparison,
)
from engines.dimension_scores import add_dimension_scores
from engines.kev_validation import load_kev, validate_exploitation
from engines.scoring_validation import map_exposure_classification


ROOT = Path(__file__).resolve().parents[1]


def scoring_config():
    return json.loads(
        (ROOT / "engines" / "scoring_config.json").read_text(encoding="utf-8")
    )


def test_asset_modes_preserve_exposure_only_default_and_support_tier_blends():
    data = pd.DataFrame(
        {
            "Critical assets": [1, 0],
            "High-criticality assets": [0, 1],
            "Medium-criticality assets": [0, 0],
            "Low-criticality assets": [0, 0],
        }
    )
    config = scoring_config()
    exposure = pd.Series([2, 4], dtype=float)

    assert asset_tier_scores(data, config["asset_criticality"]["tier_scores"]).tolist() == [
        4,
        3,
    ]
    assert asset_criticality_scores(data, exposure, config).tolist() == [2.0, 4.0]
    assert asset_criticality_scores(data, exposure, config, "tier_only").tolist() == [
        4.0,
        3.0,
    ]
    assert asset_criticality_scores(data, exposure, config, "blend").tolist() == [
        4.0,
        4.0,
    ]

    mean_config = {
        **config,
        "asset_criticality": {
            **config["asset_criticality"],
            "combine": "mean",
        },
    }
    assert asset_criticality_scores(data, exposure, mean_config, "blend").tolist() == [
        3.0,
        3.5,
    ]


def test_asset_tier_mode_rejects_missing_or_unassigned_counts():
    config = scoring_config()["asset_criticality"]["tier_scores"]
    missing = pd.DataFrame({"Critical assets": [1]})
    with pytest.raises(ValueError, match="Missing asset-tier columns"):
        asset_tier_scores(missing, config)

    empty = pd.DataFrame({column: [0] for column in config})
    with pytest.raises(ValueError, match="no assets assigned"):
        asset_tier_scores(empty, config)


def test_current_default_mode_and_pairwise_comparison_output(tmp_path):
    config = scoring_config()
    weights = json.loads(
        (ROOT / "engines" / "weight_config.json").read_text(encoding="utf-8")
    )["weights"]
    mapping = json.loads(
        (ROOT / "engines" / "taxonomy_option_a.json").read_text(encoding="utf-8")
    )["exposure_classification_mapping"]
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )
    data = validate_exploitation(data, load_kev())
    data, _ = add_dimension_scores(data, config)
    exposure, _ = map_exposure_classification(data, mapping, config)

    assert config["asset_criticality"]["mode"] == "exposure_only"
    assert asset_criticality_scores(data, exposure, config).equals(
        exposure.astype(float)
    )
    comparison = compare_asset_criticality_modes(
        data,
        exposure,
        config["asset_criticality"],
        weights,
        config,
    )
    path = write_asset_criticality_comparison(
        comparison, tmp_path / "asset_modes.csv"
    )
    saved = pd.read_csv(path)

    assert len(saved) == 3
    assert saved["Kendall_tau"].between(-1, 1).all()
    assert saved["Top_30_overlap_count"].between(0, 30).all()
    assert saved["Data_note"].eq(
        "Asset-tier counts and control descriptions are synthetic."
    ).all()
