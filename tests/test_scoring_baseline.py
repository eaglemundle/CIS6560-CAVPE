import importlib.util
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SCORING_VIEWER = ROOT / "pages" / "02_Scoring_Viewer.py"
INPUT_WORKBOOK = (
    ROOT
    / "reference_data"
    / "vulnerability_contextualization_scanner_sample_updated.xlsx"
)
WEIGHT_CONFIG = ROOT / "engines" / "weight_config.json"
OPTION_A_CONFIG = ROOT / "engines" / "taxonomy_option_a.json"
GOLDEN_FILE = ROOT / "tests" / "golden" / "option_a_v1_0.csv"


def load_scoring_viewer():
    spec = importlib.util.spec_from_file_location("scoring_viewer", SCORING_VIEWER)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load scoring module from {SCORING_VIEWER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def option_a_scores():
    module = load_scoring_viewer()
    data = pd.read_excel(INPUT_WORKBOOK)
    weights = json.loads(WEIGHT_CONFIG.read_text(encoding="utf-8"))["weights"]
    taxonomy = json.loads(OPTION_A_CONFIG.read_text(encoding="utf-8"))
    mapping = {
        str(label).strip().lower(): value
        for label, value in taxonomy["exposure_classification_mapping"].items()
    }
    data["Asset_Crit_A"] = (
        data["Exposure classification"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(mapping)
        .fillna(1)
        .astype(int)
    )
    data["Final_Risk_Score_Option_A"] = data.apply(
        lambda row: module.calculate_risk_score(row, "Asset_Crit_A", weights),
        axis=1,
    )
    data["rank"] = (
        data["Final_Risk_Score_Option_A"]
        .rank(method="min", ascending=False)
        .astype(int)
    )
    return data[["Finding ID", "Final_Risk_Score_Option_A", "rank"]]


def test_current_option_a_matches_golden_snapshot():
    expected = pd.read_csv(GOLDEN_FILE)
    actual = option_a_scores()
    pd.testing.assert_frame_equal(actual, expected, check_dtype=False)


def test_current_dataset_baseline_facts():
    data = pd.read_excel(INPUT_WORKBOOK)
    scores = option_a_scores()["Final_Risk_Score_Option_A"]

    assert data.shape == (300, 22)
    assert data["CVE ID"].nunique() == 207
    assert len(data) - data["CVE ID"].nunique() == 93
    assert data["Compensating controls"].notna().sum() == 120
    assert scores.min() == 36.7
    assert scores.max() == 63.0
    assert scores.nunique() == 55
    assert scores.eq(scores.max()).sum() == 12


def test_calculate_risk_score_hand_computed_values():
    module = load_scoring_viewer()
    weights = json.loads(WEIGHT_CONFIG.read_text(encoding="utf-8"))["weights"]

    active_finding = pd.Series(
        {
            "CVSS base score": 10.0,
            "Exploitation context": "active",
            "Asset_Crit_A": 4,
        }
    )
    no_cvss_finding = pd.Series(
        {
            "CVSS base score": float("nan"),
            "Exploitation context": "none",
            "Asset_Crit_A": 2,
        }
    )

    assert module.calculate_risk_score(active_finding, "Asset_Crit_A", weights) == 78.0
    assert module.calculate_risk_score(no_cvss_finding, "Asset_Crit_A", weights) == 18.0
