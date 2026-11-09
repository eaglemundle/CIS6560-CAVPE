import json
from pathlib import Path

import pandas as pd

from engines.scoring import calculate_risk_score


ROOT = Path(__file__).resolve().parents[1]
INPUT_WORKBOOK = (
    ROOT
    / "reference_data"
    / "vulnerability_contextualization_scanner_sample_updated.xlsx"
)
WEIGHT_CONFIG = ROOT / "engines" / "weight_config.json"


def test_current_dataset_baseline_facts():
    data = pd.read_excel(INPUT_WORKBOOK)

    assert data.shape == (300, 22)
    assert data["CVE ID"].nunique() == 207
    assert len(data) - data["CVE ID"].nunique() == 93
    assert data["Compensating controls"].notna().sum() == 120


def test_calculate_risk_score_hand_computed_values():
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

    assert calculate_risk_score(active_finding, "Asset_Crit_A", weights) == 78.0
    assert calculate_risk_score(no_cvss_finding, "Asset_Crit_A", weights) == 18.0
