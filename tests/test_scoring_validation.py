import json
from pathlib import Path

import pandas as pd

from engines.scoring_validation import cvss_severity, map_exposure_classification


ROOT = Path(__file__).resolve().parents[1]


def scoring_config():
    return json.loads(
        (ROOT / "engines" / "scoring_config.json").read_text(encoding="utf-8")
    )


def test_exposure_mapping_normalizes_whitespace_and_case():
    data = pd.DataFrame(
        {
            "Finding ID": ["VULN-1", "VULN-2"],
            "Exposure classification": ["  INTERNET-FACING ", "Internal"],
        }
    )
    mapping = {"internet-facing": 4, "internal": 2}

    scores, quality = map_exposure_classification(data, mapping, scoring_config())

    assert scores.tolist() == [4, 2]
    assert quality["blank_count"] == 0
    assert quality["unmapped_count"] == 0


def test_blank_and_unmapped_exposures_are_counted_and_configured():
    data = pd.DataFrame(
        {
            "Finding ID": ["VULN-1", "VULN-2", "VULN-3"],
            "Exposure classification": [None, "unknown zone", "INTERNAL"],
        }
    )
    mapping = {"internal": 2, "internet-facing": 4}

    scores, quality = map_exposure_classification(data, mapping, scoring_config())

    assert scores.tolist() == [2, 1, 2]
    assert quality["blank_count"] == 1
    assert quality["blank_finding_ids"] == ["VULN-1"]
    assert quality["unmapped_count"] == 1
    assert quality["unmapped_labels"] == ["unknown zone"]
    assert quality["unmapped_finding_ids"] == ["VULN-2"]


def test_missing_default_label_mapping_is_an_explicit_error():
    data = pd.DataFrame(
        {"Finding ID": ["VULN-1"], "Exposure classification": [None]}
    )

    try:
        map_exposure_classification(
            data,
            {"internet-facing": 4},
            scoring_config(),
        )
    except ValueError as error:
        assert "exposure_default_label" in str(error)
    else:
        raise AssertionError("Expected missing default taxonomy label to fail")


def test_cvss_severity_band_edges():
    thresholds = scoring_config()["cvss_severity_thresholds"]

    assert [cvss_severity(score, thresholds) for score in [3.9, 4.0, 6.9, 7.0, 8.9, 9.0]] == [
        "Low",
        "Medium",
        "Medium",
        "High",
        "High",
        "Critical",
    ]
    assert cvss_severity(float("nan"), thresholds) is None
    assert cvss_severity(0.0, thresholds) == "None"


def test_dataset_severity_labels_have_28_mismatches_before_recomputation():
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )
    thresholds = scoring_config()["cvss_severity_thresholds"]
    recomputed = data["CVSS base score"].map(
        lambda value: cvss_severity(value, thresholds)
    )
    mismatches = (
        data["CVSS severity"].fillna("").astype(str).str.casefold()
        != recomputed.fillna("").astype(str).str.casefold()
    )

    assert int(mismatches.sum()) == 28
    assert set(recomputed.dropna().unique()) <= {
        "Critical",
        "High",
        "Medium",
        "Low",
        "None",
    }


def test_current_dataset_has_no_silent_exposure_fallbacks():
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )
    config = scoring_config()

    for option in "AB":
        taxonomy = json.loads(
            (ROOT / "engines" / f"taxonomy_option_{option.lower()}.json").read_text(
                encoding="utf-8"
            )
        )
        scores, quality = map_exposure_classification(
            data,
            taxonomy["exposure_classification_mapping"],
            config,
        )
        assert len(scores) == len(data)
        assert quality["blank_count"] == 0
        assert quality["unmapped_count"] == 0
