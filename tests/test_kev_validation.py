import json
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

import pandas as pd

from engines.kev_validation import (
    DEFAULT_KEV_PATH,
    KevCatalog,
    catalog_warning,
    cve_level_kev_summary,
    load_kev,
    validate_exploitation,
)

ROOT = Path(__file__).resolve().parents[1]


def test_validate_exploitation_returns_all_four_catalog_statuses():
    catalog = KevCatalog(
        cve_ids=frozenset({"CVE-2024-0001", "CVE-2024-0003"}),
        version="test",
        date_released=datetime(2026, 10, 30, tzinfo=timezone.utc),
    )
    data = pd.DataFrame(
        {
            "CVE ID": [
                "CVE-2024-0001",
                "CVE-2024-0002",
                "CVE-2024-0003",
                "CVE-2024-0004",
            ],
            "Exploitation context": [
                "Known exploited (validate current KEV status)",
                "Known exploited (validate current KEV status)",
                "No confirmed evidence in this sample",
                "No confirmed evidence in this sample",
            ],
        }
    )

    result = validate_exploitation(data, catalog)

    assert result["KEV_status"].tolist() == [
        "in KEV and flagged in dataset",
        "flagged in dataset, not in KEV",
        "in KEV, not flagged in dataset",
        "not in KEV and not flagged in dataset",
    ]
    assert result["Exploited_score"].tolist() == [2, 1, 2, 0]
    assert "KEV_status" not in data


def test_missing_catalog_is_explicit_and_provisional():
    data = pd.DataFrame(
        {
            "CVE ID": ["CVE-2024-0001", "CVE-2024-0002"],
            "Exploitation context": ["Known exploited", "No confirmed evidence"],
        }
    )

    result = validate_exploitation(data, None)

    assert result["KEV_status"].eq("unverified (no KEV file)").all()
    assert result["Exploited_score"].tolist() == [1, 0]
    assert "missing" in catalog_warning(None).lower()


def test_load_kev_reads_snapshot_metadata_and_ids(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "catalogVersion": "2026.10.30",
                "dateReleased": "2026-10-30T17:02:45Z",
                "vulnerabilities": [{"cveID": "CVE-2024-0001"}],
            }
        ),
        encoding="utf-8",
    )

    catalog = load_kev(path)

    assert catalog is not None
    assert catalog.version == "2026.10.30"
    assert catalog.cve_ids == frozenset({"CVE-2024-0001"})
    assert load_kev(tmp_path / "missing.json") is None


def test_stale_catalog_warning_uses_fourteen_day_threshold():
    catalog = KevCatalog(
        cve_ids=frozenset(),
        version="old",
        date_released=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert "refresh" in catalog_warning(catalog).lower()


def test_cve_summary_deduplicates_repeated_findings():
    catalog = KevCatalog(
        cve_ids=frozenset({"CVE-2024-0001"}),
        version="test",
        date_released=datetime(2026, 10, 30, tzinfo=timezone.utc),
    )
    data = pd.DataFrame(
        {
            "CVE ID": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002"],
            "Exploitation context": [
                "Known exploited",
                "Known exploited",
                "No confirmed evidence",
            ],
        }
    )

    summary = cve_level_kev_summary(data, catalog)

    assert len(summary) == 2
    assert summary["CVE ID"].nunique() == 2
    assert summary["KEV_catalog_version"].eq("test").all()


def test_current_catalog_validates_dataset_without_unverified_rows():
    catalog = load_kev(DEFAULT_KEV_PATH)
    assert catalog is not None
    data = pd.read_excel(
        ROOT
        / "reference_data"
        / "vulnerability_contextualization_scanner_sample_updated.xlsx"
    )

    result = validate_exploitation(data, catalog)

    assert not result["KEV_status"].eq("unverified (no KEV file)").any()
    in_catalog = (
        result["CVE ID"].astype(str).str.strip().str.upper().isin(catalog.cve_ids)
    )
    assert result.loc[in_catalog, "Exploited_score"].eq(2).all()


def test_calculate_risk_score_uses_normalized_kev_score():
    source = ROOT / "pages" / "02_Scoring_Viewer.py"
    spec = importlib.util.spec_from_file_location("scoring_viewer_kev", source)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load scoring module from {source}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    weights = json.loads(
        (ROOT / "engines" / "weight_config.json").read_text(encoding="utf-8")
    )["weights"]
    row = pd.Series(
        {
            "CVSS base score": 0.0,
            "Exploitation context": "No confirmed evidence",
            "Asset_Crit_A": 2,
            "Exploited_score": 2,
        }
    )

    score = module.calculate_risk_score(row, "Asset_Crit_A", weights)

    assert score == 33.0
