"""Load and apply a point-in-time CISA Known Exploited Vulnerabilities catalog."""

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


DEFAULT_KEV_PATH = (
    Path(__file__).resolve().parents[1]
    / "reference_data"
    / "known_exploited_vulnerabilities.json"
)
STALE_CATALOG_DAYS = 14


@dataclass(frozen=True)
class KevCatalog:
    cve_ids: frozenset[str]
    version: str
    date_released: datetime


def load_kev(path: str | Path = DEFAULT_KEV_PATH) -> KevCatalog | None:
    """Load a CISA KEV JSON snapshot; return None only when the file is absent."""
    catalog_path = Path(path)
    if not catalog_path.is_file():
        return None

    with catalog_path.open(encoding="utf-8") as catalog_file:
        payload: dict[str, Any] = json.load(catalog_file)

    try:
        version = str(payload["catalogVersion"])
        date_released = datetime.fromisoformat(
            str(payload["dateReleased"]).replace("Z", "+00:00")
        )
        entries = payload["vulnerabilities"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid CISA KEV catalog metadata in {catalog_path}") from error

    if not isinstance(entries, list):
        raise ValueError(f"Invalid vulnerabilities list in {catalog_path}")

    cve_ids = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("cveID"), str):
            raise ValueError(f"Invalid vulnerability entry in {catalog_path}")
        cve_ids.add(entry["cveID"].strip().upper())

    return KevCatalog(
        cve_ids=frozenset(cve_ids),
        version=version,
        date_released=date_released,
    )


def catalog_warning(catalog: KevCatalog | None) -> str | None:
    if catalog is None:
        return "CISA KEV catalog is missing; exploitation scores are provisional."

    age = (datetime.now(timezone.utc).date() - catalog.date_released.date()).days
    if age > STALE_CATALOG_DAYS:
        return (
            f"CISA KEV catalog {catalog.version} is {age} days old "
            f"(released {catalog.date_released.date()}); refresh it."
        )
    return None


def _dataset_flagged(value: object) -> bool:
    text = str(value).strip().lower()
    return "known exploited" in text or text == "active"


def _status(dataset_flagged: bool, in_kev: bool) -> tuple[str, int]:
    if in_kev and dataset_flagged:
        return "in KEV and flagged in dataset", 2
    if in_kev:
        return "in KEV, not flagged in dataset", 2
    if dataset_flagged:
        return "flagged in dataset, not in KEV", 1
    return "not in KEV and not flagged in dataset", 0


def validate_exploitation(
    data: pd.DataFrame,
    catalog: KevCatalog | None,
    cve_column: str = "CVE ID",
    context_column: str = "Exploitation context",
) -> pd.DataFrame:
    """Add KEV status and a 0-2 exploited score without mutating input data."""
    result = data.copy()
    flagged = result[context_column].map(_dataset_flagged)

    if catalog is None:
        result["KEV_status"] = "unverified (no KEV file)"
        result["Exploited_score"] = flagged.astype(int)
        return result

    in_kev = result[cve_column].astype(str).str.strip().str.upper().isin(catalog.cve_ids)
    status_scores = [
        _status(is_flagged, is_in_kev)
        for is_flagged, is_in_kev in zip(flagged.tolist(), in_kev.tolist())
    ]
    result["KEV_status"] = [status for status, _ in status_scores]
    result["Exploited_score"] = [score for _, score in status_scores]
    return result


def cve_level_kev_summary(
    data: pd.DataFrame,
    catalog: KevCatalog | None,
    cve_column: str = "CVE ID",
    context_column: str = "Exploitation context",
) -> pd.DataFrame:
    """Summarize dataset and catalog KEV state once per CVE."""
    summary = (
        data.assign(_Dataset_flagged=data[context_column].map(_dataset_flagged))
        .groupby(cve_column, dropna=False, as_index=False)
        .agg(Dataset_flagged=("_Dataset_flagged", "any"))
    )

    if catalog is None:
        summary["In_KEV"] = pd.NA
        summary["KEV_status"] = "unverified (no KEV file)"
    else:
        summary["In_KEV"] = (
            summary[cve_column].astype(str).str.strip().str.upper().isin(catalog.cve_ids)
        )
        summary["KEV_status"] = [
            _status(flagged, in_kev)[0]
            for flagged, in_kev in zip(
                summary["Dataset_flagged"].tolist(), summary["In_KEV"].tolist()
            )
        ]

    summary["KEV_catalog_version"] = catalog.version if catalog else pd.NA
    summary["KEV_date_released"] = (
        catalog.date_released.isoformat() if catalog else pd.NA
    )
    return summary
