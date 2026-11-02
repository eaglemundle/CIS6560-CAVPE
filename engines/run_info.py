"""Export provenance metadata for a scoring run."""

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import pandas as pd

from engines.kev_validation import KevCatalog


def _file_hash(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version(package: str) -> str:
    try:
        return version(package)
    except PackageNotFoundError:
        return "not installed"


def _git_commit(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return result.stdout.strip()


def build_run_info(
    root: str | Path,
    input_path: str | Path,
    input_rows: int,
    weight_config_path: str | Path,
    weight_config: dict[str, Any],
    scoring_config_path: str | Path,
    scoring_config: dict[str, Any],
    taxonomy_paths: dict[str, str | Path],
    kev_catalog: KevCatalog | None,
) -> pd.DataFrame:
    root_path = Path(root)
    records = [
        ("run_timestamp_utc", datetime.now(timezone.utc).isoformat()),
        ("scoring_config_version", scoring_config["version"]),
        ("input_file", Path(input_path).name),
        ("input_rows", input_rows),
        ("input_sha256", _file_hash(input_path)),
        ("weight_config_version", weight_config["version"]),
        ("weight_config_sha256", _file_hash(weight_config_path)),
        ("scoring_config_sha256", _file_hash(scoring_config_path)),
        ("kev_catalog_version", kev_catalog.version if kev_catalog else "not loaded"),
        (
            "kev_date_released",
            kev_catalog.date_released.isoformat() if kev_catalog else "not loaded",
        ),
        ("git_commit", _git_commit(root_path)),
        ("python_version", platform.python_version()),
        ("pandas_version", _package_version("pandas")),
        ("numpy_version", _package_version("numpy")),
        ("scipy_version", _package_version("scipy")),
        ("streamlit_version", _package_version("streamlit")),
        ("openpyxl_version", _package_version("openpyxl")),
    ]
    records.extend(
        (f"weight_{name}", value)
        for name, value in weight_config["weights"].items()
    )
    for option, path in taxonomy_paths.items():
        with Path(path).open(encoding="utf-8") as taxonomy_file:
            taxonomy = json.load(taxonomy_file)
        records.extend(
            [
                (f"taxonomy_{option}_version", taxonomy["version"]),
                (f"taxonomy_{option}_sha256", _file_hash(path)),
            ]
        )
    return pd.DataFrame(records, columns=["Item", "Value"])
