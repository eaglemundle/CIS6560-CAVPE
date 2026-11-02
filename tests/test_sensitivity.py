import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SENSITIVITY_SCRIPT = ROOT / "scripts" / "sensitivity.py"
INPUT_WORKBOOK = (
    ROOT
    / "reference_data"
    / "vulnerability_contextualization_scanner_sample_updated.xlsx"
)
WEIGHT_CONFIG_PATH = ROOT / "engines" / "weight_config.json"


def load_sensitivity_module():
    spec = importlib.util.spec_from_file_location(
        "sensitivity_analysis", SENSITIVITY_SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(
            f"Unable to load sensitivity script from {SENSITIVITY_SCRIPT}"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_sensitivity_run_generates_metrics_movers_and_chart(tmp_path):
    input_hash = file_hash(INPUT_WORKBOOK)
    weight_hash = file_hash(WEIGHT_CONFIG_PATH)

    subprocess.run(
        [
            sys.executable,
            str(SENSITIVITY_SCRIPT),
            "--input",
            str(INPUT_WORKBOOK),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    summary_path = tmp_path / "sensitivity_summary.csv"
    movers_path = tmp_path / "sensitivity_rank_movers.csv"
    chart_path = tmp_path / "sensitivity_kendall_tau.html"

    summary = pd.read_csv(summary_path)
    movers = pd.read_csv(movers_path)
    assert {"finding", "cve"} == set(summary["Record_level"])
    assert {
        "baseline_option_a",
        "cvss_only",
        "taxonomy_option_b",
        "weight_severity_minus_10pct",
        "rule_patch_direction_harder_is_lower",
    }.issubset(set(summary["Scenario"]))
    baseline = summary[summary["Scenario"] == "baseline_option_a"]
    assert baseline["Kendall_tau"].eq(1.0).all()
    assert baseline["Top_n_overlap_count"].eq(30).all()
    assert (
        summary.loc[summary["Record_level"] == "finding", "Entity_count"]
        .eq(300)
        .all()
    )
    assert (
        summary.loc[summary["Record_level"] == "cve", "Entity_count"]
        .eq(207)
        .all()
    )
    assert {"Rank_delta", "Rank_baseline", "Rank_scenario"}.issubset(movers.columns)
    assert chart_path.is_file()
    assert file_hash(INPUT_WORKBOOK) == input_hash
    assert file_hash(WEIGHT_CONFIG_PATH) == weight_hash


def test_weight_sweep_preserves_total_without_mutating_config():
    module = load_sensitivity_module()
    weights = json.loads(WEIGHT_CONFIG_PATH.read_text(encoding="utf-8"))["weights"]

    adjusted = module._perturb_weight(weights, "severity", 1.1)

    assert abs(sum(adjusted.values()) - sum(weights.values())) < 1e-12
    assert adjusted["severity"] > weights["severity"]
    assert adjusted != weights
