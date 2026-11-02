import pandas as pd

from engines.reporting import write_scoring_export


def test_scoring_export_has_all_report_worksheets(tmp_path):
    data = pd.DataFrame(
        [
            {
                "Finding ID": "VULN-1",
                "CVE ID": "CVE-2025-0001",
                "Exploitation context": "active",
                "KEV_status": "flagged in dataset, not in KEV",
                "Severity_label_mismatch": False,
            }
        ]
    )
    quality = {
        "exposure": {
            option: {
                "blank_count": 0,
                "blank_finding_ids": [],
                "unmapped_count": 0,
                "unmapped_labels": [],
                "unmapped_finding_ids": [],
            }
            for option in "ABC"
        },
        "dimension": {
            "unknown_count": 0,
            "unknown_labels": [],
            "unknown_finding_ids": [],
            "controls_filled_count": 0,
            "controls_unmatched_count": 0,
            "controls_unmatched_finding_ids": [],
            "poc_coverage": 0,
            "risk_register_covered_findings": 0,
        },
        "severity_mismatches_before": 0,
        "severity_mismatches_after": 0,
    }
    run_info = pd.DataFrame([{"Item": "scoring_config_version", "Value": "2.0.0"}])
    output = tmp_path / "scoring.xlsx"

    written_path = write_scoring_export(data, quality, None, run_info, output)

    assert written_path == output
    assert pd.ExcelFile(output).sheet_names == [
        "Scores",
        "KEV_Review",
        "Data_Quality",
        "Run_Info",
    ]
    assert pd.read_excel(output, sheet_name="Scores")["Finding ID"].tolist() == [
        "VULN-1"
    ]
