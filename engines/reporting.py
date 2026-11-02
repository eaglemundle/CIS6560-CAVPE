"""Scoring export reports."""

from pathlib import Path

import pandas as pd

from engines.kev_validation import KevCatalog, cve_level_kev_summary


def build_data_quality_report(
    data: pd.DataFrame, quality: dict, catalog: KevCatalog | None
) -> pd.DataFrame:
    report = cve_level_kev_summary(data, catalog)
    report["Record_type"] = "CVE"
    dimension = quality["dimension"]
    metric_rows = []
    for option, counts in quality["exposure"].items():
        metric_rows.extend(
            [
                {
                    "Record_type": "Exposure",
                    "Metric": f"Option {option} blank exposure values",
                    "Count": counts["blank_count"],
                    "Finding IDs": ", ".join(counts["blank_finding_ids"]),
                },
                {
                    "Record_type": "Exposure",
                    "Metric": f"Option {option} unmapped exposure values",
                    "Count": counts["unmapped_count"],
                    "Values": ", ".join(counts["unmapped_labels"]),
                    "Finding IDs": ", ".join(counts["unmapped_finding_ids"]),
                },
            ]
        )
    metric_rows.extend(
        [
            {
                "Record_type": "Patch",
                "Metric": "Unknown patch-complexity values",
                "Count": dimension["unknown_count"],
                "Values": ", ".join(dimension["unknown_labels"]),
                "Finding IDs": ", ".join(dimension["unknown_finding_ids"]),
            },
            {
                "Record_type": "Controls",
                "Metric": "Filled control rows",
                "Count": dimension["controls_filled_count"],
            },
            {
                "Record_type": "Controls",
                "Metric": "Control rows with no category match",
                "Count": dimension["controls_unmatched_count"],
                "Finding IDs": ", ".join(
                    dimension["controls_unmatched_finding_ids"]
                ),
            },
            {
                "Record_type": "PoC",
                "Metric": "PoC lookup coverage",
                "Count": dimension["poc_coverage"],
            },
            {
                "Record_type": "Risk transfer",
                "Metric": "Findings covered by risk register",
                "Count": dimension["risk_register_covered_findings"],
            },
            {
                "Record_type": "Dataset note",
                "Metric": "Asset tiers and control descriptions",
                "Count": "Synthetic dataset values",
            },
            {
                "Record_type": "Severity",
                "Metric": "CVSS severity label mismatches before recomputation",
                "Count": quality["severity_mismatches_before"],
                "Finding IDs": ", ".join(
                    data.loc[
                        data["Severity_label_mismatch"], "Finding ID"
                    ].astype(str)
                ),
            },
            {
                "Record_type": "Severity",
                "Metric": "CVSS severity label mismatches after recomputation",
                "Count": quality["severity_mismatches_after"],
            },
        ]
    )
    return pd.concat([report, pd.DataFrame(metric_rows)], ignore_index=True)


def write_scoring_export(
    data: pd.DataFrame,
    quality: dict,
    catalog: KevCatalog | None,
    run_info: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    kev_review = data[
        data["KEV_status"].isin(
            ["flagged in dataset, not in KEV", "in KEV, not flagged in dataset"]
        )
    ]
    quality_report = build_data_quality_report(data, quality, catalog)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        data.to_excel(writer, sheet_name="Scores", index=False)
        kev_review.to_excel(writer, sheet_name="KEV_Review", index=False)
        quality_report.to_excel(writer, sheet_name="Data_Quality", index=False)
        run_info.to_excel(writer, sheet_name="Run_Info", index=False)
    return path
