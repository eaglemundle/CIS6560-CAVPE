# Changelog

## Phase 1 - Baseline and safety net

- Corrected the handoff paths to match this repository: the current scoring
  function is in `pages/02_Scoring_Viewer.py`; the assumed `scripts/`,
  `engines/scoring.py`, `kev_validation.py`, `dimension_scores.py`, and
  `engines/scoring_config.json` do not exist yet.
- Verified the input workbook has 300 findings and 22 columns, 207 unique CVEs,
  93 repeated-CVE rows, and 120 nonblank compensating-control descriptions.
- Captured the actual current Option A output in
  `tests/golden/option_a_v1_0.csv`. Its baseline is 36.70-63.00, 55 distinct
  scores, and 12 findings tied at the maximum. These values match the v1.0
  figures in the handoff, not its stated v1.2 baseline of 40.17-82.50.
- Added golden regression, dataset baseline, and hand-computed scoring tests.
- No scoring weights, exposure mappings, input data, or other scoring behavior
  changed. KEV, severity, patch, controls, and other dimension-specific tests
  are deferred until those scoring helpers are implemented in later phases.

## Phase 2 - CISA KEV validation

- Added the CISA KEV JSON snapshot at
  `reference_data/known_exploited_vulnerabilities.json` (catalog `2026.10.30`,
  released 2026-10-30, 1,766 entries).
- Added `engines/kev_validation.py` to load catalog metadata, normalize CVE
  identifiers, assign the four dataset/catalog statuses, summarize by CVE, and
  report missing or older-than-14-day catalogs. Missing catalogs keep flagged
  findings provisional and are explicitly surfaced as a warning.
- Updated the scoring viewer to use normalized exploited scores, show the
  snapshot release, and export `Scores`, `KEV_Review`, and CVE-deduplicated
  `Data_Quality` worksheets.
- On the 300-row workbook, 211 findings are in the snapshot and score 2;
  89 are not in the snapshot and are not dataset-flagged. Zero rows are
  unverified. Relative to the captured baseline, the 211 catalog-confirmed rows
  gain 15 points under the existing 15% exploitation weight; Option A's actual
  observed range changes from 36.70-63.00 to 37.50-78.00 (76 distinct scores,
  11 findings tied at the maximum).
- No weights, exposure mappings, or input workbook values changed.
