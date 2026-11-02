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

## Phase 3 - Input validation hardening

- Added `engines/scoring_config.json` with documented exposure defaults and
  CVSS severity thresholds. Blank exposure uses the configured `internal`
  label; unknown nonblank labels use the configured score of 1, with both cases
  counted and listed in `Data_Quality` and shown as dashboard warnings.
- Added case- and whitespace-tolerant exposure mapping with explicit errors
  when the configured blank-value label is not present in a taxonomy.
- Added score-derived CVSS severity to the scoring export, retained the source
  mismatch flag, and switched the CVE-level report and SOC dashboard to display
  recomputed severity labels. The workbook has 28 mismatches before
  recomputation and zero after.
- Fixed the SOC dashboard's taxonomy paths to use `engines/taxonomy_option_*.json`;
  it previously looked for taxonomy files under `pages/` and silently fell back
  to criticality 1 for every row.
- Current dataset before/after counts: 0 blank exposure labels, 0 unmapped
  labels, and 28 source severity-label mismatches (0 after recomputation).
  Existing configured fallbacks preserve prior behavior when bad input is
  encountered; no charter weights or mapping values changed.

## Phase 4 - Dimension accuracy

- Added shared scoring and dimension modules under `engines/` (the assumed
  `scripts/` directory does not exist). Patch complexity now uses the configured
  1/2/3/3 map and `harder_is_higher` default, with a configurable flipped
  direction and a reported default for unknown labels.
- Added configurable controls categories, equal-weight default profile, and
  the switchable effectiveness profile. `Controls_types` and `Controls_score`
  are exported. All 120 nonblank control descriptions in the current workbook
  match at least one configured category; zero are unmatched.
- Added optional manual PoC and risk-register CSV readers. With neither file
  present, the configured PoC placeholder remains 0.5 normalized (0 of 207 CVEs
  have lookup coverage) and risk transfer has no effect (0 covered findings).
  Risk transfer defaults to the configured reducer, supports additive as an
  alternative, and honors the configured minimum score.
- Both the SOC dashboard and scoring viewer now call the shared scorer. No
  charter weights or taxonomy exposure mappings changed.
- Repository divergence: the actual v1.0 scorer had constant patch and control
  placeholders, not the existing dimension helpers described by the handoff.
  Therefore the requested patch/control implementation necessarily changes
  scores rather than reproducing the golden file except for KEV changes. With
  the current KEV snapshot, Option A changes from 37.50-78.00 (76 distinct
  scores, 11 tied at maximum) before these dimensions to 40.17-90.00 (146
  distinct scores, 2 tied at maximum). This is an intended dimension update,
  not a weight or taxonomy change.
