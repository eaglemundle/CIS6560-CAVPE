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

## Phase 5 - Option A asset criticality alternatives

- Added the configurable `asset_criticality` block with `exposure_only` as the
  default, highest-nonzero-tier scoring, and `max`/`mean` blend options.
  `Asset_Tier_Score` is included in the score export; the default Option A
  score still uses only the charter exposure mapping.
- Added the pairwise comparison report at
  `outputs/asset_criticality_modes.csv`, including Kendall's tau and top-30
  overlap. It labels the asset-tier and control descriptions as synthetic.
- On the current 300 findings: exposure-only vs tier-only tau 0.83398 and
  top-30 overlap 21/30; exposure-only vs blend tau 0.84874 and overlap 21/30;
  tier-only vs blend tau 0.98524 and overlap 30/30. No exposure mappings or
  charter weights changed.
- Added SciPy to requirements for the requested Kendall tau calculation.

## Phase 6 - Score scale, risk bands, and ranking

- Added configurable native and rescaled score ranges and both band sets. The
  default is the charter's 1-24 scale and 1-6/7-12/13-18/19-24 bands; the
  0-100 alternative remains available. Rescaled display values are rounded to
  the nearest integer, while native unrounded scores drive ranks.
- Added `Score_Rescaled_Option_A/B/C`, `Risk_Level_Option_A/B/C`, and unique
  ranks using score descending, exploited score descending, CVSS descending,
  then Finding ID ascending. Exported `outputs/band_distribution.csv` for all
  three options under both scale modes.
- Current rescaled band counts (Low/Medium/High/Critical): Option A 0/6/193/101,
  Option B 0/8/202/90, Option C 0/5/186/109. Native-scale counts: A
  0/7/174/119, B 0/9/180/111, C 0/6/171/123. Each mode totals 300 findings.

## Phase 7 - Reproducible scoring pipeline and exports

- Added a shared pure-data scoring pipeline and vectorized risk-score
  calculation used by both dashboards and asset-criticality comparisons.
  Retained the row-wise scoring wrapper for existing callers and regression
  tests.
- Cached input workbook reads with file modification time and size in the cache
  key, and cached scoring results from their input/configuration arguments.
- Added run provenance for input/configuration hashes, config/taxonomy/KEV
  versions, weights, Python and key package versions, and Git commit.
- Scoring workbooks are written only after an explicit export action. The
  shared writer produces `Scores`, `KEV_Review`, `Data_Quality`, and `Run_Info`
  sheets under `outputs/`; both dashboards now use it.
- Replaced the SOC dashboard's broken subprocess control, which referenced a
  nonexistent `SCORING_SCRIPT_PATH`, with the shared explicit export action.
- Added tests for vectorized/wrapper equivalence within `1e-9`, cache
  invalidation after workbook changes, and all four export worksheets.
  Validation: full pytest suite, Python compilation, and Streamlit AppTest
  rendering for both dashboards passed. AppTest confirmed no scoring workbook
  is created automatically on page render. The input workbook is unchanged.

## Phase 8 - Scoring sensitivity analysis

- Added the standalone, non-Streamlit command `python scripts/sensitivity.py`.
  It runs the configured Option A baseline, ±10% one-at-a-time weight sweeps
  (other weights are proportionally rescaled to preserve the total), all three
  taxonomy options, asset/patch/control/risk-transfer/PoC rule alternatives,
  and a CVSS-only 0-100 benchmark.
- Compares each scenario with the current Option A baseline at both finding
  level and CVE level. CVE scores use the highest finding score per CVE.
  Reports Kendall's tau, top-30 overlap, absolute score/rank deltas, and
  per-finding/per-CVE rank movers.
- One command regenerates `outputs/sensitivity_summary.csv`,
  `outputs/sensitivity_rank_movers.csv`, and the interactive
  `outputs/sensitivity_kendall_tau.html` chart. The current run contains 26
  scenarios, 52 summary rows, and 6,731 finding/CVE rank-mover rows.
- Added tests for the one-command CLI, both reporting levels, weight-total
  preservation, and unchanged input/config files. No charter weights,
  taxonomy mappings, or input workbook values were modified.
