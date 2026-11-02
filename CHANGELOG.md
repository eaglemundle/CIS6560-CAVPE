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
