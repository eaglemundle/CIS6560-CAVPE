import importlib.util
import os
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SCORING_VIEWER = ROOT / "pages" / "02_Scoring_Viewer.py"


def load_scoring_viewer():
    spec = importlib.util.spec_from_file_location("scoring_viewer_cache", SCORING_VIEWER)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load scoring viewer from {SCORING_VIEWER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_input_cache_invalidates_when_workbook_changes(tmp_path):
    module = load_scoring_viewer()
    workbook = tmp_path / "input.xlsx"
    pd.DataFrame({"value": [111]}).to_excel(workbook, index=False)
    original_stat = workbook.stat()
    original = module.load_input_data(
        str(workbook), original_stat.st_mtime_ns, original_stat.st_size
    )

    pd.DataFrame({"value": [222]}).to_excel(workbook, index=False)
    os.utime(
        workbook,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
    )
    updated_stat = workbook.stat()
    updated = module.load_input_data(
        str(workbook), updated_stat.st_mtime_ns, updated_stat.st_size
    )

    assert original.loc[0, "value"] == 111
    assert updated.loc[0, "value"] == 222
