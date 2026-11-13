import datetime
import json
import os
import sys
import numpy as np
import pandas as pd
import streamlit as st

try:
    st.set_page_config(page_title="Scenario Dataset Generator", layout="wide")
except st.errors.StreamlitAPIException:
    pass

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) == "pages":
    ROOT_DIR = os.path.dirname(ROOT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app_utils.config_manager import get_config_version, update_dataset_path

REF_DIR = os.path.join(ROOT_DIR, "reference_data")
DEFAULT_SOURCE = os.path.join(REF_DIR, "vulnerability_contextualization_scanner_sample_updated.xlsx")
TAX_A_PATH = os.path.join(ROOT_DIR, "engines", "taxonomy_option_a.json")

# Load exact exposure labels directly from taxonomy_option_a.json
def get_valid_exposure_labels():
    if os.path.exists(TAX_A_PATH):
        with open(TAX_A_PATH, "r", encoding="utf-8") as f:
            keys = list(json.load(f).get("exposure_classification_mapping", {}).keys())
        ext = next((k for k in keys if "internet" in k.lower() or "ext" in k.lower()), "Internet-facing")
        intr = next((k for k in keys if "internal" in k.lower()), "Internal")
        seg = next((k for k in keys if k not in (ext, intr)), "Restricted")
        return [ext, intr, seg]
    return ["Internet-facing", "Internal", "Restricted"]

EXP_LABELS = get_valid_exposure_labels()

SCENARIOS = {
    "High Exposure": ("External Attack Surface Heavy", (60, 25, 15), (3, 24), (10, 39), (10, 34), (5, 24), 0.60, "high_exposure"),
    "Crown Jewel": ("Segmented High-Value Assets Heavy", (10, 30, 60), (20, 59), (15, 44), (0, 14), (0, 9), 0.35, "crown_jewel"),
    "Custom": ("User-Defined Parameters", (34, 33, 33), (5, 30), (10, 40), (10, 40), (5, 30), 0.50, "custom"),
}

# 1. Top Controls
c1, c2, c3 = st.columns(3)
name = c1.selectbox("Scenario", list(SCENARIOS.keys()))
desc, probs, c_rng, h_rng, m_rng, l_rng, drop_prob, prefix = SCENARIOS[name]
n_rows = c2.number_input("Row Count", 1, 300, 300)
up_file = c3.file_uploader("Upload Source Excel (Optional)", type=["xlsx"])

if name == "Custom":
    p1, p2, p3, p4 = st.columns(4)
    probs = (
        p1.number_input(f"{EXP_LABELS} %", 0, 100, 34),
        p2.number_input(f"{EXP_LABELS} %", 0, 100, 33),
        p3.number_input(f"{EXP_LABELS} %", 0, 100, 33),
    )
    drop_prob = p4.slider("Control Drop Prob", 0.0, 1.0, 0.50)

    s1, s2, s3, s4 = st.columns(4)
    c_rng = s1.slider("Critical assets", 0, 100, (5, 30))
    h_rng = s2.slider("High-criticality assets", 0, 100, (10, 40))
    m_rng = s3.slider("Medium-criticality assets", 0, 100, (10, 40))
    l_rng = s4.slider("Low-criticality assets", 0, 100, (5, 30))

# 2. Scenario Preview Box
st.info(f"**{name}:** {desc}")
preview_df = pd.DataFrame([{
    f"{EXP_LABELS} / {EXP_LABELS} / {EXP_LABELS}": f"{probs}% / {probs}% / {probs}%",
    "Critical Assets": f"{c_rng} ~ {c_rng}",
    "High Assets": f"{h_rng} ~ {h_rng}",
    "Medium Assets": f"{m_rng} ~ {m_rng}",
    "Low Assets": f"{l_rng} ~ {l_rng}",
    "Control Drop Rate": f"{drop_prob:.0%}",
}])
st.dataframe(preview_df, hide_index=True, use_container_width=True)

# 3. Generate, Save, and Auto-Activate Version
if st.button("Generate Dataset", type="primary"):
    src = up_file if up_file else DEFAULT_SOURCE
    if not up_file and not os.path.exists(DEFAULT_SOURCE):
        st.error("Source file not found in reference_data.")
        st.stop()

    excel_sheets = pd.read_excel(src, sheet_name=None)
    target_sheet = next((s for s, d in excel_sheets.items() if "Finding ID" in d.columns), list(excel_sheets.keys()))
    raw_df = excel_sheets[target_sheet]

    df = raw_df.sample(n=n_rows, replace=True).reset_index(drop=True)
    df["Finding ID"] = [f"VULN-{i:04d}" for i in range(1, n_rows + 1)]

    asset_cols = [("Critical assets", c_rng), ("High-criticality assets", h_rng), ("Medium-criticality assets", m_rng), ("Low-criticality assets", l_rng)]
    for col, (lo, hi) in asset_cols:
        df[col] = np.random.randint(lo, hi + 1, size=n_rows)
    df["Total affected assets"] = df[[c for c, _ in asset_cols]].sum(axis=1)

    weights = np.array(probs, dtype=float)
    weights = weights / weights.sum() if weights.sum() > 0 else [1 / 3, 1 / 3, 1 / 3]
    df["Exposure classification"] = np.random.choice(EXP_LABELS, size=n_rows, p=weights)
    df["Internet-facing assets"] = np.where(
        df["Exposure classification"] == EXP_LABELS,
        np.random.randint(1, df["Total affected assets"].clip(lower=2)),
        0,
    )

    valid_controls = raw_df["Compensating controls"].dropna().unique()
    sampled_controls = np.random.choice(valid_controls, size=n_rows) if len(valid_controls) > 0 else np.nan
    df["Compensating controls"] = np.where(np.random.rand(n_rows) < drop_prob, np.nan, sampled_controls)

    excel_sheets[target_sheet] = df
    os.makedirs(REF_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = os.path.join(REF_DIR, f"generated_{prefix}_{ts}.xlsx")
    with pd.ExcelWriter(save_path, engine="openpyxl") as writer:
        for s_name, s_df in excel_sheets.items():
            s_df.to_excel(writer, sheet_name=s_name, index=False)

    # Auto-activate new dataset and bump config version (v1.0.0 -> v1.0.1)
    ok, err = update_dataset_path(save_path, validate=True, note=f"Generated {name} scenario")
    if ok:
        st.success(f"Saved & Activated (`{get_config_version()}`): `{os.path.basename(save_path)}`")
    else:
        st.warning(f"Saved file, but failed to activate: {err}")

    st.dataframe(df.head(20), use_container_width=True)
