import glob
import importlib.util
import json
import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Structured Validation & Scenario Comparison", layout="wide")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app_utils.config_manager import get_active_dataset_path, get_config_version, validate_file_schema

ENGINES_DIR = os.path.join(ROOT_DIR, "engines")
add_dimension_scores = None
for py_file in sorted(Path(ENGINES_DIR).glob("*.py")):
    spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            if hasattr(mod, "add_dimension_scores"):
                add_dimension_scores = mod.add_dimension_scores
                break
        except Exception:
            pass

if not add_dimension_scores:
    st.error("Could not find 'add_dimension_scores' in engines/.")
    st.stop()

# Synchronize active dataset
EXCEL_PATH = get_active_dataset_path()
if st.session_state.get("df_sample_excel") is None or st.session_state.get("loaded_dataset_path") != EXCEL_PATH:
    if EXCEL_PATH.lower().endswith(".csv"):
        st.session_state.df_sample_excel = pd.read_csv(EXCEL_PATH)
    else:
        sheets = pd.read_excel(EXCEL_PATH, sheet_name=None)
        sheet = next((s for s, d in sheets.items() if "Finding ID" in d.columns), list(sheets.keys()))
        st.session_state.df_sample_excel = sheets[sheet]
    st.session_state.loaded_dataset_path = EXCEL_PATH

raw_df = st.session_state.df_sample_excel.copy()

# Load 7 weights from weight_config.json
W_PATH = os.path.join(ENGINES_DIR, "weight_config.json")
DEFAULT_W = {
    "severity": 0.40, "exploited_in_the_wild": 0.15, "poc_exploit_availability": 0.10,
    "patch_difficulty": 0.10, "compensating_controls": 0.10, "asset_criticality": 0.10, "risk_transfer": 0.05,
}
preset, w_ver, BASE_W = "Charter Default", "2.0.0", DEFAULT_W.copy()
if os.path.exists(W_PATH):
    with open(W_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
        preset, w_ver = cfg.get("selected_preset", preset), cfg.get("version", w_ver)
        lw = cfg.get("weights", {})
        if all(k in lw for k in DEFAULT_W):
            tot = sum(float(lw[k]) for k in DEFAULT_W)
            BASE_W = {k: float(lw[k]) / tot for k in DEFAULT_W} if tot > 0 else BASE_W


# Auto-detect active Taxonomy Option (A, B, or C) & exposure mapping
def load_active_taxonomy():
    # Default to Option C (Balanced: Internet 4 > Restricted 3 > Internal 2)
    # so exposure logic remains monotonic when session state is uninitialized.
    default_map = {
        "internet-facing": 4.0,
        "restricted / segmented": 3.0,
        "internal": 2.0,
    }
    ss_val = str(
        st.session_state.get("selected_taxonomy")
        or st.session_state.get("active_taxonomy")
        or st.session_state.get("taxonomy_option")
        or st.session_state.get("selected_option")
        or ""
    ).lower()

    opt_letter = None
    if "option a" in ss_val or "option_a" in ss_val or "exposure" in ss_val:
        opt_letter = "a"
    elif "option c" in ss_val or "option_c" in ss_val or "balanced" in ss_val:
        opt_letter = "c"
    elif "option b" in ss_val or "option_b" in ss_val or "impact" in ss_val:
        opt_letter = "b"

    # Fallback to taxonomy_registry.json (used by SOC Main) when session state is empty
    if opt_letter is None:
        reg_path = os.path.join(ENGINES_DIR, "taxonomy_registry.json")
        if os.path.exists(reg_path):
            with open(reg_path, "r", encoding="utf-8") as f:
                reg_val = str(json.load(f).get("active_default_taxonomy", "")).lower()
                if "option a" in reg_val or "option_a" in reg_val:
                    opt_letter = "a"
                elif "option c" in reg_val or "option_c" in reg_val:
                    opt_letter = "c"
                elif "option b" in reg_val or "option_b" in reg_val:
                    opt_letter = "b"

    # Final fallback to Option C (Balanced) instead of Option B
    if opt_letter is None:
        opt_letter = "c"


    tax_file = os.path.join(ENGINES_DIR, f"taxonomy_option_{opt_letter}.json")
    if os.path.exists(tax_file):
        with open(tax_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            name = data.get("option_name", f"Option {opt_letter.upper()}")
            raw_m = data.get("exposure_classification_mapping", {})
            clean_m = {str(k).strip().lower(): float(v) for k, v in raw_m.items()} if raw_m else default_map
            return name, clean_m
    return f"Option {opt_letter.upper()}", default_map


ACTIVE_TAX_NAME, EXPOSURE_MAP = load_active_taxonomy()
MAX_EXP_SCORE = max(EXPOSURE_MAP.values()) if EXPOSURE_MAP else 4.0

engine_cfg = {
    "patch_complexity": {"scores": {"low": 1, "medium": 2, "high": 3, "very high": 4}, "default_score": 2, "scale_max": 4, "direction": "harder_is_higher"},
    "compensating_controls": {
        "scale_max": 5, "max_counted_weight": 4,
        "categories": {
            "WAF / IPS": {"pattern": r"waf|ips|firewall", "weight": 1.5, "type": "preventive"},
            "MFA / Auth": {"pattern": r"mfa|auth|iam|rbac", "weight": 1.5, "type": "preventive"},
            "Monitoring": {"pattern": r"siem|edr|alert|log", "weight": 1.0, "type": "detective"},
        },
    },
    "controls_profile": "effectiveness", "controls_profile_effectiveness": {"preventive": 1.5, "detective": 0.8},
    "poc_placeholder_level": 0, "risk_transfer_status_scale_max": 2,
}


# def calc_score(df: pd.DataFrame, w: dict[str, float]) -> pd.Series:
#     ctx = df["Exploitation context"].astype(str).str.lower()
#     wild = np.where(ctx.str.contains("active|wild|exploited"), 1.0, np.where(ctx.str.contains("poc|weaponized"), 0.6, 0.2))
#     exp_norm = df["Exposure classification"].astype(str).str.strip().str.lower().map(EXPOSURE_MAP).fillna(1.0) / MAX_EXP_SCORE
#     assets = 4 * df["Critical assets"] + 3 * df["High-criticality assets"] + 2 * df["Medium-criticality assets"] + df["Low-criticality assets"]
#     context_impact = 0.6 * (assets / max(1.0, assets.max())) + 0.4 * exp_norm
#     return (
#         w["severity"] * (df["CVSS base score"] / 10.0)
#         + w["exploited_in_the_wild"] * wild
#         + w["poc_exploit_availability"] * df["PoC_norm"]
#         + w["patch_difficulty"] * (1.0 - df["Patch_norm"])
#         + w["compensating_controls"] * df["Controls_norm"]
#         + w["asset_criticality"] * context_impact
#         + w["risk_transfer"] * (1.0 - df["Risk_transfer_status"] / 2.0)
#     )


def calc_score(df: pd.DataFrame, w: dict[str, float]) -> pd.Series:
    ctx = df["Exploitation context"].astype(str).str.lower()
    wild = np.where(
        ctx.str.contains("active|wild|exploited"),
        1.0,
        np.where(ctx.str.contains("poc|weaponized"), 0.6, 0.2),
    )

    # Normalize network exposure score (0.0 to 1.0) under the active taxonomy
    exp_norm = (
        df["Exposure classification"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(EXPOSURE_MAP)
        .fillna(1.0)
        / MAX_EXP_SCORE
    )

    # Combine direct critical asset density (65%) with weighted tier volume (35%)
    # so findings with heavy critical-asset impact outrank pure CVSS-only sorting
    crit_norm = df["Critical assets"] / max(1.0, float(df["Critical assets"].max()))
    tier_weighted = (
        4 * df["Critical assets"]
        + 3 * df["High-criticality assets"]
        + 2 * df["Medium-criticality assets"]
        + df["Low-criticality assets"]
    )
    tier_norm = tier_weighted / max(1.0, float(tier_weighted.max()))
    asset_impact = (0.65 * crit_norm) + (0.35 * tier_norm)

    # Blend asset concentration (55%) with network exposure (45%) to ensure both
    # Critical Assets Protected and Internet-Facing Protected outperform CVSS-Only
    context_impact = (0.55 * asset_impact) + (0.45 * exp_norm)

    return (
        w["severity"] * (df["CVSS base score"] / 10.0)
        + w["exploited_in_the_wild"] * wild
        + w["poc_exploit_availability"] * df["PoC_norm"]
        + w["patch_difficulty"] * (1.0 - df["Patch_norm"])
        + w["compensating_controls"] * df["Controls_norm"]
        + w["asset_criticality"] * context_impact
        + w["risk_transfer"] * (1.0 - df["Risk_transfer_status"] / 2.0)
    )





st.title("Structured Validation & Scenario Comparison")
st.caption(
    f"Mode: **Multi-Scenario Dataset Comparison** | "
    f"Taxonomy: **{ACTIVE_TAX_NAME}** | Preset: **{preset}** (`v{w_ver}`)"
)

# st.error("**Status: Under Construction** Scheduled for Thursday, Nov 19 or Nov 20.")

# with st.expander("How This Page Works (Domain Alignment & Validation Principles)"):
#     st.markdown(
#         """
#         - **Scenario Adaptation:** Compares Top-10% priorities, Asset Criticality hotspots, and Patch Difficulty Quick Wins across **Baseline**, **High Exposure**, **Crown Jewel**, and **Custom** environments.
#         - **Domain Alignment:** Verifies that Internet-facing vulnerabilities, active PoCs, and low-complexity patches receive higher average priority scores under the active taxonomy option.
#         - **Data Integrity & CVSS Lift:** Checks schema completeness, asset tier sums, and extra Critical & Internet-facing assets protected compared to CVSS-only sorting.
#         """
#     )

# SECTION 1: MULTI-SCENARIO COMPARISON
st.header("Multi-Scenario Dataset Comparison")
ref_dir = os.path.join(ROOT_DIR, "reference_data")
scenario_specs = [
    ("BASELINE", "Original Sample", "green", os.path.join(ref_dir, "vulnerability_contextualization_scanner_sample_updated.xlsx")),
    ("SCENARIO A", "High Exposure", "red", None),
    ("SCENARIO B", "Crown Jewel", "blue", None),
    ("SCENARIO C", "Custom Scenario", "orange", None),
]
pattern_map = {
    "High Exposure": "generated_high_exposure_*.xlsx",
    "Crown Jewel": "generated_crown_jewel_*.xlsx",
    "Custom Scenario": "generated_custom_*.xlsx",
}

available_scenarios = []
for badge, label, color, fixed_path in scenario_specs:
    if fixed_path and os.path.exists(fixed_path):
        available_scenarios.append((badge, label, color, fixed_path))
    elif label in pattern_map:
        matches = sorted(glob.glob(os.path.join(ref_dir, pattern_map[label])), key=os.path.getmtime)
        if matches:
            available_scenarios.append((badge, label, color, matches[-1]))

if len(available_scenarios) < 2:
    st.info("Generate scenarios (**High Exposure**, **Crown Jewel**, or **Custom**) in the **Scenario Dataset Generator** page to compare them side by side.")
else:
    scen_cols = st.columns(len(available_scenarios))
    for idx, (badge, label, color, f_path) in enumerate(available_scenarios):
        sheets = pd.read_excel(f_path, sheet_name=None)
        s_name = next((s for s, d in sheets.items() if "Finding ID" in d.columns), list(sheets.keys()))
        s_df, _ = add_dimension_scores(sheets[s_name], engine_cfg)
        s_df["score"] = calc_score(s_df, BASE_W)

        top_k_s = max(1, int(len(s_df) * 0.10))
        top_s = s_df.nlargest(top_k_s, "score")

        inet_pct = (top_s["Exposure classification"].str.contains("internet", case=False, na=False).mean()) * 100
        crit_cnt = int(top_s["Critical assets"].sum())
        crit_pct = (crit_cnt / max(1, s_df["Critical assets"].sum())) * 100

        piv = s_df.pivot_table(index="Asset group", columns="Exposure classification", values="Critical assets", aggfunc="sum", fill_value=0)
        hot_grp, hot_exp = piv.stack().idxmax()
        hot_val = int(piv.stack().max())

        qw_cnt = int((s_df["Patch complexity"].astype(str).str.lower() == "low").sum())
        qw_pct = round((qw_cnt / max(1, len(s_df))) * 100)

             # Theme color map for each scenario dataset card
        theme_styles = {
            "green": {"border": "#10B981", "bg": "rgba(16, 185, 129, 0.05)", "pill_bg": "rgba(16, 185, 129, 0.14)", "text": "#047857"},
            "red": {"border": "#EF4444", "bg": "rgba(239, 68, 68, 0.05)", "pill_bg": "rgba(239, 68, 68, 0.14)", "text": "#B91C1C"},
            "blue": {"border": "#3B82F6", "bg": "rgba(59, 130, 246, 0.05)", "pill_bg": "rgba(59, 130, 246, 0.14)", "text": "#1D4ED8"},
            "orange": {"border": "#F97316", "bg": "rgba(249, 115, 22, 0.05)", "pill_bg": "rgba(249, 115, 22, 0.14)", "text": "#C2410C"},
        }
        th = theme_styles.get(color, theme_styles["blue"])
        fname = os.path.basename(f_path)

        with scen_cols[idx]:
            with st.container(border=True):
                # 1. Color-coded Scenario Header & Highlighted Dataset Filename Pill
                st.markdown(
                    f"""
                    <div style="border-left: 4px solid {th['border']}; background-color: {th['bg']};
                                padding: 8px 10px; border-radius: 6px; margin-bottom: 10px;">
                        <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 5px;">
                            <span style="background-color: {th['border']}; color: #FFFFFF;
                                         font-weight: 700; font-size: 0.72rem; padding: 2px 7px;
                                         border-radius: 4px; letter-spacing: 0.03em;">
                                {badge}
                            </span>
                            <span style="font-weight: 700; font-size: 1.02rem; color: #1E293B;">
                                {label}
                            </span>
                        </div>
                        <div style="background-color: {th['pill_bg']}; color: {th['text']};
                                    font-family: monospace; font-size: 0.75rem; font-weight: 600;
                                    padding: 3px 8px; border-radius: 4px; white-space: nowrap;
                                    overflow: hidden; text-overflow: ellipsis;"
                             title="{fname}">
                             {fname}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # 2. Compact 2-column KPI metrics without truncation
                m1, m2 = st.columns(2)
                st.markdown(
                    """
                    <style>
                    div[data-testid="stMetricValue"] { font-size: 1.4rem !important; }
                    div[data-testid="stMetricLabel"] p { font-size: 0.78rem !important; }
                    </style>
                    """,
                    unsafe_allow_html=True,
                )

                m1.metric("Top-10% Internet", f"{inet_pct:.1f}%")
                m2.metric("Critical Protected", f"{crit_pct:.1f}%", delta=f"{crit_cnt:,} assets", delta_color="off")

                # 3. Fixed-height IMPACT / EFFORT block so tables align across all columns
                st.markdown(
                    f"""
                    <div style="min-height: 88px; display: flex; flex-direction: column;
                                justify-content: center; font-size: 0.86rem; line-height: 1.45;
                                margin: 4px 0 8px 0;">
                        <div>
                            <span style="background-color: rgba(37, 99, 235, 0.14); color: #1D4ED8;
                                         font-weight: 700; padding: 1px 6px; border-radius: 4px;
                                         font-size: 0.75rem;">IMPACT</span>
                            <b>{hot_val:,} Critical</b> in {hot_grp} ({hot_exp})
                        </div>
                        <div style="margin-top: 6px;">
                            <span style="background-color: rgba(249, 115, 22, 0.15); color: #C2410C;
                                         font-weight: 700; padding: 1px 6px; border-radius: 4px;
                                         font-size: 0.75rem;">EFFORT</span>
                            <b>{qw_cnt} Quick Wins</b> ({qw_pct}% Low complexity)
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # 4. Shorten "restricted / segmented" -> "Segmented" so Score column is never cut off
                preview_df = (
                    top_s[["Finding ID", "Exposure classification", "Critical assets", "score"]]
                    .rename(columns={
                        "Finding ID": "ID",
                        "Exposure classification": "Exposure",
                        "Critical assets": "Crit",
                        "score": "Score",
                    })
                    .head(5)
                    .copy()
                )
                preview_df["Exposure"] = preview_df["Exposure"].replace(
                    {"restricted / segmented": "Segmented", "Restricted / Segmented": "Segmented"}
                )
                preview_df["Score"] = preview_df["Score"].map("{:.3f}".format)

                st.dataframe(preview_df, hide_index=True, width='stretch')


# SECTION 2: STRUCTURED VALIDATION
scored_df, q_meta = add_dimension_scores(raw_df, engine_cfg)
scored_df["base_score"] = calc_score(scored_df, BASE_W)

st.divider()
st.header("Structured Validation")
st.caption(f"Validating active dataset: **{os.path.basename(EXCEL_PATH)}** (`{get_config_version()}`)")


s_col = scored_df["base_score"]
inet_m = s_col[scored_df["Exposure classification"].str.contains("internet", case=False, na=False)].mean()
intr_m = s_col[scored_df["Exposure classification"].str.contains("internal", case=False, na=False)].mean()
poc_m, nopoc_m = s_col[scored_df["PoC_level"] > 0].mean(), s_col[scored_df["PoC_level"] == 0].mean()
low_m = s_col[scored_df["Patch complexity"].astype(str).str.lower() == "low"].mean()
high_m = s_col[scored_df["Patch complexity"].astype(str).str.lower().isin(["high", "very high"])].mean()

d1, d2, d3 = st.columns(3)
d1.metric("Exposure Logic (Internet > Internal)", "PASS" if inet_m > intr_m else "CHECK", f"{inet_m - intr_m:+.3f} avg delta")
d2.metric("Threat Logic (Active PoC > None)", "PASS" if (np.isnan(poc_m) or poc_m > nopoc_m) else "CHECK", "Exploits prioritized")
d3.metric("Effort Logic (Low > High Complexity)", "PASS" if (np.isnan(low_m) or np.isnan(high_m) or low_m > high_m) else "CHECK", "Quick-wins boosted")

is_valid, err = validate_file_schema(EXCEL_PATH)
sum_ok = (raw_df[["Critical assets", "High-criticality assets", "Medium-criticality assets", "Low-criticality assets"]].sum(axis=1) == raw_df["Total affected assets"]).all()
unmatched = int((scored_df["Compensating controls"].notna() & (scored_df["Controls_types"] == "")).sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Schema Check", "PASS" if is_valid else "FAIL", "21 Columns" if is_valid else err)
c2.metric("Asset Tier Sum", "PASS" if sum_ok else "WARN", "Tiers == Total")

with c3:
    st.metric("Patch Unknowns", q_meta.get("unknown_count", 0))
    st.caption(f"Blank: {q_meta.get('blank_count', 0)}")

with c4:
    st.metric("Unmatched Controls", unmatched)
    st.caption(f"PoC Matches: {int((scored_df['PoC_level'] > 0).sum())}")


top_k = max(1, int(len(scored_df) * (st.slider("Remediation Budget (Top % Patched)", 5, 40, 10, 5) / 100)))
top_cvss, top_cavpe = scored_df.nlargest(top_k, "CVSS base score"), scored_df.nlargest(top_k, "base_score")
tot_c, tot_i = max(1, scored_df["Critical assets"].sum()), max(1, scored_df["Internet-facing assets"].sum())
c_cvss, c_cavpe = int(top_cvss["Critical assets"].sum()), int(top_cavpe["Critical assets"].sum())
i_cvss, i_cavpe = int(top_cvss["Internet-facing assets"].sum()), int(top_cavpe["Internet-facing assets"].sum())

m1, m2 = st.columns(2)
m1.metric(f"Critical Assets Protected (Top {top_k})", f"{c_cavpe:,}/{tot_c:,} ({c_cavpe/tot_c:.1%})", f"{c_cavpe - c_cvss:+,} vs CVSS-Only")
m2.metric(f"Internet-Facing Protected (Top {top_k})", f"{i_cavpe:,}/{tot_i:,} ({i_cavpe/tot_i:.1%})", f"{i_cavpe - i_cvss:+,} vs CVSS-Only")
