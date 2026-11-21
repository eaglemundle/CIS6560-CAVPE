import importlib.util
import json
import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from scipy.stats import spearmanr
import streamlit as st

st.set_page_config(page_title="Sensitivity Analysis", layout="wide")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app_utils.config_manager import get_active_dataset_path, get_config_version

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

LABELS = {
    "severity": "Severity (CVSS)", "exploited_in_the_wild": "Wild Exploit",
    "poc_exploit_availability": "PoC Availability", "patch_difficulty": "Patch Difficulty",
    "compensating_controls": "Controls", "asset_criticality": "Asset Criticality", "risk_transfer": "Risk Transfer",
}


# Auto-detect active Taxonomy Option (A, B, or C) & exposure mapping
def load_active_taxonomy():
    default_map = {"internet-facing": 4.0, "internal": 2.0, "restricted / segmented": 1.0}
    ss_val = str(
        st.session_state.get("selected_taxonomy")
        or st.session_state.get("active_taxonomy")
        or st.session_state.get("taxonomy_option")
        or st.session_state.get("selected_option")
        or ""
    ).lower()

    opt_letter = "b"
    if "option a" in ss_val or "option_a" in ss_val or "exposure" in ss_val:
        opt_letter = "a"
    elif "option c" in ss_val or "option_c" in ss_val or "balanced" in ss_val:
        opt_letter = "c"
    elif "option b" in ss_val or "option_b" in ss_val or "impact" in ss_val:
        opt_letter = "b"
    else:
        for cfg_name in ["taxonomy_config.json", "active_taxonomy.json", "weight_config.json"]:
            cfg_p = os.path.join(ENGINES_DIR, cfg_name)
            if os.path.exists(cfg_p):
                with open(cfg_p, "r", encoding="utf-8") as f:
                    txt = f.read().lower()
                    if "option_a" in txt or "option a" in txt:
                        opt_letter = "a"
                        break
                    elif "option_c" in txt or "option c" in txt:
                        opt_letter = "c"
                        break

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


def calc_score(df: pd.DataFrame, w: dict[str, float]) -> pd.Series:
    ctx = df["Exploitation context"].astype(str).str.lower()
    wild = np.where(ctx.str.contains("active|wild|exploited"), 1.0, np.where(ctx.str.contains("poc|weaponized"), 0.6, 0.2))
    exp_norm = df["Exposure classification"].astype(str).str.strip().str.lower().map(EXPOSURE_MAP).fillna(1.0) / MAX_EXP_SCORE
    assets = 4 * df["Critical assets"] + 3 * df["High-criticality assets"] + 2 * df["Medium-criticality assets"] + df["Low-criticality assets"]
    context_impact = 0.6 * (assets / max(1.0, assets.max())) + 0.4 * exp_norm
    return (
        w["severity"] * (df["CVSS base score"] / 10.0)
        + w["exploited_in_the_wild"] * wild
        + w["poc_exploit_availability"] * df["PoC_norm"]
        + w["patch_difficulty"] * (1.0 - df["Patch_norm"])
        + w["compensating_controls"] * df["Controls_norm"]
        + w["asset_criticality"] * context_impact
        + w["risk_transfer"] * (1.0 - df["Risk_transfer_status"] / 2.0)
    )

import plotly.express as px

st.markdown(
    "# Sensitivity Analysis<br>"
    "<span style='font-size: 0.6em; font-weight: 500; color: #64748B;'>"
    "(Weight Config History & Score Delta)"
    "</span>",
    unsafe_allow_html=True,
)

st.caption(
    f"Dataset: **{os.path.basename(EXCEL_PATH)}** (`{get_config_version()}`) | "
    f"Taxonomy: **{ACTIVE_TAX_NAME}** | Current Preset: **{preset}** (`v{w_ver}`)"
)

with st.expander("How This Page Works (Weight History & Stability Principles)"):
    st.markdown(
        """
        - **Configuration History Tracking:** Reads all logged weight revisions stored in `engines/weight_config.json` to compare how policy updates affect prioritization.
        - **Rank Stability & Top-10% Retention:** Evaluates how consistent the priority ranking remains across historical weight revisions compared to the baseline version.
        - **Version-to-Version Score Delta:** Compares any two logged weight versions side by side to inspect exact score shifts (`Target Score - Reference Score`).
        """
    )

scored_df, _ = add_dimension_scores(raw_df, engine_cfg)

# --- 1. Extract All Logged Weight Versions from weight_config.json ---
def load_weight_history_logs(w_json_path: str, current_w: dict, cur_ver: str, cur_preset: str) -> list[dict]:
    logs = []
    if os.path.exists(w_json_path):
        with open(w_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw_hist = data.get("version_history") or data.get("history") or []
        for idx, entry in enumerate(raw_hist):
            if isinstance(entry, dict) and isinstance(entry.get("weights"), dict):
                ew = entry["weights"]
                if all(k in ew for k in DEFAULT_W):
                    tot = sum(float(ew[k]) for k in DEFAULT_W)
                    norm_w = {k: float(ew[k]) / tot for k in DEFAULT_W} if tot > 0 else current_w
                    ver_tag = entry.get("version") or entry.get("Version") or f"v1.{idx}"
                    p_name = entry.get("selected_preset") or entry.get("preset") or entry.get("Note") or "Logged Config"
                    ts = entry.get("last_updated") or entry.get("Timestamp") or ""
                    logs.append({
                        "label": f"{ver_tag} — {p_name}" + (f" ({ts})" if ts else ""),
                        "version": str(ver_tag),
                        "weights": norm_w,
                    })

    # Ensure the current active config is always included
    cur_label = f"v{str(cur_ver).lstrip('v')} — {cur_preset} (Current)"
    if not any(item["version"].lstrip("v") == str(cur_ver).lstrip("v") for item in logs):
        logs.append({"label": cur_label, "version": f"v{str(cur_ver).lstrip('v')}", "weights": current_w})

    # Sort chronologically if multiple logs exist
    return logs


history_entries = load_weight_history_logs(W_PATH, BASE_W, w_ver, preset)

# Compute scores across all logged versions
for item in history_entries:
    item["scores"] = calc_score(scored_df, item["weights"])

# --- 2. Visual Comparison Across All Logged Versions ---
c_left, c_right = st.columns((52, 48), vertical_alignment="top")

with c_left:
    with st.container(border=True):
        st.markdown("**Weight Allocation Across Logged Versions (%)**")

        # Keep baseline (first) + up to 5 most recent versions if history grows large
        if len(history_entries) > 6:
            display_entries = list(history_entries[:1]) + list(history_entries[-5:])
        else:
            display_entries = history_entries

        transposed_rows = list()
        for k in DEFAULT_W:
            row = {"Factor": LABELS[k]}
            for item in display_entries:
                row[item["version"]] = f"{item['weights'][k] * 100:.0f}%"
            transposed_rows.append(row)

        df_weights_table = pd.DataFrame(transposed_rows)

        # Highlight cells in orange where weight changed compared to the previous displayed version
        def highlight_weight_changes(df: pd.DataFrame) -> pd.DataFrame:
            styles = pd.DataFrame("", index=df.index, columns=df.columns)
            ver_cols = [c for c in df.columns if c != "Factor"]
            for i in range(1, len(ver_cols)):
                prev_col = ver_cols[i - 1]
                curr_col = ver_cols[i]
                changed = df[curr_col] != df[prev_col]
                styles.loc[changed, curr_col] = "color: #EA580C; font-weight: 700;"
            return styles


        styled_weights = df_weights_table.style.apply(highlight_weight_changes, axis=None)

        st.dataframe(
            styled_weights,
            hide_index=True,
            width='stretch',
            height=290,
            column_config={
                "Factor": st.column_config.TextColumn("Factor", pinned=True)
            },
        )



with c_right:
    with st.container(border=True):
        st.markdown("**Rank Stability & Top-10% Retention vs. Earliest Log**")
        ref_scores = history_entries[0]["scores"]
        top_n = max(1, int(len(scored_df) * 0.10))
        ref_top_ids = set(scored_df.assign(s=ref_scores).nlargest(top_n, "s")["Finding ID"])

        stab_rows = []
        for item in history_entries:
            rho, _ = spearmanr(ref_scores, item["scores"])
            cur_top_ids = set(scored_df.assign(s=item["scores"]).nlargest(top_n, "s")["Finding ID"])
            ret_pct = len(ref_top_ids & cur_top_ids) / top_n * 100
            stab_rows.append({
                "Version": item["version"],
                "Rank Stability (%)": round(rho * 100, 1),
                "Top-10% Retention (%)": round(ret_pct, 1),
            })

        stab_df = pd.DataFrame(stab_rows).melt(id_vars="Version", var_name="Metric", value_name="Score (%)")
        fig_stab = px.bar(
            stab_df, x="Version", y="Score (%)", color="Metric", barmode="group", text_auto=True,
            color_discrete_map={
                "Rank Stability (%)": "#CBD5E1",       
                "Top-10% Retention (%)": "#F97316",   
            },
            range_y=(0, 115),
        )

        fig_stab.update_layout(
            height=300,
            margin=dict(l=0, r=10, t=55, b=5),
            xaxis_title="",
            legend=dict(orientation="h", yanchor="bottom", y=1.04, xanchor="left", x=0, title=""),
        )
        st.plotly_chart(fig_stab, width='stretch')


# --- 3. Pairwise Version Comparison & Score Delta Distribution ---
st.divider()
st.subheader("Pairwise Version Score Delta Comparison")

labels_list = [item["label"] for item in history_entries]
sel_c1, sel_c2 = st.columns(2)
ref_idx = sel_c1.selectbox("Reference Version (Before)", range(len(labels_list)), index=0, format_func=lambda i: labels_list[i])
tgt_idx = sel_c2.selectbox("Target Version (After)", range(len(labels_list)), index=len(labels_list) - 1, format_func=lambda i: labels_list[i])

scored_df["before_score"] = history_entries[ref_idx]["scores"]
scored_df["after_score"] = history_entries[tgt_idx]["scores"]
scored_df["delta"] = scored_df["after_score"] - scored_df["before_score"]

rho_pair, _ = spearmanr(scored_df["before_score"], scored_df["after_score"])
top_before = set(scored_df.nlargest(top_n, "before_score")["Finding ID"])
top_after = set(scored_df.nlargest(top_n, "after_score")["Finding ID"])
ret_pair = len(top_before & top_after) / top_n * 100

met_col, dist_col = st.columns((42, 58), vertical_alignment="center")
with met_col:
    with st.container(border=True):
        m1, m2 = st.columns(2)
        m1.metric("Pairwise Rank Stability", f"{rho_pair:.4f}", delta="1.0 = Identical order", delta_color="off")
        with m2:
            st.markdown(
                f"""
                <div style="background-color: rgba(249, 115, 22, 0.10); border: 1.5px solid #F97316;
                            border-radius: 8px; padding: 8px 12px;">
                    <div style="font-size: 0.8rem; font-weight: 700; color: #EA580C;">
                        Top-10% Retention
                    </div>
                    <div style="font-size: 1.75rem; font-weight: 700; color: #1E293B; line-height: 1.2;">
                        {ret_pair:.1f}%
                    </div>
                    <div style="font-size: 0.78rem; color: #C2410C; font-weight: 600;">
                        {len(top_before & top_after)}/{top_n} critical items kept
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        st.divider()
        m3, m4 = st.columns(2)
        m3.metric("Max Single Score Delta", f"±{scored_df['delta'].abs().max():.3f}")
        m4.metric("Average |Score Delta", f"{scored_df['delta'].abs().mean():.3f}")


with dist_col:
    with st.container(border=True):
        st.markdown("**Score Delta Distribution (Target - Reference)**")
        fig_dist = px.histogram(
            scored_df, x="delta", nbins=25, color_discrete_sequence=["#3B82F6"],
            labels={"delta": "Score Delta"}
        )
        fig_dist.add_vline(x=0, line_dash="dash", line_color="#EF4444", annotation_text="0.000")
        fig_dist.update_layout(height=180, margin=dict(l=0, r=10, t=10, b=5), yaxis_title="Findings", bargap=0.08)
        st.plotly_chart(fig_dist, width='stretch')

# --- 4. Top-20 Vulnerability Score Delta Table ---
h1, h2 = st.columns((70, 30), vertical_alignment="center")
h1.markdown("**Vulnerability Priority Score Impact Table (Top 20)**")
sort_by = h2.selectbox(
    "Sort",
    ["Highest Target Score", "Largest Positive Delta (+)", "Largest Negative Delta (-)", "Largest Absolute Delta (|Δ|)"],
    label_visibility="collapsed",
)

sort_map = {
    "Highest Target Score": ("after_score", False),
    "Largest Positive Delta (+)": ("delta", False),
    "Largest Negative Delta (-)": ("delta", True),
}
if sort_by in sort_map:
    col_name, is_asc = sort_map[sort_by]
    view = scored_df.sort_values(by=col_name, ascending=is_asc).head(20)
else:
    view = scored_df.reindex(scored_df["delta"].abs().sort_values(ascending=False).index).head(20)

st.dataframe(pd.DataFrame({
    "Finding ID": view["Finding ID"], "CVE ID": view["CVE ID"], "Title": view["Vulnerability title"],
    "Exposure": view["Exposure classification"], "Crit Assets": view["Critical assets"], "Complexity": view["Patch complexity"],
    "Reference Score": view["before_score"].map("{:.3f}".format),
    "Target Score": view["after_score"].map("{:.3f}".format),
    "Score Delta": view["delta"].map("{:+.3f}".format),
}), hide_index=True, width='stretch')
