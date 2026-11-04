import streamlit as st, pandas as pd, plotly.express as px, os, io, json
from datetime import datetime
from engines.scoring_validation import cvss_severity

st.set_page_config(page_title="CVE-level analysis", layout="wide")
st.title("CVE-Level Analysis, Baseline ranked list v0")
st.markdown("CVSS-only Baseline Prioritization Report with Deduplication (Press Ctrl+P to save as PDF)")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCORING_CONFIG_PATH = os.path.join(ROOT_DIR, "engines", "scoring_config.json")

@st.cache_data
def load_data(path):
    if not os.path.exists(path): return pd.DataFrame(columns=["Finding ID", "CVE ID", "Vulnerability title", "Affected product", "Asset group", "CVSS base score", "CVSS severity", "Internet-facing assets", "Total affected assets"])
    df = pd.read_excel(path)
    for c in df.select_dtypes(include=['object', 'string']).columns: df[c] = df[c].astype(str).str.strip()
    with open(SCORING_CONFIG_PATH, encoding="utf-8") as config_file:
        severity_thresholds = json.load(config_file)["cvss_severity_thresholds"]
    df["CVSS severity (source)"] = df["CVSS severity"]
    df["CVSS severity"] = df["CVSS base score"].map(
        lambda value: cvss_severity(value, severity_thresholds)
    )
    return df

df = load_data("reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx")

st.markdown("### Filter Workspace")
f1, f2 = st.columns(2)
with f1: 
    sev_opt = sorted(df["CVSS severity"].unique()) if not df.empty else []
    sel_sev = st.multiselect("Select CVSS Severity", options=sev_opt, default=sev_opt)
with f2:
    ast_opt = sorted(df["Asset group"].unique()) if not df.empty else []
    if "all_ast" not in st.session_state: st.session_state["all_ast"] = True
    def toggle():
        for a in ast_opt: st.session_state[f"chk_{a}"] = st.session_state["all_ast"]
    s1, s2 = st.columns(2)
    with s1: 
        st.markdown("<div style='padding-top:25px;'></div>", unsafe_allow_html=True)
        st.checkbox("Select All", value=st.session_state["all_ast"], key="all_ast", on_change=toggle)
with s2:
    with st.expander("Show Individual Asset Groups", expanded=False):
        sel_ast = [a for a in ast_opt if st.checkbox(a, key=f"chk_{a}", value=st.session_state["all_ast"])]

raw = df.copy()
if sel_sev: raw = raw[raw["CVSS severity"].isin(sel_sev)]
raw = raw[raw["Asset group"].isin(sel_ast)] if sel_ast else raw[raw["Asset group"].isin([])]

dedup = raw.sort_values(by=["CVSS base score", "Total affected assets"], ascending=False).drop_duplicates(subset=["CVE ID"], keep="first")
final = dedup.sort_values(by="CVE ID", ascending=False)
removed = raw[~raw.index.isin(dedup.index)].sort_values(by="CVE ID", ascending=False)

tot_cve, tot_raw, tot_rem = len(final), len(raw), len(removed)
high_cnt = len(final[final["CVSS base score"] >= 7.0]) if tot_cve > 0 else 0
cve_2026 = final["CVE ID"].str.upper().str.startswith("CVE-2026", na=False).sum()

st.markdown("---")
c1, c2, c3 = st.columns(3)
c1.metric("Unique CVEs Analyzed", f"{tot_cve:,}", f"{tot_raw:,} raw findings", delta_color="normal")
c2.metric("High-Severity CVEs (CVSS >= 7.0)", f"{high_cnt:,}")
c3.metric("Unique 2026 CVEs", f"{cve_2026:,}")
st.markdown("---")

if tot_cve > 0:
    lc1, lc2, lc3 = st.columns(3)
    with lc1: st.subheader("Data Workspace")
        
    meta = {"Report Name": "CVSS Baseline Report", "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Severities": ", ".join(sel_sev) if sel_sev else "All", "Assets": ", ".join(sel_ast) if sel_ast else "None", "Unique CVEs": tot_cve, "Raw Logs": tot_raw}
        
    with lc2:
        ex_buf = io.BytesIO()
        with pd.ExcelWriter(ex_buf, engine='openpyxl') as w:
            final.to_excel(w, index=False, sheet_name='CVSS Baseline')
            pd.DataFrame(list(meta.items()), columns=["Key", "Value"]).to_excel(w, index=False, sheet_name='Metadata')
        st.download_button("Download Excel Baseline", data=ex_buf.getvalue(), file_name=f"cvss_baseline_{datetime.now().strftime('%Y%m%d')}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", width='stretch')
    with lc3:
        st.download_button("Download JSON Baseline", data=json.dumps({"metadata": meta, "cve_records": final.to_dict(orient="records")}, indent=4, ensure_ascii=False), file_name=f"cvss_baseline_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json", width='stretch')

    severity_order = ["Critical", "High", "Medium", "Low"]
    sev_type = pd.CategoricalDtype(categories=severity_order, ordered=True)

    def sort_by_cve_risk(target_df):
        if target_df.empty: return target_df
        temp_df = target_df.copy()
        temp_df["_sev_sort"] = temp_df["CVSS severity"].astype(sev_type)
        sorted_df = temp_df.sort_values(
            by=["CVSS base score", "_sev_sort", "Total affected assets"], 
            ascending=[False, True, False]
        ).drop(columns=["_sev_sort"])
        return sorted_df

    final_sorted = sort_by_cve_risk(final)
    removed_sorted = sort_by_cve_risk(removed)
    raw_sorted = sort_by_cve_risk(raw)

    t1, t2, t3 = st.tabs([f"1. Final View ({tot_cve})", f"2. Removed Duplicates ({tot_rem})", f"3. Raw Data ({tot_raw})"])
    cols = ["Finding ID", "CVE ID", "Vulnerability title", "Affected product", "Asset group", "CVSS base score", "CVSS severity", "Total affected assets"]
    
    with t1: 
        st.dataframe(final_sorted[[c for c in final_sorted.columns if c in cols and c != "Finding ID" and c != "Affected product"] + ["Internet-facing assets", "Recommended remediation"]], width='stretch', hide_index=True)
    with t2: 
        st.dataframe(removed_sorted[[c for c in removed_sorted.columns if c in cols]], width='stretch', hide_index=True)
    with t3: 
        st.dataframe(raw_sorted[[c for c in raw_sorted.columns if c in cols]], width='stretch', hide_index=True) 
else:
    st.warning("No records match the current filter selections. Please select options above.")
