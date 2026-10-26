import os
import requests
import pandas as pd
import streamlit as st

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY", "")

def interpret_risk(score):
    if score <= 6: return "Low", "Routine monitoring is sufficient."
    if score <= 12: return "Medium", "Moderate risk requiring planned remediation."
    if score <= 18: return "High", "Significant risk. Prioritized remediation is recommended."
    return "Critical", "Severe risk requiring immediate attention."

def calculate_risk_score(cvss_score, exploited_score, poc_score, patch_score, control_score, asset_score, acceptance_score, weights):
    """ Normalized risk formula applied engine-wide """
    weighted_score = (
        (cvss_score * weights["severity"]) +
        (exploited_score * weights["exploited"]) +
        (poc_score * weights["poc"]) +
        (patch_score * weights["patch"]) +
        (control_score * weights["controls"]) +
        (asset_score * weights["asset"])
    )
    acceptance_reduction = acceptance_score * weights["transfer"]
    calculated_score = (weighted_score - acceptance_reduction) * 2.4
    return round(min(max(calculated_score, 1.0), 24.0), 1)

def simulated_threat_factors(cvss_score):
    simulated_exploited = 2 if cvss_score >= 8.5 else 1 if cvss_score >= 6.0 else 0
    simulated_poc = 2 if cvss_score >= 7.0 else 1 if cvss_score >= 4.0 else 0
    return simulated_exploited, simulated_poc

st.title("NVD API Search Query & Analysis")

with st.container(border=True):
    input_col, slider_col = st.columns(2)
    with input_col:
        keyword = st.text_input("Search Keyword", placeholder="Example: CVE-1999-0524, Apache, OpenSSL")
    with slider_col:
        results_per_page = st.slider("Max Results to Fetch", min_value=5, max_value=100, value=30, step=5)
    fetch_button = st.button("Fetch and Run Analysis Matrix", use_container_width=True, type="primary")

if fetch_button:
    with st.spinner("Retrieving vulnerability data from the NVD API..."):
        @st.cache_data(ttl=600, show_spinner=False)
        def fetch_nvd_data(query_keyword, limit, api_key_present):
            params = {"resultsPerPage": limit}
            if query_keyword and query_keyword.strip(): params["keywordSearch"] = query_keyword.strip()
            headers = {"apiKey": API_KEY} if api_key_present and API_KEY else {}
            try:
                res = requests.get(BASE_URL, headers=headers, params=params, timeout=20)
                res.raise_for_status()
                return res.json(), None
            except Exception as e: return None, str(e)

        data, error = fetch_nvd_data(keyword, results_per_page, bool(API_KEY))
        if error: st.error(error)
        elif data:
            st.session_state.nvd_data = data
            st.session_state.has_fetched = True

if not st.session_state.get("has_fetched", False):
    st.info("Enter a keyword or leave it blank, choose the number of records, then select Fetch and Run Analysis Matrix.")
elif st.session_state.get("nvd_data"):
    cve_records = []
    for item in st.session_state.nvd_data.get("vulnerabilities", []):
        cve_core = item.get("cve", {})
        cve_id = cve_core.get("id", "Unknown CVE")
        desc = next((d.get("value") for d in cve_core.get("descriptions", []) if d.get("lang") == "en"), "No description available.")
        
        metrics = cve_core.get("metrics", {})
        cvss_score = 0.0
        cvss_version = "No CVSS"
        cvss_severity = "Not Rated"
        
        for vk in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            records = metrics.get(vk, [])
            if records and isinstance(records, list):
                cvss_data = records[0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                cvss_version = vk.replace("cvssMetric", "CVSS ")
                cvss_severity = cvss_data.get("baseSeverity", "Unknown")
                break

        sim_exploited, sim_poc = simulated_threat_factors(cvss_score)
        final_score = calculate_risk_score(cvss_score, sim_exploited, sim_poc, patch_score=2.0, control_score=1.0, asset_score=3.0, acceptance_score=0, weights=st.session_state.weights)
        risk_level, risk_interpretation = interpret_risk(final_score)

        cve_records.append({
            "CVE ID": cve_id, "CVSS Version": cvss_version, "CVSS Score": cvss_score, "CVSS Severity": cvss_severity,
            "Calculated Risk Score": final_score, "Risk Level": risk_level, "Interpretation": risk_interpretation,
            "Published": cve_core.get("published"), "Description": desc
        })

    df_manual = pd.DataFrame(cve_records)
    if not df_manual.empty:
        df_manual_sorted = df_manual.sort_values(by="Calculated Risk Score", ascending=False).reset_index(drop=True)
        st.subheader("Risk Distribution Trend")
        st.bar_chart(df_manual_sorted.head(10), x="CVE ID", y="Calculated Risk Score", use_container_width=True)
        st.dataframe(df_manual_sorted, use_container_width=True, hide_index=True)