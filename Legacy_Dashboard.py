import os
import glob
import re
import time
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv

# ==========================================
# 1. INITIALIZATION & CORE SETTINGS
# ==========================================
load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPORTS_DIR = "scan_reports"
CSV_FILE_PATH = "reference_data/Inventory_Lists.csv"

st.set_page_config(
    page_title="SOC Dashboard - CIS6560 Sec02 - Context-Aware Vulnerability Prioritization",
    layout="wide"
)

st.markdown("""
<style>
    .block-container {
        padding-top: 1rem;
        padding-bottom: 0rem;
        max-width: 100%;
    }
    h1 {
        margin-top: 0rem;
        margin-bottom: 0.5rem;
        font-size: 1.8rem !important;
    }
    h3 {
        margin-top: 0rem;
        margin-bottom: 0.3rem;
        font-size: 1.2rem !important;
    }
    .stMarkdown div p {
        margin-bottom: 0.2rem;
    }
    div[data-testid="stForm"] {
        padding: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# 2. GLOBAL SESSION STATE MANAGEMENT
# ==========================================
if "nvd_data" not in st.session_state:
    st.session_state.nvd_data = None
if "last_keyword" not in st.session_state:
    st.session_state.last_keyword = ""
if "last_limit" not in st.session_state:
    st.session_state.last_limit = 30
if "has_fetched" not in st.session_state:
    st.session_state.has_fetched = False
if "df_assets" not in st.session_state:
    st.session_state.df_assets = None
if "df_pipeline_results" not in st.session_state:
    st.session_state.df_pipeline_results = None


# ==========================================
# 3. SIDEBAR NAVIGATION SYSTEM
# ==========================================
st.sidebar.title("Operations Hub")
st.sidebar.markdown("Navigate through your enterprise risk sub-modules.")

menu_selection = st.sidebar.radio(
    "Select View:",
    ["CVE Query & Tuning Matrix", "Greenbone NVD Pipeline", "System Configuration"]
)

st.sidebar.markdown("---")
st.sidebar.caption("Scoring Engine v0.0")


# ==========================================
# 4. DATA INGESTION & PARSING BACKEND
# ==========================================

def extract_cves_by_asset(directory_path):
    """ Extracts deduplicated CVE IDs mapped per target host IP from Greenbone XMLs """
    search_path = os.path.join(directory_path, "*.xml")
    xml_files = glob.glob(search_path)
    if not xml_files:
        return {}

    asset_cve_map = {}
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    ip_pattern = re.compile(r"<host>([^<]+)</host>")

    for file_path in xml_files:
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            ip_match = ip_pattern.search(content)
            ip_address = ip_match.group(1).strip() if ip_match else file_name.replace(".xml", "")
            
            if ip_address not in asset_cve_map:
                asset_cve_map[ip_address] = set()

            found_cves = cve_pattern.findall(content)
            for cve_id in found_cves:
                asset_cve_map[ip_address].add(cve_id.strip())
        except Exception:
            pass

    return {ip: list(cves) for ip, cves in asset_cve_map.items()}

def get_nvd_realtime_data(cve_id, session):
    """ Queries official NVD APIv2 endpoint for real-time triage scoring telemetry """
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    if API_KEY:
        headers["apiKey"] = API_KEY.strip("'\" ")

    try:
        response = session.get(BASE_URL, headers=headers, params={"cveId": cve_id}, timeout=15)
        if response.status_code == 200:
            vulnerabilities = response.json().get("vulnerabilities", [])
            if vulnerabilities:
                metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
                for version_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    records = metrics.get(version_key, [])
                    if records and isinstance(records, list):
                        cvss_data = records[0].get("cvssData", {})
                        return float(cvss_data.get("baseScore", 0.0)), version_key.replace("cvssMetric", "CVSS ")
            return 0.0, "None"
        elif response.status_code == 403:
            time.sleep(5)
            return get_nvd_realtime_data(cve_id, session)
        return 0.0, "API_Error"
    except Exception:
        return 0.0, "Network_Error"



# ==========================================
# 5. CORE RISK SCORING ENGINE MATHEMATICS
# ==========================================

def interpret_risk(score):
    if score <= 6: return "Low", "Routine monitoring is sufficient."
    if score <= 12: return "Medium", "Moderate risk requiring planned remediation."
    if score <= 18: return "High", "Significant risk. Prioritized remediation is recommended."
    return "Critical", "Severe risk requiring immediate attention."

def calculate_risk_score(cvss_score, exploited_score, poc_score, patch_score, control_score, asset_score, acceptance_score, weights):
    """ Normalized 1-24 risk formula applied engine-wide """
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


# ==========================================
# 6. SHARED ASSET INVENTORY COMPONENT
# ==========================================
if st.session_state.df_assets is None and os.path.exists(CSV_FILE_PATH):
    try:
        st.session_state.df_assets = pd.read_csv(CSV_FILE_PATH, nrows=7)
    except Exception as e:
        st.error(f"Error reading asset inventory: {e}")


# ==========================================
# 7. ROUTING AND VIEW LOGIC INTERFACES
# ==========================================

# --- VIEW 1: MANUAL QUERY & WEIGHT TUNING MATRIX ---
if menu_selection == "CVE Query & Tuning Matrix":
    st.title("Dashboard V0.0 - Lab Dataset")
    
    st.subheader("Asset Management")
    if st.session_state.df_assets is not None:
        st.session_state.df_assets = st.data_editor(st.session_state.df_assets, use_container_width=True, hide_index=True, num_rows="dynamic")
    
    st.write("---") 

    main_col, config_col = st.columns([1.8, 1.2], gap="medium")

    # Weigh Tuning Slider
    with config_col:
        with st.container(border=True):
            st.subheader("Risk Weight Tuning Options")
            w_severity = st.slider("Severity (CVSS)", 0.0, 1.0, 0.40, 0.05, key="sev")
            w_exploited = st.slider("Simulated Exploited in Wild", 0.0, 1.0, 0.15, 0.05, key="exp")
            w_poc = st.slider("Simulated PoC Availability", 0.0, 1.0, 0.10, 0.05, key="poc")
            w_patch = st.slider("Patch Difficulty", 0.0, 1.0, 0.10, 0.05, key="patch")
            w_controls = st.slider("Compensating Controls", 0.0, 1.0, 0.10, 0.05, key="ctrl")
            w_asset = st.slider("Asset Criticality", 0.0, 1.0, 0.10, 0.05, key="asset")
            w_transfer = st.slider("Risk Acceptance / Transfer", 0.0, 1.0, 0.05, 0.05, key="trans")

            total_weight = round(w_severity + w_exploited + w_poc + w_patch + w_controls + w_asset + w_transfer, 2)
            if total_weight == 1.00:
                st.success(f"Weights verified: total = {total_weight:.2f}")
            else:
                st.error(f"Weights invalid: must equal 1.00 (current total: {total_weight:.2f})")

    # NVD API Search Query
    with main_col:
        with st.container(border=True):
            st.subheader("NVD API Search Query")
            input_col, slider_col = st.columns(2)
            with input_col:
                keyword = st.text_input("Search Keyword", placeholder="Example: CVE-1999-0524, Apache, OpenSSL")
            with slider_col:
                results_per_page = st.slider("Max Results to Fetch", min_value=5, max_value=100, value=30, step=5)
            fetch_button = st.button("Fetch and Run Analysis Matrix", use_container_width=True, type="primary")

        if fetch_button and total_weight == 1.00:
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

        if not st.session_state.has_fetched:
            st.info("Enter a keyword or leave it blank, choose the number of records, then select Fetch and Run Analysis Matrix.")
        elif st.session_state.nvd_data:
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
                weights_dict = {"severity": w_severity, "exploited": w_exploited, "poc": w_poc, "patch": w_patch, "controls": w_controls, "asset": w_asset, "transfer": w_transfer}
                
                final_score = calculate_risk_score(cvss_score, sim_exploited, sim_poc, 2, 1, 3, 0, weights_dict)
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



# --- VIEW 2: AUTOMATED GREENBONE LIVE PIPELINE ---
elif menu_selection == "Greenbone NVD Pipeline":
    st.title("Greenbone NVD Automated Scoring Pipeline")
    st.markdown("Automated asset-linked vulnerability Ingestion engine mapped against context database matrices.")
    # st.hr()
    st.markdown("---") # Fixed
  

    weights_pipeline = {"severity": 0.35, "exploited": 0.20, "poc": 0.15, "patch": 0.10, "controls": 0.10, "asset": 0.10, "transfer": 0.00}

    run_pipeline = st.button("Sync Reports & Run Ingestion Pipeline", use_container_width=True)

    if run_pipeline:
        with st.spinner("Injecting telemetry configurations and extracting asset clusters..."):
            asset_cve_data = extract_cves_by_asset(REPORTS_DIR)
            
            if not asset_cve_data:
                st.error("Ingestion failure: No raw diagnostic scan telemetry files discoverable inside directory map.")
            else:
                pipeline_records = []
                session = requests.Session()
                session.trust_env = False
                delay = 1.0 if API_KEY else 6.0

                for ip_address, cve_list in asset_cve_data.items():
                    max_cvss = 0.0
                    context_asset_crit = 3.0
                    context_controls = 1.0
                    context_patch = 2.0
                    
                    if st.session_state.df_assets is not None and not st.session_state.df_assets.empty:
                        df_inv = st.session_state.df_assets
                        # Secure element scanning loop bypassing unstable iloc calls
                        for idx, row in df_inv.iterrows():
                            # row_str = " ".join(row.astype(str).tolist())
                            # Map all items to string before joining
                            row_str = " ".join(map(str, row.tolist()))
                            if ip_address in row_str:
                                context_asset_crit = float(row.get("Asset Criticality", 3.0))
                                context_controls = float(row.get("Compensating Controls", 1.0))
                                context_patch = float(row.get("Patch Difficulty", 2.0))
                                break

                    for cve_id in cve_list[:5]:
                        score, _ = get_nvd_realtime_data(cve_id, session)
                        if score > max_cvss: max_cvss = score
                        time.sleep(delay)

                    sim_exp, sim_poc = simulated_threat_factors(max_cvss)
                    
                    calculated_risk = calculate_risk_score(
                        cvss_score=max_cvss, exploited_score=sim_exp, poc_score=sim_poc,
                        patch_score=context_patch, control_score=context_controls,
                        asset_score=context_asset_crit, acceptance_score=0, weights=weights_pipeline
                    )
                    risk_class, _ = interpret_risk(calculated_risk)

                    pipeline_records.append({
                        "Asset Host IP": ip_address, "Max Base CVSS": max_cvss,
                        "Context Criticality": context_asset_crit, "Context Controls": context_controls,
                        "Calculated Engine Score": calculated_risk, "Risk Classification": risk_class,
                        "Total Target Footprint CVEs": len(cve_list)
                    })

                st.session_state.df_pipeline_results = pd.DataFrame(pipeline_records)
                st.success("Telemetry pipeline synchronization complete!")

    if st.session_state.df_pipeline_results is not None and not st.session_state.df_pipeline_results.empty:
        df_p = st.session_state.df_pipeline_results

        st.subheader("Network-Wide Security Metrics")
        m1, m2, m3 = st.columns(3)
        highest_row = df_p.loc[df_p['Calculated Engine Score'].idxmax()]
        m1.metric(label="Maximum Risk Asset Score", value=f"{highest_row['Calculated Engine Score']} / 24.0", delta=highest_row['Asset Host IP'], delta_color="inverse")
        m2.metric(label="Average Network Risk Score", value=f"{round(df_p['Calculated Engine Score'].mean(), 1)} / 24.0")
        m3.metric(label="Total Monitored Endpoints", value=len(df_p))
        
        st.markdown("---")

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Asset Risk Profile Comparison")
            fig_bar = px.bar(df_p, x="Asset Host IP", y="Calculated Engine Score", color="Risk Classification",
                             color_discrete_map={"Critical": "#EF553B", "High": "#FF7F0E", "Medium": "#FECB52", "Low": "#636EFA"}, text="Calculated Engine Score")
            fig_bar.update_layout(yaxis_range=[0, 24.5])
            st.plotly_chart(fig_bar, use_container_width=True)

        with c2:
            st.subheader("Criticality Distribution Matrix")
            fig_pie = px.pie(df_p, names="Risk Classification", hole=0.4, color="Risk Classification",
                             color_discrete_map={"Critical": "#EF553B", "High": "#FF7F0E", "Medium": "#FECB52", "Low Risk": "#636EFA"})
            st.plotly_chart(fig_pie, use_container_width=True)

        st.markdown("---")
        st.subheader("Granular Scoring Pipeline Metrics")
        st.dataframe(df_p.style.background_gradient(cmap='YlOrRd', subset=['Calculated Engine Score', 'Max Base CVSS']), use_container_width=True, hide_index=True)
    else:
        st.info("Click the Sync Reports button above to stream live diagnostic records through the triage pipeline matrix mapping engine.")


# --- VIEW 3: SYSTEM CONFIGURATION VIEW LIGHT ---
elif menu_selection == "System Configuration":
    st.title("System Configuration")
    st.markdown("### Management Options")
    st.write(f"**Target Scan Directory Route:** `{REPORTS_DIR}/`")
    st.write(f"**NVD Authorized Token Active:** `{'Yes (Key Detected)' if API_KEY else 'No (Anonymized Request Constraints Apply)'}`")
