import datetime
import io
import json
import os
import sys
import time
import pandas as pd
import requests
import streamlit as st

# Add PROJECT_ROOT to sys.path at index 0 to ensure app_utils is resolved first
S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)
if P_DIR not in sys.path:
    sys.path.insert(0, P_DIR)

from app_utils.config_manager import (
    get_active_dataset_path,
    get_config_version,
    get_nvd_api_key,
    load_active_dataset,
)


NVD_API_KEY = get_nvd_api_key()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DELAY = 0.7 if NVD_API_KEY else 6.5  # NVD rate limit: 50/30s with key, 5/30s without


def fetch_cve(cve_id):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(4):
        time.sleep(DELAY)
        try:
            r = requests.get(
                NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30
            )
        except requests.RequestException:
            time.sleep(2**attempt)
            continue
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        if r.status_code in (403, 429, 503):
            time.sleep(5 * 2**attempt)
            continue
        break
    return "ERROR"


def cvss(cve):
    versions = {
        "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0",
        "cvssMetricV40": "4.0",
        "cvssMetricV2": "2.0",
    }
    for key, ver in versions.items():
        for m in sorted(
            cve.get("metrics", {}).get(key, []), key=lambda e: e["type"] != "Primary"
        ):
            d = m["cvssData"]
            return d["baseScore"]
    return None


def check(row, cve):
    if cve == "ERROR":
        return {
            "Status": "ERROR",
            "NVD score": None,
            "Issues": "NVD request failed",
        }
    if cve is None:
        return {
            "Status": "NOT_FOUND",
            "NVD score": None,
            "Issues": "CVE not in NVD",
        }

    nvd_score = cvss(cve)
    sheet_score = row["CVSS base score"]

    issues = []
    if nvd_score is None:
        issues.append(f"No CVSS yet ({cve.get('vulnStatus')})")
        status = "REVIEW"
    else:
        if abs(float(sheet_score) - nvd_score) > 0.1:
            issues.append(f"Score mismatch (Sheet={sheet_score}, NVD={nvd_score})")
            status = "REVIEW"
        else:
            status = "VALID"

    return {"Status": status, "NVD score": nvd_score, "Issues": "; ".join(issues)}


@st.cache_data(show_spinner=False)
def cached_fetch(cve_id):
    return fetch_cve(cve_id)


st.title("NVD Score Match Validator")
if not NVD_API_KEY:
    st.warning("NVD_API_KEY not found in Streamlit Secrets or environment variables — using slow public rate limit.")

active_path = get_active_dataset_path()
active_ver = get_config_version()
data_source = st.radio(
    "Select Dataset Source for Validation",
    options=[
        f"Use Active Configured Dataset ({os.path.basename(active_path)} · {active_ver})",
        "Upload a Custom Dataset File (.xlsx / .csv)",
    ],
)


uploaded_file = None
if data_source.startswith("Upload"):
    uploaded_file = st.file_uploader("Scanner findings (.xlsx, .csv)", type=["xlsx", "csv"])

limit = st.number_input(
    "Limit unique CVEs (0 = all)", min_value=0, value=0, step=1
)

if st.button("Validate", type="primary"):
    df = None
    if data_source.startswith("Use Active"):
        try:
            df = load_active_dataset(validate=True).copy()
        except Exception as e:
            st.error(f"Failed to load active dataset: {e}")
    else:
        if uploaded_file is None:
            st.warning("Please upload a dataset file before running validation.")
        else:
            try:
                if uploaded_file.name.lower().endswith(".csv"):
                    df = pd.read_csv(uploaded_file)
                else:
                    # Fallback to default sheet if 'Scanner Findings' sheet name is not present
                    xl = pd.ExcelFile(uploaded_file)
                    sheet = "Scanner Findings" if "Scanner Findings" in xl.sheet_names else 0
                    df = pd.read_excel(xl, sheet_name=sheet)
            except Exception as e:
                st.error(f"Failed to read uploaded file: {e}")

    if df is not None and not df.empty:
        cves = list(dict.fromkeys(df["CVE ID"].astype(str).str.strip().str.upper()))
        if limit:
            cves = cves[:limit]

        bar = st.progress(0.0)
        nvd = {}
        for i, c in enumerate(cves, 1):
            nvd[c] = cached_fetch(c)
            bar.progress(i / len(cves), text=f"{c} ({i}/{len(cves)})")

        rows = [
            check(r, nvd[str(r["CVE ID"]).strip().upper()])
            for _, r in df.iterrows()
            if str(r["CVE ID"]).strip().upper() in nvd
        ]

        out = pd.concat(
            [
                df[df["CVE ID"].astype(str).str.strip().str.upper().isin(nvd)].reset_index(
                    drop=True
                ),
                pd.DataFrame(rows),
            ],
            axis=1,
        )

        out["Score Diff"] = (
            pd.to_numeric(out["NVD score"]) - pd.to_numeric(out["CVSS base score"])
        ).round(1)
        out["Score Match"] = out["Score Diff"].map(
            lambda d: "N/A" if pd.isna(d) else ("Match" if abs(d) <= 0.1 else "Mismatch")
        )
        out["NVD Link"] = [
            f"https://nvd.nist.gov/vuln/detail/{str(c).strip().upper()}"
            if s in ("VALID", "REVIEW")
            else None
            for c, s in zip(out["CVE ID"], out["Status"])
        ]

        # Build a clean dictionary mapping CVE ID to its validated NVD score
        valid_rows = out.dropna(subset=["NVD score"])
        validated_map = {
            str(cve).strip().upper(): float(score)
            for cve, score in zip(valid_rows["CVE ID"], valid_rows["NVD score"])
        }

        # Save validated scores to outputs/nvd_validated_scores.json for dashboard integration
        json_out_path = os.path.join(P_DIR, "outputs", "nvd_validated_scores.json")
        os.makedirs(os.path.dirname(json_out_path), exist_ok=True)

        run_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {
            "last_validated": run_timestamp,
            "config_version": active_ver,
            "dataset": os.path.basename(active_path),
            "total_validated_cves": len(validated_map),
            "scores": validated_map,
        }

        with open(json_out_path, "w", encoding="utf-8") as json_file:
            json.dump(payload, json_file, indent=2)

        # Build CISA KEV catalog directly from NVD 2.0 response ('cisaExploitAdd' field)
        kev_entries = []
        for cve_id, cve_obj in nvd.items():
            if isinstance(cve_obj, dict) and cve_obj.get("cisaExploitAdd"):
                kev_entries.append({
                    "cveID": cve_id,
                    "dateAdded": cve_obj.get("cisaExploitAdd"),
                })
        kev_payload = {
            "catalogVersion": datetime.datetime.now().strftime("%Y.%m.%d"),
            "dateReleased": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "count": len(kev_entries),
            "vulnerabilities": kev_entries,
        }

        kev_path = os.path.join(P_DIR, "reference_data", "known_exploited_vulnerabilities.json")
        os.makedirs(os.path.dirname(kev_path), exist_ok=True)
        with open(kev_path, "w", encoding="utf-8") as kf:
            json.dump(kev_payload, kf, indent=2)



        with open(json_out_path, "w", encoding="utf-8") as json_file:
            json.dump(payload, json_file, indent=2)

        # Persist DataFrame and timestamp in session_state across menu navigation
        st.session_state["nvd_last_out"] = out
        st.session_state["nvd_last_time"] = run_timestamp

# Render last session results if available
if (
    "nvd_last_out" in st.session_state
    and st.session_state["nvd_last_out"] is not None
):
    out = st.session_state["nvd_last_out"]
    last_time = st.session_state.get("nvd_last_time", "")

    st.success(
        f"Showing validated NVD scores ({len(out.dropna(subset=['NVD score']))}"
        f" findings, last run: {last_time}) — saved to"
        " outputs/nvd_validated_scores.json"
    )

    st.dataframe(
        out[[
            "Finding ID",
            "CVE ID",
            "CVSS base score",
            "NVD score",
            "Score Diff",
            "Score Match",
            "Status",
            "Issues",
            "NVD Link",
        ]],
        column_config={
            "NVD Link": st.column_config.LinkColumn(
                "NVD Link", display_text="Open NVD"
            )
        },
    )
    st.bar_chart(out["Status"].value_counts())

    st.subheader("CVSS score: sheet vs NVD")
    cmp = out.dropna(subset=["NVD score"])
    a, b, c = st.columns(3)
    a.metric("Match", int((cmp["Score Match"] == "Match").sum()))
    b.metric("Mismatch", int((cmp["Score Match"] == "Mismatch").sum()))
    c.metric("No NVD score", int(out["NVD score"].isna().sum()))

    if not cmp.empty:
        st.scatter_chart(cmp, x="CVSS base score", y="NVD score")
        bad = cmp[cmp["Score Match"] == "Mismatch"]
        if not bad.empty:
            st.write("Mismatches")
            st.dataframe(
                bad[[
                    "Finding ID",
                    "CVE ID",
                    "CVSS base score",
                    "NVD score",
                    "Score Diff",
                ]]
            )

    buf = io.BytesIO()
    out.to_excel(buf, index=False)
    st.download_button(
        "Download results (.xlsx)", buf.getvalue(), "nvd_score_validation.xlsx"
    )
