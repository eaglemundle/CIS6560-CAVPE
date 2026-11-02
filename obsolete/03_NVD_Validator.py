import io
import os
import re
import time

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

# 1. Load environment variables from the local .env file
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DELAY = 0.7 if NVD_API_KEY else 6.5  # NVD rate limit: 50/30s with key, 5/30s without


def fetch_cve(cve_id):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(4):
        time.sleep(DELAY)
        try:
            r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
        except requests.RequestException:
            time.sleep(2 ** attempt)
            continue
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        if r.status_code in (403, 429, 503):
            time.sleep(5 * 2 ** attempt)
            continue
        break
    return "ERROR"


def cvss(cve):
    versions = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV40": "4.0", "cvssMetricV2": "2.0"}
    for key, ver in versions.items():
        for m in sorted(cve.get("metrics", {}).get(key, []), key=lambda e: e["type"] != "Primary"):
            d = m["cvssData"]
            sev = (d.get("baseSeverity") or m.get("baseSeverity") or "").title()
            return d["baseScore"], sev, ver, f"{m.get('source')} ({m.get('type')})"
    return None, None, None, None


def tokens(text):
    return {t for t in re.sub(r"[^a-z0-9]+", " ", str(text).lower()).split() if len(t) > 2}


def check(row, cve, kev_map):
    if cve == "ERROR":
        return {"Status": "ERROR", "Issues": "NVD request failed"}
    if cve is None:
        return {"Status": "NOT_FOUND", "Issues": "CVE not in NVD"}
    score, sev, ver, src = cvss(cve)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    cpe = " ".join(
        m["criteria"].split(":")[3] + " " + m["criteria"].split(":")[4]
        for c in cve.get("configurations", [])
        for n in c.get("nodes", [])
        for m in n.get("cpeMatch", [])
    ).replace("_", " ")
    haystack = tokens(cpe + " " + desc)
    product = tokens(row["Affected product"])
    cid = row["CVE ID"].strip().upper()
    kev = kev_map.get(cid) if kev_map is not None else cve.get("cisaExploitAdd")  # CISA feed, NVD as fallback
    claims = "known exploited" in str(row["Exploitation context"]).lower()

    issues = []
    if score is None:
        issues.append(f"No CVSS yet ({cve.get('vulnStatus')})")
    else:
        if abs(float(row["CVSS base score"]) - score) > 0.1:
            issues.append(f"Score sheet={row['CVSS base score']} NVD={score}")
        if str(row["CVSS severity"]).lower() != sev.lower():
            issues.append(f"Severity sheet={row['CVSS severity']} NVD={sev}")
    if product and not product & haystack:
        issues.append("Product not found in NVD CPE/description")
    if kev and not claims:
        issues.append(f"In CISA KEV ({kev}) but sheet says no evidence")
    if claims and not kev:
        issues.append("Sheet says exploited, not in KEV (verify manually)")
    return {
        "Status": "REVIEW" if issues else "VALID",
        "NVD score": score, "NVD severity": sev, "NVD CVSS ver.": ver, "NVD score source": src, "NVD status": cve.get("vulnStatus"),
        "KEV": kev or "No", "Issues": "; ".join(issues),
    }


@st.cache_data(ttl=3600, show_spinner=False)
def load_kev():
    try:
        r = requests.get(KEV_URL, timeout=30)
        r.raise_for_status()
        return {v["cveID"].upper(): v["dateAdded"] for v in r.json()["vulnerabilities"]}
    except (requests.RequestException, KeyError, ValueError):
        return None


@st.cache_data(show_spinner=False)
def cached_fetch(cve_id):
    return fetch_cve(cve_id)


st.title("NVD Validator")
if not NVD_API_KEY:
    st.warning("NVD_API_KEY not found in .env - using slow public rate limit.")

file = st.file_uploader("Scanner findings (.xlsx)", type="xlsx")
limit = st.number_input("Limit unique CVEs (0 = all)", min_value=0, value=5)

if file and st.button("Validate"):
    df = pd.read_excel(file, sheet_name="Scanner Findings")
    cves = list(dict.fromkeys(df["CVE ID"].str.strip().str.upper()))
    if limit:
        cves = cves[:limit]
    kev_map = load_kev()
    if kev_map is None:
        st.warning("CISA KEV feed unavailable - falling back to NVD's KEV field.")
    else:
        st.caption(f"CISA KEV feed loaded: {len(kev_map)} entries")
    bar = st.progress(0.0)
    nvd = {}
    for i, c in enumerate(cves, 1):
        nvd[c] = cached_fetch(c)
        bar.progress(i / len(cves), text=f"{c} ({i}/{len(cves)})")

    rows = [check(r, nvd[r["CVE ID"].strip().upper()], kev_map) for _, r in df.iterrows()
            if r["CVE ID"].strip().upper() in nvd]
    out = pd.concat([df[df["CVE ID"].str.strip().str.upper().isin(nvd)].reset_index(drop=True),
                     pd.DataFrame(rows)], axis=1)
    for col in ("NVD score", "NVD severity", "NVD CVSS ver.", "NVD score source"):
        if col not in out:
            out[col] = None
    out["Score Diff"] = (pd.to_numeric(out["NVD score"]) - pd.to_numeric(out["CVSS base score"])).round(1)
    out["Score Match"] = out["Score Diff"].map(lambda d: "N/A" if pd.isna(d) else ("✅" if abs(d) <= 0.1 else "❌"))
    out["NVD Link"] = [
        f"https://nvd.nist.gov/vuln/detail/{c.strip().upper()}" if s in ("VALID", "REVIEW") else None
        for c, s in zip(out["CVE ID"], out["Status"])
    ]
    st.dataframe(
        out[["Finding ID", "CVE ID", "CVSS base score", "NVD score", "Score Diff", "Score Match",
             "CVSS severity", "NVD severity", "NVD CVSS ver.", "NVD score source", "KEV", "Status", "Issues", "NVD Link"]],
        column_config={"NVD Link": st.column_config.LinkColumn("NVD Link", display_text="NVD ↗")},
    )
    st.bar_chart(out["Status"].value_counts())

    st.subheader("CVSS score: sheet vs NVD")
    cmp = out.dropna(subset=["NVD score"])
    a, b, c = st.columns(3)
    a.metric("Match", int((cmp["Score Match"] == "✅").sum()))
    b.metric("Mismatch", int((cmp["Score Match"] == "❌").sum()))
    c.metric("No NVD score", int(out["NVD score"].isna().sum()))
    if not cmp.empty:
        st.scatter_chart(cmp, x="CVSS base score", y="NVD score")
        bad = cmp[cmp["Score Match"] == "❌"]
        if not bad.empty:
            st.write("Mismatches")
            st.dataframe(bad[["Finding ID", "CVE ID", "CVSS base score", "NVD score", "Score Diff"]])

    buf = io.BytesIO()
    out.to_excel(buf, index=False)
    st.download_button("Download results (.xlsx)", buf.getvalue(), "nvd_validation.xlsx")
