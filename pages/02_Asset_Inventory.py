import os
import pandas as pd
import streamlit as st

EXCEL_FILE_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
COORDINATED_LEDGER_PATH = "reference_data/vulnerability_coordinated_ledger.xlsx"

if st.session_state.get("df_sample_excel") is None and os.path.exists(EXCEL_FILE_PATH):
    try: st.session_state.df_sample_excel = pd.read_excel(EXCEL_FILE_PATH)
    except Exception as e: st.error(f"Error reading sample excel: {e}")

if st.session_state.get("df_coordinated_excel") is None and os.path.exists(COORDINATED_LEDGER_PATH):
    try: st.session_state.df_coordinated_excel = pd.read_excel(COORDINATED_LEDGER_PATH)
    except Exception as e: st.error(f"Error reading coordinated ledger: {e}")

st.title("Asset Inventory Master List")
st.markdown("Aggregated infrastructure summary with an interactive deep-dive vulnerability drill-down interface.")

if st.session_state.get("df_coordinated_excel") is not None:
    df_base = st.session_state.df_coordinated_excel.copy()
    
    if "Asset group" in df_base.columns:
        df_base.columns = [str(c).strip() for c in df_base.columns]
        
        qty_cols = ["Total affected assets", "Critical assets", "High-criticality assets", "Medium-criticality assets", "Low-criticality assets", "Internet-facing assets"]
        for col in qty_cols:
            if col in df_base.columns:
                df_base[col] = pd.to_numeric(df_base[col], errors="coerce").fillna(0).astype(int)

        agg_dict = {"detected_vuln_count": "sum"}
        df_base["detected_vuln_count"] = 1
        
        if "CVSS base score" in df_base.columns: agg_dict["CVSS base score"] = "max"
        if "Contextual risk score" in df_base.columns: agg_dict["Contextual risk score"] = "max"
        for col in qty_cols:
            if col in df_base.columns: agg_dict[col] = "max"

        df_asset_inv = df_base.groupby("Asset group").agg(agg_dict).reset_index()
        
        rename_mapping = {
            "Asset group": "Asset Group Name", "detected_vuln_count": "Total Vulnerabilities Found",
            "CVSS base score": "Highest CVSS Score", "Total affected assets": "Total Assets",
            "Critical assets": "Critical Assets", "High-criticality assets": "High Criticality",
            "Medium-criticality assets": "Medium Criticality", "Low-criticality assets": "Low Criticality",
            "Internet-facing assets": "Internet Facing Assets", "Contextual risk score": "Highest Contextual Risk"
        }
        df_asset_inv = df_asset_inv.rename(columns=rename_mapping)
        if "Total Assets" in df_asset_inv.columns:
            df_asset_inv = df_asset_inv.sort_values(by="Total Assets", ascending=False)

        # Calculate absolute metrics and relative impact bounds
        total_assets_sum = df_asset_inv['Total Assets'].sum() if 'Total Assets' in df_asset_inv.columns else 0
        total_internet_sum = df_asset_inv['Internet Facing Assets'].sum() if 'Internet Facing Assets' in df_asset_inv.columns else 0
        internet_pct = (total_internet_sum / total_assets_sum * 100) if total_assets_sum > 0 else 0

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Asset Groups", f"{len(df_asset_inv)} clusters")
        c2.metric("Total Managed Assets", f"{total_assets_sum:,} units")
        c3.metric("Critical Infrastructure", f"{df_asset_inv['Critical Assets'].sum() if 'Critical Assets' in df_asset_inv.columns else 0:,} nodes")
        
        with c4:
            st.metric("Internet Facing Nodes", f"{total_internet_sum:,} units")
            st.caption(f"{internet_pct:.1f}% of total managed assets")

        st.subheader("Asset Distribution vs Internet Exposure by Cluster")
        st.bar_chart(
            data=df_asset_inv, 
            x="Asset Group Name", 
            y=["Total Assets", "Internet Facing Assets"], 
            use_container_width=True
        )

        st.subheader("Group Summary Matrix")
        with st.container(border=True):
            all_cols = list(df_asset_inv.columns)
            front_cols = [c for c in ["Asset Group Name", "Highest Contextual Risk", "Total Vulnerabilities Found", "Highest CVSS Score"] if c in all_cols]
            df_asset_inv = df_asset_inv[front_cols + [c for c in all_cols if c not in front_cols]]

            inv_config = {col: st.column_config.NumberColumn(format="%.2f") for col in df_asset_inv.select_dtypes(include=["float"]).columns}
            for int_col in ["Total Vulnerabilities Found", "Total Assets", "Critical Assets", "High Criticality", "Medium Criticality", "Low Criticality", "Internet Facing Assets"]:
                if int_col in df_asset_inv.columns: inv_config[int_col] = st.column_config.NumberColumn(format="%d")
            st.dataframe(df_asset_inv, use_container_width=True, hide_index=True, height=250, column_config=inv_config)
    else: 
        st.error("Asset group column missing.")
else: st.warning("Please instantiate master tracking data ledger streams to interact with inventory tools.")
