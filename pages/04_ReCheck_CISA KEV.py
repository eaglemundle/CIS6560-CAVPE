import os
import json
import pandas as pd
import openpyxl
from openpyxl.styles import PatternFill
from datetime import datetime
import matplotlib.pyplot as plt
import streamlit as st

# 1. Page Configuration
st.set_page_config(page_title="CVE Validator", layout="wide")
st.title("CISA KEV Validation & Ledger Management")
st.markdown("---")

# 2. Path Configuration
CISA_KEV_CSV = "reference_data/known_exploited_vulnerabilities.csv"
INPUT_EXCEL = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
COORDINATED_LEDGER = "reference_data/vulnerability_coordinated_ledger.xlsx"

CURRENT_DATE = datetime.now().strftime("%Y%m%d")
AUDIT_COL = f"AUDIT_MARKING_{CURRENT_DATE}"
STATUS_COL = f"DATA_STATUS_{CURRENT_DATE}"

# 3. Top Section: Pipeline Configurations
config_container = st.container(border=True)
with config_container:
    st.markdown("### Runtime Pipeline Configurations")
    col_info1, col_info2 = st.columns(2)
    col_info1.markdown(f"**Target Audit Column to Generate:** `{AUDIT_COL}`")
    col_info2.markdown(f"**Target Status Column to Generate:** `{STATUS_COL}`")

st.markdown("")

# 4. Action Button to Trigger New Scan
if st.button("Run Coordinated Validation Pipeline (Append Today's Audit)", type="primary", use_container_width=True):
    if not os.path.exists(CISA_KEV_CSV) or not os.path.exists(INPUT_EXCEL):
        st.error("Missing target database files inside your reference_data/ directory.")
    else:
        try:
            with st.spinner("Processing offline threat intelligence and appending to master ledger..."):
                # Load CISA KEV
                cisa_df = pd.read_csv(CISA_KEV_CSV, encoding="utf-8-sig")
                cisa_df.columns = [str(c).strip() for c in cisa_df.columns]
                cisa_cve_col = next((col for col in cisa_df.columns if "CVE" in col.upper()), None)
                cisa_master_set = set(cisa_df[cisa_cve_col].dropna().astype(str).str.strip().str.upper())

                # Load Input Scanner File
                master_df = pd.read_excel(INPUT_EXCEL, engine="openpyxl")
                norm_cols = [str(c).strip().upper().replace(" ", "_") for c in master_df.columns]
                cve_idx = next((i for i, c in enumerate(norm_cols) if c in ["CVE_ID", "CVE"]), None)
                status_idx = next((i for i, c in enumerate(norm_cols) if "DATA_STATUS" in c), None)
                finding_idx = next((i for i, c in enumerate(norm_cols) if "FINDING_ID" in c), None)
                
                cve_col_name = master_df.columns[cve_idx]
                original_status_col_name = master_df.columns[status_idx]
                
                if finding_idx is not None:
                    finding_col = master_df.columns[finding_idx]
                    master_df = master_df[master_df[finding_col].notna() & master_df[finding_col].astype(str).str.contains("VULN-", na=False)]
                master_df = master_df[master_df[cve_col_name].notna() & (master_df[cve_col_name].astype(str).str.strip() != "")]
                master_df = master_df.reset_index(drop=True)

                clean_cve_series = master_df[cve_col_name].astype(str).str.strip().str.upper()
                match_vector = clean_cve_series.isin(cisa_master_set)

                # Prepare new columns
                new_audit_values = match_vector.map({True: "PASS (Verified in CISA KEV Sheet)", False: "NOT_IN_KEV / VERIFY REQUIRED"})
                new_status_values = match_vector.map({True: f"VALIDATED ({CURRENT_DATE}): Record matches CISA KEV.", False: f"VALIDATED ({CURRENT_DATE}): Verified. No active exploit logged."})

                # Check if Coordinated Ledger already exists to append columns horizontally
                if os.path.exists(COORDINATED_LEDGER):
                    ledger_df = pd.read_excel(COORDINATED_LEDGER, engine="openpyxl")
                    # Clean existing columns for today if re-running
                    if AUDIT_COL in ledger_df.columns: ledger_df = ledger_df.drop(columns=[AUDIT_COL])
                    if STATUS_COL in ledger_df.columns: ledger_df = ledger_df.drop(columns=[STATUS_COL])
                    
                    # Insert new columns right after CVE_ID
                    ledger_df.insert(loc=1, column=STATUS_COL, value=new_status_values)
                    ledger_df.insert(loc=1, column=AUDIT_COL, value=new_audit_values)
                    final_ledger_df = ledger_df
                else:
                    # Initialize Ledger with standard 4-column layout
                    final_ledger_df = pd.DataFrame({
                        "CVE_ID": clean_cve_series,
                        AUDIT_COL: new_audit_values,
                        STATUS_COL: new_status_values,
                        "Data_Status": master_df[original_status_col_name]
                    })

                # Save Data
                final_ledger_df.to_excel(COORDINATED_LEDGER, index=False, engine="openpyxl")

                # Style Excel Cells (Orange Highlights)
                wb = openpyxl.load_workbook(COORDINATED_LEDGER)
                ws = wb.active
                orange_fill = PatternFill(start_color="FFB366", end_color="FFB366", fill_type="solid")
                
                # Dynamic column index lookup for styling
                audit_col_idx = next(i for i, cell in enumerate(ws[1]) if cell.value == AUDIT_COL) + 1
                for row_idx in range(2, ws.max_row + 1):
                    status_cell = ws.cell(row=row_idx, column=audit_col_idx)
                    if status_cell.value == "NOT_IN_KEV / VERIFY REQUIRED":
                        ws.cell(row=row_idx, column=1).fill = orange_fill  # CVE_ID
                        status_cell.fill = orange_fill

                wb.save(COORDINATED_LEDGER)
            st.success(f"Successfully processed and appended results into the master tracking ledger!")
        except Exception as e:
            st.error(f"Runtime processing error: {e}")

st.markdown("---")

# ==================================================================================== 
# SECTION 5: Single Source of Truth Viewer 
# ==================================================================================== 
if not os.path.exists(COORDINATED_LEDGER): 
    st.info("No historical tracking ledger detected yet. Run the pipeline above to initialize the master audit logs.") 
else: 
    # Read the full master ledger file containing all historical columns 
    master_ledger = pd.read_excel(COORDINATED_LEDGER, engine="openpyxl") 
    
    # Automatically identify all past audit columns from the ledger sheet 
    historical_audit_cols = sorted([col for col in master_ledger.columns if col.startswith("AUDIT_MARKING_")], reverse=True) 
    
    if not historical_audit_cols: 
        st.warning("Ledger file found, but no historical 'AUDIT_MARKING_' columns were detected.") 
    else: 
        selected_audit_col = historical_audit_cols[0] 
        
        # Isolate dates for display logic (Extracting YYYYMMDD prefix) 
        selected_date_str = selected_audit_col.replace("AUDIT_MARKING_", "") 
        corresponding_status_col = f"DATA_STATUS_{selected_date_str}" 
        
        # Calculate snapshot counts for the selected session date 
        total_audit_rows = len(master_ledger) 
        fail_count = len(master_ledger[master_ledger[selected_audit_col] == "NOT_IN_KEV / VERIFY REQUIRED"]) 
        pass_count = total_audit_rows - fail_count 
        

        st.subheader(f"Tracking Snapshot: {selected_date_str}")
        
        # Display Historical KPI widgets for the selected session date 
        metric_col1, metric_col2, metric_col3 = st.columns(3) 
        metric_col1.metric(f"Total Audited Assets ({selected_date_str})", total_audit_rows) 
        metric_col2.metric("Historical PASS Count", pass_count) 
        metric_col3.metric("Historical REJECT / Orange Count", fail_count)

        
# Render Pie Chart for the selected session date
st.markdown(f"#### Compliance Chart Snapshot for Session: `{selected_date_str}`")

col1, col2 = st.columns([1, 2])

with col1:
    fig, ax = plt.subplots(figsize=(3, 3)) 
    
    pd.Series([pass_count, fail_count], index=["PASS", "NOT_IN_KEV"]).plot(
        kind="pie",
        autopct="%1.1f%%",
        startangle=90,
        colors=["#66BB6A", "#FFB366"],
        textprops={"fontsize": 9, "weight": "bold"},
        ax=ax
    )
    
    ax.set_ylabel("")
    fig.patch.set_alpha(0.0)
    

    st.pyplot(fig, use_container_width=False)
        
