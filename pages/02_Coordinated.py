import os
import pandas as pd
import streamlit as st

EXCEL_FILE_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
COORDINATED_LEDGER_PATH = "reference_data/vulnerability_coordinated_ledger.xlsx"

if st.session_state.get("df_sample_excel") is None and os.path.exists(EXCEL_FILE_PATH):
    try:
        st.session_state.df_sample_excel = pd.read_excel(EXCEL_FILE_PATH)
    except Exception as e:
        st.error(f"Error reading sample excel dataset: {e}")

if st.session_state.get("df_coordinated_excel") is None and os.path.exists(COORDINATED_LEDGER_PATH):
    try:
        st.session_state.df_coordinated_excel = pd.read_excel(COORDINATED_LEDGER_PATH)
    except Exception as e:
        st.error(f"Error reading coordinated ledger dataset: {e}")

# -------------------------------------------------------------
# Validated Coordinated Output Section
# -------------------------------------------------------------
st.title("Coordinated Dataset")

if st.session_state.get("df_coordinated_excel") is not None:
    with st.container(border=True):
        df_sorted = st.session_state.df_coordinated_excel.sort_values(
            by="Contextual risk score", ascending=False
        )
        
        if "Data status" in df_sorted.columns and any(col.startswith("Data_Status_") for col in df_sorted.columns):
            df_sorted = df_sorted.drop(columns=["Data status"])

        front_cols = [c for c in ["Contextual risk score", "CVSS base score", "Contextual priority", "Illustartive contextual priority", "Min remediation effort (hours)"] if c in df_sorted.columns]
        remaining_cols = [c for c in df_sorted.columns if c not in front_cols]
          
        df_sorted = df_sorted[front_cols + remaining_cols]

        display_config = {
            col: st.column_config.NumberColumn(format="%.2f") 
            for col in df_sorted.select_dtypes(include=["float"]).columns
        }

        st.dataframe(
            df_sorted, 
            use_container_width=True, 
            hide_index=True, 
            height=450,
            column_config=display_config
        )
else:
    st.warning(f"Coordinated dataset ledger not generated yet at path: {COORDINATED_LEDGER_PATH}")
    st.info("Run the validation engine processing step to build your single source of truth tracking matrix.")

# -------------------------------------------------------------
# Source Input Module Section
# -------------------------------------------------------------
st.title("Project-Supplied Sample Dataset")

if st.session_state.get("df_sample_excel") is not None:
    with st.container(border=True):
        df_sample = st.session_state.df_sample_excel.copy()
        
        if "Data status" in df_sample.columns and any(col.startswith("Data_Status_") for col in df_sample.columns):
            df_sample = df_sample.drop(columns=["Data status"])
            
        sample_num_config = {
            col: st.column_config.NumberColumn(format="%.2f") 
            for col in df_sample.select_dtypes(include=["float"]).columns
        }

        st.dataframe(
            df_sample, 
            use_container_width=True, 
            hide_index=True, 
            height=350,
            column_config=sample_num_config
        )
else:
    st.warning(f"Sample dataset not found at path: {EXCEL_FILE_PATH}")

st.markdown("---") 
