import os
import pandas as pd
import streamlit as st

# local data warehouse paths
EXCEL_FILE_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
COORDINATED_LEDGER_PATH = "reference_data/vulnerability_coordinated_ledger.xlsx"

# 1. original raw sample dataset
if st.session_state.get("df_sample_excel") is None and os.path.exists(EXCEL_FILE_PATH):
    try:
        st.session_state.df_sample_excel = pd.read_excel(EXCEL_FILE_PATH)
    except Exception as e:
        st.error(f"Error reading sample excel dataset: {e}")

# 2. verified coordinated ledger master dataset
if st.session_state.get("df_coordinated_excel") is None and os.path.exists(COORDINATED_LEDGER_PATH):
    try:
        st.session_state.df_coordinated_excel = pd.read_excel(COORDINATED_LEDGER_PATH)
    except Exception as e:
        st.error(f"Error reading coordinated ledger dataset: {e}")

# -------------------------------------------------------------
#  A: Render Source Input Module Section
# -------------------------------------------------------------
st.title("Sample Dataset")

if st.session_state.get("df_sample_excel") is not None:
    with st.container(border=True):
        st.dataframe(st.session_state.df_sample_excel, use_container_width=True, hide_index=True, height=350)
else:
    st.warning(f"Sample dataset not found at path: {EXCEL_FILE_PATH}")

st.markdown("---") # Visual horizontal rule separator

# -------------------------------------------------------------
#  B: Render Validated Coordinated Output Section
# -------------------------------------------------------------
st.title("Coordinated Dataset")

if st.session_state.get("df_coordinated_excel") is not None:
    with st.container(border=True):
        # Displays the permanent master tracking ledger across the full monitor width
        st.dataframe(st.session_state.df_coordinated_excel, use_container_width=True, hide_index=True, height=450)
else:
    # If the pipeline hasn't been run yet, provide an informative alert status
    st.warning(f"Coordinated dataset ledger not generated yet at path: {COORDINATED_LEDGER_PATH}")
    st.info("Run the validation engine processing step to build your single source of truth tracking matrix.")
