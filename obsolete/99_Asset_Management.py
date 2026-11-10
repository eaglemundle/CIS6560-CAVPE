import os
import pandas as pd
import streamlit as st

CSV_FILE_PATH = "reference_data/Inventory_Lists.csv"

if st.session_state.get("df_assets") is None and os.path.exists(CSV_FILE_PATH):
    try:
        st.session_state.df_assets = pd.read_csv(CSV_FILE_PATH)
    except Exception as e:
        st.error(f"Error reading asset inventory: {e}")

st.title("Asset Management - Lab Inventory")

if st.session_state.df_assets is not None:
    with st.container(border=True):
        st.session_state.df_assets = st.data_editor(
            st.session_state.df_assets, 
            use_container_width=True, 
            hide_index=True, 
            num_rows="dynamic"
        )
else:
    st.warning("No asset inventory data found or loaded. Check reference_data/Inventory_Lists.csv path.")