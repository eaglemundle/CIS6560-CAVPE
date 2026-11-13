import os
import sys
import json
import pandas as pd
import streamlit as st
import numpy as np

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app_utils.config_manager import get_active_dataset_path

EXCEL_FILE_PATH = get_active_dataset_path()
COORDINATED_LEDGER_PATH = os.path.join(ROOT_DIR, "reference_data", "vulnerability_coordinated_ledger.xlsx")
REMEDIATION_JSON_PATH = os.path.join(ROOT_DIR, "engines", "remediation_weights.json")
WEIGHT_CONFIG_JSON_PATH = os.path.join(ROOT_DIR, "engines", "weight_config.json")

# --- Load remediation mapping data directly from JSON ---
with open(REMEDIATION_JSON_PATH, "r", encoding="utf-8") as f:
    rem_data = json.load(f)

effort_weight_map = rem_data["effort_weights"]
complexity_order = rem_data["complexity_order"]
patch_complexity_descriptions = rem_data["patch_complexity_descriptions"]

# --- Load risk scoring configuration directly from JSON ---
with open(WEIGHT_CONFIG_JSON_PATH, "r", encoding="utf-8") as f:
    risk_data = json.load(f)

raw_risk_data = risk_data
weights_config = risk_data["weights"]
selected_preset = risk_data["selected_preset"]

# --- Load Excel/CSV datasets ---
if (
    st.session_state.get("df_sample_excel") is None
    or st.session_state.get("loaded_dataset_path") != EXCEL_FILE_PATH
):
    if os.path.exists(EXCEL_FILE_PATH):
        try:
            if EXCEL_FILE_PATH.lower().endswith(".csv"):
                st.session_state.df_sample_excel = pd.read_csv(EXCEL_FILE_PATH)
            else:
                st.session_state.df_sample_excel = pd.read_excel(EXCEL_FILE_PATH)
            st.session_state.loaded_dataset_path = EXCEL_FILE_PATH
        except Exception as e:
            st.error(f"Error reading sample dataset: {e}")

if st.session_state.get("df_coordinated_excel") is not None:
    pass
elif os.path.exists(COORDINATED_LEDGER_PATH):
    try:
        st.session_state.df_coordinated_excel = pd.read_excel(COORDINATED_LEDGER_PATH)
    except Exception as e:
        st.error(f"Error reading coordinated ledger dataset: {e}")


# --- Active Dataset Status & Schema Health ---
st.subheader("Active Dataset Status")
if os.path.exists(current_dataset_path):
    is_valid, schema_err = validate_file_schema(current_dataset_path)
    if is_valid:
        st.success(f"**Current Active Dataset:** `{current_dataset_path}` (Schema Validated)")
    else:
        st.error(f"**Active Dataset Schema Error:** `{current_dataset_path}` — {schema_err}")
else:
    st.warning(f"**Configured Dataset Not Found:** `{current_dataset_path}`")

with st.expander("View Required Dataset Schema & Detected Columns"):
    st.write("**Required Columns (`REQUIRED_COLUMNS`):**")
    st.code(", ".join(REQUIRED_COLUMNS) if REQUIRED_COLUMNS else "(None - All schemas allowed)", language="text")

    if os.path.exists(current_dataset_path):
        try:
            if current_dataset_path.lower().endswith(".csv"):
                sample_cols = list(pd.read_csv(current_dataset_path, nrows=0).columns)
            else:
                sample_cols = list(pd.read_excel(current_dataset_path, nrows=0).columns)
            st.write("**Actual Columns Detected in Current File:**")
            st.code(", ".join(str(c) for c in sample_cols), language="text")
        except Exception as e:
            st.write(f"Could not read file headers: {e}")

st.markdown("---")

# --- Change Target Dataset ---
st.subheader("Change Target Dataset")
operator_name = st.text_input(
    "Operator Name (Optional — auto-detects client IP if left blank)",
    value=st.session_state.get("current_user", ""),
    placeholder="e.g., Analyst Name",
)

# Default Tab = Select from Reference Folder
tab_select, tab_upload, tab_manual = st.tabs([
    "Select from Reference Folder",
    "Upload New Dataset",
    "Manual Path Input",
])

# Option 1 (Default): Select an existing file sorted by newest first
with tab_select:
    raw_files = list_reference_datasets()
    available_files = sorted(
        raw_files,
        key=lambda f: os.path.getmtime(os.path.join(REF_DATA_DIR, f)),
        reverse=True,
    )
    if available_files:
        current_filename = os.path.basename(current_dataset_path)
        default_idx = available_files.index(current_filename) if current_filename in available_files else 0

        selected_file = st.selectbox(
            "Select an existing dataset in reference_data/ (Newest first)",
            options=available_files,
            index=default_idx,
        )

        if st.button("Apply Selected Dataset", type="primary"):
            selected_full_path = os.path.join(REF_DATA_DIR, selected_file)
            ok, err = update_dataset_path(
                selected_full_path, validate=True, note="Selected from reference_data", changed_by=operator_name
            )
            if ok:
                st.success(f"Dataset switched to: `{selected_file}`")
                st.rerun()
            else:
                st.error(f"Selection rejected — {err}")
    else:
        st.info("No dataset files (.xlsx, .csv) found in the `reference_data` directory.")

# Option 2: Upload a new dataset file
with tab_upload:
    uploaded_file = st.file_uploader(
        "Upload a new dataset file (.xlsx, .xls, .csv)",
        type=["xlsx", "xls", "csv"],
    )
    if uploaded_file is not None:
        if st.button("Save & Apply Uploaded Dataset", type="primary"):
            is_valid, err_msg = validate_file_schema(uploaded_file)
            if not is_valid:
                st.error(f"Upload rejected — {err_msg}")
            else:
                save_path = os.path.join(REF_DATA_DIR, uploaded_file.name)
                try:
                    with open(save_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())

                    ok, err = update_dataset_path(
                        save_path, validate=False, note="Uploaded new dataset", changed_by=operator_name
                    )
                    if ok:
                        st.success(f"Uploaded and applied: `{uploaded_file.name}`")
                        st.rerun()
                    else:
                        st.error(f"Failed to update config: {err}")
                except Exception as e:
                    st.error(f"Failed to save uploaded file: {e}")

# Option 3: Manually enter the full dataset path
with tab_manual:
    new_dataset_path = st.text_input("Target Raw Dataset Location Path", value=current_dataset_path)
    if st.button("Update Manual Path"):
        if new_dataset_path != current_dataset_path:
            ok, err = update_dataset_path(
                new_dataset_path, validate=True, note="Manual path update", changed_by=operator_name
            )
            if ok:
                st.success("Dataset location path tracking committed successfully.")
                st.rerun()
            else:
                st.error(f"Path update rejected — {err}")

# --- Version History Log ---
st.markdown("---")
history = get_version_history()
with st.expander("Configuration Version History", expanded=bool(history)):
    if history:
        st.dataframe(pd.DataFrame(history), hide_index=True, use_container_width=True)
    else:
        st.caption("No version changes recorded yet (Baseline v1.0.0).")

st.write(f"**NVD Authorized Token Active:** `{'Yes (Key Detected)' if API_KEY else 'No (Anonymized Request Constraints Apply)'}`")
