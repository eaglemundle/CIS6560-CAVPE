import os
import sys
import json
import pandas as pd
import streamlit as st
import numpy as np
from app_utils.config_manager import (
    get_active_dataset_path,
    validate_file_schema,
    REQUIRED_COLUMNS,
    list_reference_datasets,
    REF_DATA_DIR,
    update_dataset_path,
    update_default_taxonomy,
    get_version_history,
)



try:
    API_KEY = st.secrets.get("NVD_API_KEY", "")
except Exception:
    API_KEY = os.getenv("NVD_API_KEY", "")


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

EXCEL_FILE_PATH = get_active_dataset_path()
COORDINATED_LEDGER_PATH = os.path.join(ROOT_DIR, "reference_data", "vulnerability_coordinated_ledger.xlsx")
REMEDIATION_JSON_PATH = os.path.join(ROOT_DIR, "engines", "remediation_weights.json")
WEIGHT_CONFIG_JSON_PATH = os.path.join(ROOT_DIR, "engines", "weight_config.json")
TAXONOMY_REGISTRY_PATH = os.path.join(ROOT_DIR, "engines", "taxonomy_registry.json")

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


@st.cache_data(show_spinner=False)
def detect_impacted_files(root_dir):
    """Scan active project Python files that reference taxonomy_registry or active_taxonomy."""
    impacted = []
    keywords = ("taxonomy_registry.json", "active_taxonomy")
    ignore_dirs = {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".pytest_cache",
        "obsolete",
    }

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Prune ignored directories (including obsolete/) in-place
        dirnames[:] = [d for d in dirnames if d.lower() not in ignore_dirs]
        for fname in sorted(filenames):
            if fname.endswith(".py"):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                    if any(kw in content for kw in keywords):
                        rel_path = os.path.relpath(fpath, root_dir).replace("\\", "/")
                        impacted.append(rel_path)
                except OSError:
                    continue
    return impacted


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
current_dataset_path = get_active_dataset_path()

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

# --- Taxonomy Registry & Default Perspective Management ---
st.markdown("---")
st.subheader("Default Risk Taxonomy Configuration")

if os.path.exists(TAXONOMY_REGISTRY_PATH):
    try:
        with open(TAXONOMY_REGISTRY_PATH, "r", encoding="utf-8") as f:
            tax_registry = json.load(f)

        # Render high-contrast Dead Zone alert banner with dynamically scanned file references
        dead_zone_msg = tax_registry.get("_dead_zone_notice")
        impacted_files = detect_impacted_files(ROOT_DIR)

        if dead_zone_msg:
            if impacted_files:
                scope_items_html = "".join(
                    [f"<li><code>{path}</code></li>" for path in impacted_files]
                )
            else:
                scope_items_html = "<li>No direct file references detected.</li>"

            st.markdown(
                f"""
                <div style="
                    background-color: #FFF0F0;
                    border: 1px solid #D32F2F;
                    border-left: 6px solid #B71C1C;
                    border-radius: 6px;
                    padding: 14px 18px;
                    margin-bottom: 14px;
                    color: #212121;
                ">
                    <div style="
                        display: inline-block;
                        background-color: #B71C1C;
                        color: #FFFFFF;
                        font-size: 0.75rem;
                        font-weight: 700;
                        padding: 2px 8px;
                        border-radius: 4px;
                        letter-spacing: 0.05em;
                        margin-bottom: 8px;
                    ">
                        SYSTEM DEAD ZONE · CRITICAL IMPACT
                    </div>
                    <div style="font-size: 0.92rem; font-weight: 600; color: #7F0000; margin-bottom: 8px;">
                        {dead_zone_msg}
                    </div>
                    <div style="font-size: 0.85rem; font-weight: 600; color: #424242;">
                        Detected Referencing Files:
                    </div>
                    <ul style="margin: 4px 0 0 18px; padding: 0; font-size: 0.85rem; color: #333333;">
                        {scope_items_html}
                    </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

        registered_list = tax_registry.get("registered_taxonomies", [])
        current_default_key = tax_registry.get("active_default_taxonomy", "Option C")

        if registered_list:
            # Map system keys to display option names
            key_to_label = {
                item["system_key"]: item["option_name"] for item in registered_list
            }
            system_keys = list(key_to_label.keys())
            default_index = (
                system_keys.index(current_default_key)
                if current_default_key in system_keys
                else 0
            )

            selected_tax_key = st.selectbox(
                "Select Default Active Taxonomy Perspective",
                options=system_keys,
                index=default_index,
                format_func=lambda k: key_to_label.get(k, k),
            )

            if st.button("Save Default Taxonomy", type="primary"):
                ok, err = update_default_taxonomy(
                    selected_tax_key,
                    TAXONOMY_REGISTRY_PATH,
                    note=f"Default taxonomy set to {key_to_label[selected_tax_key]}",
                    changed_by=operator_name,
                )
                if ok:
                    # Synchronize current active session state immediately
                    st.session_state.active_taxonomy = selected_tax_key
                    st.success(f"Default taxonomy updated to: `{key_to_label[selected_tax_key]}`")
                    st.rerun()
                else:
                    st.error(f"Failed to update default taxonomy: {err}")


    except (OSError, json.JSONDecodeError) as e:
        st.error(f"Error reading `taxonomy_registry.json`: {e}")
else:
    st.warning(f"Registry file not found: `{TAXONOMY_REGISTRY_PATH}`")

# --- Version History Log ---
st.markdown("---")
history = get_version_history()
with st.expander("Configuration Version History", expanded=bool(history)):
    if history:
        st.dataframe(pd.DataFrame(history), hide_index=True, width='stretch')
    else:
        st.caption("No version changes recorded yet (Baseline v1.0.0).")

st.write(f"**NVD Authorized Token Active:** `{'Yes (Key Detected)' if API_KEY else 'No (Anonymized Request Constraints Apply)'}`")
