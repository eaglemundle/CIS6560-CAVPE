import datetime
import os
import sys
import pandas as pd
import streamlit as st

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app_utils.config_manager import (
    DEFAULT_DATASET_PATH,
    REF_DATA_DIR,
    get_active_dataset_path,
    get_config_version,
    list_reference_datasets,
    load_active_dataset,
    update_dataset_path,
)

def to_clean_relpath(abs_path: str) -> str:
    """Convert an absolute path to a clean forward-slash relative path from project root."""
    try:
        return os.path.relpath(abs_path, ROOT_DIR).replace("\\", "/")
    except ValueError:
        return abs_path

EXCEL_FILE_PATH = DEFAULT_DATASET_PATH
COORDINATED_LEDGER_PATH = os.path.join(REF_DATA_DIR, "vulnerability_coordinated_ledger.xlsx")

active_path = get_active_dataset_path()
active_name = os.path.basename(active_path)
coord_name = os.path.basename(COORDINATED_LEDGER_PATH)
sample_name = os.path.basename(EXCEL_FILE_PATH)

# -------------------------------------------------------------
# 1. Reference Datasets Repository (Manage / Activate / Delete)
# -------------------------------------------------------------
st.title("Reference Datasets Repository")
st.caption(
    f"**Active Dataset:** `{to_clean_relpath(active_path)}`  |  "
    f"**Config Version:** `{get_config_version()}`"
)

files = sorted(
    list_reference_datasets(),
    key=lambda f: os.path.getmtime(os.path.join(REF_DATA_DIR, f)),
    reverse=True,
)

if files:
    with st.container(border=True):
        inventory = []
        for f in files:
            fp = os.path.join(REF_DATA_DIR, f)
            stat = os.stat(fp)
            category = (
                "Generated Scenario" if f.startswith("generated_")
                else "Coordinated Ledger" if "coordinated" in f.lower()
                else "Baseline Sample" if f == sample_name
                else "Custom / Uploaded"
            )
            inventory.append({
                "Status": "ACTIVE" if f == active_name else "",
                "Filename": f,
                "Category": category,
                "Size (KB)": round(stat.st_size / 1024, 1),
                "Last Modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        st.dataframe(pd.DataFrame(inventory), use_container_width=True, hide_index=True)

        selected_file = st.selectbox("Select Dataset to Manage", options=files)
        target_fp = os.path.join(REF_DATA_DIR, selected_file)

        c1, c2, c3 = st.columns([2, 2, 1.5])
        if c1.button("Set as Active Dataset", type="primary", use_container_width=True):
            ok, err = update_dataset_path(target_fp, validate=True, note="Activated from Dataset Manager")
            if ok:
                st.success(f"Activated `{selected_file}` ({get_config_version()})")
                st.rerun()
            else:
                st.error(f"Activation rejected: {err}")

        with open(target_fp, "rb") as raw_f:
            c2.download_button("Download File", data=raw_f.read(), file_name=selected_file, use_container_width=True)

        is_protected = selected_file in (sample_name, coord_name, active_name)
        if c3.button("Delete File", disabled=is_protected, use_container_width=True):
            os.remove(target_fp)
            st.success(f"Deleted `{selected_file}`")
            st.rerun()

st.markdown("---")

# -------------------------------------------------------------
# 2. Active Configured Dataset Section (Synced with System Config)
# -------------------------------------------------------------
st.title(f"Active Dataset")
st.caption(f"Source Path: `{to_clean_relpath(active_path)}`")

try:
    df_active = load_active_dataset(validate=False).copy()
    with st.container(border=True):
        if "Data status" in df_active.columns and any(col.startswith("Data_Status_") for col in df_active.columns):
            df_active = df_active.drop(columns=["Data status"])

        active_num_config = {
            col: st.column_config.NumberColumn(format="%.2f")
            for col in df_active.select_dtypes(include=["float"]).columns
        }
        st.dataframe(df_active, use_container_width=True, hide_index=True, height=350, column_config=active_num_config)
except Exception as e:
    st.error(f"Error reading active dataset: {e}")

st.markdown("---")

# -------------------------------------------------------------
# 3. Validated Coordinated Output Section
# -------------------------------------------------------------
st.title(f"Coordinated Dataset")
st.caption(f"Source Path: `{to_clean_relpath(COORDINATED_LEDGER_PATH)}`")

if os.path.exists(COORDINATED_LEDGER_PATH):
    try:
        df_coordinated = pd.read_excel(COORDINATED_LEDGER_PATH)
        with st.container(border=True):
            df_sorted = df_coordinated.sort_values(by="Contextual risk score", ascending=False)

            if "Data status" in df_sorted.columns and any(col.startswith("Data_Status_") for col in df_sorted.columns):
                df_sorted = df_sorted.drop(columns=["Data status"])

            front_cols = [
                c for c in [
                    "Contextual risk score", "CVSS base score", "Contextual priority",
                    "Illustartive contextual priority", "Min remediation effort (hours)"
                ] if c in df_sorted.columns
            ]
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
                column_config=display_config,
            )
    except Exception as e:
        st.error(f"Error reading coordinated ledger dataset: {e}")
else:
    st.warning(f"Coordinated dataset ledger not generated yet at path: `{to_clean_relpath(COORDINATED_LEDGER_PATH)}`")
    st.info("Run the validation engine processing step to build your single source of truth tracking matrix.")

st.markdown("---")

# -------------------------------------------------------------
# 4. Source Input Module Section
# -------------------------------------------------------------
st.title(f"Project-Supplied Sample Dataset")
st.caption(f"Source Path: `{to_clean_relpath(EXCEL_FILE_PATH)}`")

if os.path.exists(EXCEL_FILE_PATH):
    try:
        df_sample = pd.read_excel(EXCEL_FILE_PATH)
        with st.container(border=True):
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
                column_config=sample_num_config,
            )
    except Exception as e:
        st.error(f"Error reading sample excel dataset: {e}")
else:
    st.warning(f"Sample dataset not found at path: `{to_clean_relpath(EXCEL_FILE_PATH)}`")

st.markdown("---")
