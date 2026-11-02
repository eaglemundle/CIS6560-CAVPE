import os, json
import streamlit as st

st.set_page_config(page_title="System Configuration", layout="wide")

S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)
W_CONF = os.path.join(P_DIR, "engines", "weight_config.json")

def load_config():
    if os.path.exists(W_CONF):
        try: return json.load(open(W_CONF, "r", encoding="utf-8"))
        except: pass
    return {}

config_data = load_config()

REPORTS_DIR = "scan_reports"
API_KEY = os.getenv("NVD_API_KEY", "")
DEFAULT_PATH = os.path.abspath(os.path.join(P_DIR, "reference_data", "vulnerability_contextualization_scanner_sample_updated.xlsx"))
DATASET_PATH = config_data.get("dataset_path", DEFAULT_PATH)

st.title("System Configuration")

# Display active version metric at the top
st.write(f"**Active Configuration Version:** `v{config_data.get('version', '1.0.0')}`")

st.markdown("---")

# Render input element on its own clean vertical row boundary
new_dataset_path = st.text_input("Target Raw Dataset Location Path", value=DATASET_PATH)
if new_dataset_path != DATASET_PATH:
    config_data["dataset_path"] = new_dataset_path
    try:
        with open(W_CONF, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)
        st.success("Dataset location path tracking committed successfully.")
        st.rerun()
    except Exception as e:
        st.error(f"Failed to commit system file path modification: {e}")

st.markdown("---")

# Environment token status and scan routing traces placed at the very bottom
st.write(f"**NVD Authorized Token Active:** `{'Yes (Key Detected)' if API_KEY else 'No (Anonymized Request Constraints Apply)'}`")

#st.write(f"**Target Scan Directory Route:** `{REPORTS_DIR}/`")
