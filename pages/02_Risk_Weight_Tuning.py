import json, os, datetime
import streamlit as st

# Page Configuration - native multipage feature
st.set_page_config(
    page_title="Risk Weight Tuning Matrix",
    layout="wide",
    initial_sidebar_state="expanded"  # Forces the sidebar to stay open
)

S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)
E_DIR = os.path.join(P_DIR, "engines")
W_CONF = os.path.join(E_DIR, "weight_config.json")
B_DIR = os.path.join(E_DIR, "backups") # Target folder for version backups

st.title("Risk Weight Tuning Matrix")
st.markdown("Modify and tune mathematical risk engine multipliers with integrated version control.")

# 0. Core Configuration Loaders and Savers
def load_weights():
    if os.path.exists(W_CONF):
        try:
            with open(W_CONF, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return {"version": "1.0.0", "last_updated": str(datetime.datetime.now()), "weights": {}}

def save_weights_with_versioning(data, updated_weights):
    try:
        # Parse current version or fallback
        curr_ver = data.get("version", "1.0.0")
        parts = curr_ver.split(".")
        if len(parts) == 3:
            parts[-1] = str(int(parts[-1]) + 1) # Auto-increment patch version
            new_ver = ".".join(parts)
        else:
            new_ver = "1.0.1"

        # Update root structural metadata
        data["version"] = new_ver
        data["last_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["weights"] = updated_weights

        # Create backups folder if missing
        if not os.path.exists(B_DIR):
            os.makedirs(B_DIR)

        # Write historic backup trace snapshot file
        backup_filename = f"weight_config_v{new_ver}.json"
        with open(os.path.join(B_DIR, backup_filename), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        # Overwrite the production live matrix config file
        with open(W_CONF, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        st.success(f"Successfully committed and upgraded configuration layout to Version {new_ver}")
        return True
    except Exception as e:
        st.error(f"Failed to execute version commit rewrite pipeline: {e}")
        return False

config_data = load_weights()
weights = config_data.get("weights", {})
current_version = config_data.get("version", "1.0.0")
last_updated = config_data.get("last_updated", "Never")

# 1. Configuration Metadata Header Row
c_meta1, c_meta2 = st.columns(2)
c_meta1.metric(label="Active Weights Profile Version", value=f"v{current_version}")
c_meta2.metric(label="Last Structural Modification Timetrace", value=last_updated)
st.markdown("---")

if weights:
    # 2. Interactive Tuning Interface Split Matrix
    st.subheader("Adjust Mathematical Multipliers")
    updated_weights = {}
    col1, col2 = st.columns(2)
    
    for idx, (k, v) in enumerate(weights.items()):
        target_col = col1 if idx % 2 == 0 else col2
        label = k.replace("_", " ").title()
        
        if isinstance(v, (int, float)):
            updated_weights[k] = target_col.number_input(
                label=f"{label} (Multiplier)",
                min_value=0.0, max_value=1.0, value=float(v), step=0.01, format="%.2f"
            )
        else:
            updated_weights[k] = target_col.text_input(label=label, value=str(v))
            
    st.markdown("---")
    
    # 3. Commit Execution Triggers
    if st.button("Save Weight Configurations & Bump Version", use_container_width=True):
        if save_weights_with_versioning(config_data, updated_weights):
            st.rerun()
        
    # 4. Storage Diagnostic Tree Previews
    col_l, col_r = st.columns(2)
    with col_l:
        st.subheader("Staged State Payload Map Preview")
        st.json(updated_weights)
    with col_r:
        st.subheader("Raw File Serialization Tree Profile")
        st.json(config_data)
else:
    st.error("weight_config.json configuration structure could not be mapped or file is missing.")
    st.info(f"Target profile path: `{W_CONF}`")
