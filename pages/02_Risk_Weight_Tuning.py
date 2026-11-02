import json, os, datetime
import streamlit as st

S_DIR = os.path.dirname(os.path.abspath(__file__))
# Target deployment path mapped safely into engines directory architecture
W_CONF = os.path.join(os.path.dirname(S_DIR), "engines", "weight_config.json")

st.title("Risk Weight Tuning Matrix")

# Preset configuration profiles optimized for the requested structural order
PRESETS = {
    "Custom Profile": None,
    "Asset Criticality Model": {
        "asset_value": 0.25, 
        "exploit_evidence": 0.10, 
        "exposure": 0.20, 
        "compensating_controls": 0.10, 
        "business_impact": 0.30, 
        "patch_feasibility": 0.05, 
        "severity": 0.00
    },
    "Patch Complexity Model": {
        "asset_value": 0.10, 
        "exploit_evidence": 0.15, 
        "exposure": 0.10, 
        "compensating_controls": 0.20, 
        "business_impact": 0.10, 
        "patch_feasibility": 0.35, 
        "severity": 0.00
    }
}

# Load current active profile settings from disk
try:
    with open(W_CONF, "r", encoding="utf-8") as f:
        config_data = json.load(f)
except:
    config_data = {
        "taxonomy_name": "CIS6560_Risk_Scoring_Weights_OptionB",
        "version": "1.3.0",
        "selected_preset": "Custom Profile",
        "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "weights": {"asset_value": 0.25, "exploit_evidence": 0.25, "exposure": 0.10, "compensating_controls": 0.15, "business_impact": 0.15, "patch_feasibility": 0.10, "severity": 0.00}
    }

weights = config_data.get("weights", {})
saved_preset_name = config_data.get("selected_preset", "Custom Profile")

# Resolve proper dropdown baseline position index mapping
preset_keys = list(PRESETS.keys())
try:
    default_index = preset_keys.index(saved_preset_name)
except ValueError:
    default_index = 0

selected_preset = st.selectbox("Select Profile Preset:", preset_keys, index=default_index)
updated_weights = {}

# Exact structural sequence alignment: asset value, exploit evidence, exposure, compensating_controls, business_impact, and patch feasibility.
target_keys = ["asset_value", "exploit_evidence", "exposure", "compensating_controls", "business_impact", "patch_feasibility", "severity"]

for k in target_keys:
    # Resolve initial default metrics based on profile selection triggers
    if PRESETS[selected_preset] is not None:
        initial_val = float(PRESETS[selected_preset].get(k, 0.0))
    else:
        # If toggling back to Custom Profile, fallback to current loaded file parameters
        initial_val = float(weights.get(k, 0.0))
        
    label_name = "severity (CVSS base score)" if k == "severity" else k
    updated_weights[k] = st.number_input(label=f"{label_name} weight multiplier", min_value=0.0, max_value=1.0, value=initial_val, step=0.01, format="%.2f", key=f"k_{k}_{selected_preset}")

st.markdown("---")

# Compliance check calculation logic
weights_sum = sum(updated_weights.values())

if round(weights_sum, 2) == 1.00:
    st.success(f"Governance Compliant: Weight sum equals {weights_sum:.2f}")
    if st.button("Save Weight Configurations", use_container_width=True):
        # Update both parameters block, chosen model string tracker, and root serialization timetrace data safely
        config_data["selected_preset"] = selected_preset
        config_data["last_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        config_data["weights"] = updated_weights
        
        os.makedirs(os.path.dirname(W_CONF), exist_ok=True)
        with open(W_CONF, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)
        st.success("Configuration successfully deployed.")
        st.rerun()
else:
    st.error(f"Non-Compliant Grid Matrix: Total weight must equal 1.00 (Current: {weights_sum:.2f})")

# --- Production Deployment Real-Time File Blueprint Inspector ---
st.markdown("---")
st.subheader("Saved JSON File Configuration Snapshot View")
if os.path.exists(W_CONF):
    try:
        with open(W_CONF, "r", encoding="utf-8") as f:
            current_file_state = json.load(f)
        st.json(current_file_state)
    except:
        st.info("System baseline file currently active in transient memory state.")
else:
    st.info("System baseline file currently active in transient memory state.")
