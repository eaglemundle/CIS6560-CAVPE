import json, os
import streamlit as st

st.set_page_config(page_title="Taxonomy Registry Setup", layout="wide")

S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)
R_CONF = os.path.join(P_DIR, "engines", "taxonomy_registry.json")

st.title("Taxonomy Registry Management")
st.markdown("This view dynamically loads and displays options directly parsed from **`taxonomy_registry.json`**.")

def load_registry():
    if os.path.exists(R_CONF):
        try:
            with open(R_CONF, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            st.error(f"Failed to read JSON: {e}")
    return None

raw_data = load_registry()

if raw_data is not None:
    st.success("Connected successfully to engines/taxonomy_registry.json")
    
    # Extract keys or lists safely
    opts = []
    if isinstance(raw_data, dict):
        opts = raw_data.get("registered_taxonomies", [])
    elif isinstance(raw_data, list):
        opts = raw_data
        
    c1, c2 = st.columns(2)
    c1.metric(label="Registered Taxonomies", value=len(opts))
    c2.metric(label="Data Layout Strategy", value="Dictionary Object" if isinstance(raw_data, dict) else "Flat List Array")
        
    st.markdown("---")
    
    col_l, col_r = st.columns(2)
    with col_l:
        st.subheader("Parsed Selectable Options Queue")
        if opts:
            for opt in opts: st.info(str(opt))
        else:
            st.warning("The parsed options collection list inside the registry is currently empty.")
            
    with col_r:
        st.subheader("Raw JSON Context Tree View")
        st.json(raw_data)
else:
    st.error("taxonomy_registry.json file could not be found.")
    st.info(f"Expected path: `{R_CONF}`")
