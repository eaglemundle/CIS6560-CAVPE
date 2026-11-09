import streamlit as st
import os
from datetime import datetime

# Global Streamlit Page Configuration (Must be called at the very top)
st.set_page_config(
    page_title="Context-Aware Vulnerability Prioritization Engine",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Function to render the central version selector dashboard (app.py main content)
def render_home_page():
    st.title("Context-Aware Vulnerability Prioritization Engine")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Column 1: Legacy Version 0.0
    with col1:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", use_container_width=True):
            st.switch_page("Legacy_Dashboard.py")
            
    # Column 2: Old Version 1.0
    with col2:
        st.subheader("Old Version 1.0")
        st.caption("Before Nov 2")
        if st.button("Run Old V1.0", key="go_v1_old", use_container_width=True):
            st.switch_page("pages/01_SOC_Main.py")
            
    # Column 3: Active Development Version 1.0
    with col3:
        st.subheader("Version 1.0")
        st.caption("Active Development")
        if st.button("Run Dev V1.7", key="go_v1_dev", type="primary", use_container_width=True):
            st.switch_page("pages/01_v1_dashboard.py")
            
    # Column 4: Version 2.0 (New)
    with col4:
        st.subheader("Version 2.0")
        st.caption("Latest Stable Version")
        if st.button("Run Version 2.0", key="go_v2", type="primary", use_container_width=True):
            st.switch_page("pages/01_v2_dashboard.py")

    # Lower Section: Calendar & Project Documentation
    st.markdown("<br>", unsafe_allow_html=True)
    st.divider()
    st.subheader("Calendar & Project Documentation")
    st.write("View the current schedule and official project artifacts.")
    
    doc_col1, doc_col2, doc_col3, doc_col4 = st.columns(4)
    with doc_col1:
        if st.button("Open Project Calendar", key="go_calendar", use_container_width=True):
            st.switch_page("cavpe_calendar.py")
            
    with doc_col2:
        doc_path = "doc/project_charter.pdf"
        if os.path.exists(doc_path):
            with open(doc_path, "rb") as file:
                st.download_button(
                    label="Download Project Charter",
                    data=file,
                    file_name=os.path.basename(doc_path),
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="download_charter",
                    help="Click to download the local Project Charter file."
                )
        else:
            st.error("File missing: doc/project_charter.pdf")

# 1. Map the entrypoint file to a formal st.Page object
home_page = st.Page(render_home_page, title="Home Selector")

# 2. Dynamically scan and list all Python files inside the 'pages/' directory
pages_dir = "pages"
dynamic_pages = []

if os.path.exists(pages_dir):
    # Sort files alphabetically to respect the numeric prefixes (01_, 02_, etc.)
    sorted_files = sorted(os.listdir(pages_dir))
    for filename in sorted_files:
        if filename.endswith(".py"):
            full_path = os.path.join(pages_dir, filename).replace("\\", "/")
            dynamic_pages.append(full_path)

# 3. Configure Navigation Menu by passing the full list of generated paths
pages_dict = {
    "Main Menu": [
        home_page, 
        "cavpe_calendar.py",
        "Legacy_Dashboard.py"
    ],
    "Pages Directory": dynamic_pages
}

# 4. Render the comprehensive multi-page navigation framework on the sidebar
pg = st.navigation(pages_dict, position="sidebar", expanded=True)

# Display file modification metadata in the sidebar
file_path = __file__
if os.path.exists(file_path):
    mtime = os.path.getmtime(file_path)
    last_modified_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
    st.sidebar.caption(f"**Last Modified:** {last_modified_date}")
st.sidebar.divider()

# 5. Run the Streamlit Navigation Router
pg.run()
