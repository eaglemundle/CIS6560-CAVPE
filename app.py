import streamlit as st
import os
from datetime import datetime

if "selected_version" not in st.session_state:
    st.session_state.selected_version = None

if st.session_state.selected_version is None:
    st.set_page_config(
        page_title="Context-Aware Vulnerability Prioritization Engine Version Selector",
        layout="wide",
        initial_sidebar_state="expanded"
    )

# File modification metadata tracking
file_path = __file__
mtime = os.path.getmtime(file_path)
last_modified_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

# Sidebar Metadata Display
st.sidebar.divider()
st.sidebar.caption(f"**Last Modified:** {last_modified_date}")

# Multi-page navigation
calendar_page = st.Page("cavpe_calendar.py", title="Calendar")
v0_page = st.Page("Legacy_Dashboard.py", title="Version 0.0 (before Oct 14)")
v1_old_page = st.Page("pages/01_SOC_Main.py", title="Old Version 1.0 (before Nov 2)")
v1_dev_page = st.Page("pages/01_v1_dashboard.py", title="Version 1.0 (Development)")
v2_page = st.Page("pages/01_v2_dashboard.py", title="Version 2.0 (Latest)")  # Added Version 2.0

if st.session_state.selected_version is None:
    st.title("Context-Aware Vulnerability Prioritization Engine")
    col1, col2, col3, col4 = st.columns(4)

    # Column 1: Legacy Version 0.0
    with col1:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", use_container_width=True):
            st.session_state.selected_version = v0_page
            st.rerun()

    # Column 2: Old Version 1.0 (Before Nov 2)
    with col2:
        st.subheader("Old Version 1.0")
        st.caption("Before Nov 2")
        if st.button("Run Old V1.0", key="go_v1_old", use_container_width=True):
            st.session_state.selected_version = v1_old_page
            st.rerun()

    # Column 3: Active Development Version 1.0
    with col3:
        st.subheader("Version 1.0")
        st.caption("Active Development")
        if st.button("Run Dev V1.7", key="go_v1_dev", type="primary",use_container_width=True):
            st.session_state.selected_version = v1_dev_page
            st.rerun()

    # Column 4: Version 2.0 (New)
    with col4:
        st.subheader("Version 2.0")
        st.caption("Latest Stable Version")
        if st.button("Run Version 2.0", key="go_v2", type="primary", use_container_width=True):
            st.session_state.selected_version = v2_page
            st.rerun()

    # Lower Section: Calendar & Project Documentation
    st.markdown("<br>", unsafe_allow_html=True)
    st.divider()
    
    st.subheader("Calendar & Project Documentation")
    st.write("View the current schedule and official project artifacts.")
    
    doc_col1, doc_col2, doc_col3, doc_col4 = st.columns(4)  
    
    with doc_col1:
        if st.button("Open Project Calendar", key="go_calendar", use_container_width=True):
            st.session_state.selected_version = calendar_page
            st.rerun()
            
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

else:
    pg = st.navigation([st.session_state.selected_version], position="sidebar", expanded=True)
    pg.run()
