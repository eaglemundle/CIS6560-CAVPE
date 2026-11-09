import streamlit as st
import os
from datetime import datetime

st.set_page_config(
    page_title="Context-Aware Vulnerability Prioritization Engine",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar HTML Injection for Last Modified
file_path = __file__
if os.path.exists(file_path):
    mtime = os.path.getmtime(file_path)
    last_modified_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
    
    st.markdown(
        f"""
        <style>
            [data-testid="stSidebarNav"]::before {{
                content: "Last Modified: {last_modified_date}";
                display: block;
                padding: 1rem 1rem 0.5rem 1rem;
                font-size: 0.8rem;
                color: var(--text-color);
                font-weight: bold;
                opacity: 0.7;
                border-bottom: 1px solid rgba(49, 51, 63, 0.2);
                margin-bottom: 1rem;
            }}
        </style>
        """,
        unsafe_allow_html=True
    )

def render_home_page():
    st.title("Context-Aware Vulnerability Prioritization Engine")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", use_container_width=True):
            st.switch_page("Legacy_Dashboard.py")
            
    with col2:
        st.subheader("Old Version 1.0")
        st.caption("Before Nov 2")
        if st.button("Run Old V1.0", key="go_v1_old", use_container_width=True):
            st.switch_page("pages/01_SOC_Main.py")
            
    with col3:
        st.subheader("Version 1.0")
        st.caption("Active Development")
        if st.button("Run Dev V1.7", key="go_v1_dev", type="primary", use_container_width=True):
            st.switch_page("pages/01_v1_dashboard.py")
            
    with col4:
        st.subheader("Version 2.0")
        st.caption("Latest Stable Version")
        if st.button("Run Version 2.0", key="go_v2", type="primary", use_container_width=True):
            st.switch_page("pages/01_v2_dashboard.py")

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

# Define explicitly to avoid duplicate page objects
home_page = st.Page(render_home_page, title="Home Selector")
calendar_page = st.Page("cavpe_calendar.py", title="Calendar")
legacy_page = st.Page("Legacy_Dashboard.py", title="Legacy Dashboard")

# Scan pages/ directory
pages_dir = "pages"
dynamic_pages_objects = []

if os.path.exists(pages_dir):
    sorted_files = sorted(os.listdir(pages_dir))
    for filename in sorted_files:
        if filename.endswith(".py"):
            full_path = os.path.join(pages_dir, filename).replace("\\", "/")
            # Generate st.Page object instead of raw strings to handle complex layouts smoothly
            clean_title = filename.replace(".py", "").replace("_", " ")
            dynamic_pages_objects.append(st.Page(full_path, title=clean_title))

# Combined dictionary structure
pages_dict = {
    "Main Menu": [home_page, calendar_page, legacy_page],
    "Pages Directory": dynamic_pages_objects
}

# Single call to st.navigation with default structural behavior
# Setting expanded=True keeps sections open, while we leverage strict object routing
pg = st.navigation(pages_dict, position="sidebar", expanded=True)

# Run router pipeline
pg.run()
