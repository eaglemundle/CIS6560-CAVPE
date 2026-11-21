import streamlit as st
import os
from datetime import datetime
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("America/Toronto")

# 1. Global Page Config (Must be the absolute first Streamlit command)
st.set_page_config(
    page_title="Context-Aware Vulnerability Prioritization Engine",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Sidebar HTML Injection for Last Modified Metadata
file_path = __file__
if os.path.exists(file_path):
    mtime = os.path.getmtime(file_path)
    last_modified_date = datetime.fromtimestamp(mtime, tz=LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
    
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

# 3. Main Dashboard Renderer
def render_home_page():
    st.title("Context-Aware Vulnerability Prioritization Engine")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", width='stretch'):
            st.switch_page("Legacy_Dashboard.py")
            
    with col2:
        st.subheader("Old Version 1.0")
        st.caption("Before Nov 2")
        if st.button("Run Old V1.0", key="go_v1_old", width='stretch'):
            st.switch_page("pages/01_SOC_Main.py")
            
    with col3:
        st.subheader("Version 1.0")
        st.caption("Development")
        if st.button("Run Dev V1.7", key="go_v1_dev", type="primary", width='stretch'):
            st.switch_page("pages/00_v1_dashboard.py")
            
    with col4:
        st.subheader("Version 2.0")
        st.caption("Latest Development")
        if st.button("Run Version 2.0", key="go_v2", type="primary", width='stretch'):
            st.switch_page("pages/00_v2_Patch_Difficulty.py")

    st.markdown("<br>", unsafe_allow_html=True)
    st.divider()
    st.subheader("Calendar & Project Documentation")
    st.write("View the current schedule and official project artifacts.")
    
    doc_col1, doc_col2, doc_col3, doc_col4 = st.columns(4)
    with doc_col1:
        if st.button("Open Project Calendar", key="go_calendar", width='stretch'):
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
                    width='stretch',
                    key="download_charter",
                    help="Click to download the local Project Charter file."
                )
        else:
            st.error("File missing: doc/project_charter.pdf")

# Resolve absolute directory of app.py to ensure consistent path resolution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOC_MAIN_FILE = "00_SOC_Main.py"

# 3. Main Dashboard Renderer
def render_home_page():
    st.title("Context-Aware Vulnerability Prioritization Engine")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", width='stretch'):
            st.switch_page(os.path.join(BASE_DIR, "Legacy_Dashboard.py"))
            
    with col2:
        st.subheader("SOC Main (Latest)")
        st.caption("Primary Dashboard")
        if st.button("Run SOC Main", key="go_v1_old", type="primary", width='stretch'):
            st.switch_page(os.path.join(BASE_DIR, "pages", SOC_MAIN_FILE))
            
    with col3:
        st.subheader("Version 1.0")
        st.caption("Development")
        if st.button("Run Dev V1.7", key="go_v1_dev", width='stretch'):
            st.switch_page(os.path.join(BASE_DIR, "pages", "00_v1_dashboard.py"))
            
    with col4:
        st.subheader("Version 2.0")
        st.caption("Latest Development")
        if st.button("Run Version 2.0", key="go_v2", width='stretch'):
            st.switch_page(os.path.join(BASE_DIR, "pages", "00_v2_Patch_Difficulty.py"))

    st.markdown("<br>", unsafe_allow_html=True)
    st.divider()
    st.subheader("Calendar & Project Documentation")
    st.write("View the current schedule and official project artifacts.")
    
    doc_col1, doc_col2, doc_col3, doc_col4 = st.columns(4)
    with doc_col1:
        if st.button("Open Project Calendar", key="go_calendar", width='stretch'):
            st.switch_page(os.path.join(BASE_DIR, "cavpe_calendar.py"))
            
    with doc_col2:
        doc_path = os.path.join(BASE_DIR, "doc", "project_charter.pdf")
        if os.path.exists(doc_path):
            with open(doc_path, "rb") as file:
                st.download_button(
                    label="Download Project Charter",
                    data=file,
                    file_name=os.path.basename(doc_path),
                    mime="application/octet-stream",
                    width='stretch',
                    key="download_charter",
                    help="Click to download the local Project Charter file."
                )
        else:
            st.error("File missing: doc/project_charter.pdf")

# 4. Explicitly Setup Page Objects
# home_page = st.Page(render_home_page, title="Home Selector")
soc_main_path = os.path.join(BASE_DIR, "pages", SOC_MAIN_FILE)
soc_main_page = st.Page(soc_main_path, title="SOC Main", default=True)

# 5. Dynamically Collect Pages with Safety Validation
pages_dir = os.path.join(BASE_DIR, "pages")
dynamic_pages = []

if os.path.exists(pages_dir):
    sorted_files = sorted(os.listdir(pages_dir))
    for filename in sorted_files:
        # Exclude 00_SOC_Main.py since it is registered explicitly as default
        if filename.endswith(".py") and filename != SOC_MAIN_FILE:
            full_path = os.path.join(pages_dir, filename)
            dynamic_pages.append(full_path)

# 6. Construct Strict Framework Data Structure
pages_dict = {
    "Main Menu": [
        soc_main_page
        # home_page,
        # os.path.join(BASE_DIR, "cavpe_calendar.py")
        # os.path.join(BASE_DIR, "Legacy_Dashboard.py")
    ],
    "Pages Directory": dynamic_pages
}

# 7. Single Entry Navigation Instance Execution
pg = st.navigation(pages_dict, position="sidebar", expanded=True)
pg.run()


