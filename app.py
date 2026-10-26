import streamlit as st
import os

# Define pages for multi-page navigation
calendar_page = st.Page("cavpe_calendar.py", title="Calendar")
v0_page = st.Page("Legacy_Dashboard.py", title="Version 0.0 (before Oct 14)")
v1_page = st.Page("pages/01_SOC_Main.py", title="Version 1.0 (Development)")

# Initialize session state for version selection
if "selected_version" not in st.session_state:
    st.session_state.selected_version = None

# Display version selection screen if no version is selected
if st.session_state.selected_version is None:

    st.set_page_config(
        page_title="Context-Aware Vulnerability Prioritization Engine Version Selector",
        layout="centered",
    initial_sidebar_state="expanded"  # Forces the sidebar to stay open
    )

    st.title("Context-Aware Vulnerability Prioritization Engine")
    st.subheader("Version Selection")
    st.write("Select a system version to run. (V0.0: Streamlit Test | V1.0: In Development)")
    st.divider()

    # Main 3-column layout
    col1, col2, col3 = st.columns(3)

    # Column 1: Schedule & Project Documentation
    with col1:
        st.subheader("Calendar & Docs")
        st.caption("View schedule & charter")
        
        # Split Column 1 into two sub-columns for horizontal button placement
        sub_col1, sub_col2 = st.columns(2)
        
        with sub_col1:
            # Navigation button to Calendar page
            if st.button("Open Calendar", key="go_calendar", width="stretch"):
                st.session_state.selected_version = calendar_page
                st.rerun()
                
        with sub_col2:
            # Local file download button for Project Charter
            file_path = "doc/project_charter.pdf" 
            if os.path.exists(file_path):
                with open(file_path, "rb") as file:
                    st.download_button(
                        label="Project Charter",
                        data=file,
                        file_name=os.path.basename(file_path),
                        mime="application/octet-stream",
                        width="stretch",
                        key="download_charter",
                        help="Click to download the local Project Charter file."
                    )
            else:
                st.error("File missing")

    # Column 2: Legacy Version 0.0
    with col2:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", width="stretch"):
            st.session_state.selected_version = v0_page
            st.rerun()

    # Column 3: Active Development Version 1.0
    with col3:
        st.subheader("Version 1.0")
        st.caption("In Development")
        if st.button("Run Version 1.0", key="go_v1", type="primary", width="stretch"):
            st.session_state.selected_version = v1_page
            st.rerun()

# Run navigation if a specific page/version is active
else:
    pg = st.navigation([st.session_state.selected_version], position="sidebar", expanded=True)
    pg.run()
