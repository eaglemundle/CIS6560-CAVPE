import datetime
import json
import math
import os
import socket
from zoneinfo import ZoneInfo

import streamlit as st

LOCAL_TZ = ZoneInfo("America/Toronto")
S_DIR = os.path.dirname(os.path.abspath(__file__))
W_CONF = os.path.join(os.path.dirname(S_DIR), "engines", "weight_config.json")


CHARTER_WEIGHTS = {
    "severity": 0.40,
    "exploited_in_the_wild": 0.15,
    "poc_exploit_availability": 0.10,
    "patch_difficulty": 0.10,
    "compensating_controls": 0.10,
    "asset_criticality": 0.10,
    "risk_transfer": 0.05,
}

WEIGHT_LABELS = {
    "severity": "Severity (CVSS 0-10)",
    "exploited_in_the_wild": "Exploited in the wild (0-2)",
    "poc_exploit_availability": "PoC exploit availability (0-2)",
    "patch_difficulty": "Patch difficulty (1-3)",
    "compensating_controls": (
        "Compensating controls (0-3; fewer controls score higher)"
    ),
    "asset_criticality": "Asset criticality (1-4)",
    "risk_transfer": "Risk transfer (0-2)",
}

PRESETS = {
    "Charter Default": CHARTER_WEIGHTS,
    "Custom Profile": None,
}

WEIGHT_CONFIG_KEYS = {
    "taxonomy_name",
    "version",
    "weights",
    "selected_preset",
    "last_updated",
    "last_updated_by",
    "version_history",
}


def _get_client_ip() -> str:
    """Detect client public IP on Streamlit Cloud or fallback to local IP."""
    try:
        headers = st.context.headers
        forwarded = headers.get("X-Forwarded-For") or headers.get("X-Real-Ip")
        if forwarded:
            return forwarded.split(",")[0].strip()
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "Unknown IP"


def _bump_patch_version(ver_str: str) -> str:
    """Increment patch version (e.g., 2.0.0 -> 2.0.1)."""
    clean = str(ver_str).lstrip("vV").strip()
    try:
        major, minor, patch = map(int, clean.split("."))
        return f"{major}.{minor}.{patch + 1}"
    except ValueError:
        return "2.0.1"


def load_weight_config() -> dict:
    """Load risk-weight configuration fields including author and version_history."""
    try:
        with open(W_CONF, "r", encoding="utf-8") as weight_file:
            raw_config = json.load(weight_file)
    except FileNotFoundError:
        raw_config = {}
    except (OSError, json.JSONDecodeError) as error:
        st.error(f"Could not load the weight configuration: {error}")
        st.stop()

    config_data = {
        key: raw_config[key]
        for key in WEIGHT_CONFIG_KEYS
        if key in raw_config
    }

    config_data.setdefault("taxonomy_name", "CIS6560_Risk_Scoring_Weights")
    config_data.setdefault("version", "2.0.0")
    config_data.setdefault("weights", dict(CHARTER_WEIGHTS))
    config_data.setdefault("selected_preset", "Charter Default")
    config_data.setdefault("last_updated_by", "Charter Baseline")
    config_data.setdefault("version_history", [])

    # Seed initial baseline entry if version_history is empty
    if not config_data["version_history"]:
        config_data["version_history"].append({
            "version": f"v{str(config_data['version']).lstrip('v')}",
            "selected_preset": config_data["selected_preset"],
            "last_updated": config_data.get(
                "last_updated",
                datetime.datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S"),
            ),
            "updated_by": config_data.get("last_updated_by", "Charter Baseline"),
            "weights": dict(config_data["weights"]),
        })

    return config_data


def save_weight_config(config_data: dict) -> tuple[bool, str | None]:
    """Save risk-weight fields, actor metadata, and version_history."""
    cleaned_config = {
        key: config_data[key]
        for key in WEIGHT_CONFIG_KEYS
        if key in config_data
    }

    try:
        with open(W_CONF, "w", encoding="utf-8") as weight_file:
            json.dump(cleaned_config, weight_file, indent=2, ensure_ascii=False)
        return True, None
    except OSError as error:
        return False, str(error)


st.title("Risk Weight Tuning Matrix")

config_data = load_weight_config()

weights = config_data.get("weights", {})
if set(weights) != set(CHARTER_WEIGHTS):
    st.error(
        "The saved weights do not match the seven scoring dimensions. "
        "Restore the charter defaults before tuning."
    )
    st.stop()

col_prof, col_author = st.columns(2)
saved_preset = config_data.get("selected_preset", "Custom Profile")
selected_preset = col_prof.selectbox(
    "Select profile:",
    list(PRESETS),
    index=(
        list(PRESETS).index(saved_preset)
        if saved_preset in PRESETS
        else 1
    ),
)
operator_name = col_author.text_input(
    "Operator Name (Optional — auto-detects IP if left blank):",
    value=st.session_state.get("current_user", ""),
    placeholder="e.g., Myunghee Jung",
).strip()

initial_weights = PRESETS[selected_preset] or weights

updated_weights = {}
weight_items = list(WEIGHT_LABELS.items())

# Display 7 weight inputs in a 3-column grid (leaves cols[1] and cols[2] on row 3)
cols = st.columns(3)
for idx, (key, label) in enumerate(weight_items):
    with cols[idx % 3]:
        updated_weights[key] = st.number_input(
            f"{label} weight",
            min_value=0.0,
            max_value=1.0,
            value=float(initial_weights[key]),
            step=0.01,
            format="%.2f",
            key=f"weight_{selected_preset}_{key}",
        )

weights_sum = sum(updated_weights.values())
is_valid_sum = math.isclose(weights_sum, 1.0, rel_tol=0.0, abs_tol=1e-9)

# Place total metric in the 8th slot (row 3, col 2)
with cols[1]:
    st.metric("Current weight total", f"{weights_sum:.2f}")

# Place validation status & Save button in the 9th slot (row 3, col 3)
with cols[2]:
    if is_valid_sum:
        st.success(f"Valid total: weights sum to {weights_sum:.2f}.")
        if st.button("Save Weight Configurations", use_container_width=True):
            is_default = all(
                math.isclose(
                    updated_weights[key],
                    CHARTER_WEIGHTS[key],
                    rel_tol=0.0,
                    abs_tol=1e-9,
                )
                for key in CHARTER_WEIGHTS
            )

            new_preset = "Charter Default" if is_default else "Custom Profile"
            now_str = datetime.datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
            new_ver = _bump_patch_version(config_data.get("version", "2.0.0"))

            client_ip = _get_client_ip()
            if operator_name:
                st.session_state["current_user"] = operator_name
                actor = f"{operator_name} (IP: {client_ip})"
            else:
                actor = f"IP: {client_ip}"

            config_data["selected_preset"] = new_preset
            config_data["last_updated"] = now_str
            config_data["last_updated_by"] = actor
            config_data["version"] = new_ver
            config_data["weights"] = dict(updated_weights)

            history = config_data.get("version_history", [])
            history.append({
                "version": f"v{new_ver}",
                "selected_preset": new_preset,
                "last_updated": now_str,
                "updated_by": actor,
                "weights": dict(updated_weights),
            })
            config_data["version_history"] = history[-15:]

            saved, error = save_weight_config(config_data)

            if not saved:
                st.error(f"Could not save the weight configuration: {error}")
            else:
                st.success(
                    f"Configuration v{new_ver} deployed and logged by {actor}."
                )
                st.rerun()
    else:
        st.error(
            "Weights must sum to 1.00 before saving. "
            f"Current total: {weights_sum:.2f}."
        )

st.markdown("---")
st.subheader("Saved JSON File Configuration")

display_config = {
    key: config_data[key]
    for key in WEIGHT_CONFIG_KEYS
    if key in config_data
}
st.json(display_config)

st.markdown("### Configuration Management")
col_reset, col_download = st.columns(2)

# 1. Reset configuration and version history back to Charter Default (v2.0.0)
with col_reset:
    if st.button("Reset to Charter Default (Clear History)", type="secondary", use_container_width=True):
        now_str = datetime.datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
        client_ip = _get_client_ip()
        actor = f"{operator_name} (IP: {client_ip})" if operator_name else f"IP: {client_ip}"

        reset_data = {
            "taxonomy_name": "CIS6560_Risk_Scoring_Weights",
            "version": "2.0.0",
            "weights": dict(CHARTER_WEIGHTS),
            "selected_preset": "Charter Default",
            "last_updated": now_str,
            "last_updated_by": actor,
            "version_history": [
                {
                    "version": "v2.0.0",
                    "selected_preset": "Charter Default",
                    "last_updated": now_str,
                    "updated_by": actor,
                    "weights": dict(CHARTER_WEIGHTS),
                }
            ],
        }
        saved, error = save_weight_config(reset_data)
        if saved:
            st.success("Configuration and history reset to Charter Default (v2.0.0).")
            st.rerun()
        else:
            st.error(f"Reset failed: {error}")

# 2. Download current weight_config.json as a backup
with col_download:
    st.download_button(
        label="Download weight_config.json",
        data=json.dumps(display_config, indent=2, ensure_ascii=False),
        file_name="weight_config.json",
        mime="application/json",
        use_container_width=True,
    )

# 3. Rollback to a previously saved version from version_history
history_list = config_data.get("version_history", [])
if len(history_list) > 1:
    st.markdown("#### Rollback to Previous Version")
    version_options = [
        f"{item.get('version', 'Unknown')} | {item.get('selected_preset', 'Custom')} "
        f"({item.get('last_updated', 'N/A')} by {item.get('updated_by') or item.get('last_updated_by') or 'Unknown'})"
        for item in reversed(history_list)
    ]

    selected_ver_label = st.selectbox("Select a version to restore:", version_options)

    if st.button("Restore Selected Version"):
        # Find the original index of the selected version in history_list
        selected_idx = len(history_list) - 1 - version_options.index(selected_ver_label)
        target_entry = history_list[selected_idx]

        now_str = datetime.datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
        new_ver = _bump_patch_version(config_data.get("version", "2.0.0"))
        client_ip = _get_client_ip()
        actor = f"{operator_name} (IP: {client_ip})" if operator_name else f"IP: {client_ip}"

        restored_preset = target_entry.get("selected_preset", "Custom Profile")
        restored_ver = target_entry.get("version", "Previous")

        config_data["weights"] = dict(target_entry["weights"])
        config_data["selected_preset"] = restored_preset
        config_data["version"] = new_ver
        config_data["last_updated"] = now_str
        config_data["last_updated_by"] = actor

        history_list.append({
            "version": f"v{new_ver}",
            "selected_preset": restored_preset,
            "last_updated": now_str,
            "updated_by": f"{actor} (Restored {restored_ver})",
            "weights": dict(target_entry["weights"]),
        })
        config_data["version_history"] = history_list[-15:]

        saved, error = save_weight_config(config_data)
        if saved:
            st.success(f"Restored weights from {target_entry['version']} as v{new_ver}.")
            st.rerun()
        else:
            st.error(f"Restore failed: {error}")
