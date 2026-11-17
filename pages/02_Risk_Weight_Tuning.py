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
st.caption(
    "Weights apply to both taxonomy perspectives; risk transfer always reduces "
    "risk."
)

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
for key, label in WEIGHT_LABELS.items():
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
st.metric("Current weight total", f"{weights_sum:.2f}")

if math.isclose(weights_sum, 1.0, rel_tol=0.0, abs_tol=1e-9):
    st.success(f"Governance compliant: weights sum to {weights_sum:.2f}.")

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
        "Weights must sum to 1.00 before they can be saved. "
        f"Current total: {weights_sum:.2f}; adjust the displayed values to "
        "proceed."
    )

st.markdown("---")
st.subheader("Saved JSON File Configuration")

display_config = {
    key: config_data[key]
    for key in WEIGHT_CONFIG_KEYS
    if key in config_data
}
st.json(display_config)
