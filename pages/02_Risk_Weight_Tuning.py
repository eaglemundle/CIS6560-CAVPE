import datetime
import json
import math
import os

import streamlit as st


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
}


def load_weight_config() -> dict:
    """Load only risk-weight configuration fields."""
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

    config_data.setdefault(
        "taxonomy_name",
        "CIS6560_Risk_Scoring_Weights",
    )
    config_data.setdefault("version", "2.0.0")
    config_data.setdefault("weights", dict(CHARTER_WEIGHTS))
    config_data.setdefault("selected_preset", "Charter Default")

    return config_data


def save_weight_config(config_data: dict) -> tuple[bool, str | None]:
    """Save only risk-weight fields; never save dataset_path here."""
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

saved_preset = config_data.get("selected_preset", "Custom Profile")
selected_preset = st.selectbox(
    "Select profile:",
    list(PRESETS),
    index=(
        list(PRESETS).index(saved_preset)
        if saved_preset in PRESETS
        else 1
    ),
)

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

        config_data["selected_preset"] = (
            "Charter Default" if is_default else "Custom Profile"
        )
        config_data["last_updated"] = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        config_data["weights"] = updated_weights

        saved, error = save_weight_config(config_data)

        if not saved:
            st.error(f"Could not save the weight configuration: {error}")
        else:
            st.success("Configuration successfully deployed.")
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