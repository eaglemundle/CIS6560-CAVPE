import datetime
import json
import os
import socket
import pandas as pd
import streamlit as st

UTILS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(UTILS_DIR)

D_CONF = os.path.join(PROJECT_ROOT, "engines", "dataset_config.json")
REF_DATA_DIR = os.path.join(PROJECT_ROOT, "reference_data")
DEFAULT_DATASET_REL_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
DEFAULT_DATASET_PATH = os.path.abspath(os.path.join(PROJECT_ROOT, DEFAULT_DATASET_REL_PATH))

REQUIRED_COLUMNS = [
    "Finding ID", "CVE ID", "Vulnerability title", "Affected product",
    "Asset group", "Vulnerability class", "CVSS base score", "CVSS severity",
    "Exploitation context", "Internet-facing assets", "Exposure classification",
    "Total affected assets", "Critical assets", "High-criticality assets",
    "Medium-criticality assets", "Low-criticality assets", "Patch complexity",
    "Estimated remediation effort", "Recommended remediation",
    "Contextual priority", "Data status",
]

os.makedirs(REF_DATA_DIR, exist_ok=True)
os.makedirs(os.path.dirname(D_CONF), exist_ok=True)


def _to_portable_path(path_str: str) -> str:
    """Convert path inside PROJECT_ROOT to a forward-slash relative path for cross-OS portability."""
    abs_p = os.path.abspath(path_str)
    try:
        rel_p = os.path.relpath(abs_p, PROJECT_ROOT).replace("\\", "/")
        if not rel_p.startswith(".."):
            return rel_p
    except ValueError:
        pass
    return abs_p


def _resolve_abs_path(stored_path: str) -> str:
    """Resolve a stored relative (or legacy Windows/Linux) path to a valid local absolute path."""
    if not stored_path:
        return DEFAULT_DATASET_PATH
    normalized = stored_path.replace("\\", "/")
    if not os.path.isabs(normalized) and not (len(normalized) > 1 and normalized[1] == ":"):
        return os.path.abspath(os.path.join(PROJECT_ROOT, normalized))
    if os.path.exists(normalized):
        return os.path.abspath(normalized)
    # Fallback: check if filename exists inside local reference_data/
    candidate = os.path.join(REF_DATA_DIR, os.path.basename(normalized))
    return os.path.abspath(candidate) if os.path.exists(candidate) else DEFAULT_DATASET_PATH


def load_config() -> dict:
    if os.path.exists(D_CONF):
        try:
            with open(D_CONF, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(data: dict) -> tuple[bool, str | None]:
    try:
        with open(D_CONF, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True, None
    except Exception as e:
        return False, str(e)


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


def _increment_version(current_ver: str, bump_type: str = "patch") -> str:
    clean = str(current_ver).lstrip("vV").strip()
    try:
        major, minor, patch = map(int, clean.split("."))
    except ValueError:
        major, minor, patch = 1, 0, 0

    if bump_type == "major":
        major, minor, patch = major + 1, 0, 0
    elif bump_type == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    return f"v{major}.{minor}.{patch}"


def get_config_version() -> str:
    return load_config().get("config_version", "v1.0.0")


def get_last_updated_by() -> str:
    return load_config().get("last_updated_by", f"IP: {_get_client_ip()}")


def get_version_history() -> list[dict]:
    return load_config().get("version_history", [])


def reset_config_to_default() -> tuple[bool, str | None]:
    """Reset dataset configuration and version back to v1.0.0 default with portable path."""
    default_data = {
        "dataset_path": DEFAULT_DATASET_REL_PATH,
        "config_version": "v1.0.0",
        "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_updated_by": f"Reset by IP: {_get_client_ip()}",
        "version_history": [],
    }
    ok, err = save_config(default_data)
    if ok:
        st.session_state["dataset_path"] = DEFAULT_DATASET_PATH
    return ok, err


def validate_dataset_schema(
    df: pd.DataFrame, required_cols: list[str] | None = None
) -> tuple[bool, list[str]]:
    target_cols = required_cols if required_cols is not None else REQUIRED_COLUMNS
    existing_cols = {str(col).strip() for col in df.columns}
    missing_cols = [col for col in target_cols if col not in existing_cols]
    return len(missing_cols) == 0, missing_cols


def validate_file_schema(
    file_source, required_cols: list[str] | None = None
) -> tuple[bool, str | None]:
    try:
        filename = file_source.name if hasattr(file_source, "name") else str(file_source)
        if filename.lower().endswith(".csv"):
            df_header = pd.read_csv(file_source, nrows=0)
        else:
            df_header = pd.read_excel(file_source, nrows=0)

        if hasattr(file_source, "seek"):
            file_source.seek(0)

        is_valid, missing_cols = validate_dataset_schema(df_header, required_cols)
        if not is_valid:
            return False, f"Missing required columns: {', '.join(missing_cols)}"
        return True, None
    except Exception as e:
        return False, f"Failed to parse dataset file: {e}"


def get_active_dataset_path() -> str:
    if "dataset_path" in st.session_state and st.session_state["dataset_path"]:
        resolved = _resolve_abs_path(st.session_state["dataset_path"])
        if os.path.exists(resolved):
            return resolved

    config_data = load_config()
    resolved = _resolve_abs_path(config_data.get("dataset_path", DEFAULT_DATASET_REL_PATH))
    st.session_state["dataset_path"] = resolved
    return resolved


def update_dataset_path(
    new_path: str,
    validate: bool = True,
    note: str = "Dataset switched",
    changed_by: str | None = None,
) -> tuple[bool, str | None]:
    """Validate schema, save portable relative path, bump version, and log Name + IP."""
    abs_path = _resolve_abs_path(new_path)
    if not os.path.exists(abs_path):
        return False, f"Target file does not exist: {abs_path}"

    if validate:
        is_valid, err_msg = validate_file_schema(abs_path)
        if not is_valid:
            return False, err_msg

    config_data = load_config()
    old_abs = _resolve_abs_path(config_data.get("dataset_path", ""))
    current_ver = config_data.get("config_version", "v1.0.0")

    client_ip = _get_client_ip()
    manual_name = (changed_by or st.session_state.get("current_user") or "").strip()
    if manual_name:
        st.session_state["current_user"] = manual_name
        actor = f"{manual_name} (IP: {client_ip})"
    else:
        actor = f"IP: {client_ip}"

    new_ver = _increment_version(current_ver, "patch") if abs_path != old_abs else current_ver
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    portable_path = _to_portable_path(abs_path)

    config_data["dataset_path"] = portable_path
    config_data["config_version"] = new_ver
    config_data["last_updated"] = now_str
    config_data["last_updated_by"] = actor

    history = config_data.get("version_history", [])
    history.insert(0, {
        "Version": new_ver,
        "Timestamp": now_str,
        "Changed By": actor,
        "Dataset": os.path.basename(abs_path),
        "Note": note,
    })
    config_data["version_history"] = history[:10]

    ok, err = save_config(config_data)
    if ok:
        st.session_state["dataset_path"] = abs_path
    return ok, err


def list_reference_datasets() -> list[str]:
    if not os.path.exists(REF_DATA_DIR):
        return []
    return sorted([
        f for f in os.listdir(REF_DATA_DIR)
        if f.endswith((".xlsx", ".xls", ".csv")) and not f.startswith("~$")
    ])


@st.cache_data(show_spinner="Loading dataset...")
def _read_file_cached(file_path: str, mtime: float) -> pd.DataFrame:
    if file_path.lower().endswith(".csv"):
        return pd.read_csv(file_path)
    return pd.read_excel(file_path)


def load_active_dataset(validate: bool = True) -> pd.DataFrame:
    file_path = get_active_dataset_path()
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    mtime = os.path.getmtime(file_path)
    df = _read_file_cached(file_path, mtime)

    if validate:
        is_valid, missing_cols = validate_dataset_schema(df)
        if not is_valid:
            raise ValueError(f"Dataset schema validation failed. Missing columns: {', '.join(missing_cols)}")

    return df


def get_nvd_api_key() -> str:
    try:
        if "NVD_API_KEY" in st.secrets:
            return str(st.secrets["NVD_API_KEY"]).strip()
    except Exception:
        pass
    return os.getenv("NVD_API_KEY", "").strip()
