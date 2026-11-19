import ast
import os
import re
from pathlib import Path

# 1. Configuration
MAIN_FILE = "app.py"
PROJECT_ROOT = Path(".").resolve()
IGNORE_DIRS = {'.git', 'venv', '.venv', 'env', '__pycache__', '.streamlit', 'node_modules'}
IGNORE_FILES = {'check_deps.py', 'requirements.txt', '.gitignore', 'README.md'}

def collect_project_files():
    """Collect all .py files and non-python resource files in the project."""
    py_files = {}     # stem -> Path
    other_files = []  # list of Path

    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
        for file in files:
            if file in IGNORE_FILES or file.startswith('.'):
                continue
            full_path = Path(root) / file
            if file.endswith(".py"):
                py_files[full_path.stem] = full_path
            else:
                other_files.append(full_path)
    return py_files, other_files

def find_direct_dependencies(file_path, py_files, other_files):
    """Find both imported .py modules and referenced non-py files in a single Python file."""
    used_py = set()
    used_other = set()

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        
        # A. Find imported Python modules via AST
        tree = ast.parse(content, filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split('.')[0]
                    if mod in py_files:
                        used_py.add(py_files[mod])
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module.split('.')[0]
                if mod in py_files:
                    used_py.add(py_files[mod])
                for alias in node.names:
                    if alias.name in py_files:
                        used_py.add(py_files[alias.name])

        # B. Find referenced non-python files (CSV, JSON, images, etc.) by filename match
        for other_path in other_files:
            # Match exact filename (e.g., "data.csv" or "logo.png") inside quotes or paths
            if re.search(rf"['\"/\\]{re.escape(other_path.name)}['\"]", content):
                used_other.add(other_path)

    except Exception as e:
        print(f"Error parsing {file_path.name}: {e}")

    return used_py, used_other

def trace_all_from_entry(entry_path, py_files, other_files):
    """Recursively trace all .py and non-py files used by an entry point (app.py or a page)."""
    visited_py = set()
    collected_other = set()
    queue = [entry_path]

    while queue:
        current = queue.pop(0)
        if current in visited_py:
            continue
        visited_py.add(current)

        deps_py, deps_other = find_direct_dependencies(current, py_files, other_files)
        collected_other.update(deps_other)

        for dep in deps_py:
            if dep not in visited_py:
                queue.append(dep)

    # Exclude the entry file itself from its own dependency list
    visited_py.discard(entry_path)
    return sorted(visited_py), sorted(collected_other)

# --- Execution ---
py_files, other_files = collect_project_files()

# Gather entry points: app.py + everything in pages/
entry_points = []
if (PROJECT_ROOT / MAIN_FILE).exists():
    entry_points.append(PROJECT_ROOT / MAIN_FILE)

pages_dir = PROJECT_ROOT / "pages"
if pages_dir.exists():
    entry_points.extend(sorted(pages_dir.glob("*.py")))

print("=== 1:1 Dependency Mapping (app.py & pages/) ===\n")
all_used_files = set(entry_points)

for entry in entry_points:
    rel_entry = entry.relative_to(PROJECT_ROOT)
    used_py, used_other = trace_all_from_entry(entry, py_files, other_files)
    
    all_used_files.update(used_py)
    all_used_files.update(used_other)

    print(f"📄 {rel_entry}")
    if not used_py and not used_other:
        print("   └── (No external project files used)")
    else:
        for p in used_py:
            print(f"   ├── [PY]   {p.relative_to(PROJECT_ROOT)}")
        for o in used_other:
            print(f"   ├── [FILE] {o.relative_to(PROJECT_ROOT)}")
    print()

# Bonus: Summary of completely unused files across the entire project
all_project_files = set(py_files.values()) | set(other_files)
unused = sorted(all_project_files - all_used_files)

print("=== Completely Unused Files (Safe to review/delete) ===")
if not unused:
    print("None! Every file in the project is being used.")
else:
    for u in unused:
        print(f"- {u.relative_to(PROJECT_ROOT)}")
