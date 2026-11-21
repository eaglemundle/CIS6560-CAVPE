import streamlit.web.cli as stcli
import os, sys, importlib.util

def resolve_path(path):
    if getattr(sys, "frozen", False):
        basedir = sys._MEIPASS
    else:
        basedir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(basedir, path)

def register_local_package(pkg_name):
    pkg_dir = resolve_path(pkg_name)
    if os.path.isdir(pkg_dir) and pkg_name not in sys.modules:
        spec = importlib.util.spec_from_loader(pkg_name, loader=None, is_package=True)
        module = importlib.util.module_from_spec(spec)
        module.__path__ = [pkg_dir]
        sys.modules[pkg_name] = module

if __name__ == "__main__":
    bundle_dir = resolve_path("")
    
    os.chdir(bundle_dir)

    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)

    for folder in ["app_utils", "engines"]:
        register_local_package(folder)

    sys.argv = [
        "streamlit",
        "run",
        resolve_path("app.py"),
        "--global.developmentMode=false",
    ]
    sys.exit(stcli.main())
