"""Ensure src/ is first on sys.path to avoid shadowing by root-level boring_secret_hunter.py."""

import sys
from pathlib import Path

# Insert src/ at the front of sys.path so the package is found
# before the legacy boring_secret_hunter.py in the project root.
_src = str(Path(__file__).resolve().parent.parent / "src")
if _src in sys.path:
    sys.path.remove(_src)
sys.path.insert(0, _src)

# If the wrong module was already cached, purge it
_cached = sys.modules.get("boring_secret_hunter")
if (
    _cached
    and hasattr(_cached, "__file__")
    and _cached.__file__
    and "src" not in _cached.__file__
):
    # Remove all cached submodules
    to_remove = [
        k
        for k in sys.modules
        if k == "boring_secret_hunter" or k.startswith("boring_secret_hunter.")
    ]
    for k in to_remove:
        del sys.modules[k]
