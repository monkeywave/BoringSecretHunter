"""Root conftest: ensure src/ package takes priority over legacy boring_secret_hunter_ghidra.py."""

import sys
from pathlib import Path

_src = str(Path(__file__).resolve().parent / "src")

# Remove '' (cwd) temporarily, insert src first, then re-add cwd after
if _src in sys.path:
    sys.path.remove(_src)
sys.path.insert(0, _src)

# Purge any cached import of the legacy module
to_remove = [
    k
    for k in list(sys.modules)
    if k == "boring_secret_hunter" or k.startswith("boring_secret_hunter.")
]
for k in to_remove:
    del sys.modules[k]
