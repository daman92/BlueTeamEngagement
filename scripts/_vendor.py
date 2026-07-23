"""Make bundled pure-Python dependencies importable without pip (offline kit).

The portable kit is deployed onto client networks that are frequently air-gapped, so
`pip install pyyaml jinja2` is not an option in the field. PyYAML, Jinja2, and MarkupSafe
are vendored (pure-Python) under vendor/python/; importing this module first prepends
nothing and *appends* that directory to sys.path — so a real site/venv install still
wins, and the vendored copy is used only when the dep is otherwise absent.

Usage: `import _vendor  # noqa: F401` as the first import in any script that needs
yaml/jinja2, BEFORE the `import yaml` / `import jinja2` line.
"""

from __future__ import annotations

import sys
from pathlib import Path

# scripts/_vendor.py -> repo root is one level up from scripts/
_VENDORED = Path(__file__).resolve().parent.parent / "vendor" / "python"

if _VENDORED.is_dir():
    p = str(_VENDORED)
    if p not in sys.path:
        sys.path.append(p)  # append: installed packages take precedence over vendored
