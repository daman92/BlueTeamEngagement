import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (REPO_ROOT / "scripts", REPO_ROOT / "response" / "scripts"):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

# Fall back to the bundled pure-Python deps (vendor/python) when PyYAML/Jinja2 aren't
# installed — mirrors scripts/_vendor.py so tests that `import yaml` directly work on a
# bare interpreter (as CI's pytest job runs them, proving the vendored copy is complete).
_vendored = REPO_ROOT / "vendor" / "python"
if _vendored.is_dir() and str(_vendored) not in sys.path:
    sys.path.append(str(_vendored))
