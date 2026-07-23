import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (REPO_ROOT / "scripts", REPO_ROOT / "response" / "scripts"):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)
