"""Pytest configuration.

We keep the application code under the top-level `src/` package.
Depending on how pytest is invoked (e.g., via the `pytest` console_script) and
the active import mode, the repository root may not be on `sys.path`, which
breaks imports like `from src.modules...`.

This file makes test imports robust by explicitly adding the repo root to
`sys.path` during test collection.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

# NOTE: Insert at the front so local imports win over any similarly named
# third-party packages.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
