"""
Pytest session setup.

Isolates the SQLite dashboard store from the real ./threat_model_output/
dashboard.db so test runs never pollute (or depend on) state from a real
local run, or from a previous pytest invocation. Must set the env var
before any test module imports config.py / dashboard_store.py — both build
module-level singletons at import time — and conftest.py's top-level code
runs before test collection/import, which is why this isn't a fixture.
"""

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

_test_db_dir = tempfile.mkdtemp(prefix="shadow_ai_test_")
os.environ.setdefault("DASHBOARD_DB_PATH", str(Path(_test_db_dir) / "dashboard_test.db"))
atexit.register(shutil.rmtree, _test_db_dir, True)
