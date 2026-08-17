import os
import tempfile

# Must run before backend.config (and therefore backend.app) is imported by
# ANY test module: backend/config.py computes its DB path from
# ASLISIEM_DATA_DIR at import time, once, as a module-level constant. If that
# happens with no override, tests that go through create_app() would bind to
# the real user database at ~/.aslisiem_data -- pytest's conftest.py is
# collected before test modules are imported, which is what makes setting
# this here (and not in a fixture) actually effective.
os.environ["ASLISIEM_DATA_DIR"] = tempfile.mkdtemp(prefix="aslisiem_pytest_")
