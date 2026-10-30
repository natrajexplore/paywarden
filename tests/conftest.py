"""Test-process settings, applied before any test module imports the app."""
import os

# Every TestClient request comes from the same address, so the per-IP limit (120/min by default)
# would throttle the suite itself. Production keeps the configured limit.
os.environ.setdefault("RATE_LIMIT_PER_MIN", "100000")

import pytest  # noqa: E402


@pytest.fixture(autouse=True, scope="module")
def _isolated_proposals():
    """Modules share one app instance; start each with no payment history so velocity, duplicate
    and daily-limit controls see only that module's payments. The audit table is left intact."""
    from app.main import store
    with store.lock:
        store.conn.execute("DELETE FROM proposals")
        store.conn.commit()
    yield
