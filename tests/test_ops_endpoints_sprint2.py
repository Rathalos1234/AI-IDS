# PT-22: Ops endpoints
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def test_ops_health_and_retention_and_backup():
    c = api.app.test_client()
    h1 = c.get("/healthz")
    h2 = c.get("/api/healthz")
    assert h1.status_code in (200, 204)
    assert h2.status_code in (200, 204)
    rr = c.post("/api/retention/run")
    assert rr.status_code in (200, 202)
    bk = c.get("/api/backup/db")
    assert bk.status_code == 200
    ct = bk.headers.get("Content-Type", "").lower()
    assert ("octet-stream" in ct) or ("sqlite" in ct) or ("zip" in ct)
