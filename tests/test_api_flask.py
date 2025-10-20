# PT-10/PT-15 alternate API smoke (importorskip)
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def test_health_ok():
    c = api.app.test_client()
    r = c.get("/api/stats")
    assert r.status_code in (200, 401, 403)  # if auth required, gating is OK
