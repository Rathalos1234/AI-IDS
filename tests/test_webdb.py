# PT-11: WebDB tests (importorskip)
import pytest

webdb = pytest.importorskip("webdb", reason="webdb module not found")

pytestmark = pytest.mark.unit


def test_schema_init_and_list():
    webdb.init()
    alerts = webdb.list_alerts(limit=1)
    blocks = webdb.list_blocks(limit=1)
    assert isinstance(alerts, list)
    assert isinstance(blocks, list)
