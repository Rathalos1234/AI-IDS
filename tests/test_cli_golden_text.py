# PT-9: CLI golden-text checks
import io
import sys
import os
import pytest
import main as cli

pytestmark = pytest.mark.unit


def _run(argv):
    old = sys.argv[:]
    sys.argv = ["prog"] + argv[:]
    try:
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main()
        return code, buf.getvalue()
    finally:
        sys.argv = old


def test_config_validate_ok_uses_repo_config():
    code, out = _run(["config-validate"])
    assert code == 0
    assert "OK" in out.upper()


@pytest.mark.skipif(
    not os.path.exists("models/iforest.joblib"), reason="model bundle missing"
)
def test_verify_model_prints_expected_fields():
    code, out = _run(["verify-model", "-m", "models/iforest.joblib"])
    assert code == 0
    for token in [
        "Model bundle info",
        "Version",
        "Trained at",
        "IF params",
        "Feature count",
        "Feature checksum",
        "Feature order",
    ]:
        assert token in out
