from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "1pux_shape.py"


@pytest.fixture
def shape_script(monkeypatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("1pux_shape_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_zip_report_is_value_free(shape_script: ModuleType, tmp_path: Path):
    archive = tmp_path / "sample.1pux"
    attributes = {
        "version": 3,
        "description": "1Password Unencrypted Export",
        "timestamp": 1760000000,
    }
    data = {
        "accounts": [
            {
                "attrs": {"email": "secret@example.com"},
                "favorite": True,
                "score": 3.5,
                "vaults": [{"attrs": {"name": "Private"}, "items": []}],
            }
        ]
    }
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("export.attributes", json.dumps(attributes))
        zf.writestr("export.data", json.dumps(data))
        zf.writestr("files/doc__note.txt", b"contents")

    report = shape_script.build_report(archive)

    assert set(report) == {"export.attributes", "export.data", "files"}
    assert report["files"] == {"count": 1}
    assert report["export.attributes"]["keys"]["version"] == {"type": "integer"}
    assert report["export.data"]["keys"]["accounts"]["length"] == 1
    account = report["export.data"]["keys"]["accounts"]["items"][0]
    assert account["keys"]["attrs"]["keys"]["email"] == {"type": "string"}
    assert account["keys"]["favorite"] == {"type": "boolean"}
    assert account["keys"]["score"] == {"type": "number", "finite": True}
    rendered = json.dumps(report)
    assert "1760000000" not in rendered
    assert "secret@example.com" not in rendered
    assert "Private" not in rendered
    assert '"favorite": true' not in rendered
    assert "3.5" not in rendered
    assert "contents" not in rendered
