from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "json_shape.py"


@pytest.fixture
def shape_script(monkeypatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("json_shape_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_object_report_is_value_free(shape_script: ModuleType, tmp_path: Path):
    source = tmp_path / "data.json"
    source.write_text(
        json.dumps(
            {
                "name": "secret",
                "enabled": True,
                "score": 3.5,
                "items": [{"id": 1}, {"id": 2}],
            }
        )
    )

    report = shape_script.build_report(source)

    assert report["type"] == "object"
    keys = report["keys"]
    assert keys["name"] == {"type": "string"}
    assert keys["enabled"] == {"type": "boolean"}
    assert keys["score"] == {"type": "number", "finite": True}
    assert keys["items"]["length"] == 2
    assert keys["items"]["items"] == [
        {"type": "object", "keys": {"id": {"type": "integer"}}}
    ]
    rendered = json.dumps(report)
    assert "secret" not in rendered
    assert '"enabled": true' not in rendered
    assert "3.5" not in rendered


def test_array_and_scalar_roots(shape_script: ModuleType, tmp_path: Path):
    source = tmp_path / "data.json"
    source.write_text('[1, "x", true]')
    report = shape_script.build_report(source)
    assert report["type"] == "array"
    assert report["length"] == 3
    assert len(report["items"]) == 3

    source.write_text('"hello"')
    assert shape_script.build_report(source) == {"type": "string"}


def test_zip_input_is_rejected(shape_script: ModuleType, tmp_path: Path, capsys):
    archive = tmp_path / "data.json"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("export.data", "{}")

    assert shape_script.main([str(archive)]) == 1
    error = capsys.readouterr().err
    assert "scripts/1pux_shape.py" in error


def test_invalid_json_reports_the_path_and_suffix(
    shape_script: ModuleType, tmp_path: Path, capsys
):
    source = tmp_path / "broken.1pux"
    source.write_text("{not json")

    assert shape_script.main([str(source)]) == 1
    error = capsys.readouterr().err
    assert str(source) in error
    assert "not valid JSON" in error
    assert "extension suggests" in error


def test_utf8_bom_is_accepted(shape_script: ModuleType, tmp_path: Path):
    source = tmp_path / "data.json"
    source.write_bytes(b"\xef\xbb\xbf" + b'{"name": "value"}')

    report = shape_script.build_report(source)

    assert report["keys"]["name"] == {"type": "string"}


def test_output_file(shape_script: ModuleType, tmp_path: Path, capsys):
    source = tmp_path / "data.json"
    source.write_text('{"a": 1}')
    output = tmp_path / "nested" / "shape.json"

    assert shape_script.main([str(source), "-o", str(output)]) == 0
    assert capsys.readouterr().out.strip() == str(output)
    report = json.loads(output.read_text())
    assert report["keys"]["a"] == {"type": "integer"}
