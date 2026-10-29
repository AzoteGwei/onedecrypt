#!/usr/bin/env python3
"""Print a value-free shape report for an existing 1PUX archive.

This is a diagnostic tool for comparing an export produced by onedecrypt with
an export produced by the official 1Password app.  It reads only the ZIP's
``export.attributes`` and ``export.data`` JSON and emits field names, JSON
types, array lengths and object key sets.  It never prints string, number or
boolean values.

Examples::

    python3 scripts/1pux_shape.py official.1pux
    python3 scripts/1pux_shape.py official.1pux -o /tmp/opencode/official-shape.json

The on-disk file is only read; nothing is written except the optional report
path.  The report is safe to share: passwords, usernames, URLs, titles, notes
and document names are not included.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import zipfile
from pathlib import Path
from typing import Any


def shape(value: Any) -> dict[str, Any]:
    """Describe a JSON value without including any of its contents."""
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number", "finite": math.isfinite(value)}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        shapes: dict[str, dict[str, Any]] = {}
        for item in value:
            descriptor = shape(item)
            shapes[json.dumps(descriptor, sort_keys=True)] = descriptor
        return {
            "type": "array",
            "length": len(value),
            "items": list(shapes.values()),
        }
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": {key: shape(child) for key, child in value.items()},
        }
    return {"type": type(value).__name__}


def build_report(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        attributes = json.loads(archive.read("export.attributes"))
        data = json.loads(archive.read("export.data"))
    file_entries = [name for name in names if name.startswith("files/")]
    return {
        "export.attributes": shape(attributes),
        "export.data": shape(data),
        "files": {"count": len(file_entries)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a value-free shape report for a 1PUX archive."
    )
    parser.add_argument("archive", type=Path, help="path to the .1pux file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the report here instead of stdout",
    )
    args = parser.parse_args(argv)

    try:
        report = build_report(args.archive)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(args.output)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
