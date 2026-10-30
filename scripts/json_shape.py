#!/usr/bin/env python3
"""Print a value-free shape report for any JSON document.

The report contains only JSON types, object key names, array lengths and the
distinct shapes of array elements.  String, number and boolean values are never
printed.

Examples::

    python3 scripts/json_shape.py data.json
    python3 scripts/json_shape.py data.json -o /tmp/opencode/data-shape.json

A ZIP/1PUX archive is rejected with a pointer to ``scripts/1pux_shape.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Allow both ``python scripts/json_shape.py`` and
# ``python -m scripts.json_shape``.
if __package__:
    from .shape import shape
else:
    from shape import shape

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _zip_suffix_hint(path: Path) -> str:
    if path.suffix.lower() in {".1pux", ".zip"}:
        return (
            " (the extension suggests a 1PUX/ZIP archive, but the file has no "
            "ZIP magic)"
        )
    return ""


def _json_error(path: Path, exc: json.JSONDecodeError) -> ValueError:
    return ValueError(
        f"{path}: not valid JSON{_zip_suffix_hint(path)}: {exc.msg} "
        f"(line {exc.lineno}, column {exc.colno})"
    )


def build_report(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if raw[:4] in ZIP_MAGICS:
        raise ValueError(
            f"{path}: this is a ZIP archive; use scripts/1pux_shape.py for "
            "1PUX files"
        )
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _json_error(path, exc) from exc
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"{path}: not valid UTF-8/UTF-16 JSON text: {exc.reason}"
        ) from exc
    return shape(document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a value-free shape report for a JSON document."
    )
    parser.add_argument("input", type=Path, help="path to the JSON file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the report here instead of stdout",
    )
    args = parser.parse_args(argv)

    try:
        report = build_report(args.input)
    except (OSError, ValueError) as exc:
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
