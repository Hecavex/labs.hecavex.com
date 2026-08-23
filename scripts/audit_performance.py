#!/usr/bin/env python3
"""Enforce deterministic transfer-size budgets for the static Labs site."""

from __future__ import annotations

import gzip
from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent.parent
IGNORED_PARTS = {
    ".git",
    ".codex-tmp",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "_site",
    "test-results",
    "__pycache__",
    "node_modules",
}
KIB = 1024
MIB = 1024 * KIB

# These thresholds leave deliberate headroom over the 22 August 2026 baseline.
# Raising one should be treated as a reviewable product decision, not routine upkeep.
FILE_BUDGETS = {
    ".html": (48 * KIB, 12 * KIB),
    ".css": (112 * KIB, 20 * KIB),
    ".js": (144 * KIB, 36 * KIB),
    ".json": (4 * MIB, 640 * KIB),
    ".png": (224 * KIB, None),
    ".svg": (32 * KIB, 12 * KIB),
    ".woff2": (48 * KIB, None),
}
PAGE_SHELL_GZIP_BUDGET = 64 * KIB
ROUTE_DATA_GZIP_BUDGETS = {
    "attack-map": (
        1024 * KIB,
        (
            "data/attack/catalogue/enterprise.json",
            "data/attack/intelligence/official-actor-procedures.json",
            "data/attack/intelligence/reviewed-evidence.json",
            "data/attack/operations/guides.json",
            "data/attack/detections/packages.json",
            "data/attack/governance/governance.json",
        ),
    ),
    "baltic-threat-atlas": (32 * KIB, ("data/atlas/records.json",)),
    "osint-workbench": (32 * KIB, ("data/osint/resources.json",)),
    "pivot-graph": (
        32 * KIB,
        (
            "data/pivots/cases.json",
            "data/pivots/graphs/adform.json",
            "data/pivots/graphs/unipark.json",
            "data/pivots/graphs/github-python.json",
        ),
    ),
}


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        value = attributes.get("href") if tag == "link" else attributes.get("src")
        if not value:
            return
        parsed = urlparse(value)
        if parsed.scheme or parsed.netloc or Path(parsed.path).suffix not in {".css", ".js"}:
            return
        self.assets.add(unquote(parsed.path).lstrip("/"))


def public_files(suffix: str) -> list[Path]:
    return [
        path
        for path in ROOT.rglob(f"*{suffix}")
        if not IGNORED_PARTS.intersection(path.relative_to(ROOT).parts)
        and "scripts" not in path.relative_to(ROOT).parts
    ]


def gzip_size(path: Path) -> int:
    return len(gzip.compress(path.read_bytes(), compresslevel=9, mtime=0))


def display_size(value: int) -> str:
    return f"{value / KIB:.1f} KiB"


def main() -> int:
    errors: list[str] = []
    measured: dict[Path, tuple[int, int]] = {}

    def measure(path: Path) -> tuple[int, int]:
        if path not in measured:
            measured[path] = (path.stat().st_size, gzip_size(path))
        return measured[path]

    checked_files: list[Path] = []
    for suffix, (raw_limit, gzip_limit) in FILE_BUDGETS.items():
        for path in public_files(suffix):
            checked_files.append(path)
            raw, compressed = measure(path)
            relative = path.relative_to(ROOT).as_posix()
            if raw > raw_limit:
                errors.append(f"{relative}: raw size {display_size(raw)} exceeds {display_size(raw_limit)}")
            if gzip_limit and compressed > gzip_limit:
                errors.append(
                    f"{relative}: gzip size {display_size(compressed)} exceeds {display_size(gzip_limit)}"
                )

    for html_path in public_files(".html"):
        parser = AssetParser()
        parser.feed(html_path.read_text(encoding="utf-8"))
        shell_paths = {html_path}
        for relative in parser.assets:
            asset = (ROOT / relative).resolve()
            if not asset.is_relative_to(ROOT) or not asset.is_file():
                errors.append(f"{html_path.relative_to(ROOT).as_posix()}: missing shell asset {relative}")
                continue
            shell_paths.add(asset)
        shell_size = sum(measure(path)[1] for path in shell_paths)
        if shell_size > PAGE_SHELL_GZIP_BUDGET:
            errors.append(
                f"{html_path.relative_to(ROOT).as_posix()}: document plus direct CSS/JS is "
                f"{display_size(shell_size)} gzip; budget is {display_size(PAGE_SHELL_GZIP_BUDGET)}"
            )

    for route, (limit, relatives) in ROUTE_DATA_GZIP_BUDGETS.items():
        paths = [ROOT / relative for relative in relatives]
        missing = [path.relative_to(ROOT).as_posix() for path in paths if not path.is_file()]
        if missing:
            errors.append(f"{route}: missing declared data asset(s): {', '.join(missing)}")
            continue
        transfer = sum(measure(path)[1] for path in paths)
        if transfer > limit:
            errors.append(
                f"{route}: declared data transfer is {display_size(transfer)} gzip; budget is {display_size(limit)}"
            )

    if errors:
        print(f"Performance budget failed ({len(errors)}):", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1

    largest = max(checked_files, key=lambda path: measure(path)[1])
    print(
        f"Performance budget passed for {len(checked_files)} public files; largest checked transfer is "
        f"{largest.relative_to(ROOT).as_posix()} at {display_size(measure(largest)[1])} gzip."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
