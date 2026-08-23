#!/usr/bin/env python3
"""Stage only the Labs data files explicitly approved in the public manifest."""

import argparse
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = (ROOT / "data").resolve()
MANIFEST_PATH = DATA_ROOT / "public-manifest.json"


def manifest_paths():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("default_policy") != "deny":
        raise SystemExit("Public data manifest must use a default-deny policy")

    paths = []
    for record in manifest.get("files", []):
        relative = Path(record.get("path", ""))
        source = (ROOT / relative).resolve()
        if not relative.parts or relative.parts[0] != "data" or not source.is_relative_to(DATA_ROOT):
            raise SystemExit(f"Manifest path escapes data/: {relative}")
        if not source.is_file():
            raise SystemExit(f"Manifest source is missing: {relative.as_posix()}")
        paths.append((relative, source))

    listed = [relative.as_posix() for relative, _source in paths]
    if len(listed) != len(set(listed)):
        raise SystemExit("Public data manifest contains duplicate paths")
    actual = sorted(path.relative_to(ROOT).as_posix() for path in DATA_ROOT.rglob("*") if path.is_file())
    if sorted(listed) != actual:
        missing = sorted(set(actual) - set(listed))
        stale = sorted(set(listed) - set(actual))
        raise SystemExit(f"Public data manifest mismatch; unapproved={missing}, missing={stale}")
    return paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path, help="Existing site staging directory")
    args = parser.parse_args()
    destination = args.destination.resolve()
    if not destination.is_dir():
        raise SystemExit(f"Destination directory does not exist: {destination}")

    paths = manifest_paths()
    for relative, source in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    print(f"Staged {len(paths)} explicitly approved public data files")


if __name__ == "__main__":
    main()
