#!/usr/bin/env python3
"""Stage only the Labs data files explicitly approved in the public manifest."""

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import shutil


ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = (ROOT / "data").resolve()
MANIFEST_PATH = DATA_ROOT / "public-manifest.json"
PIVOT_CASES_PATH = DATA_ROOT / "pivots" / "cases.json"
ANALYTICS_ENVIRONMENT = "HECAVEX_ANALYTICS_TOKEN"
ANALYTICS_SOURCE = "https://static.cloudflareinsights.com/beacon.min.js"


def analytics_loader(token: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", token):
        raise SystemExit("Cloudflare analytics token has an invalid format")
    encoded_token = json.dumps(token)
    return f'''<script data-hecavex-analytics>
    (() => {{
      if (navigator.doNotTrack === '1' || window.doNotTrack === '1') return;
      const beacon = document.createElement('script');
      beacon.type = 'module';
      beacon.src = '{ANALYTICS_SOURCE}';
      beacon.dataset.cfBeacon = JSON.stringify({{ token: {encoded_token} }});
      document.head.appendChild(beacon);
    }})();
  </script>'''


def stage_analytics(destination: Path, token: str, *, required: bool) -> int:
    if not token:
        if required:
            raise SystemExit("Cloudflare analytics token is required for the production artifact")
        return 0

    loader = analytics_loader(token)
    html_files = sorted(destination.rglob("*.html"))
    if not html_files:
        raise SystemExit("Production artifact contains no HTML pages for analytics staging")

    for path in html_files:
        text = path.read_text(encoding="utf-8")
        if "data-hecavex-analytics" in text or ANALYTICS_SOURCE in text:
            raise SystemExit(f"Analytics loader already exists in staged page: {path.relative_to(destination)}")
        if text.count("</body>") != 1:
            raise SystemExit(f"Staged page has no unique closing body tag: {path.relative_to(destination)}")
        rendered = text.replace("</body>", f"  {loader}\n</body>", 1)
        path.write_text(rendered, encoding="utf-8", newline="\n")

    for path in html_files:
        text = path.read_text(encoding="utf-8")
        if text.count("data-hecavex-analytics") != 1 or text.count(ANALYTICS_SOURCE) != 1:
            raise SystemExit(f"Staged analytics loader count is invalid: {path.relative_to(destination)}")
        if token not in text:
            raise SystemExit(f"Configured analytics token is missing from staged page: {path.relative_to(destination)}")

    return len(html_files)


def validate_pivot_publication(listed_paths: set[str]) -> None:
    """Require an explicit approval record for every publicly staged case graph."""

    catalogue = json.loads(PIVOT_CASES_PATH.read_text(encoding="utf-8"))
    cases = catalogue.get("cases", [])
    if not cases:
        raise SystemExit("The public pivot catalogue must contain at least one approved case")

    approved_graphs: set[str] = set()
    case_ids: set[str] = set()
    for case in cases:
        case_id = str(case.get("id", "")).strip()
        if not case_id or case_id in case_ids:
            raise SystemExit("Public pivot cases require unique non-empty ids")
        case_ids.add(case_id)

        if case.get("publication_approved") is not True:
            raise SystemExit(f"Pivot case is not explicitly approved for publication: {case_id}")
        approved_at = str(case.get("publication_approved_at", ""))
        try:
            date.fromisoformat(approved_at)
        except ValueError as error:
            raise SystemExit(f"Pivot case has no valid publication approval date: {case_id}") from error

        graph = str(case.get("graph", "")).lstrip("/")
        if not graph.startswith("data/pivots/graphs/") or graph not in listed_paths:
            raise SystemExit(f"Approved pivot graph is not in the public manifest: {case_id} -> {graph}")
        approved_graphs.add(graph)

    staged_graphs = {
        path for path in listed_paths if path.startswith("data/pivots/graphs/") and path.endswith(".json")
    }
    if approved_graphs != staged_graphs:
        raise SystemExit(
            "Public pivot graph approval mismatch; "
            f"unapproved={sorted(staged_graphs - approved_graphs)}, "
            f"missing={sorted(approved_graphs - staged_graphs)}"
        )


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
    validate_pivot_publication(set(listed))
    return paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path, help="Existing site staging directory")
    parser.add_argument("--require-analytics", action="store_true", help="fail unless analytics is configured in every staged HTML page")
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
    token = os.environ.get(ANALYTICS_ENVIRONMENT, "").strip()
    analytics_pages = stage_analytics(destination, token, required=args.require_analytics)
    if analytics_pages:
        print(f"Verified Cloudflare Web Analytics in {analytics_pages} staged HTML pages")


if __name__ == "__main__":
    main()
