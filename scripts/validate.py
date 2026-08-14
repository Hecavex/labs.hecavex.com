#!/usr/bin/env python3
"""Dependency-free structural validation for HECAVEX Labs."""

from html.parser import HTMLParser
from html import unescape
import json
from pathlib import Path
import sys


class Parser(HTMLParser):
    pass


root = Path(__file__).resolve().parent.parent
required = {"index.html", "baltic-threat-atlas/index.html", "pivot-graph/index.html", "cra-reporting/index.html", "CNAME", "robots.txt", "sitemap.xml", ".well-known/security.txt"}
missing = sorted(path for path in required if not (root / path).is_file())
if missing:
    print("Missing required endpoints: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)

for path in root.rglob("*.html"):
    Parser().feed(path.read_text(encoding="utf-8"))
for path in root.rglob("*.json"):
    json.loads(path.read_text(encoding="utf-8"))

atlas_path = root / "data/baltic-threat-atlas.json"
atlas = json.loads(atlas_path.read_text(encoding="utf-8"))
records = atlas.get("records", [])
if not records:
    print("Baltic Threat Atlas contains no records.", file=sys.stderr)
    raise SystemExit(1)

required_record_fields = {"id", "date", "country", "type", "title", "summary", "sector", "attribution", "confidence", "source"}
record_ids = set()
atlas_html = unescape((root / "baltic-threat-atlas/index.html").read_text(encoding="utf-8"))
for record in records:
    missing_fields = sorted(required_record_fields - record.keys())
    if missing_fields:
        print(f"Atlas record {record.get('id', '<unknown>')} is missing: {', '.join(missing_fields)}", file=sys.stderr)
        raise SystemExit(1)
    if record["id"] in record_ids:
        print(f"Duplicate Atlas record id: {record['id']}", file=sys.stderr)
        raise SystemExit(1)
    record_ids.add(record["id"])
    if record["country"] not in {"Lithuania", "Latvia", "Estonia"}:
        print(f"Unsupported Atlas country in {record['id']}: {record['country']}", file=sys.stderr)
        raise SystemExit(1)
    if not record["source"].startswith("https://"):
        print(f"Atlas source must use HTTPS in {record['id']}", file=sys.stderr)
        raise SystemExit(1)
    if record["title"] not in atlas_html:
        print(f"Atlas record is missing from the rendered page: {record['id']}", file=sys.stderr)
        raise SystemExit(1)

print(f"Validated {len(list(root.rglob('*.html')))} HTML files, {len(list(root.rglob('*.json')))} JSON files, {len(records)} Atlas records and all required endpoints.")
