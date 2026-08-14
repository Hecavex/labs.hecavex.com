#!/usr/bin/env python3
"""Dependency-free structural validation for HECAVEX Labs."""

from html.parser import HTMLParser
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

print(f"Validated {len(list(root.rglob('*.html')))} HTML files, {len(list(root.rglob('*.json')))} JSON files and all required endpoints.")
