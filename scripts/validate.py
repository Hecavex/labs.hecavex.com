#!/usr/bin/env python3
"""Dependency-free production validation for HECAVEX Labs."""

from html.parser import HTMLParser
import json
from pathlib import Path
import sys
from urllib.parse import urlparse


class DocumentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.references = []
        self.html_lang = ""
        self.title_depth = 0
        self.title = ""
        self.metas = []
        self.canonicals = []
        self.main_count = 0
        self.h1_count = 0
        self.images_without_alt = 0
        self.controls = []
        self.labels = set()
        self.json_ld = []
        self._json_depth = 0
        self._json_buffer = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "html":
            self.html_lang = attributes.get("lang", "")
        if tag == "title":
            self.title_depth += 1
        if tag == "meta":
            self.metas.append(attributes)
        if tag == "link" and "canonical" in attributes.get("rel", "").split():
            self.canonicals.append(attributes.get("href", ""))
        if tag == "main":
            self.main_count += 1
        if tag == "h1":
            self.h1_count += 1
        if tag == "img" and "alt" not in attributes:
            self.images_without_alt += 1
        if tag in {"input", "select", "textarea"}:
            self.controls.append(attributes)
        if tag == "label" and attributes.get("for"):
            self.labels.add(attributes["for"])
        if tag == "script" and attributes.get("type") == "application/ld+json":
            self._json_depth = 1
            self._json_buffer = []
        if "id" in attributes:
            self.ids.append(attributes["id"])
        for name in ("href", "src"):
            value = attributes.get(name)
            if value:
                self.references.append(value)

    def handle_data(self, data):
        if self.title_depth:
            self.title += data
        if self._json_depth:
            self._json_buffer.append(data)

    def handle_endtag(self, tag):
        if tag == "title" and self.title_depth:
            self.title_depth -= 1
        if tag == "script" and self._json_depth:
            self.json_ld.append("".join(self._json_buffer))
            self._json_depth = 0
            self._json_buffer = []


root = Path(__file__).resolve().parent.parent
required = {
    "index.html",
    "baltic-threat-atlas/index.html",
    "pivot-graph/index.html",
    "cra-reporting/index.html",
    "assets/styles.css",
    "assets/site.js",
    "assets/atlas.js",
    "assets/pivot-graph.js",
    "assets/cra-reporting.js",
    "data/baltic-threat-atlas.json",
    "data/pivot-graph-adform.json",
    "CNAME",
    "robots.txt",
    "sitemap.xml",
    "LICENSE.md",
    ".well-known/security.txt",
}

errors = []
missing = sorted(path for path in required if not (root / path).is_file())
if missing:
    errors.append("Missing required files: " + ", ".join(missing))

mojibake_markers = ("â€", "Â", "ï¿½", "�")
html_files = list(root.rglob("*.html"))
canonicals = {}
for path in html_files:
    text = path.read_text(encoding="utf-8")
    parser = DocumentParser()
    parser.feed(text)
    duplicates = sorted({value for value in parser.ids if parser.ids.count(value) > 1})
    if duplicates:
        errors.append(f"Duplicate HTML ids in {path.relative_to(root)}: {', '.join(duplicates)}")
    if any(marker in text for marker in mojibake_markers):
        errors.append(f"Possible mojibake in {path.relative_to(root)}")
    relative = path.relative_to(root)
    if not parser.html_lang:
        errors.append(f"Missing html lang in {relative}")
    if not parser.title.strip():
        errors.append(f"Missing title in {relative}")
    meta_by_name = {item.get("name"): item.get("content", "") for item in parser.metas if item.get("name")}
    meta_by_property = {item.get("property"): item.get("content", "") for item in parser.metas if item.get("property")}
    if not meta_by_name.get("description", "").strip():
        errors.append(f"Missing meta description in {relative}")
    if len(parser.canonicals) != 1:
        errors.append(f"Expected one canonical in {relative}, found {len(parser.canonicals)}")
    elif parser.canonicals[0] in canonicals:
        errors.append(f"Duplicate canonical in {relative} and {canonicals[parser.canonicals[0]]}")
    else:
        canonicals[parser.canonicals[0]] = relative
    for key in ("og:title", "og:description", "og:url", "og:image", "og:image:width", "og:image:height", "og:image:alt"):
        if not meta_by_property.get(key, "").strip():
            errors.append(f"Missing {key} in {relative}")
    for key in ("twitter:card", "twitter:title", "twitter:description", "twitter:image", "twitter:image:alt"):
        if not meta_by_name.get(key, "").strip():
            errors.append(f"Missing {key} in {relative}")
    if parser.main_count != 1:
        errors.append(f"Expected one main landmark in {relative}, found {parser.main_count}")
    if parser.h1_count != 1:
        errors.append(f"Expected one h1 in {relative}, found {parser.h1_count}")
    if parser.images_without_alt:
        errors.append(f"Images without alt attributes in {relative}: {parser.images_without_alt}")
    for control in parser.controls:
        control_id = control.get("id", "")
        if not control.get("aria-label") and not control.get("aria-labelledby") and control_id not in parser.labels:
            errors.append(f"Unlabelled form control in {relative}: {control_id or control.get('name', control.get('type', 'unknown'))}")
    if len(parser.json_ld) != 1:
        errors.append(f"Expected one consolidated JSON-LD graph in {relative}, found {len(parser.json_ld)}")
    for payload in parser.json_ld:
        try:
            schema = json.loads(payload)
            graph_items = schema.get("@graph", [])
            if not isinstance(graph_items, list):
                errors.append(f"JSON-LD is not an @graph in {relative}")
                graph_items = []
            graph_ids = {item.get("@id") for item in graph_items}
            expected_ids = {
                "https://hecavex.com/#organization",
                "https://hecavex.com/#deividas-lis",
                "https://hecavex.com/#website",
                "https://apt.hecavex.com/#website",
                "https://labs.hecavex.com/#website",
            }
            missing_ids = expected_ids - graph_ids
            if missing_ids:
                errors.append(f"JSON-LD is missing shared HECAVEX identities in {relative}: {', '.join(sorted(missing_ids))}")

            pending = [schema]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
                elif isinstance(value, str):
                    parsed = urlparse(value)
                    if parsed.hostname != "labs.hecavex.com":
                        continue
                    local_path = parsed.path or "/"
                    target = root / local_path.lstrip("/")
                    if local_path.endswith("/"):
                        target = target / "index.html"
                    if not target.is_file():
                        errors.append(f"Broken local URL in JSON-LD for {relative}: {value}")
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON-LD in {relative}: {exc}")
    for reference in parser.references:
        if not reference.startswith("/") or reference.startswith("//"):
            continue
        local = reference.split("#", 1)[0].split("?", 1)[0]
        if not local:
            continue
        target = root / local.lstrip("/")
        if local.endswith("/"):
            target = target / "index.html"
        if not target.is_file():
            errors.append(f"Broken local asset in {path.relative_to(root)}: {reference}")

for path in root.rglob("*.json"):
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in {path.relative_to(root)}: {exc}")

atlas = json.loads((root / "data/baltic-threat-atlas.json").read_text(encoding="utf-8"))
records = atlas.get("records", [])
if not records:
    errors.append("Baltic Threat Atlas contains no records")

required_record_fields = {"id", "date", "country", "type", "title", "summary", "sector", "attribution", "confidence", "source"}
record_ids = set()
for record in records:
    record_id = record.get("id", "<unknown>")
    missing_fields = sorted(required_record_fields - record.keys())
    if missing_fields:
        errors.append(f"Atlas record {record_id} is missing: {', '.join(missing_fields)}")
    if record_id in record_ids:
        errors.append(f"Duplicate Atlas record id: {record_id}")
    record_ids.add(record_id)
    if record.get("country") not in {"Lithuania", "Latvia", "Estonia"}:
        errors.append(f"Unsupported Atlas country in {record_id}: {record.get('country')}")
    if urlparse(record.get("source", "")).scheme != "https":
        errors.append(f"Atlas source must use HTTPS in {record_id}")
    for reference in record.get("apt_refs", []):
        if urlparse(reference.get("url", "")).hostname != "apt.hecavex.com":
            errors.append(f"Invalid APT Notes mapping in {record_id}: {reference.get('url')}")

atlas_html = (root / "baltic-threat-atlas/index.html").read_text(encoding="utf-8")
if 'id="atlas-records"' not in atlas_html or '/assets/atlas.js' not in atlas_html:
    errors.append("Atlas page is not wired to the canonical JSON renderer")
if any(record["title"] in atlas_html for record in records):
    errors.append("Atlas records must not be duplicated in HTML")

graph = json.loads((root / "data/pivot-graph-adform.json").read_text(encoding="utf-8"))
nodes = graph.get("nodes", [])
edges = graph.get("edges", [])
node_ids = {node.get("id") for node in nodes}
if len(node_ids) != len(nodes) or None in node_ids:
    errors.append("Pivot graph node ids must be present and unique")
for node in nodes:
    missing_node_fields = {"id", "class", "label", "short_label", "x", "y", "meaning", "confidence", "evidence"} - node.keys()
    if missing_node_fields:
        errors.append(f"Pivot node {node.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_node_fields))}")
for edge in edges:
    if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
        errors.append(f"Pivot edge references an unknown node: {edge}")
    if not edge.get("relationship"):
        errors.append(f"Pivot edge has no relationship: {edge}")

cra_html = (root / "cra-reporting/index.html").read_text(encoding="utf-8")
for question in ("role", "market", "exploitation", "severe-data", "severe-code"):
    if f'data-question="{question}"' not in cra_html:
        errors.append(f"CRA triage is missing question: {question}")
for control in ("copy-summary", "export-json", "aware-at"):
    if f'id="{control}"' not in cra_html:
        errors.append(f"CRA triage is missing control: {control}")

if errors:
    print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
    raise SystemExit(1)

print(
    f"Validated {len(html_files)} HTML pages, {len(records)} Atlas records, "
    f"{len(nodes)} pivot nodes, {len(edges)} typed edges and all required production endpoints."
)
