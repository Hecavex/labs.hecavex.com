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
    "attack-map/index.html",
    "osint-workbench/index.html",
    "assets/styles.css",
    "assets/site.js",
    "assets/atlas.js",
    "assets/pivot-graph.js",
    "assets/attack-map.js",
    "assets/osint-workbench.js",
    "data/baltic-threat-atlas.json",
    "data/osint-resources.json",
    "data/pivot-cases.json",
    "data/pivot-graph-adform.json",
    "data/pivot-graph-unipark.json",
    "data/pivot-graph-github-python.json",
    "data/attack-evidence.json",
    "data/enterprise-attack.json",
    "scripts/update_attack_catalog.py",
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

case_catalogue = json.loads((root / "data/pivot-cases.json").read_text(encoding="utf-8"))
cases = case_catalogue.get("cases", [])
case_ids = [case.get("id") for case in cases]
if not cases:
    errors.append("Pivot case catalogue must contain at least one case")
if len(case_ids) != len(set(case_ids)) or None in case_ids:
    errors.append("Pivot case ids must be present and unique")

allowed_classes = {"observed", "derived", "assessment", "limitation"}
catalogued_graphs = set()
total_nodes = 0
total_edges = 0
for case in cases:
    missing_case_fields = {"id", "title", "short_title", "summary", "status", "updated", "graph", "research", "tags"} - case.keys()
    if missing_case_fields:
        errors.append(f"Pivot case {case.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_case_fields))}")
        continue
    if urlparse(case["research"]).scheme != "https":
        errors.append(f"Pivot case research URL must use HTTPS in {case['id']}")
    graph_path = case["graph"].lstrip("/")
    catalogued_graphs.add(graph_path)
    if not (root / graph_path).is_file():
        errors.append(f"Pivot case graph does not exist for {case['id']}: {graph_path}")
        continue
    graph = json.loads((root / graph_path).read_text(encoding="utf-8"))
    if graph.get("case", {}).get("id") != case["id"]:
        errors.append(f"Pivot catalogue and graph case ids differ for {case['id']}")
    if not graph.get("case", {}).get("boundary"):
        errors.append(f"Pivot graph has no explicit boundary for {case['id']}")
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    total_nodes += len(nodes)
    total_edges += len(edges)
    node_ids = {node.get("id") for node in nodes}
    if len(node_ids) != len(nodes) or None in node_ids:
        errors.append(f"Pivot graph node ids must be present and unique in {case['id']}")
    node_classes = {node.get("class") for node in nodes}
    if not {"assessment", "limitation"}.issubset(node_classes):
        errors.append(f"Pivot graph must include an assessment and limitation in {case['id']}")
    for node in nodes:
        missing_node_fields = {"id", "class", "label", "short_label", "x", "y", "meaning", "confidence", "evidence_label", "evidence"} - node.keys()
        if missing_node_fields:
            errors.append(f"Pivot node {case['id']}/{node.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_node_fields))}")
        if node.get("class") not in allowed_classes:
            errors.append(f"Unsupported pivot evidence class in {case['id']}/{node.get('id')}: {node.get('class')}")
        if urlparse(node.get("evidence", "")).scheme != "https":
            errors.append(f"Pivot evidence URL must use HTTPS in {case['id']}/{node.get('id')}")
    for edge in edges:
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            errors.append(f"Pivot edge references an unknown node in {case['id']}: {edge}")
        if not edge.get("relationship"):
            errors.append(f"Pivot edge has no relationship in {case['id']}: {edge}")

graph_files = {str(path.relative_to(root)).replace("\\", "/") for path in (root / "data").glob("pivot-graph-*.json")}
if graph_files != catalogued_graphs:
    errors.append(f"Pivot catalogue mismatch. Catalogued: {sorted(catalogued_graphs)}; present: {sorted(graph_files)}")

pivot_html = (root / "pivot-graph/index.html").read_text(encoding="utf-8")
if 'id="case-selector"' not in pivot_html or "/data/pivot-cases.json" not in pivot_html:
    errors.append("Pivot Workspace is not wired to the case catalogue")

attack = json.loads((root / "data/attack-evidence.json").read_text(encoding="utf-8"))
attack_actors = attack.get("actors", [])
attack_behaviours = attack.get("behaviours", [])
attack_tactics = attack.get("tactics", [])
attack_records = [record for actor in attack_actors for record in actor.get("evidence", [])]
behaviour_records = [record for behaviour in attack_behaviours for record in behaviour.get("techniques", [])]
if {actor.get("id") for actor in attack_actors} != {"apt28", "apt44"}:
    errors.append("ATT&CK Evidence Map must contain the reviewed APT28 and APT44 records")
if len(attack_tactics) != 14 or len(set(attack_tactics)) != 14:
    errors.append("ATT&CK Evidence Map must contain the 14 unique Enterprise tactics")
if len(attack_records) != 19:
    errors.append(f"ATT&CK Evidence Map expected 19 evidence records, found {len(attack_records)}")
required_attack_fields = {"technique_id", "technique", "tactics", "status", "confidence", "campaign", "first_observed", "last_observed", "notes", "attack_url", "sources"}
for actor in attack_actors:
    if urlparse(actor.get("profile_url", "")).hostname != "apt.hecavex.com":
        errors.append(f"ATT&CK actor profile must link to APT Notes: {actor.get('id')}")
    for record in actor.get("evidence", []):
        record_name = f"{actor.get('id')}/{record.get('technique_id', '<unknown>')}"
        missing_attack_fields = required_attack_fields - record.keys()
        if missing_attack_fields:
            errors.append(f"ATT&CK record {record_name} is missing: {', '.join(sorted(missing_attack_fields))}")
        technique_id = record.get("technique_id", "")
        if not technique_id.startswith("T") or not technique_id[1:].replace(".", "").isdigit():
            errors.append(f"Invalid ATT&CK technique id in {record_name}")
        if not record.get("tactics") or not set(record.get("tactics", [])).issubset(set(attack_tactics)):
            errors.append(f"Invalid tactic mapping in {record_name}: {record.get('tactics')}")
        if record.get("status") not in {"reported", "observed", "assessed"}:
            errors.append(f"Invalid evidence status in {record_name}: {record.get('status')}")
        if record.get("confidence") not in {"high", "moderate", "low"}:
            errors.append(f"Invalid ATT&CK confidence in {record_name}: {record.get('confidence')}")
        if urlparse(record.get("attack_url", "")).hostname != "attack.mitre.org":
            errors.append(f"Invalid MITRE ATT&CK URL in {record_name}")
        if not record.get("sources"):
            errors.append(f"ATT&CK record has no public source: {record_name}")
        for source in record.get("sources", []):
            if not {"title", "publisher", "published", "url"}.issubset(source):
                errors.append(f"Incomplete ATT&CK source in {record_name}")
            if urlparse(source.get("url", "")).scheme != "https":
                errors.append(f"ATT&CK source must use HTTPS in {record_name}: {source.get('url')}")

if {behaviour.get("id") for behaviour in attack_behaviours} != {"phishing"}:
    errors.append("ATT&CK Behaviour Explorer must contain the bounded phishing model")
required_behaviour_fields = {"technique_id", "technique", "tactics", "role", "branch", "stage", "notes", "caveat", "attack_url", "sources"}
for behaviour in attack_behaviours:
    behaviour_id = behaviour.get("id", "<unknown>")
    branch_ids = {branch.get("id") for branch in behaviour.get("branches", [])}
    if len(branch_ids) < 4 or None in branch_ids:
        errors.append(f"ATT&CK behaviour {behaviour_id} must define its analytical branches")
    if not behaviour.get("boundary"):
        errors.append(f"ATT&CK behaviour {behaviour_id} has no explicit analytical boundary")
    for record in behaviour.get("techniques", []):
        record_name = f"{behaviour_id}/{record.get('technique_id', '<unknown>')}"
        missing_fields = required_behaviour_fields - record.keys()
        if missing_fields:
            errors.append(f"ATT&CK behaviour record {record_name} is missing: {', '.join(sorted(missing_fields))}")
        if record.get("role") not in {"delivery", "conditional", "outcome"}:
            errors.append(f"Invalid behaviour role in {record_name}: {record.get('role')}")
        if record.get("branch") not in branch_ids:
            errors.append(f"Unknown behaviour branch in {record_name}: {record.get('branch')}")
        if not record.get("tactics") or not set(record.get("tactics", [])).issubset(set(attack_tactics)):
            errors.append(f"Invalid behaviour tactic mapping in {record_name}: {record.get('tactics')}")
        if urlparse(record.get("attack_url", "")).hostname != "attack.mitre.org":
            errors.append(f"Invalid MITRE ATT&CK URL in behaviour record {record_name}")
        if not record.get("sources"):
            errors.append(f"ATT&CK behaviour record has no public source: {record_name}")
        for source in record.get("sources", []):
            if not {"title", "publisher", "published", "url"}.issubset(source):
                errors.append(f"Incomplete ATT&CK behaviour source in {record_name}")
            if urlparse(source.get("url", "")).scheme != "https":
                errors.append(f"ATT&CK behaviour source must use HTTPS in {record_name}: {source.get('url')}")

attack_html = (root / "attack-map/index.html").read_text(encoding="utf-8")
if 'id="attack-matrix"' not in attack_html or "/assets/attack-map.js" not in attack_html:
    errors.append("ATT&CK Evidence Map is not wired to its canonical renderer")

attack_catalogue = json.loads((root / "data/enterprise-attack.json").read_text(encoding="utf-8"))
catalogue_tactics = attack_catalogue.get("tactics", [])
catalogue_techniques = attack_catalogue.get("techniques", [])
if len(catalogue_tactics) != 15:
    errors.append(f"Enterprise ATT&CK catalogue expected 15 tactics, found {len(catalogue_tactics)}")
if len(catalogue_techniques) < 650:
    errors.append(f"Enterprise ATT&CK catalogue appears incomplete: {len(catalogue_techniques)} techniques")
catalogue_ids = [record.get("id") for record in catalogue_techniques]
if len(catalogue_ids) != len(set(catalogue_ids)) or None in catalogue_ids:
    errors.append("Enterprise ATT&CK technique ids must be present and unique")
catalogue_tactic_names = {tactic.get("name") for tactic in catalogue_tactics}
required_catalogue_fields = {"id", "name", "url", "description", "tactics", "platforms", "subtechnique", "parent", "modified", "version", "groups", "campaigns", "software", "mitigations", "detections"}
for record in catalogue_techniques:
    record_name = record.get("id", "<unknown>")
    missing_fields = required_catalogue_fields - record.keys()
    if missing_fields:
        errors.append(f"Enterprise ATT&CK record {record_name} is missing: {', '.join(sorted(missing_fields))}")
    if urlparse(record.get("url", "")).hostname != "attack.mitre.org":
        errors.append(f"Invalid official ATT&CK URL in catalogue record {record_name}")
    if not set(record.get("tactics", [])).issubset(catalogue_tactic_names):
        errors.append(f"Unknown tactic in catalogue record {record_name}: {record.get('tactics')}")
for path in html_files:
    if path.name == "index.html" and path.parent in {root, root / "baltic-threat-atlas", root / "pivot-graph", root / "osint-workbench", root / "attack-map"}:
        if "/attack-map/" not in path.read_text(encoding="utf-8"):
            errors.append(f"ATT&CK Evidence Map is missing from navigation in {path.relative_to(root)}")

osint = json.loads((root / "data/osint-resources.json").read_text(encoding="utf-8"))
osint_sections = osint.get("sections", [])
curation_sources = osint.get("curation_sources", [])
if len(curation_sources) != 3:
    errors.append("OSINT Workbench must identify its three curation sources")
for source in curation_sources:
    if urlparse(source.get("url", "")).hostname != "github.com":
        errors.append(f"OSINT curation source must be a GitHub repository: {source}")

section_ids = [section.get("id") for section in osint_sections]
if len(section_ids) != len(set(section_ids)) or None in section_ids:
    errors.append("OSINT section ids must be present and unique")
tool_ids = []
required_tool_fields = {"id", "name", "url", "access", "format", "use_when", "why", "caution"}
for section in osint_sections:
    tools = section.get("tools", [])
    if len(tools) < 2:
        errors.append(f"OSINT section must contain several selected tools: {section.get('id')}")
    for tool in tools:
        tool_ids.append(tool.get("id"))
        missing_tool_fields = required_tool_fields - tool.keys()
        if missing_tool_fields:
            errors.append(f"OSINT tool {tool.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_tool_fields))}")
        if urlparse(tool.get("url", "")).scheme != "https":
            errors.append(f"OSINT tool URL must use HTTPS: {tool.get('id')}")
if len(tool_ids) != len(set(tool_ids)) or None in tool_ids:
    errors.append("OSINT tool ids must be present and unique")

osint_html = (root / "osint-workbench/index.html").read_text(encoding="utf-8")
if 'id="resource-list"' not in osint_html or "/data/osint-resources.json" not in osint_html:
    errors.append("OSINT Workbench is not wired to its canonical dataset")
if any("cra-reporting" in path.read_text(encoding="utf-8").lower() for path in html_files):
    errors.append("Retired CRA Triage links remain in public HTML")

if errors:
    print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
    raise SystemExit(1)

print(
    f"Validated {len(html_files)} HTML pages, {len(records)} Atlas records, "
    f"{len(cases)} pivot cases, {total_nodes} pivot nodes, {total_edges} typed edges, "
    f"{len(catalogue_techniques)} Enterprise ATT&CK techniques, {len(attack_records)} actor evidence records, "
    f"{len(behaviour_records)} behaviour mappings and {len(tool_ids)} OSINT tools "
    f"across {len(osint_sections)} sections."
)
