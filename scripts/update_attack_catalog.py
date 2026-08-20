#!/usr/bin/env python3
"""Build the compact HECAVEX Enterprise ATT&CK catalogue from MITRE's STIX bundle."""

from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen


SOURCE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "attack" / "catalogue" / "enterprise.json"
PROCEDURES_OUTPUT = ROOT / "data" / "attack" / "intelligence" / "official-actor-procedures.json"
CITATION_URLS = {}


def active(item):
    return not item.get("revoked", False) and not item.get("x_mitre_deprecated", False)


def external(item):
    references = item.get("external_references", [])
    return next((ref for ref in references if ref.get("source_name") == "mitre-attack"), {})


def clean(text):
    text = re.sub(r"\[(.+?)\]\([^)]*\)", r"\1", text or "")
    text = re.sub(r"\[(.+?)\]\[[^]]+\]", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\(Citation:[^)]+\)", "", text)
    text = text.replace("**", "").replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def entity(item):
    reference = external(item)
    return {
        "id": reference.get("external_id", ""),
        "name": item.get("name", ""),
        "url": reference.get("url", ""),
    }


def source_links(item):
    links = []
    for reference in item.get("external_references", []):
        url = reference.get("url", "") or CITATION_URLS.get(reference.get("source_name", ""), "")
        if not url.startswith("https://") or reference.get("source_name") == "mitre-attack":
            continue
        value = {"source": reference.get("source_name", "Public source"), "url": url}
        if value not in links:
            links.append(value)
    return links


request = Request(SOURCE, headers={"User-Agent": "HECAVEX-Labs-ATTACK-catalogue/1.0"})
with urlopen(request, timeout=120) as response:
    bundle = json.load(response)

objects = [item for item in bundle["objects"] if active(item)]
by_id = {item["id"]: item for item in objects}
for item in objects:
    for reference in item.get("external_references", []):
        source_name = reference.get("source_name", "")
        url = reference.get("url", "")
        if source_name and url.startswith("https://"):
            CITATION_URLS.setdefault(source_name, url)
collection = next(item for item in objects if item.get("type") == "x-mitre-collection")
matrix = next(item for item in objects if item.get("type") == "x-mitre-matrix" and item.get("name") == "Enterprise ATT&CK")

tactics = []
tactic_names = {}
for tactic_ref in matrix.get("tactic_refs", []):
    item = by_id[tactic_ref]
    reference = external(item)
    short = item.get("x_mitre_shortname", "")
    tactic_names[short] = item["name"]
    tactics.append({
        "id": reference.get("external_id", ""),
        "name": item["name"],
        "shortname": short,
        "description": clean(item.get("description", "")),
        "url": reference.get("url", ""),
    })

parents = {}
associations = defaultdict(lambda: defaultdict(list))
group_procedures = defaultdict(list)
relation_labels = {
    "intrusion-set": "groups",
    "campaign": "campaigns",
    "malware": "software",
    "tool": "software",
    "course-of-action": "mitigations",
    "x-mitre-detection-strategy": "detections",
}

for relationship in (item for item in objects if item.get("type") == "relationship"):
    source = by_id.get(relationship.get("source_ref"))
    target = by_id.get(relationship.get("target_ref"))
    if not source or not target:
        continue
    relation = relationship.get("relationship_type")
    if relation == "subtechnique-of" and source.get("type") == "attack-pattern" and target.get("type") == "attack-pattern":
        parents[source["id"]] = target["id"]
        continue
    technique = None
    related = None
    if target.get("type") == "attack-pattern" and source.get("type") in relation_labels:
        technique, related = target, source
    elif source.get("type") == "attack-pattern" and target.get("type") in relation_labels:
        technique, related = source, target
    if not technique or relation not in {"uses", "mitigates", "detects"}:
        continue
    if source.get("type") == "intrusion-set" and target.get("type") == "attack-pattern" and relation == "uses":
        group_reference = external(source)
        technique_reference = external(target)
        group_id = group_reference.get("external_id", "")
        technique_id = technique_reference.get("external_id", "")
        if group_id and technique_id:
            procedure = {
                "technique_id": technique_id,
                "description": clean(relationship.get("description", "")),
                "sources": source_links(relationship),
            }
            if procedure not in group_procedures[group_id]:
                group_procedures[group_id].append(procedure)
    label = relation_labels[related["type"]]
    value = entity(related)
    if value not in associations[technique["id"]][label]:
        associations[technique["id"]][label].append(value)

techniques = []
for item in (obj for obj in objects if obj.get("type") == "attack-pattern"):
    reference = external(item)
    technique_id = reference.get("external_id")
    if not technique_id:
        continue
    parent = by_id.get(parents.get(item["id"], ""), {})
    parent_reference = external(parent) if parent else {}
    relations = associations[item["id"]]
    entry = {
        "id": technique_id,
        "name": item["name"],
        "url": reference.get("url", ""),
        "description": clean(item.get("description", "")),
        "tactics": [tactic_names.get(phase["phase_name"], phase["phase_name"]) for phase in item.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"],
        "platforms": sorted(item.get("x_mitre_platforms", [])),
        "subtechnique": bool(item.get("x_mitre_is_subtechnique", False)),
        "parent": {"id": parent_reference.get("external_id", ""), "name": parent.get("name", ""), "url": parent_reference.get("url", "")} if parent else None,
        "modified": item.get("modified", "")[:10],
        "version": item.get("x_mitre_version", ""),
    }
    for label in relation_labels.values():
        entry[label] = sorted(relations[label], key=lambda value: (value["name"].lower(), value["id"]))
    techniques.append(entry)

techniques.sort(key=lambda item: tuple(int(part) for part in item["id"][1:].split(".")))

group_techniques = defaultdict(list)
for technique in techniques:
    for group in technique["groups"]:
        group_techniques[group["id"]].append(technique["id"])

groups = []
for item in (obj for obj in objects if obj.get("type") == "intrusion-set"):
    reference = external(item)
    group_id = reference.get("external_id")
    if not group_id:
        continue
    aliases = []
    for alias in [*item.get("aliases", []), *item.get("x_mitre_aliases", [])]:
        known = {value.casefold() for value in aliases}
        if alias and alias.casefold() != item.get("name", "").casefold() and alias.casefold() not in known:
            aliases.append(alias)
    procedures = sorted(group_procedures[group_id], key=lambda value: tuple(int(part) for part in value["technique_id"][1:].split(".")))
    groups.append({
        "id": group_id,
        "name": item.get("name", ""),
        "aliases": aliases,
        "url": reference.get("url", ""),
        "description": clean(item.get("description", "")),
        "created": item.get("created", "")[:10],
        "modified": item.get("modified", "")[:10],
        "version": item.get("x_mitre_version", ""),
        "techniques": sorted(set(group_techniques[group_id]), key=lambda value: tuple(int(part) for part in value[1:].split("."))),
        "procedures": procedures,
        "sources": source_links(item),
    })

groups.sort(key=lambda item: (item["name"].casefold(), item["id"]))
procedure_groups = []
for group in groups:
    procedure_groups.append({"id": group["id"], "name": group["name"], "procedures": group.pop("procedures")})
generated = datetime.now(timezone.utc).date().isoformat()
payload = {
    "schema_version": "1.1",
    "generated": generated,
    "source": SOURCE,
    "domain": "Enterprise",
    "version": collection.get("x_mitre_version", ""),
    "modified": collection.get("modified", ""),
    "notice": "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
    "terms": "https://attack.mitre.org/resources/terms-of-use/",
    "tactics": tactics,
    "groups": groups,
    "techniques": techniques,
}
procedure_payload = {
    "schema_version": "1.0",
    "generated": generated,
    "source": SOURCE,
    "domain": "Enterprise",
    "version": collection.get("x_mitre_version", ""),
    "boundary": "Official MITRE ATT&CK group-to-technique procedure relationships and available public citations. This reference layer is not a HECAVEX attribution or current-activity assessment.",
    "groups": procedure_groups,
}
OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
PROCEDURES_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
PROCEDURES_OUTPUT.write_text(json.dumps(procedure_payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
procedure_count = sum(len(group["procedures"]) for group in procedure_groups)
print(f"Wrote {len(techniques)} active Enterprise ATT&CK techniques, {len(groups)} groups and {procedure_count} official actor procedures across {len(tactics)} tactics")
