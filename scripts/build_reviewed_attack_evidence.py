#!/usr/bin/env python3
"""Build the Labs ATT&CK evidence dataset from a local APT Notes build.

APT Notes remains the editorial source of truth. Labs publishes a compact,
read-only projection containing only explicit ``technique_evidence`` records.
The script never infers a mapping from actor technique lists or free text.

Typical use from the Labs repository::

    python scripts/build_reviewed_attack_evidence.py
    python scripts/build_reviewed_attack_evidence.py --check

The default source is the sibling ``sites/apt.hecavex.com/dist`` directory.
Set ``APT_NOTES_DIST`` or pass ``--apt-dist`` when the repositories live in a
different layout. In an isolated Labs checkout, ``--check`` still validates
the committed projection and reports that cross-repository drift was not
checked.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_APT_DIST = ROOT.parent.parent / "sites" / "apt.hecavex.com" / "dist"
DEFAULT_OUTPUT = ROOT / "data" / "attack" / "intelligence" / "reviewed-evidence.json"
VALID_CONFIDENCE = {"high", "moderate", "low"}
VALID_STATUS = {"observed", "reported", "assessed", "inferred", "disputed", "rejected"}
ENTERPRISE_TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)


class ContractError(RuntimeError):
    """Raised when the source or generated publication breaks the contract."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"Required APT Notes build file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError(f"Invalid JSON in {path}: {exc}") from exc


def api_records(api_root: Path, collection: str) -> dict[str, dict[str, Any]]:
    directory = api_root / collection
    if not directory.is_dir():
        raise ContractError(f"APT Notes API collection is missing: {directory}")
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("*.json")):
        record = read_json(path).get("record")
        if not isinstance(record, dict) or not record.get("id"):
            raise ContractError(f"APT Notes record envelope is invalid: {path}")
        records[str(record["id"])] = record
    return records


def source_projection(source_id: str, sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    source = sources.get(source_id)
    if not source:
        raise ContractError(f"Technique evidence references unknown source: {source_id}")
    return {
        "id": source_id,
        "title": source.get("title") or source.get("name") or source_id,
        "publisher": source.get("publisher") or "Unknown publisher",
        "published": (source.get("published_at") or "")[:10],
        "source_type": source.get("source_type") or "unspecified",
        "url": source.get("source_url") or source.get("url") or "",
        "apt_notes_url": source.get("url") or f"https://apt.hecavex.com/sources/{source_id}/",
    }


def tactic_projection(value: Any) -> list[str]:
    """Normalize the compact APT Notes tactic field without inventing tactics."""
    text = str(value or "")
    matches = [tactic for tactic in ENTERPRISE_TACTICS if tactic in text]
    return matches or ["Unspecified"]


def evidence_projection(
    actor: dict[str, Any],
    evidence: dict[str, Any],
    techniques: dict[str, dict[str, Any]],
    campaigns: dict[str, dict[str, Any]],
    sources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    technique_slug = str(evidence.get("technique") or "")
    technique = techniques.get(technique_slug)
    if not technique:
        raise ContractError(f"{actor['id']} references unknown technique: {technique_slug}")
    mitre_id = str(technique.get("mitre_id") or "")
    if not mitre_id.startswith("T"):
        raise ContractError(f"Technique {technique_slug} has no valid MITRE ATT&CK ID")

    campaign_slug = str(evidence.get("campaign") or "")
    campaign = campaigns.get(campaign_slug)
    if campaign_slug and not campaign:
        raise ContractError(f"{actor['id']} references unknown campaign: {campaign_slug}")

    confidence = str(evidence.get("confidence") or "").lower()
    if confidence not in VALID_CONFIDENCE:
        raise ContractError(f"{actor['id']} {technique_slug} has invalid confidence: {confidence}")

    # APT Notes currently publishes explicit source-backed procedure mappings.
    # A future record may supply a narrower evidence status; absent one, the
    # projection transparently labels it as reported rather than observed.
    mapping_status = str(evidence.get("status") or "reported").lower()
    if mapping_status not in VALID_STATUS:
        raise ContractError(f"{actor['id']} {technique_slug} has invalid status: {mapping_status}")

    source_ids = [str(value) for value in evidence.get("sources", [])]
    if not source_ids:
        raise ContractError(f"{actor['id']} {technique_slug} has no public sources")

    tactics = tactic_projection(technique.get("tactic"))
    attack_path = mitre_id.replace(".", "/")
    return {
        "id": f"{actor['id']}:{mitre_id}:{campaign_slug or 'uncampaigned'}",
        "technique_id": mitre_id,
        "technique": technique.get("name") or technique_slug,
        "technique_slug": technique_slug,
        "tactics": tactics,
        "mapping_status": mapping_status,
        "confidence": confidence,
        "campaign": {
            "id": campaign_slug,
            "name": (campaign or {}).get("name") or campaign_slug or "Not assigned",
            "url": (campaign or {}).get("url") or "",
        },
        "first_observed": str(evidence.get("first_observed") or "Unknown"),
        "last_observed": str(evidence.get("last_observed") or "Unknown"),
        "notes": str(evidence.get("notes") or ""),
        "uncertainty": str(
            evidence.get("editorial_note")
            or "Review the cited reporting before reusing this mapping; the record does not establish attribution beyond its stated actor and campaign scope."
        ),
        "attack_url": f"https://attack.mitre.org/techniques/{attack_path}/",
        "apt_notes_url": technique.get("url") or f"https://apt.hecavex.com/techniques/{technique_slug}/",
        "sources": [source_projection(source_id, sources) for source_id in source_ids],
    }


def build_payload(apt_dist: Path) -> dict[str, Any]:
    api_root = apt_dist / "api"
    actor_collection = read_json(api_root / "actors.json")
    actors = api_records(api_root, "actors")
    techniques = api_records(api_root, "techniques")
    campaigns = api_records(api_root, "campaigns")
    sources = api_records(api_root, "references")

    source_ids = {str(record.get("id")) for record in actor_collection.get("records", [])}
    if source_ids != set(actors):
        raise ContractError("APT Notes actors collection and individual actor records have drifted")

    projected_actors: list[dict[str, Any]] = []
    all_evidence: list[dict[str, Any]] = []
    for actor in sorted(actors.values(), key=lambda value: str(value.get("name", "")).casefold()):
        evidence = [
            evidence_projection(actor, item, techniques, campaigns, sources)
            for item in actor.get("technique_evidence", [])
        ]
        evidence.sort(key=lambda item: (item["technique_id"], item["campaign"]["id"]))
        if not evidence:
            continue
        projected = {
            "id": actor["id"],
            "name": actor.get("name") or actor["id"],
            "slug": actor.get("slug") or actor["id"],
            "summary": actor.get("summary") or "",
            "status": actor.get("status") or "unknown",
            "confidence": actor.get("confidence") or "unknown",
            "last_reviewed": (actor.get("last_reviewed_at") or actor.get("last_reviewed") or "")[:10],
            "aliases": [value.get("name") for value in actor.get("aliases", []) if value.get("name")],
            "url": actor.get("url") or f"https://apt.hecavex.com/actors/{actor['id']}/",
            "json_url": actor.get("json_url") or f"https://apt.hecavex.com/api/actors/{actor['id']}.json",
            "evidence": evidence,
        }
        projected_actors.append(projected)
        all_evidence.extend(evidence)

    if not projected_actors or not all_evidence:
        raise ContractError("APT Notes produced no explicit actor technique evidence")

    tactic_counts = Counter(tactic for item in all_evidence for tactic in item["tactics"])
    technique_count = len({item["technique_id"] for item in all_evidence})
    campaign_count = len({item["campaign"]["id"] for item in all_evidence if item["campaign"]["id"]})
    generated_at = actor_collection.get("released_at") or datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": "2.0.0",
        "generated_at": generated_at,
        "source_system": {
            "name": "APT Notes by HECAVEX",
            "url": "https://apt.hecavex.com/",
            "api_url": "https://apt.hecavex.com/api/actors.json",
            "release_id": actor_collection.get("release_id") or "unknown",
            "dataset_version": actor_collection.get("dataset_version") or "unknown",
            "released_at": actor_collection.get("released_at") or "",
            "method": "Generated only from explicit technique_evidence records in published APT Notes actor dossiers.",
        },
        "framework": {
            "name": "MITRE ATT&CK",
            "domain": "Enterprise",
            "terms": "https://attack.mitre.org/resources/terms-of-use/",
            "notice": "MITRE ATT&CK technique identifiers and links are used for reference. HECAVEX procedure summaries and analytical boundaries remain separately attributed.",
        },
        "provenance_model": {
            "default_mapping_status": "reported",
            "status_values": sorted(VALID_STATUS),
            "confidence_values": ["high", "moderate", "low"],
            "mapping_unit": "One actor, campaign and procedure claim mapped to the most specific technique explicitly published by APT Notes.",
            "known_limit": "The dataset is a reviewed evidence index, not an exhaustive ATT&CK catalogue, threat prevalence measure, automated attribution system or defensive coverage score.",
        },
        "summary": {
            "actors": len(projected_actors),
            "mappings": len(all_evidence),
            "techniques": technique_count,
            "campaigns": campaign_count,
            "tactics": [{"name": name, "mappings": count} for name, count in sorted(tactic_counts.items())],
        },
        "actors": projected_actors,
    }


def validate_payload(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != "2.0.0":
        errors.append("schema_version must be 2.0.0")
    source = payload.get("source_system", {})
    if not source.get("release_id") or not source.get("dataset_version"):
        errors.append("source_system release metadata is required")
    actors = payload.get("actors")
    if not isinstance(actors, list) or not actors:
        return [*errors, "actors must be a non-empty list"]
    actor_ids: set[str] = set()
    evidence_ids: set[str] = set()
    for actor in actors:
        actor_id = actor.get("id")
        if not actor_id or actor_id in actor_ids:
            errors.append(f"invalid or duplicate actor id: {actor_id}")
        actor_ids.add(actor_id)
        if not str(actor.get("url", "")).startswith("https://apt.hecavex.com/actors/"):
            errors.append(f"actor {actor_id} must link to its APT Notes dossier")
        for item in actor.get("evidence", []):
            evidence_id = item.get("id")
            if not evidence_id or evidence_id in evidence_ids:
                errors.append(f"invalid or duplicate evidence id: {evidence_id}")
            evidence_ids.add(evidence_id)
            if item.get("mapping_status") not in VALID_STATUS:
                errors.append(f"{evidence_id} has an invalid mapping status")
            if item.get("confidence") not in VALID_CONFIDENCE:
                errors.append(f"{evidence_id} has an invalid confidence")
            if not str(item.get("attack_url", "")).startswith("https://attack.mitre.org/techniques/"):
                errors.append(f"{evidence_id} has an invalid ATT&CK URL")
            if not item.get("notes") or not item.get("uncertainty") or not item.get("sources"):
                errors.append(f"{evidence_id} is missing notes, uncertainty or sources")
            for source_item in item.get("sources", []):
                if not str(source_item.get("url", "")).startswith("https://"):
                    errors.append(f"{evidence_id} source {source_item.get('id')} lacks a public HTTPS URL")
    summary = payload.get("summary", {})
    evidence_total = sum(len(actor.get("evidence", [])) for actor in actors)
    if summary.get("actors") != len(actors) or summary.get("mappings") != evidence_total:
        errors.append("summary counts do not match the actor evidence records")
    return errors


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apt-dist", type=Path, default=Path(os.environ.get("APT_NOTES_DIST", DEFAULT_APT_DIST)))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Validate the committed output and fail when an available APT build produces a diff.")
    parser.add_argument("--require-source", action="store_true", help="Fail if the APT Notes build is not available.")
    args = parser.parse_args()

    try:
        if args.apt_dist.is_dir():
            expected = build_payload(args.apt_dist)
            errors = validate_payload(expected)
            if errors:
                raise ContractError("\n".join(errors))
            if args.check:
                current = read_json(args.output)
                current_errors = validate_payload(current)
                if current_errors:
                    raise ContractError("\n".join(current_errors))
                if canonical(current) != canonical(expected):
                    raise ContractError(
                        "Reviewed ATT&CK evidence has drifted from APT Notes. "
                        "Run scripts/build_reviewed_attack_evidence.py and review the diff."
                    )
                print(
                    f"Reviewed ATT&CK evidence is current: {expected['summary']['actors']} actors, "
                    f"{expected['summary']['mappings']} mappings, source {expected['source_system']['release_id']}"
                )
                return 0
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(canonical(expected), encoding="utf-8")
            print(
                f"Wrote {args.output}: {expected['summary']['actors']} actors, "
                f"{expected['summary']['mappings']} mappings"
            )
            return 0

        if args.require_source or not args.check:
            raise ContractError(f"APT Notes build not found: {args.apt_dist}")
        current = read_json(args.output)
        errors = validate_payload(current)
        if errors:
            raise ContractError("\n".join(errors))
        print(
            "Committed reviewed ATT&CK evidence passed its schema contract; "
            "APT Notes was unavailable, so cross-repository drift was not checked."
        )
        return 0
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
