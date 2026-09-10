"""Refresh only existing Atlas actor-context metadata from an explicit APT release.

This never adds an actor, Baltic observation, relevance link or analytical claim.
"""
import argparse
import json
from pathlib import Path
from build_reviewed_attack_evidence import ROOT, DEFAULT_APT_DIST

parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("--check", action="store_true")
mode.add_argument("--write", action="store_true")
parser.add_argument("--apt-dist", type=Path, default=DEFAULT_APT_DIST)
args = parser.parse_args()
path = ROOT / "data/atlas/records.json"
original = json.loads(path.read_text(encoding="utf-8"))
atlas = json.loads(json.dumps(original))
upstream = json.loads((args.apt_dist / "api/actors.json").read_text(encoding="utf-8"))
actors = {record["id"]: record for record in upstream["records"]}
for field in ("dataset_version", "release_id", "released_at"):
    atlas["actor_context_source"][field] = upstream[field]
for actor in atlas["actor_context"]:
    source = actors[actor["id"]]
    actor.update(name=source["name"], status=source["status"], confidence=source["confidence"], source_record_version=source["version"], last_reviewed=str(source["last_reviewed_at"])[:10], apt_url=source["url"], apt_json_url=source["json_url"])
assert atlas["records"] == original["records"], "Context refresh must not modify observations"
if args.check:
    assert original == atlas, "Atlas actor-context metadata differs from the explicit APT release"
else:
    path.write_text(json.dumps(atlas, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"Existing Atlas context metadata matches {upstream['release_id']}; observation claims are unchanged.")
