"""Compare declared catalogue semantics and framework metadata with a pinned APT build."""
import argparse
import json
from pathlib import Path
import subprocess
from build_reviewed_attack_evidence import ROOT, read_attack_manifest, ContractError

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--apt-dist", type=Path, required=True)
parser.add_argument("--require-revision", action="store_true")
args = parser.parse_args()
pin = json.loads((ROOT / "scripts/upstream-release.json").read_text(encoding="utf-8"))
version = json.loads((args.apt_dist / "api/version.json").read_text(encoding="utf-8"))
catalogue = json.loads((ROOT / "data/catalogue.json").read_text(encoding="utf-8"))
entry = next(item for item in catalogue["related_datasets"] if item["id"] == "apt-notes-actors")
assert entry["schema_version"] == version["schema_version"], "APT catalogue schema differs from upstream"
assert pin["release_id"] == version["release_id"], "APT release differs from reviewed pin"
assert entry["timestamp_field"] == "released_at" and version.get("released_at") and "generated_at" not in version, "APT timestamp semantics differ"
if args.require_revision:
    actual = subprocess.check_output(["git", "-C", str(args.apt_dist.parent), "rev-parse", "HEAD"], text=True).strip()
    assert actual == pin["revision"], "APT source revision differs from declared pin"
techniques = json.loads((args.apt_dist / "api/techniques.json").read_text(encoding="utf-8"))["records"]
manifest = read_attack_manifest()
for technique in techniques:
    expected = manifest["techniques"].get(technique["mitre_id"])
    if expected:
        names = [manifest["tactics"][key]["name"] for key in expected["tactics"]]
        assert technique["framework_version"] == manifest["framework"]["version"] and sorted(technique["tactics"]) == sorted(names), f"Framework drift: {technique['mitre_id']}"
print(f"APT catalogue and shared technique contracts match {pin['release_id']}.")
