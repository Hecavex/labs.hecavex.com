"""Executable boundaries for dates, confidence, cross-country comparison and reproduction."""
import json
from copy import deepcopy
from build_reviewed_attack_evidence import ROOT, validate_payload, canonical

atlas = json.loads((ROOT / "data/atlas/records.json").read_text(encoding="utf-8"))
for record in atlas["records"]:
    timing = record["temporal_scope"]
    assert timing["date_basis"] in {"not-recorded", "reporting-period", "publication-date", "activity-year"}
    if timing["date_basis"] == "publication-date":
        assert timing["activity_first"] is None and timing["activity_last"] is None
    comparison = record["comparability"]
    for key in ("unit", "population", "definition", "period", "source_edition", "visibility_changes", "reason"):
        assert comparison[key]
    assert comparison["decision"] == "exclude-from-country-ranking"
    assert record["review"]["reviewed_at"] is None
dns = next(record for record in atlas["records"] if record["id"] == "lv-2026-q1-dns-protection")
assert "266" in dns["summary"] and "several near-incidents" in dns["summary"]
assert "before they became incidents" not in dns["summary"]
assert dns["source_metadata"]["locator"] and dns["source_metadata"]["published_at"] == "2026-06-03"
assert dns["date"] == "2026-Q1" and dns["temporal_scope"]["date_basis"] == "reporting-period"
for record in atlas["records"]:
    if "unc1151" in record["id"]:
        assert record["temporal_scope"]["date_basis"] == "publication-date"

payload = json.loads((ROOT / "data/attack/intelligence/reviewed-evidence.json").read_text(encoding="utf-8"))
assert validate_payload(payload) == []
assert (ROOT / "data/attack/intelligence/reviewed-evidence.json").read_bytes() == canonical(payload).encode("utf-8"), "Projection bytes must be deterministic across Windows and CI"
browser_contract = (ROOT / "assets/attack-map.js").read_text(encoding="utf-8")
assert f"data.schema_version !== '{payload['schema_version']}'" in browser_contract, "Browser and evidence schema gates must agree"
apt31 = next(actor for actor in payload["actors"] if actor["id"] == "apt31")
assert {item["technique_id"] for item in apt31["evidence"]} == {"T1598.003", "T1114.002"}
for item in apt31["evidence"]:
    assert item["confidence"] == "moderate" and item["assessment"]["method"] == "ai-assisted-source-comparison"
    assert item["claim_review"]["reviewed_at"] is None and item["sources"][0]["source_identity"]["body_sha256"] is None
invalid = deepcopy(payload)
bad = next(actor for actor in invalid["actors"] if actor["id"] == "apt31")["evidence"][0]
bad["claim_review"].update(state="reviewed", reviewed_at="2026-09-10")
assert any("cannot certify human review" in error for error in validate_payload(invalid))
cases = json.loads((ROOT / "data/pivots/cases.json").read_text(encoding="utf-8"))["cases"]
for case in cases:
    scope = case["reproducibility"]
    for key in ("preserved_inputs", "transformations", "source_attributed_conclusions", "unavailable", "analytical_cutoff"):
        assert scope[key]
    assert scope["independent_reproduction_verified_at"] is None
github = next(case for case in cases if case["id"] == "github-python-loader-2024")
assert "final stage is unavailable" in github["reproducibility"]["unavailable"]
assert "evidence_bundle" not in github
print("Analytical contracts passed: dates, 18 comparability exclusions, Latvia wording, two bounded APT31 corrections and four reproduction boundaries.")
