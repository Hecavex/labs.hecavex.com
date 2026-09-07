"""Reject false claim review state without altering the published evidence fixture."""
from copy import deepcopy
import json
from build_reviewed_attack_evidence import ROOT, validate_payload

payload = json.loads((ROOT / "data/attack/intelligence/reviewed-evidence.json").read_text(encoding="utf-8"))
assert validate_payload(payload) == []

def first_mapping(value):
    return value["actors"][0]["evidence"][0]

invented = deepcopy(payload)
first_mapping(invented)["claim_review"]["reviewed_at"] = "2026-09-07"
assert any("invented claim review date" in error for error in validate_payload(invented))

unsupported = deepcopy(payload)
first_mapping(unsupported)["source_locators"] = [{"source": "not-a-supporting-source", "locator": "A claimed section", "checked_at": "2026-09-07"}]
assert any("source locator lacks supporting source" in error for error in validate_payload(unsupported))

correction = deepcopy(payload)
first_mapping(correction)["claim_review"].update(state="corrected", reviewed_at="2026-09-07", rationale="Fixture correction", correction_note="")
assert any("correction needs a note" in error for error in validate_payload(correction))
print("Claim provenance regressions passed: valid projection, unknown review dates, source scope and explicit corrections.")

atlas = json.loads((ROOT / "data/atlas/records.json").read_text(encoding="utf-8"))
corrected = [record for record in atlas["records"] if record.get("corrections")]
assert {record["id"] for record in corrected} == {"lt-2024-annual-incidents", "lt-2025-incident-volume", "lt-2025-phishing-fraud-shift", "lv-2026-q1-incident-volume", "ee-2020-unit29155-ministry-compromise"}
for record in corrected:
    comparison = record["corrections"][-1]
    assert comparison["method"] == "ai-assisted-source-comparison"
    assert comparison["human_reviewed_at"] is None
    assert record["source_metadata"]["locator"] and record["source_metadata"]["title"]
    assert "human" in record["review"]["note"]
claim = next(record for record in corrected if record["id"] == "lt-2025-phishing-fraud-shift")
assert claim["date"] == "2025" and claim["confidence"] == "reported" and claim["attribution"] == "None"
assert "1,551" in claim["summary"] and "49%" in claim["summary"] and "907" in claim["summary"]
assert all(record["review"]["reviewed_at"] is None for record in atlas["records"])
trail = claim["corrections"][0]
assert trail["method"] == "automated-source-consistency-check" and trail["human_reviewed_at"] is None
assert trail["source"] == claim["source"] + "#page=17" and "2.2.2 Lithuania" in trail["locator"]
assert trail["version"] == claim["claim_version"] and trail["previous_version"] == "1.0.0"
assert trail["affected_field"] == "source_caveat" and round(1551 / 2888 * 100, 1) == 53.7
print("Atlas source tranche passed: five bounded comparisons, preserved arithmetic caveat and no invented human reviews.")
