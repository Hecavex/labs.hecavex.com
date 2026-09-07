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
