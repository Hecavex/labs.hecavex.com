"""Check publication and evidence boundaries of the approved AI-tooling case."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

from stage_public_data import manifest_paths, validate_pivot_publication

ROOT = Path(__file__).resolve().parent.parent
CASE_ID = "ai-tooling-supply-chain-2026"
CATALOGUE = json.loads((ROOT / "data/pivots/cases.json").read_text(encoding="utf-8"))
CASE = next(record for record in CATALOGUE["cases"] if record["id"] == CASE_ID)
GRAPH = json.loads((ROOT / CASE["graph"].lstrip("/")).read_text(encoding="utf-8"))


class ApprovedAiToolingPivotTests(unittest.TestCase):
    def test_explicit_approval_and_exact_manifest(self):
        for record in (CASE, GRAPH["case"]):
            self.assertIs(record["publication_approved"], True)
            self.assertEqual(record["publication_approved_at"], "2026-10-09")
            self.assertEqual(record["status"], "published")
        paths = {relative.as_posix() for relative, _source in manifest_paths()}
        self.assertIn(CASE["graph"].lstrip("/"), paths)
        manifest = json.loads((ROOT / "data/public-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["default_policy"], "deny")
        self.assertFalse((ROOT / "curation/pivots/ai-tooling-supply-chain.case.json").exists())
        self.assertFalse((ROOT / "curation/pivots/ai-tooling-supply-chain.graph.json").exists())

    def test_gate_rejects_unapproved_or_unlisted_graph(self):
        listed = {CASE["graph"].lstrip("/")}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cases.json"
            bad = deepcopy(CASE)
            bad["publication_approved"] = False
            path.write_text(json.dumps({"cases": [bad]}), encoding="utf-8")
            with patch("stage_public_data.PIVOT_CASES_PATH", path):
                with self.assertRaisesRegex(SystemExit, "not explicitly approved"):
                    validate_pivot_publication(listed)
            path.write_text(json.dumps({"cases": [CASE]}), encoding="utf-8")
            with patch("stage_public_data.PIVOT_CASES_PATH", path):
                with self.assertRaisesRegex(SystemExit, "not in the public manifest"):
                    validate_pivot_publication(set())
                with self.assertRaises(SystemExit):
                    validate_pivot_publication(listed | {"data/pivots/graphs/unapproved.json"})

    def test_graph_schema_and_resolvable_edges(self):
        self.assertEqual(GRAPH["schema_version"], "2.0.0")
        self.assertEqual(GRAPH["case"]["id"], CASE["id"])
        nodes = {node["id"]: node for node in GRAPH["nodes"]}
        self.assertEqual(len(nodes), len(GRAPH["nodes"]))
        self.assertEqual({node["class"] for node in nodes.values()}, {"observed", "derived", "assessment", "limitation"})
        required = {"id", "class", "label", "short_label", "x", "y", "meaning", "confidence", "evidence_label", "evidence"}
        for node in nodes.values():
            self.assertTrue(required.issubset(node))
            self.assertTrue(1 <= len(node["short_label"]) <= 2)
            self.assertTrue(70 <= node["y"] <= 550)
        for edge in GRAPH["edges"]:
            self.assertIn(edge["source"], nodes)
            self.assertIn(edge["target"], nodes)
            self.assertNotEqual(edge["source"], edge["target"])
            self.assertTrue(edge["relationship"])

    def test_canonical_articles_and_source_roles(self):
        expected = {
            "en": "https://hecavex.com/en/research/fakegit-ai-skills-mutable-downloads/",
            "lt": "https://hecavex.com/lt/tyrimai/fakegit-ai-igudziai-kintantys-atsisiuntimai/",
        }
        for record in (CASE, GRAPH["case"]):
            self.assertEqual(record["research"], expected["en"])
            self.assertEqual(record["research_translations"], expected)
        urls = [CASE["research"], CASE["evidence_bundle"], *expected.values(), *GRAPH["case"]["support_records"]]
        urls.extend(node["evidence"] for node in GRAPH["nodes"])
        for url in urls:
            parsed = urlparse(url)
            self.assertEqual(parsed.scheme, "https")
            self.assertIn(parsed.hostname, {"hecavex.com", "apiiro.com", "github.com", "polygonscan.com", "snyk.io"})
            self.assertFalse(parsed.query)
            self.assertNotRegex(parsed.path.lower(), r"(?:\.zip$|/raw/|/releases/download/)")
        text = json.dumps([CASE, GRAPH], ensure_ascii=False)
        self.assertNotIn("never-delete-only-re-pointed", text)
        nodes = {node["id"]: node for node in GRAPH["nodes"]}
        self.assertTrue(nodes["acquired-bytes"]["evidence"].endswith("/static-analysis.json"))
        self.assertTrue(nodes["constant-data"]["evidence"].endswith("/constant-replay/README.md"))
        self.assertTrue(nodes["pinned-chain-states"]["evidence"].endswith("/ioc-observations.json"))

    def test_defanged_indicators_and_no_private_material(self):
        text = json.dumps([CASE, GRAPH], ensure_ascii=False)
        self.assertNotRegex(text, r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self.assertNotRegex(text, r"(?i)(?:(?<![a-z])[a-z]:[\\/]|localhost|127\[\.\]0|workbench[\\/]|raw\.githubusercontent|loopback)")
        self.assertNotIn("hxxp://", text)
        self.assertNotIn("artifact", {key for node in GRAPH["nodes"] for key in node})
        self.assertNotIn("prepared for owner review", text)
        self.assertNotIn("held_support_records", GRAPH["case"])

    def test_separate_context_and_bounded_reproduction(self):
        nodes = {node["id"]: node for node in GRAPH["nodes"]}
        self.assertFalse(any("separate-toxic-context" in (edge["source"], edge["target"]) for edge in GRAPH["edges"]))
        main = {"historical-list", "readme-repoint", "acquired-bytes", "constant-data", "installer-source", "conditional-copy", "trust-boundary", "runtime-boundary"}
        chain = {"reported-polygon", "pinned-chain-states", "chain-boundary"}
        self.assertFalse(any((edge["source"] in main and edge["target"] in chain) or (edge["source"] in chain and edge["target"] in main) for edge in GRAPH["edges"]))
        self.assertIn("not a recovered", nodes["reported-polygon"]["meaning"])
        self.assertIn("five selected original source-pair proofs", nodes["constant-data"]["meaning"])
        self.assertIn("independent arithmetic recomputed all 539 outputs", nodes["constant-data"]["meaning"])
        self.assertIn("one fixed placeholder template", nodes["constant-data"]["meaning"])
        self.assertIn("not revalidated", nodes["constant-data"]["meaning"])
        self.assertIn("No Lua", nodes["runtime-boundary"]["meaning"])
        self.assertIn("conditional", nodes["conditional-copy"]["confidence"])
        self.assertIn("end", nodes["pinned-chain-states"]["meaning"])
        self.assertIn("No complete public original-sample", CASE["reproducibility"]["unavailable"])
        self.assertIsNone(CASE["reproducibility"]["independent_reproduction_verified_at"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
