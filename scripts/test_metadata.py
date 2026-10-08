"""Check published language links without inventing translated analytical pages."""
from html.parser import HTMLParser
from pathlib import Path
import unittest

from site_contract import LOCALIZED_ROUTE_PAIRS, ROUTES


class Head(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.canonicals = []
        self.alternates = {}
        self.robots = ""
        self.refresh = ""
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "meta" and values.get("name") == "robots":
            self.robots = values.get("content", "")
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            self.refresh = values.get("content", "")
        if tag == "link" and values.get("rel") == "canonical":
            self.canonicals.append(values.get("href"))
        if tag == "link" and "hreflang" in values:
            language = values["hreflang"]
            if language in self.alternates:
                raise AssertionError(f"Duplicate alternate: {language}")
            self.alternates[language] = values["href"]


class MetadataTest(unittest.TestCase):
    def test_actual_routes_and_reciprocal_localized_summaries(self):
        root = Path(__file__).resolve().parent.parent
        heads = {route.public_path: Head((root / route.path).read_text(encoding="utf-8")) for route in ROUTES}
        for route in ROUTES:
            with self.subTest(path=route.public_path):
                if route.public_path == "/404.html":
                    self.assertIn("noindex", heads[route.public_path].robots)
                    continue
                head = heads[route.public_path]
                # This compatibility route redirects to the portfolio's canonical data catalogue.
                expected_canonical = "https://hecavex.com/data/" if route.public_path == "/data/" else route.canonical_url
                self.assertEqual(head.canonicals, [expected_canonical])
                if route.public_path == "/data/":
                    self.assertIn("https://hecavex.com/data/", head.refresh)
                pair = next((pair for pair in LOCALIZED_ROUTE_PAIRS if route.public_path in pair), None)
                if pair is None:
                    self.assertEqual(head.alternates, {}, "No translation exists for this workspace")
                    continue
                english, lithuanian = pair
                expected = {"en": f"https://labs.hecavex.com{english}", "lt": f"https://labs.hecavex.com{lithuanian}", "x-default": f"https://labs.hecavex.com{english}"}
                self.assertEqual(head.alternates, expected)
                self.assertEqual(head.alternates, heads[english].alternates)
                self.assertEqual(head.alternates, heads[lithuanian].alternates)


if __name__ == "__main__":
    unittest.main()
