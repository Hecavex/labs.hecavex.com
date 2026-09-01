#!/usr/bin/env python3
"""Produce a non-blocking availability report for public HTTPS destinations.

Remote websites fail, rate-limit or reject automation for reasons unrelated to
the Labs publication. This audit therefore distinguishes a confirmed 404/410
from a reachable-but-restricted response and an indeterminate network result.
Availability findings never gate deployment unless a maintainer explicitly
passes ``--strict`` after reviewing the environment and report.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import ssl
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / ".codex-tmp" / "external-link-audit.json"
TEXT_SUFFIXES = {".html", ".json", ".md", ".txt"}
IGNORED_DIRECTORIES = {".git", ".codex-tmp", "_site", "__pycache__"}
URL_PATTERN = re.compile(r"https://[^\s<>'\"`)]+")
USER_AGENT = "HECAVEX-Labs-Link-Audit/1.0 (+https://labs.hecavex.com/about/)"


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: set[str] = set()

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value and value.startswith("https://"):
                self.urls.add(value)


def normalise(url: str) -> str:
    return urldefrag(url.rstrip(".,;"))[0]


def collect_urls() -> dict[str, list[str]]:
    sources: dict[str, set[str]] = {}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if IGNORED_DIRECTORIES.intersection(relative.parts):
            continue
        text = path.read_text(encoding="utf-8")
        urls = set(URL_PATTERN.findall(text))
        if path.suffix.lower() == ".html":
            parser = LinkParser()
            parser.feed(text)
            urls.update(parser.urls)
        for value in urls:
            url = normalise(value)
            parsed = urlparse(url)
            if parsed.scheme == "https" and parsed.hostname:
                sources.setdefault(url, set()).add(relative.as_posix())
    return {url: sorted(paths) for url, paths in sorted(sources.items())}


def request_status(url: str, timeout: float) -> tuple[int | None, str, str]:
    context = ssl.create_default_context()

    def attempt(method: str) -> tuple[int, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json;q=0.9,*/*;q=0.1"}
        if method == "GET":
            headers["Range"] = "bytes=0-0"
        request = Request(url, headers=headers, method=method)
        with urlopen(request, timeout=timeout, context=context) as response:
            if method == "GET":
                response.read(1)
            return response.status, response.geturl()

    try:
        status, final_url = attempt("HEAD")
    except HTTPError as error:
        if error.code in {401, 403, 405, 429}:
            return error.code, "reachable-restricted", error.geturl()
        try:
            status, final_url = attempt("GET")
        except HTTPError as get_error:
            if get_error.code in {404, 410}:
                return get_error.code, "unavailable", get_error.geturl()
            if get_error.code in {401, 403, 405, 429}:
                return get_error.code, "reachable-restricted", get_error.geturl()
            return get_error.code, "indeterminate-http", get_error.geturl()
        except (URLError, TimeoutError, OSError) as get_error:
            return None, "indeterminate-network", str(get_error)
    except (URLError, TimeoutError, OSError) as error:
        return None, "indeterminate-network", str(error)

    classification = "available" if 200 <= status < 400 else "indeterminate-http"
    return status, classification, final_url


def audit(url: str, source_files: list[str], timeout: float) -> dict[str, Any]:
    status, classification, detail = request_status(url, timeout)
    return {
        "url": url,
        "status": status,
        "classification": classification,
        "detail": detail,
        "source_files": source_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--strict", action="store_true", help="fail only for confirmed HTTP 404 or 410 destinations")
    parser.add_argument("--github-annotations", action="store_true")
    args = parser.parse_args()

    sources = collect_urls()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as executor:
        pending = {
            executor.submit(audit, url, paths, args.timeout): url
            for url, paths in sources.items()
        }
        for future in as_completed(pending):
            results.append(future.result())
    results.sort(key=lambda item: item["url"])

    counts: dict[str, int] = {}
    for result in results:
        counts[result["classification"]] = counts.get(result["classification"], 0) + 1
        if args.github_annotations and result["classification"] == "unavailable":
            source = result["source_files"][0]
            print(f"::warning file={source}::Confirmed HTTP {result['status']} for {result['url']}")

    payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": "Informational by default. Only confirmed HTTP 404/410 responses are classified unavailable; restricted and network-failure results are not treated as broken.",
        "summary": {"urls": len(results), **counts},
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Audited {len(results)} HTTPS destinations: {json.dumps(counts, sort_keys=True)}")
    print(f"Report: {args.output}")
    unavailable = counts.get("unavailable", 0)
    return 1 if args.strict and unavailable else 0


if __name__ == "__main__":
    raise SystemExit(main())
