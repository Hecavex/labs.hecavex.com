#!/usr/bin/env python3
"""Dependency-free production validation for HECAVEX Labs."""

from html.parser import HTMLParser
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlparse

from stage_public_data import ANALYTICS_SOURCE, analytics_loader
from sync_shell import ROUTES as SHELL_ROUTES, transform as render_shell


class DocumentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.references = []
        self.html_lang = ""
        self.title_depth = 0
        self.title = ""
        self.metas = []
        self.canonicals = []
        self.stylesheets = []
        self.main_count = 0
        self.h1_count = 0
        self.images_without_alt = 0
        self.controls = []
        self.labels = set()
        self.json_ld = []
        self._json_depth = 0
        self._json_buffer = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "html":
            self.html_lang = attributes.get("lang", "")
        if tag == "title":
            self.title_depth += 1
        if tag == "meta":
            self.metas.append(attributes)
        if tag == "link" and "canonical" in attributes.get("rel", "").split():
            self.canonicals.append(attributes.get("href", ""))
        if tag == "link" and "stylesheet" in attributes.get("rel", "").split():
            self.stylesheets.append(attributes.get("href", ""))
        if tag == "main":
            self.main_count += 1
        if tag == "h1":
            self.h1_count += 1
        if tag == "img" and "alt" not in attributes:
            self.images_without_alt += 1
        if tag in {"input", "select", "textarea"}:
            self.controls.append(attributes)
        if tag == "label" and attributes.get("for"):
            self.labels.add(attributes["for"])
        if tag == "script" and attributes.get("type") == "application/ld+json":
            self._json_depth = 1
            self._json_buffer = []
        if "id" in attributes:
            self.ids.append(attributes["id"])
        for name in ("href", "src"):
            value = attributes.get(name)
            if value:
                self.references.append(value)

    def handle_data(self, data):
        if self.title_depth:
            self.title += data
        if self._json_depth:
            self._json_buffer.append(data)

    def handle_endtag(self, tag):
        if tag == "title" and self.title_depth:
            self.title_depth -= 1
        if tag == "script" and self._json_depth:
            self.json_ld.append("".join(self._json_buffer))
            self._json_depth = 0
            self._json_buffer = []


root = Path(__file__).resolve().parent.parent
ignored_validation_directories = {".git", ".codex-tmp", "_site", "test-results", "__pycache__"}


def repository_files(pattern):
    return [
        path for path in root.rglob(pattern)
        if not ignored_validation_directories.intersection(path.relative_to(root).parts)
    ]


required = {
    "index.html",
    "baltic-threat-atlas/index.html",
    "pivot-graph/index.html",
    "attack-map/index.html",
    "attack-map/guide/index.html",
    "osint-workbench/index.html",
    "data/index.html",
    "data/catalogue.json",
    "data/public-manifest.json",
    "licence/index.html",
    "methodology/index.html",
    "security/index.html",
    "assets/styles.css",
    "assets/hecavex-mark.svg",
    "assets/site.js",
    "assets/atlas.js",
    "assets/pivot-graph.js",
    "assets/attack-map.js",
    "assets/osint-workbench.js",
    "data/atlas/records.json",
    "data/osint/resources.json",
    "data/pivots/cases.json",
    "data/pivots/graphs/adform.json",
    "data/pivots/graphs/unipark.json",
    "data/pivots/graphs/github-python.json",
    "data/attack/intelligence/reviewed-evidence.json",
    "data/attack/intelligence/official-actor-procedures.json",
    "data/attack/operations/guides.json",
    "data/attack/detections/packages.json",
    "data/attack/governance/governance.json",
    "data/attack/catalogue/enterprise.json",
    "scripts/build_attack_content.py",
    "scripts/update_attack_catalog.py",
    "scripts/capture_attack_guide.py",
    "scripts/stage_public_data.py",
    "scripts/sync_shell.py",
    "scripts/test_responsive.py",
    "assets/img/attack-workbench-guide/01-choose-workflow.png",
    "assets/img/attack-workbench-guide/02-review-evidence-candidates.png",
    "assets/img/attack-workbench-guide/03-assess-coverage.png",
    "assets/img/attack-workbench-guide/04-record-capability.png",
    "assets/img/attack-workbench-guide/05-find-threat-actor.png",
    "assets/img/attack-workbench-guide/06-use-actor-procedures.png",
    "CNAME",
    "robots.txt",
    "llms.txt",
    "sitemap.xml",
    "LICENSE",
    "LICENSE.md",
    "DATA-LICENSE.md",
    ".well-known/security.txt",
}

errors = []
missing = sorted(path for path in required if not (root / path).is_file())
if missing:
    errors.append("Missing required files: " + ", ".join(missing))

robots_text = (root / "robots.txt").read_text(encoding="utf-8")
llms_text = (root / "llms.txt").read_text(encoding="utf-8")
if "Content-Signal: search=yes, ai-input=yes, ai-train=no" not in robots_text:
    errors.append("robots.txt is missing the reviewed HECAVEX content-use signal")
for required_url in (
    "https://labs.hecavex.com/data/catalogue.json",
    "https://labs.hecavex.com/data/public-manifest.json",
    "https://labs.hecavex.com/methodology/",
    "https://labs.hecavex.com/licence/",
):
    if required_url not in llms_text:
        errors.append(f"llms.txt is missing approved public reference {required_url}")

font_paths = {
    "assets/fonts/README.md",
    "assets/fonts/INTER-OFL.txt",
    "assets/fonts/IBM-PLEX-MONO-OFL.txt",
    *{
        f"assets/fonts/inter/inter-{subset}-{weight}-normal.woff2"
        for subset in ("latin", "latin-ext")
        for weight in (400, 500, 600, 700)
    },
    *{
        f"assets/fonts/inter/inter-{subset}-400-italic.woff2"
        for subset in ("latin", "latin-ext")
    },
    *{
        f"assets/fonts/ibm-plex-mono/ibm-plex-mono-{subset}-{weight}-normal.woff2"
        for subset in ("latin", "latin-ext")
        for weight in (400, 500, 600, 700)
    },
}
missing_fonts = sorted(path for path in font_paths if not (root / path).is_file())
if missing_fonts:
    errors.append("Missing self-hosted font files: " + ", ".join(missing_fonts))
styles_text = (root / "assets/styles.css").read_text(encoding="utf-8")
mark_text = (root / "assets/hecavex-mark.svg").read_text(encoding="utf-8").lower()
for required_mark_colour in ("#44c7dc", "#f2f8fb"):
    if required_mark_colour not in mark_text:
        errors.append(f"HECAVEX identity mark is missing {required_mark_colour}")
if "#ff6b6b" in mark_text:
    errors.append("HECAVEX identity mark must reserve danger red for status UI")
design_contract = {
    "--hx-bg": "#05080b",
    "--hx-surface-1": "#0b1117",
    "--hx-surface-2": "#101923",
    "--hx-border": "#1e3440",
    "--hx-border-strong": "#1e3440",
    "--hx-text": "#f2f8fb",
    "--hx-text-soft": "#b6c6cf",
    "--hx-text-muted": "#8397a3",
    "--hx-text-faint": "#8397a3",
    "--hx-border-subtle": "#1e3440",
    "--hx-accent": "#44c7dc",
    "--hx-steel": "#44c7dc",
    "--hx-steel-hover": "#44c7dc",
    "--hx-success": "#a2da68",
    "--hx-bronze": "#ffc857",
    "--hx-warning": "#ffc857",
    "--hx-danger": "#ff6b6b",
}
for token, value in design_contract.items():
    if not re.search(rf"{re.escape(token)}:\s*{re.escape(value)}\s*;", styles_text, re.IGNORECASE):
        errors.append(f"Cold Signal design token differs: {token} must be {value}")
shell_css_contract = {
    "shell maximum width": r"--shell-max:\s*94rem\s*;",
    "desktop header offset": r"--header-offset:\s*7\.25rem\s*;",
    "64px network row": r"\.network-bar\s*\{[^}]*min-height:\s*4rem\s*;",
    "52px product row": r"\.product-bar\s*\{[^}]*min-height:\s*3\.25rem\s*;",
    "36px identity mark": r"\.brand img\s*\{[^}]*width:\s*2\.25rem\s*;[^}]*height:\s*2\.25rem\s*;",
    "52px local navigation target": r"\.product-navigation a\s*\{[^}]*min-height:\s*3\.25rem\s*;",
    "1160px mobile collapse": r"@media\s*\(max-width:\s*1160px\)",
    "64px mobile header": r"@media\s*\(max-width:\s*1160px\)[\s\S]*?--header-offset:\s*4rem\s*;",
    "1.66 main reading rhythm": r"main\s*\{[^}]*line-height:\s*1\.66\s*;",
    "2rem section heading ceiling": r"h2\s*\{[^}]*font-size:\s*clamp\(1\.45rem,\s*2\.4vw,\s*2rem\)\s*;",
    "52px display heading ceiling": r"\.brand-hero h1\s*\{[^}]*font-size:\s*clamp\(2\.4rem,\s*4vw,\s*3\.25rem\)\s*;",
    "36px search control containment": r"\.header-search input,\s*\.mobile-header-search input\s*\{[^}]*min-height:\s*0\s*;[^}]*line-height:\s*1\.2\s*;",
    "44px mono call to action": r"\.button\s*\{[^}]*min-height:\s*2\.75rem\s*;[^}]*font:\s*600\s+\.68rem/1\s+var\(--font-mono\)\s*;",
    "38px mobile hero heading floor": r"\.brand-hero h1,\s*\.page-head h1\s*\{[^}]*font-size:\s*clamp\(2\.4rem,\s*11vw,\s*2\.65rem\)\s*;",
    "16px mobile hero lead floor": r"\.brand-hero \.lead,\s*\.page-head \.lead\s*\{[^}]*font-size:\s*1rem\s*;",
}
for label, pattern in shell_css_contract.items():
    if not re.search(pattern, styles_text):
        errors.append(f"Portfolio shell CSS contract differs: {label}")
for font_path in sorted(path for path in font_paths if path.endswith(".woff2")):
    if f'url("/{font_path}")' not in styles_text:
        errors.append(f"Self-hosted font is not referenced by the stylesheet: {font_path}")
if re.search(r"@(?:import|font-face)[^}]*https?://", styles_text, re.IGNORECASE | re.DOTALL):
    errors.append("Stylesheet must not load fonts from a remote origin")
font_readme = (root / "assets/fonts/README.md").read_text(encoding="utf-8")
for provenance_marker in ("Fontsource 5.3.0", "INTER-OFL.txt", "IBM-PLEX-MONO-OFL.txt"):
    if provenance_marker not in font_readme:
        errors.append(f"Font provenance note is missing: {provenance_marker}")
for forbidden_token in ("--hx-surface-3", "--hx-ember", "--hx-action"):
    if forbidden_token in styles_text:
        errors.append(f"Obsolete or ambiguous Cold Signal token remains: {forbidden_token}")
for divergent_colour in ("#14212b", "#294b59", "#3a5966", "#728993", "#7adcea", "#63b3a2", "#63b3ed", "#ff8989"):
    if divergent_colour in styles_text.lower():
        errors.append(f"Divergent Cold Signal colour remains: {divergent_colour}")
if styles_text.lower().count("#ff6b6b") != 1:
    errors.append("Danger red must be declared once and consumed through --hx-danger")
danger_selectors = (
    ".form-error-summary", "field-error", "aria-invalid", ".storage-warning",
    ".state-no-telemetry", ".dimension-gap", ".capability-progress-summary.is-incomplete",
    ".case-resilience", ".button.danger", ".status-rejected",
)
for line in styles_text.splitlines():
    if "var(--hx-danger" not in line or line.lstrip().startswith("--hx-danger"):
        continue
    selector = line.split("{", 1)[0]
    if not any(marker in selector for marker in danger_selectors):
        errors.append(f"Danger colour is applied outside a danger or warning state: {selector.strip()}")

mojibake_markers = ("â€", "Â", "ï¿½", "�")
html_files = repository_files("*.html")
canonicals = {}
documents = {}
for path in html_files:
    text = path.read_text(encoding="utf-8")
    parser = DocumentParser()
    parser.feed(text)
    documents[path.resolve()] = parser
    relative = path.relative_to(root)
    if '<header class="site-header" data-portfolio-shell="v1">' not in text:
        errors.append(f"Cold Signal site shell is missing from {relative}")
    if '<footer class="site-footer">' not in text:
        errors.append(f"Portfolio footer is missing from {relative}")
    if "document.documentElement.classList.add('js')" not in text:
        errors.append(f"Progressive-enhancement marker is missing from {relative}")
    if len(re.findall(r'<meta\s+name="theme-color"\s+content="#05080b"\s*/?>', text, re.IGNORECASE)) != 1:
        errors.append(f"Cold Signal theme colour metadata differs or is missing from {relative}")
    if re.search(r'<link[^>]+rel="stylesheet"[^>]+href="https?://', text, re.IGNORECASE):
        errors.append(f"Remote stylesheet dependency found in {relative}")
    expected_stylesheet = "/assets/styles.css?v=20260822-2"
    if parser.stylesheets != [expected_stylesheet]:
        errors.append(
            f"Versioned route stylesheet differs in {relative}: "
            f"expected {[expected_stylesheet]}, found {parser.stylesheets}"
        )
    if re.search(r'<script[^>]+src="https?://', text, re.IGNORECASE):
        errors.append(f"Remote script dependency found in {relative}")
    duplicates = sorted({value for value in parser.ids if parser.ids.count(value) > 1})
    if duplicates:
        errors.append(f"Duplicate HTML ids in {path.relative_to(root)}: {', '.join(duplicates)}")
    if any(marker in text for marker in mojibake_markers):
        errors.append(f"Possible mojibake in {path.relative_to(root)}")
    if not parser.html_lang:
        errors.append(f"Missing html lang in {relative}")
    if not parser.title.strip():
        errors.append(f"Missing title in {relative}")
    meta_by_name = {item.get("name"): item.get("content", "") for item in parser.metas if item.get("name")}
    meta_by_property = {item.get("property"): item.get("content", "") for item in parser.metas if item.get("property")}
    if not meta_by_name.get("description", "").strip():
        errors.append(f"Missing meta description in {relative}")
    if len(parser.canonicals) != 1:
        errors.append(f"Expected one canonical in {relative}, found {len(parser.canonicals)}")
    elif parser.canonicals[0] in canonicals:
        errors.append(f"Duplicate canonical in {relative} and {canonicals[parser.canonicals[0]]}")
    else:
        canonicals[parser.canonicals[0]] = relative
    for key in ("og:title", "og:description", "og:url", "og:image", "og:image:width", "og:image:height", "og:image:alt"):
        if not meta_by_property.get(key, "").strip():
            errors.append(f"Missing {key} in {relative}")
    for key in ("twitter:card", "twitter:title", "twitter:description", "twitter:image", "twitter:image:alt"):
        if not meta_by_name.get(key, "").strip():
            errors.append(f"Missing {key} in {relative}")
    if parser.main_count != 1:
        errors.append(f"Expected one main landmark in {relative}, found {parser.main_count}")
    if parser.h1_count != 1:
        errors.append(f"Expected one h1 in {relative}, found {parser.h1_count}")
    if parser.images_without_alt:
        errors.append(f"Images without alt attributes in {relative}: {parser.images_without_alt}")
    for control in parser.controls:
        if control.get("type") == "hidden":
            continue
        control_id = control.get("id", "")
        if not control.get("aria-label") and not control.get("aria-labelledby") and control_id not in parser.labels:
            errors.append(f"Unlabelled form control in {relative}: {control_id or control.get('name', control.get('type', 'unknown'))}")
    if len(parser.json_ld) != 1:
        errors.append(f"Expected one consolidated JSON-LD graph in {relative}, found {len(parser.json_ld)}")
    for payload in parser.json_ld:
        try:
            schema = json.loads(payload)
            graph_items = schema.get("@graph", [])
            if not isinstance(graph_items, list):
                errors.append(f"JSON-LD is not an @graph in {relative}")
                graph_items = []
            graph_ids = {item.get("@id") for item in graph_items}
            expected_ids = {
                "https://hecavex.com/#organization",
                "https://hecavex.com/#deividas-lis",
                "https://hecavex.com/#website",
                "https://apt.hecavex.com/#website",
                "https://labs.hecavex.com/#website",
                "https://radar.hecavex.com/#website",
            }
            missing_ids = expected_ids - graph_ids
            if missing_ids:
                errors.append(f"JSON-LD is missing shared HECAVEX identities in {relative}: {', '.join(sorted(missing_ids))}")

            portfolio_node = next(
                (item for item in graph_items if item.get("@id") == "https://hecavex.com/#website"),
                {},
            )
            portfolio_parts = {item.get("@id") for item in portfolio_node.get("hasPart", [])}
            expected_parts = {
                "https://apt.hecavex.com/#website",
                "https://labs.hecavex.com/#website",
                "https://radar.hecavex.com/#website",
            }
            if portfolio_parts != expected_parts:
                errors.append(
                    f"JSON-LD portfolio membership differs in {relative}: "
                    f"{portfolio_parts ^ expected_parts}"
                )

            pending = [schema]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
                elif isinstance(value, str):
                    parsed = urlparse(value)
                    if parsed.hostname != "labs.hecavex.com":
                        continue
                    local_path = parsed.path or "/"
                    target = root / local_path.lstrip("/")
                    if local_path.endswith("/"):
                        target = target / "index.html"
                    if not target.is_file():
                        errors.append(f"Broken local URL in JSON-LD for {relative}: {value}")
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON-LD in {relative}: {exc}")
    for reference in parser.references:
        if not reference.startswith("/") or reference.startswith("//"):
            continue
        local = reference.split("#", 1)[0].split("?", 1)[0]
        if not local:
            continue
        target = root / local.lstrip("/")
        if local.endswith("/"):
            target = target / "index.html"
        if not target.is_file():
            errors.append(f"Broken local asset in {path.relative_to(root)}: {reference}")

# Check local links again with fragments and relative-path resolution. The first
# pass above deliberately remains simple so missing root-relative assets are
# reported beside the document that references them.
for path, parser in documents.items():
    for reference in parser.references:
        parsed = urlparse(reference)
        if parsed.scheme or parsed.netloc or reference.startswith("//"):
            continue
        raw_path = unquote(parsed.path)
        if not raw_path:
            target = path
        elif raw_path.startswith("/"):
            target = (root / raw_path.lstrip("/")).resolve()
        else:
            target = (path.parent / raw_path).resolve()
        if raw_path.endswith("/"):
            target = target / "index.html"
        if not target.is_file():
            errors.append(f"Broken local link in {path.relative_to(root)}: {reference}")
            continue
        if parsed.fragment and target.suffix.lower() == ".html":
            target_document = documents.get(target.resolve())
            if not target_document or unquote(parsed.fragment) not in target_document.ids:
                errors.append(f"Broken fragment in {path.relative_to(root)}: {reference}")

switcher_targets = [
    "https://hecavex.com/en/research/",
    "https://radar.hecavex.com/",
    "https://apt.hecavex.com/",
    "https://labs.hecavex.com/",
    "https://labs.hecavex.com/data/",
]
for path in html_files:
    text = path.read_text(encoding="utf-8")
    portfolio_blocks = [
        re.search(r'<nav class="portfolio-navigation"[^>]*>(.*?)</nav>', text, re.DOTALL),
        re.search(r'<nav class="mobile-portfolio-navigation"[^>]*>(.*?)</nav>', text, re.DOTALL),
    ]
    for surface, menu in zip(("desktop", "mobile"), portfolio_blocks, strict=True):
        if not menu:
            errors.append(f"Missing {surface} portfolio navigation in {path.relative_to(root)}")
            continue
        links = re.findall(r'href="([^"]+)"', menu.group(1))
        if links != switcher_targets:
            errors.append(f"{surface.title()} portfolio targets or order differ in {path.relative_to(root)}: {links}")
        current_links = re.findall(r'<a\b(?=[^>]*aria-current="page")[^>]*href="([^"]+)"', menu.group(1))
        expected_current = "https://labs.hecavex.com/data/" if path == root / "data/index.html" else "https://labs.hecavex.com/"
        if current_links != [expected_current]:
            errors.append(
                f"{surface.title()} portfolio current state differs in {path.relative_to(root)}: "
                f"expected {expected_current}, found {current_links}"
            )

shell_route_paths = {route.path for route in SHELL_ROUTES}
html_route_paths = {path.relative_to(root).as_posix() for path in html_files}
if html_route_paths != shell_route_paths:
    errors.append(
        "Portfolio shell route inventory differs: "
        f"missing={sorted(html_route_paths - shell_route_paths)}, stale={sorted(shell_route_paths - html_route_paths)}"
    )
for route in SHELL_ROUTES:
    path = root / route.path
    text = path.read_text(encoding="utf-8")
    try:
        expected = render_shell(text, route)
    except ValueError as error:
        errors.append(str(error))
        continue
    if expected != text:
        errors.append(f"Portfolio shell is stale in {route.path}; run python scripts/sync_shell.py --write")

analytics_template = analytics_loader("a" * 32)
for marker in (
    "data-hecavex-analytics",
    "navigator.doNotTrack === '1'",
    "window.doNotTrack === '1'",
    "beacon.type = 'module'",
    ANALYTICS_SOURCE,
):
    if marker not in analytics_template:
        errors.append(f"Staged analytics template is missing its {marker!r} contract")
for forbidden_storage in ("localStorage", "sessionStorage", "indexedDB"):
    if forbidden_storage in analytics_template:
        errors.append(f"Staged analytics template must not read {forbidden_storage}")
for path in html_files:
    text = path.read_text(encoding="utf-8")
    if "data-hecavex-analytics" in text or ANALYTICS_SOURCE in text:
        errors.append(f"Source page must remain keyless before production staging: {path.relative_to(root)}")

pages_workflow = (root / ".github/workflows/pages.yml").read_text(encoding="utf-8")
for gate in ("HECAVEX_ANALYTICS_TOKEN", "stage_public_data.py _site --require-analytics"):
    if gate not in pages_workflow:
        errors.append(f"Pages deployment is missing the analytics gate: {gate}")

security_text = (root / ".well-known/security.txt").read_text(encoding="utf-8")
for field in ("Contact:", "Canonical:", "Policy:", "Preferred-Languages:", "Expires:"):
    if field not in security_text:
        errors.append(f"security.txt is missing {field}")
if "Canonical: https://labs.hecavex.com/.well-known/security.txt" not in security_text:
    errors.append("security.txt has an incorrect Canonical field")
if "Policy: https://labs.hecavex.com/security/" not in security_text:
    errors.append("security.txt has an incorrect Policy field")
expiry_match = re.search(r"^Expires:\s*(\S+)\s*$", security_text, re.MULTILINE)
try:
    expiry = datetime.fromisoformat(expiry_match.group(1).replace("Z", "+00:00")) if expiry_match else None
    if not expiry or expiry <= datetime.now(timezone.utc):
        errors.append("security.txt Expires must be a future timestamp")
except ValueError:
    errors.append("security.txt Expires is not a valid ISO timestamp")

catalogue = json.loads((root / "data/catalogue.json").read_text(encoding="utf-8"))
if catalogue.get("schema_version") != "1.0.0" or not catalogue.get("updated"):
    errors.append("Public data catalogue requires a version and update date")
required_lifecycle_states = {"maintained", "generated from upstream", "frozen", "archived"}
lifecycle_policy = catalogue.get("lifecycle_policy", {})
if not required_lifecycle_states.issubset(lifecycle_policy):
    errors.append("Public data catalogue must define maintained, generated, frozen and archived lifecycle states")
required_owned_dataset_fields = {"owner", "last_reviewed", "review_due", "archive_condition"}
for record in catalogue.get("datasets", []):
    missing_lifecycle = required_owned_dataset_fields - record.keys()
    if missing_lifecycle:
        errors.append(
            f"Owned dataset {record.get('id', '<unknown>')} is missing lifecycle fields: "
            f"{', '.join(sorted(missing_lifecycle))}"
        )
    if record.get("status") not in required_lifecycle_states:
        errors.append(f"Owned dataset {record.get('id', '<unknown>')} has an unsupported lifecycle state")
catalogue_records = [*catalogue.get("datasets", []), *catalogue.get("related_datasets", [])]
required_public_catalogue_fields = {"id", "name", "status", "schema_version", "media_type", "freshness", "update_policy", "licence", "limitation"}
for record in catalogue_records:
    missing_fields = required_public_catalogue_fields - record.keys()
    if missing_fields:
        errors.append(f"Data catalogue record {record.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_fields))}")
    if not record.get("updated") and not record.get("freshness_source"):
        errors.append(f"Data catalogue record {record.get('id', '<unknown>')} needs updated or freshness_source")
    licence = urlparse(record.get("licence", ""))
    if licence.scheme != "https":
        errors.append(f"Data catalogue record {record.get('id', '<unknown>')} needs an HTTPS licence boundary")
    for value in [record.get("content_url"), *record.get("content_urls", [])]:
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.hostname == "labs.hecavex.com":
            target = root / parsed.path.lstrip("/")
            if not target.is_file():
                errors.append(f"Data catalogue references missing distribution: {value}")

radar_record = next((record for record in catalogue_records if record.get("id") == "radar-live-signals"), {})
expected_radar_distributions = {
    "https://radar.hecavex.com/data/radar.json",
    "https://radar.hecavex.com/data/collection-health.json",
}
radar_distributions = {
    value for value in [radar_record.get("content_url"), *radar_record.get("content_urls", [])] if value
}
if radar_distributions != expected_radar_distributions:
    errors.append(f"Radar catalogue distributions differ: {radar_distributions ^ expected_radar_distributions}")
radar_freshness = f"{radar_record.get('freshness_source', '')} {radar_record.get('freshness', '')}".lower()
for distinction in ("radar.json", "collection-health.json", "separate", "continuous coverage"):
    if distinction not in radar_freshness:
        errors.append(f"Radar catalogue freshness does not distinguish {distinction}")

data_html = (root / "data/index.html").read_text(encoding="utf-8")
for distribution in expected_radar_distributions:
    if f'href="{distribution}"' not in data_html:
        errors.append(f"Human data catalogue does not link Radar distribution: {distribution}")
if "generatedAt</code> and coverage metadata" in data_html:
    errors.append("Human data catalogue still attributes collection health to radar.json")

# The catalogue's structured data must describe the datasets rather than attach
# a Dataset-only distribution property directly to DataCatalog.
data_document = documents.get((root / "data/index.html").resolve())
data_schema = json.loads(data_document.json_ld[0]) if data_document and data_document.json_ld else {}
data_graph = data_schema.get("@graph", [])
catalogue_node = next((item for item in data_graph if item.get("@type") == "DataCatalog"), {})
dataset_nodes = {item.get("@id"): item for item in data_graph if item.get("@type") == "Dataset"}
expected_dataset_ids = {f"https://labs.hecavex.com/data/#{record['id']}" for record in catalogue_records}
declared_dataset_ids = {item.get("@id") for item in catalogue_node.get("dataset", [])}
if declared_dataset_ids != expected_dataset_ids:
    errors.append(f"DataCatalog dataset references differ from catalogue.json: {declared_dataset_ids ^ expected_dataset_ids}")
if "distribution" in catalogue_node or not catalogue_node.get("encoding"):
    errors.append("DataCatalog must expose catalogue.json as an encoding and datasets through dataset")
for record in catalogue_records:
    node_id = f"https://labs.hecavex.com/data/#{record['id']}"
    node = dataset_nodes.get(node_id, {})
    if not node:
        errors.append(f"Data catalogue JSON-LD is missing Dataset {record['id']}")
        continue
    if node.get("license") != record.get("licence") or not node.get("dateModified"):
        errors.append(f"Dataset JSON-LD lacks dateModified or precise licence for {record['id']}")
    distributions = node.get("distribution", [])
    if isinstance(distributions, dict):
        distributions = [distributions]
    structured_urls = {item.get("contentUrl") for item in distributions}
    catalogue_urls = {value for value in [record.get("content_url"), *record.get("content_urls", [])] if value}
    if structured_urls != catalogue_urls:
        errors.append(f"Dataset JSON-LD distributions differ for {record['id']}: {structured_urls ^ catalogue_urls}")

manifest = json.loads((root / "data/public-manifest.json").read_text(encoding="utf-8"))
if manifest.get("schema_version") != "1.0.0" or manifest.get("default_policy") != "deny":
    errors.append("Public data manifest must be versioned and default deny")
manifest_records = manifest.get("files", [])
manifest_paths = [record.get("path", "") for record in manifest_records]
if len(manifest_paths) != len(set(manifest_paths)):
    errors.append("Public data manifest contains duplicate paths")
actual_data_paths = sorted(path.relative_to(root).as_posix() for path in (root / "data").rglob("*") if path.is_file())
if sorted(manifest_paths) != actual_data_paths:
    errors.append(f"Public data manifest is not an exact allowlist; unapproved={sorted(set(actual_data_paths) - set(manifest_paths))}, missing={sorted(set(manifest_paths) - set(actual_data_paths))}")
catalogue_ids = {record.get("id") for record in catalogue.get("datasets", [])} | {"public-data-catalogue"}
for record in manifest_records:
    path_value = record.get("path", "")
    path_parts = Path(path_value).parts
    target = (root / path_value).resolve()
    if not path_parts or path_parts[0] != "data" or not target.is_relative_to((root / "data").resolve()) or not target.is_file():
        errors.append(f"Unsafe or missing public manifest path: {path_value}")
    if record.get("catalogue_id") not in catalogue_ids:
        errors.append(f"Manifest path lacks a supported catalogue mapping: {path_value}")
    if urlparse(record.get("licence_url", "")).scheme != "https":
        errors.append(f"Manifest path lacks an HTTPS licence boundary: {path_value}")
for path in (root / "data").rglob("*"):
    if path.is_file() and any(marker in path.name.lower() for marker in ("private", "quarantine", "submission", "credential", "secret")):
        errors.append(f"Potentially sensitive material is present under the public data tree: {path.relative_to(root)}")

license_text = (root / "LICENSE").read_text(encoding="utf-8")
data_license_text = (root / "DATA-LICENSE.md").read_text(encoding="utf-8")
if "Permission is hereby granted" not in license_text or "THE SOFTWARE IS PROVIDED \"AS IS\"" not in license_text:
    errors.append("LICENSE does not contain the complete MIT grant and disclaimer")
for phrase in ("HECAVEX original data", "MITRE ATT&CK material", "Reviewed evidence and source material", "No warranty"):
    if phrase not in data_license_text:
        errors.append(f"DATA-LICENSE.md is missing: {phrase}")

for path in repository_files("*.json"):
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in {path.relative_to(root)}: {exc}")

atlas = json.loads((root / "data/atlas/records.json").read_text(encoding="utf-8"))
records = atlas.get("records", [])
if not records:
    errors.append("Baltic Threat Atlas contains no records")

required_record_fields = {"id", "date", "country", "type", "title", "summary", "sector", "attribution", "confidence", "source"}
record_ids = set()
atlas_date_patterns = (
    re.compile(r"^\d{4}$"),
    re.compile(r"^\d{4}-Q[1-4]$"),
    re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])$"),
    re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$"),
)
for record in records:
    record_id = record.get("id", "<unknown>")
    missing_fields = sorted(required_record_fields - record.keys())
    if missing_fields:
        errors.append(f"Atlas record {record_id} is missing: {', '.join(missing_fields)}")
    if record_id in record_ids:
        errors.append(f"Duplicate Atlas record id: {record_id}")
    record_ids.add(record_id)
    if record.get("country") not in {"Lithuania", "Latvia", "Estonia"}:
        errors.append(f"Unsupported Atlas country in {record_id}: {record.get('country')}")
    record_date = str(record.get("date", ""))
    if not any(pattern.fullmatch(record_date) for pattern in atlas_date_patterns):
        errors.append(f"Unsupported Atlas date format in {record_id}: {record_date}")
    elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", record_date):
        try:
            datetime.strptime(record_date, "%Y-%m-%d")
        except ValueError:
            errors.append(f"Invalid Atlas calendar date in {record_id}: {record_date}")
    if urlparse(record.get("source", "")).scheme != "https":
        errors.append(f"Atlas source must use HTTPS in {record_id}")
    for reference in record.get("apt_refs", []):
        if urlparse(reference.get("url", "")).hostname != "apt.hecavex.com":
            errors.append(f"Invalid APT Notes mapping in {record_id}: {reference.get('url')}")

atlas_html = (root / "baltic-threat-atlas/index.html").read_text(encoding="utf-8")
if 'id="atlas-records"' not in atlas_html or '/assets/atlas.js' not in atlas_html:
    errors.append("Atlas page is not wired to the canonical JSON renderer")
if any(record["title"] in atlas_html for record in records):
    errors.append("Atlas records must not be duplicated in HTML")

case_catalogue = json.loads((root / "data/pivots/cases.json").read_text(encoding="utf-8"))
cases = case_catalogue.get("cases", [])
case_ids = [case.get("id") for case in cases]
if not cases:
    errors.append("Pivot case catalogue must contain at least one case")
if len(case_ids) != len(set(case_ids)) or None in case_ids:
    errors.append("Pivot case ids must be present and unique")

allowed_classes = {"observed", "derived", "assessment", "limitation"}
catalogued_graphs = set()
total_nodes = 0
total_edges = 0
for case in cases:
    missing_case_fields = {"id", "title", "short_title", "summary", "status", "updated", "graph", "research", "tags"} - case.keys()
    if missing_case_fields:
        errors.append(f"Pivot case {case.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_case_fields))}")
        continue
    if urlparse(case["research"]).scheme != "https":
        errors.append(f"Pivot case research URL must use HTTPS in {case['id']}")
    graph_path = case["graph"].lstrip("/")
    catalogued_graphs.add(graph_path)
    if not (root / graph_path).is_file():
        errors.append(f"Pivot case graph does not exist for {case['id']}: {graph_path}")
        continue
    graph = json.loads((root / graph_path).read_text(encoding="utf-8"))
    if graph.get("case", {}).get("id") != case["id"]:
        errors.append(f"Pivot catalogue and graph case ids differ for {case['id']}")
    if not graph.get("case", {}).get("boundary"):
        errors.append(f"Pivot graph has no explicit boundary for {case['id']}")
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    total_nodes += len(nodes)
    total_edges += len(edges)
    node_ids = {node.get("id") for node in nodes}
    if len(node_ids) != len(nodes) or None in node_ids:
        errors.append(f"Pivot graph node ids must be present and unique in {case['id']}")
    node_classes = {node.get("class") for node in nodes}
    if not {"assessment", "limitation"}.issubset(node_classes):
        errors.append(f"Pivot graph must include an assessment and limitation in {case['id']}")
    for node in nodes:
        missing_node_fields = {"id", "class", "label", "short_label", "x", "y", "meaning", "confidence", "evidence_label", "evidence"} - node.keys()
        if missing_node_fields:
            errors.append(f"Pivot node {case['id']}/{node.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_node_fields))}")
        if node.get("class") not in allowed_classes:
            errors.append(f"Unsupported pivot evidence class in {case['id']}/{node.get('id')}: {node.get('class')}")
        if urlparse(node.get("evidence", "")).scheme != "https":
            errors.append(f"Pivot evidence URL must use HTTPS in {case['id']}/{node.get('id')}")
    for edge in edges:
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            errors.append(f"Pivot edge references an unknown node in {case['id']}: {edge}")
        if not edge.get("relationship"):
            errors.append(f"Pivot edge has no relationship in {case['id']}: {edge}")

graph_files = {str(path.relative_to(root)).replace("\\", "/") for path in (root / "data/pivots/graphs").glob("*.json")}
if graph_files != catalogued_graphs:
    errors.append(f"Pivot catalogue mismatch. Catalogued: {sorted(catalogued_graphs)}; present: {sorted(graph_files)}")

pivot_html = (root / "pivot-graph/index.html").read_text(encoding="utf-8")
if 'id="case-selector"' not in pivot_html or "/data/pivots/cases.json" not in pivot_html:
    errors.append("Pivot Workspace is not wired to the case catalogue")

attack = json.loads((root / "data/attack/intelligence/reviewed-evidence.json").read_text(encoding="utf-8"))
attack_actors = attack.get("actors", [])
attack_behaviours = attack.get("behaviours", [])
attack_tactics = attack.get("tactics", [])
attack_records = [record for actor in attack_actors for record in actor.get("evidence", [])]
provenance_model = attack.get("provenance_model", {})
if not {"evidence_classes", "confidence_scale", "mapping_unit", "required_context", "known_limit"}.issubset(provenance_model):
    errors.append("ATT&CK evidence is missing its publication provenance model")
for actor in attack_actors:
    if not {"owner", "last_reviewed", "review_due", "scope"}.issubset(actor.get("review", {})):
        errors.append(f"ATT&CK actor {actor.get('id', '<unknown>')} is missing review governance")
behaviour_records = [record for behaviour in attack_behaviours for record in behaviour.get("techniques", [])]
if {actor.get("id") for actor in attack_actors} != {"apt28", "apt44"}:
    errors.append("ATT&CK Workbench must contain the reviewed APT28 and APT44 records")
if len(attack_tactics) != 14 or len(set(attack_tactics)) != 14:
    errors.append("ATT&CK Workbench must contain the 14 unique Enterprise tactics")
if len(attack_records) != 19:
    errors.append(f"ATT&CK Workbench expected 19 evidence records, found {len(attack_records)}")
required_attack_fields = {"technique_id", "technique", "tactics", "status", "confidence", "campaign", "first_observed", "last_observed", "notes", "attack_url", "sources"}
for actor in attack_actors:
    if urlparse(actor.get("profile_url", "")).hostname != "apt.hecavex.com":
        errors.append(f"ATT&CK actor profile must link to APT Notes: {actor.get('id')}")
    for record in actor.get("evidence", []):
        record_name = f"{actor.get('id')}/{record.get('technique_id', '<unknown>')}"
        missing_attack_fields = required_attack_fields - record.keys()
        if missing_attack_fields:
            errors.append(f"ATT&CK record {record_name} is missing: {', '.join(sorted(missing_attack_fields))}")
        technique_id = record.get("technique_id", "")
        if not technique_id.startswith("T") or not technique_id[1:].replace(".", "").isdigit():
            errors.append(f"Invalid ATT&CK technique id in {record_name}")
        if not record.get("tactics") or not set(record.get("tactics", [])).issubset(set(attack_tactics)):
            errors.append(f"Invalid tactic mapping in {record_name}: {record.get('tactics')}")
        if record.get("status") not in {"reported", "observed", "assessed"}:
            errors.append(f"Invalid evidence status in {record_name}: {record.get('status')}")
        if record.get("confidence") not in {"high", "moderate", "low"}:
            errors.append(f"Invalid ATT&CK confidence in {record_name}: {record.get('confidence')}")
        if urlparse(record.get("attack_url", "")).hostname != "attack.mitre.org":
            errors.append(f"Invalid MITRE ATT&CK URL in {record_name}")
        if not record.get("sources"):
            errors.append(f"ATT&CK record has no public source: {record_name}")
        for source in record.get("sources", []):
            if not {"title", "publisher", "published", "url"}.issubset(source):
                errors.append(f"Incomplete ATT&CK source in {record_name}")
            if urlparse(source.get("url", "")).scheme != "https":
                errors.append(f"ATT&CK source must use HTTPS in {record_name}: {source.get('url')}")

if {behaviour.get("id") for behaviour in attack_behaviours} != {"phishing"}:
    errors.append("ATT&CK Behaviour Explorer must contain the bounded phishing model")
required_behaviour_fields = {"technique_id", "technique", "tactics", "role", "branch", "stage", "notes", "caveat", "attack_url", "sources"}
for behaviour in attack_behaviours:
    behaviour_id = behaviour.get("id", "<unknown>")
    branch_ids = {branch.get("id") for branch in behaviour.get("branches", [])}
    if len(branch_ids) < 4 or None in branch_ids:
        errors.append(f"ATT&CK behaviour {behaviour_id} must define its analytical branches")
    if not behaviour.get("boundary"):
        errors.append(f"ATT&CK behaviour {behaviour_id} has no explicit analytical boundary")
    for record in behaviour.get("techniques", []):
        record_name = f"{behaviour_id}/{record.get('technique_id', '<unknown>')}"
        missing_fields = required_behaviour_fields - record.keys()
        if missing_fields:
            errors.append(f"ATT&CK behaviour record {record_name} is missing: {', '.join(sorted(missing_fields))}")
        if record.get("role") not in {"delivery", "conditional", "outcome"}:
            errors.append(f"Invalid behaviour role in {record_name}: {record.get('role')}")
        if record.get("branch") not in branch_ids:
            errors.append(f"Unknown behaviour branch in {record_name}: {record.get('branch')}")
        if not record.get("tactics") or not set(record.get("tactics", [])).issubset(set(attack_tactics)):
            errors.append(f"Invalid behaviour tactic mapping in {record_name}: {record.get('tactics')}")
        if urlparse(record.get("attack_url", "")).hostname != "attack.mitre.org":
            errors.append(f"Invalid MITRE ATT&CK URL in behaviour record {record_name}")
        if not record.get("sources"):
            errors.append(f"ATT&CK behaviour record has no public source: {record_name}")
        for source in record.get("sources", []):
            if not {"title", "publisher", "published", "url"}.issubset(source):
                errors.append(f"Incomplete ATT&CK behaviour source in {record_name}")
            if urlparse(source.get("url", "")).scheme != "https":
                errors.append(f"ATT&CK behaviour source must use HTTPS in {record_name}: {source.get('url')}")

attack_html = (root / "attack-map/index.html").read_text(encoding="utf-8")
required_workbench_ids = {"workbench", "workspace-mode", "journey-steps", "procedure-total", "package-total", "observation-results", "observation-errors", "mapping-validation-form", "mapping-errors", "mapping-output", "group-results", "group-workspace", "intel-results", "readiness-body", "capability-editor", "capability-progress", "capability-errors", "detection-package", "incident-errors", "incident-timeline", "phishing-flow", "reference-results", "governance-summary", "capability-dialog"}
missing_workbench_ids = {item for item in required_workbench_ids if f'id="{item}"' not in attack_html}
if missing_workbench_ids or "/assets/attack-map.js" not in attack_html:
    errors.append(f"ATT&CK Operations Workbench is incomplete: {', '.join(sorted(missing_workbench_ids))}")
if 'href="/attack-map/guide/"' not in attack_html or 'class="workbench-help"' not in attack_html:
    errors.append("ATT&CK Operations Workbench has no visible first-use guide entry point")
attack_guide_html = (root / "attack-map/guide/index.html").read_text(encoding="utf-8")
expected_guide_images = {
    f'/assets/img/attack-workbench-guide/{name}.png'
    for name in (
        "01-choose-workflow",
        "02-review-evidence-candidates",
        "03-assess-coverage",
        "04-record-capability",
        "05-find-threat-actor",
        "06-use-actor-procedures",
    )
}
missing_guide_images = sorted(path for path in expected_guide_images if path not in attack_guide_html)
if missing_guide_images:
    errors.append("ATT&CK first-use guide is missing marked screenshots: " + ", ".join(missing_guide_images))
if '"@type":"HowTo"' not in attack_guide_html:
    errors.append("ATT&CK first-use guide has no HowTo structured data")
sitemap_text = (root / "sitemap.xml").read_text(encoding="utf-8")
if "https://labs.hecavex.com/attack-map/guide/" not in sitemap_text:
    errors.append("ATT&CK first-use guide is missing from sitemap.xml")
for required_public_page in ("data", "methodology", "licence", "security"):
    if f"https://labs.hecavex.com/{required_public_page}/" not in sitemap_text:
        errors.append(f"{required_public_page} page is missing from sitemap.xml")
attack_javascript = (root / "assets/attack-map.js").read_text(encoding="utf-8")
for forbidden_import_surface in ('type="file"', "import-readiness", "import-incident", "readiness-file", "incident-file"):
    if forbidden_import_surface in attack_html:
        errors.append(f"ATT&CK Workbench exposes a disabled user-import surface: {forbidden_import_surface}")
for forbidden_import_handler in ("FileReader", "showOpenFilePicker", "readJsonFile"):
    if forbidden_import_handler in attack_javascript:
        errors.append(f"ATT&CK Workbench contains a disabled user-import handler: {forbidden_import_handler}")
for validation_contract in ("showFormErrors", "validateCapabilityClaims", "aria-invalid", "field-error-message"):
    if validation_contract not in attack_javascript and validation_contract not in attack_html:
        errors.append(f"ATT&CK Workbench is missing its inline validation contract: {validation_contract}")

attack_catalogue = json.loads((root / "data/attack/catalogue/enterprise.json").read_text(encoding="utf-8"))
catalogue_tactics = attack_catalogue.get("tactics", [])
catalogue_groups = attack_catalogue.get("groups", [])
catalogue_techniques = attack_catalogue.get("techniques", [])
if len(catalogue_tactics) != 15:
    errors.append(f"Enterprise ATT&CK catalogue expected 15 tactics, found {len(catalogue_tactics)}")
if len(catalogue_techniques) < 650:
    errors.append(f"Enterprise ATT&CK catalogue appears incomplete: {len(catalogue_techniques)} techniques")
if len(catalogue_groups) < 170:
    errors.append(f"Enterprise ATT&CK group catalogue appears incomplete: {len(catalogue_groups)} groups")
catalogue_ids = [record.get("id") for record in catalogue_techniques]
if len(catalogue_ids) != len(set(catalogue_ids)) or None in catalogue_ids:
    errors.append("Enterprise ATT&CK technique ids must be present and unique")
catalogue_tactic_names = {tactic.get("name") for tactic in catalogue_tactics}
catalogue_group_ids = [record.get("id") for record in catalogue_groups]
if len(catalogue_group_ids) != len(set(catalogue_group_ids)) or None in catalogue_group_ids:
    errors.append("Enterprise ATT&CK group ids must be present and unique")
required_group_fields = {"id", "name", "aliases", "url", "description", "created", "modified", "version", "techniques", "sources"}
for record in catalogue_groups:
    group_name = record.get("id", "<unknown>")
    missing_fields = required_group_fields - record.keys()
    if missing_fields:
        errors.append(f"Enterprise ATT&CK group {group_name} is missing: {', '.join(sorted(missing_fields))}")
    if not re.fullmatch(r"G\d{4}", record.get("id", "")):
        errors.append(f"Invalid Enterprise ATT&CK group id: {group_name}")
    if urlparse(record.get("url", "")).hostname != "attack.mitre.org":
        errors.append(f"Invalid official ATT&CK URL for group {group_name}")
    for technique_id in record.get("techniques", []):
        if technique_id not in catalogue_ids:
            errors.append(f"Unknown technique {technique_id} in group {group_name}")
    for source in record.get("sources", []):
        if urlparse(source.get("url", "")).scheme != "https":
            errors.append(f"Non-HTTPS public reference in group {group_name}")
official_actor_procedures = json.loads((root / "data/attack/intelligence/official-actor-procedures.json").read_text(encoding="utf-8"))
procedure_groups = official_actor_procedures.get("groups", [])
if {group.get("id") for group in procedure_groups} != set(catalogue_group_ids):
    errors.append("Official actor procedure groups do not match the Enterprise group catalogue")
official_procedure_count = 0
for procedure_group in procedure_groups:
    group_name = procedure_group.get("id", "<unknown>")
    for procedure in procedure_group.get("procedures", []):
        official_procedure_count += 1
        if procedure.get("technique_id") not in catalogue_ids:
            errors.append(f"Unknown procedure technique {procedure.get('technique_id')} in group {group_name}")
        if not procedure.get("description", "").strip():
            errors.append(f"Official procedure has no description in group {group_name}/{procedure.get('technique_id')}")
        for source in procedure.get("sources", []):
            if urlparse(source.get("url", "")).scheme != "https":
                errors.append(f"Non-HTTPS procedure source in group {group_name}/{procedure.get('technique_id')}")
required_catalogue_fields = {"id", "name", "url", "description", "tactics", "platforms", "subtechnique", "parent", "modified", "version", "groups", "campaigns", "software", "mitigations", "detections"}
for record in catalogue_techniques:
    record_name = record.get("id", "<unknown>")
    missing_fields = required_catalogue_fields - record.keys()
    if missing_fields:
        errors.append(f"Enterprise ATT&CK record {record_name} is missing: {', '.join(sorted(missing_fields))}")
    if urlparse(record.get("url", "")).hostname != "attack.mitre.org":
        errors.append(f"Invalid official ATT&CK URL in catalogue record {record_name}")
    if not set(record.get("tactics", [])).issubset(catalogue_tactic_names):
        errors.append(f"Unknown tactic in catalogue record {record_name}: {record.get('tactics')}")

attack_operations = json.loads((root / "data/attack/operations/guides.json").read_text(encoding="utf-8"))
operational_guides = attack_operations.get("guides", [])
if len(operational_guides) < 20:
    errors.append(f"ATT&CK Operations Workbench expected at least 20 curated guides, found {len(operational_guides)}")
guide_ids = [guide.get("technique_id") for guide in operational_guides]
if len(guide_ids) != len(set(guide_ids)) or None in guide_ids:
    errors.append("ATT&CK operational guide technique ids must be present and unique")
required_guide_fields = {"technique_id", "triggers", "analyst_summary", "minimum_evidence", "telemetry", "benign_overlap", "pivots", "response"}
for guide in operational_guides:
    guide_id = guide.get("technique_id", "<unknown>")
    missing_fields = required_guide_fields - guide.keys()
    if missing_fields:
        errors.append(f"ATT&CK operational guide {guide_id} is missing: {', '.join(sorted(missing_fields))}")
    if guide_id not in catalogue_ids:
        errors.append(f"ATT&CK operational guide references unknown technique: {guide_id}")
    for field in required_guide_fields - {"technique_id", "analyst_summary"}:
        if not guide.get(field):
            errors.append(f"ATT&CK operational guide {guide_id} has an empty {field}")
readiness_states = attack_operations.get("readiness_states", [])
required_readiness_states = {"not-assessed", "no-telemetry", "telemetry", "analytic", "validated", "operational", "not-applicable"}
if {state.get("id") for state in readiness_states} != required_readiness_states:
    errors.append("ATT&CK readiness states do not match the operational capability model")
phishing_flow = attack_operations.get("phishing_flow", {})
flow_nodes = phishing_flow.get("nodes", [])
flow_node_ids = {node.get("id") for node in flow_nodes}
if len(flow_nodes) < 8 or None in flow_node_ids:
    errors.append("ATT&CK phishing flow must contain its branching investigation nodes")
for node in flow_nodes:
    if not {"id", "label", "stage", "techniques", "question", "collect", "next"}.issubset(node):
        errors.append(f"ATT&CK phishing node is incomplete: {node.get('id', '<unknown>')}")
    for technique_id in node.get("techniques", []):
        if technique_id not in catalogue_ids:
            errors.append(f"ATT&CK phishing node {node.get('id')} references unknown technique: {technique_id}")
    if not set(node.get("next", [])).issubset(flow_node_ids):
        errors.append(f"ATT&CK phishing node {node.get('id')} references an unknown next node")
for edge in phishing_flow.get("edges", []):
    if edge.get("from") not in flow_node_ids or edge.get("to") not in flow_node_ids or not edge.get("label"):
        errors.append(f"Invalid ATT&CK phishing-flow edge: {edge}")
for source in attack_operations.get("sources", []):
    if urlparse(source.get("url", "")).scheme != "https":
        errors.append(f"ATT&CK operations source must use HTTPS: {source}")

detection_packages = json.loads((root / "data/attack/detections/packages.json").read_text(encoding="utf-8"))
packages = detection_packages.get("packages", [])
if len(packages) != len(operational_guides):
    errors.append(f"Each operational guide must have a materialised detection package: {len(packages)} packages for {len(operational_guides)} guides")
required_package_fields = {"id", "technique_id", "title", "status", "scope", "hypothesis", "official_detection", "data_requirements", "analytic_logic", "benign_baseline", "known_blind_spots", "safe_validation_cases", "acceptance_criteria", "triage", "response", "lifecycle", "references"}
package_ids = []
for package in packages:
    package_id = package.get("id", "<unknown>")
    package_ids.append(package.get("id"))
    missing = required_package_fields - package.keys()
    if missing:
        errors.append(f"Detection package {package_id} is missing: {', '.join(sorted(missing))}")
    if package.get("technique_id") not in catalogue_ids:
        errors.append(f"Detection package {package_id} references an unknown ATT&CK technique")
    official = package.get("official_detection", {})
    if not {"strategy_id", "strategy_name", "url", "analytic_id", "description", "platforms", "log_sources", "mutable_elements"}.issubset(official):
        errors.append(f"Detection package {package_id} has incomplete official detection lineage")
    if urlparse(official.get("url", "")).hostname != "attack.mitre.org":
        errors.append(f"Detection package {package_id} has an invalid ATT&CK detection URL")
    if len(official.get("log_sources", [])) < 3:
        errors.append(f"Detection package {package_id} requires concrete log-source mappings")
    if len(package.get("data_requirements", [])) < 3 or any(not {"source", "acceptable_sensors", "required_fields", "quality_checks"}.issubset(item) for item in package.get("data_requirements", [])):
        errors.append(f"Detection package {package_id} has an incomplete data contract")
    case_classes = {case.get("class") for case in package.get("safe_validation_cases", [])}
    if not {"positive", "negative", "resilience"}.issubset(case_classes):
        errors.append(f"Detection package {package_id} must contain positive, negative and resilience tests")
    if not {"package_owner", "package_status", "created", "last_reviewed", "review_due", "attack_version", "technique_version", "change_policy"}.issubset(package.get("lifecycle", {})):
        errors.append(f"Detection package {package_id} has incomplete lifecycle governance")
    for reference in package.get("references", []):
        if urlparse(reference.get("url", "")).scheme != "https":
            errors.append(f"Detection package {package_id} reference must use HTTPS")
if len(package_ids) != len(set(package_ids)) or None in package_ids:
    errors.append("Detection package ids must be present and unique")

attack_governance = json.loads((root / "data/attack/governance/governance.json").read_text(encoding="utf-8"))
governance_layers = attack_governance.get("curated_layers", [])
if {layer.get("id") for layer in governance_layers} != {"official-catalogue", "official-group-procedures", "operational-guides", "actor-evidence", "detection-packages"}:
    errors.append("ATT&CK lifecycle governance is missing a curated publication layer")
for layer in governance_layers:
    if not {"id", "label", "version", "records", "last_reviewed", "review_due", "owner", "scope"}.issubset(layer):
        errors.append(f"ATT&CK governance layer is incomplete: {layer.get('id', '<unknown>')}")
catalogue_tactics = {record.get("id"): set(record.get("tactics", [])) for record in catalogue_techniques}
review_gap_count = sum(
    set(record.get("tactics", [])) != catalogue_tactics.get(record.get("technique_id"), set())
    for record in [*attack_records, *behaviour_records]
)
actor_evidence_layer = next((layer for layer in governance_layers if layer.get("id") == "actor-evidence"), {})
if actor_evidence_layer.get("review_gaps") != review_gap_count:
    errors.append("ATT&CK governance does not expose the current tactic re-review gap count")
if review_gap_count and actor_evidence_layer.get("review_due") != "Re-review required":
    errors.append("ATT&CK governance must mark unresolved tactic drift for re-review")
for package in packages:
    if package.get("starter") and package.get("lifecycle", {}).get("last_reviewed") != "Not independently reviewed":
        errors.append(f"Detection candidate {package.get('id', '<unknown>')} must not claim a review date")
governance_records = {layer.get("id"): layer.get("records") for layer in governance_layers}
expected_governance_records = {
    "official-catalogue": len(catalogue_techniques),
    "official-group-procedures": official_procedure_count,
    "operational-guides": len(operational_guides),
    "actor-evidence": len(attack_records),
    "detection-packages": len(packages),
}
if governance_records != expected_governance_records:
    errors.append(f"ATT&CK governance counts do not match their publication layers: {governance_records}")
if len(attack_governance.get("change_history", [])) < 2 or not attack_governance.get("review_triggers"):
    errors.append("ATT&CK lifecycle governance requires review triggers and visible history")
for path in html_files:
    if path.name == "index.html" and path.parent in {root, root / "baltic-threat-atlas", root / "pivot-graph", root / "osint-workbench", root / "attack-map"}:
        if "/attack-map/" not in path.read_text(encoding="utf-8"):
            errors.append(f"ATT&CK Workbench is missing from navigation in {path.relative_to(root)}")

osint = json.loads((root / "data/osint/resources.json").read_text(encoding="utf-8"))
osint_sections = osint.get("sections", [])
curation_sources = osint.get("curation_sources", [])
if len(curation_sources) != 3:
    errors.append("OSINT Workbench must identify its three curation sources")
for source in curation_sources:
    if urlparse(source.get("url", "")).hostname != "github.com":
        errors.append(f"OSINT curation source must be a GitHub repository: {source}")

section_ids = [section.get("id") for section in osint_sections]
if len(section_ids) != len(set(section_ids)) or None in section_ids:
    errors.append("OSINT section ids must be present and unique")
tool_ids = []
required_tool_fields = {"id", "name", "url", "access", "format", "use_when", "why", "caution"}
for section in osint_sections:
    tools = section.get("tools", [])
    if len(tools) < 2:
        errors.append(f"OSINT section must contain several selected tools: {section.get('id')}")
    for tool in tools:
        tool_ids.append(tool.get("id"))
        missing_tool_fields = required_tool_fields - tool.keys()
        if missing_tool_fields:
            errors.append(f"OSINT tool {tool.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_tool_fields))}")
        if urlparse(tool.get("url", "")).scheme != "https":
            errors.append(f"OSINT tool URL must use HTTPS: {tool.get('id')}")
if len(tool_ids) != len(set(tool_ids)) or None in tool_ids:
    errors.append("OSINT tool ids must be present and unique")

osint_html = (root / "osint-workbench/index.html").read_text(encoding="utf-8")
if 'id="resource-list"' not in osint_html or "/data/osint/resources.json" not in osint_html:
    errors.append("OSINT Workbench is not wired to its canonical dataset")
if any("cra-reporting" in path.read_text(encoding="utf-8").lower() for path in html_files):
    errors.append("Retired CRA Triage links remain in public HTML")

if errors:
    print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
    raise SystemExit(1)

print(
    f"Validated {len(html_files)} HTML pages, {len(records)} Atlas records, "
    f"{len(cases)} pivot cases, {total_nodes} pivot nodes, {total_edges} typed edges, "
    f"{len(catalogue_techniques)} Enterprise ATT&CK techniques, {len(catalogue_groups)} official groups, {official_procedure_count} official actor procedures, {len(attack_records)} actor evidence records, "
    f"{len(behaviour_records)} behaviour mappings, {len(operational_guides)} operational guides, {len(packages)} detection packages and {len(tool_ids)} OSINT tools "
    f"across {len(osint_sections)} sections."
)
