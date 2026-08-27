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
ignored_validation_directories = {".git", ".codex-tmp", "_site", "__pycache__"}


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
    "osint-workbench/index.html",
    "data/index.html",
    "changes/index.html",
    "changes/feed.json",
    "about/index.html",
    "data/catalogue.json",
    "data/public-manifest.json",
    "licence/index.html",
    "methodology/index.html",
    "security/index.html",
    "assets/styles.css",
    "assets/attack-evidence.css",
    "assets/hecavex-mark.svg",
    "assets/site.js",
    "assets/atlas.js",
    "assets/pivot-graph.js",
    "assets/attack-map.js",
    "data/atlas/records.json",
    "data/osint/resources.json",
    "data/pivots/cases.json",
    "data/pivots/graphs/adform.json",
    "data/pivots/graphs/hostinger.json",
    "data/pivots/graphs/unipark.json",
    "data/pivots/graphs/github-python.json",
    "data/attack/intelligence/reviewed-evidence.json",
    "scripts/build_reviewed_attack_evidence.py",
    "scripts/stage_public_data.py",
    "scripts/sync_shell.py",
    "CNAME",
    "robots.txt",
    "llms.txt",
    "sitemap.xml",
    "LICENSE",
    "LICENSE.md",
    "DATA-LICENSE.md",
    "favicon.svg",
    "favicon.ico",
    "apple-touch-icon.png",
    "icon-192.png",
    "icon-512.png",
    "site.webmanifest",
    ".well-known/security.txt",
}

errors = []
missing = sorted(path for path in required if not (root / path).is_file())
if missing:
    errors.append("Missing required files: " + ", ".join(missing))

robots_text = (root / "robots.txt").read_text(encoding="utf-8")
llms_text = (root / "llms.txt").read_text(encoding="utf-8")
manifest_data = json.loads((root / "site.webmanifest").read_text(encoding="utf-8"))
if "Content-Signal: search=yes, ai-input=yes, ai-train=no" not in robots_text:
    errors.append("robots.txt is missing the reviewed HECAVEX content-use signal")
for manifest_key in ("id", "start_url", "scope"):
    if manifest_data.get(manifest_key) != "/":
        errors.append(f"site.webmanifest {manifest_key} must be /")
if manifest_data.get("name") != "HECAVEX Labs":
    errors.append("site.webmanifest must carry the Labs origin identity")
manifest_icons = {
    (item.get("src"), item.get("sizes"), item.get("type"))
    for item in manifest_data.get("icons", [])
}
for expected_icon in (
    ("/icon-192.png", "192x192", "image/png"),
    ("/icon-512.png", "512x512", "image/png"),
):
    if expected_icon not in manifest_icons:
        errors.append(f"site.webmanifest is missing identity icon {expected_icon[0]}")
for required_url in (
    "https://labs.hecavex.com/data/catalogue.json",
    "https://labs.hecavex.com/data/public-manifest.json",
    "https://labs.hecavex.com/changes/",
    "https://labs.hecavex.com/methodology/",
    "https://labs.hecavex.com/about/",
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
identity_head_contract = (
    '<link rel="icon" href="/favicon.svg" type="image/svg+xml">',
    '<link rel="icon" href="/favicon.ico" sizes="any">',
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
    '<link rel="manifest" href="/site.webmanifest">',
)
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
    for declaration in identity_head_contract:
        if text.count(declaration) != 1:
            errors.append(f"Shared identity declaration differs or is missing from {relative}: {declaration}")
    if re.search(r'<link[^>]+rel="stylesheet"[^>]+href="https?://', text, re.IGNORECASE):
        errors.append(f"Remote stylesheet dependency found in {relative}")
    expected_stylesheet = "/assets/styles.css?v=20260826-2"
    expected_stylesheets = [expected_stylesheet]
    if relative == Path("attack-map/index.html"):
        expected_stylesheets.append("/assets/attack-evidence.css?v=20260826-2")
    if parser.stylesheets != expected_stylesheets:
        errors.append(
            f"Versioned route stylesheet differs in {relative}: "
            f"expected {expected_stylesheets}, found {parser.stylesheets}"
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
        expected_current = "https://labs.hecavex.com/"
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
    if not path.is_file():
        continue
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
if catalogue.get("catalogue_url") != "https://hecavex.com/data/":
    errors.append("Human-readable portfolio data must use the canonical hecavex.com/data location")
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
for redirect_contract in (
    '<meta http-equiv="refresh" content="0; url=https://hecavex.com/data/">',
    '<link rel="canonical" href="https://hecavex.com/data/">',
):
    if redirect_contract not in data_html:
        errors.append(f"Legacy Labs data route is missing its redirect contract: {redirect_contract}")
for route in SHELL_ROUTES:
    shell_html = (root / route.path).read_text(encoding="utf-8")
    if 'href="/data/"' in shell_html or 'href="https://hecavex.com/data/">Data</a>' not in shell_html:
        errors.append(f"Labs Data navigation is stale in {route.path}")
if "DataCatalog" in data_html or "Dataset" in data_html:
    errors.append("Legacy Labs data route must not claim canonical DataCatalog or Dataset ownership")
for legacy_copy in ("Public data catalogue", "Dataset register", "Distribution access"):
    if legacy_copy in data_html:
        errors.append(f"Legacy Labs data route still contains stale catalogue copy: {legacy_copy}")
for move_contract in (
    "HECAVEX Data has moved",
    "https://hecavex.com/data/",
    "remain stable",
):
    if move_contract not in data_html:
        errors.append(f"Legacy Labs data route is missing its move notice: {move_contract}")

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
for phrase in ("HECAVEX original data", "MITRE ATT&CK references", "Reviewed evidence and source material", "No warranty"):
    if phrase not in data_license_text:
        errors.append(f"DATA-LICENSE.md is missing: {phrase}")

for path in repository_files("*.json"):
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in {path.relative_to(root)}: {exc}")

atlas = json.loads((root / "data/atlas/records.json").read_text(encoding="utf-8"))
records = atlas.get("records", [])
actor_context = atlas.get("actor_context", [])
if not records:
    errors.append("Baltic Threat Atlas contains no records")
if not actor_context:
    errors.append("Baltic Threat Atlas contains no Europe-context actors")

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

required_context_fields = {
    "id", "name", "category", "status", "confidence", "summary",
    "europe_relevance", "baltic_observation_ids", "apt_url",
}
context_ids = set()
allowed_context_categories = {"state-sponsored", "state-aligned", "hybrid", "cybercrime", "hacktivist"}
for actor in actor_context:
    actor_id = actor.get("id", "<unknown>")
    missing_fields = sorted(required_context_fields - actor.keys())
    if missing_fields:
        errors.append(f"Atlas context actor {actor_id} is missing: {', '.join(missing_fields)}")
    if actor_id in context_ids:
        errors.append(f"Duplicate Atlas context actor id: {actor_id}")
    context_ids.add(actor_id)
    if actor.get("category") not in allowed_context_categories:
        errors.append(f"Unsupported Atlas context category in {actor_id}: {actor.get('category')}")
    if urlparse(actor.get("apt_url", "")).hostname != "apt.hecavex.com":
        errors.append(f"Atlas context actor must link to APT Notes: {actor_id}")
    mapping_ids = actor.get("baltic_observation_ids", [])
    if not isinstance(mapping_ids, list):
        errors.append(f"Atlas context actor mappings must be a list: {actor_id}")
    else:
        unknown_mappings = sorted(set(mapping_ids) - record_ids)
        if unknown_mappings:
            errors.append(f"Atlas context actor {actor_id} maps unknown observations: {', '.join(unknown_mappings)}")

atlas_html = (root / "baltic-threat-atlas/index.html").read_text(encoding="utf-8")
if 'id="atlas-records"' not in atlas_html or 'id="atlas-actor-context"' not in atlas_html or '/assets/atlas.js' not in atlas_html:
    errors.append("Atlas page is not wired to the canonical JSON renderer")
if any(record["title"] in atlas_html for record in records):
    errors.append("Atlas records must not be duplicated in HTML")

case_catalogue = json.loads((root / "data/pivots/cases.json").read_text(encoding="utf-8"))
cases = case_catalogue.get("cases", [])
case_ids = [case.get("id") for case in cases]
if case_catalogue.get("schema_version") != "1.1.0":
    errors.append("Pivot case catalogue must use the publication-approval schema 1.1.0")
if not cases:
    errors.append("Pivot case catalogue must contain at least one case")
if len(case_ids) != len(set(case_ids)) or None in case_ids:
    errors.append("Pivot case ids must be present and unique")

allowed_classes = {"observed", "derived", "assessment", "limitation"}
catalogued_graphs = set()
total_nodes = 0
total_edges = 0
for case in cases:
    missing_case_fields = {"id", "title", "short_title", "summary", "status", "publication_approved", "publication_approved_at", "updated", "graph", "research", "tags"} - case.keys()
    if missing_case_fields:
        errors.append(f"Pivot case {case.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_case_fields))}")
        continue
    if urlparse(case["research"]).scheme != "https":
        errors.append(f"Pivot case research URL must use HTTPS in {case['id']}")
    if case.get("publication_approved") is not True:
        errors.append(f"Pivot case is not explicitly approved for publication: {case['id']}")
    try:
        datetime.strptime(str(case.get("publication_approved_at", "")), "%Y-%m-%d")
    except ValueError:
        errors.append(f"Pivot case publication approval date is invalid: {case['id']}")
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
manifest_graphs = {path for path in manifest_paths if path.startswith("data/pivots/graphs/")}
if manifest_graphs != catalogued_graphs:
    errors.append(
        "Approved pivot cases and public manifest graphs differ: "
        f"cases={sorted(catalogued_graphs)}, manifest={sorted(manifest_graphs)}"
    )

pivot_html = (root / "pivot-graph/index.html").read_text(encoding="utf-8")
if 'id="case-selector"' not in pivot_html or "/data/pivots/cases.json" not in pivot_html:
    errors.append("Pivot Workspace is not wired to the case catalogue")

attack = json.loads((root / "data/attack/intelligence/reviewed-evidence.json").read_text(encoding="utf-8"))
attack_actors = attack.get("actors", [])
attack_records = [record for actor in attack_actors for record in actor.get("evidence", [])]
provenance_model = attack.get("provenance_model", {})
source_system = attack.get("source_system", {})
attack_summary = attack.get("summary", {})
if attack.get("schema_version") != "2.0.0":
    errors.append("ATT&CK Evidence Explorer requires reviewed-evidence schema 2.0.0")
if not {"release_id", "dataset_version", "released_at", "method"}.issubset(source_system):
    errors.append("ATT&CK evidence is missing its APT Notes source release contract")
if urlparse(source_system.get("url", "")).hostname != "apt.hecavex.com":
    errors.append("ATT&CK evidence source system must link to APT Notes")
if not {"default_mapping_status", "status_values", "confidence_values", "mapping_unit", "known_limit"}.issubset(provenance_model):
    errors.append("ATT&CK evidence is missing its publication provenance model")
if len(attack_actors) < 2 or not attack_records:
    errors.append("ATT&CK Evidence Explorer requires reviewed actors and explicit technique evidence")
actor_ids = [actor.get("id") for actor in attack_actors]
if len(actor_ids) != len(set(actor_ids)) or None in actor_ids:
    errors.append("ATT&CK actor ids must be present and unique")
if attack_summary.get("actors") != len(attack_actors) or attack_summary.get("mappings") != len(attack_records):
    errors.append("ATT&CK evidence summary counts do not match the published records")
expected_technique_count = len({record.get("technique_id") for record in attack_records})
expected_campaign_count = len({record.get("campaign", {}).get("id") for record in attack_records if record.get("campaign", {}).get("id")})
if attack_summary.get("techniques") != expected_technique_count or attack_summary.get("campaigns") != expected_campaign_count:
    errors.append("ATT&CK technique or campaign summary counts do not match the evidence")

valid_attack_tactics = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
}
required_actor_fields = {"id", "name", "slug", "summary", "status", "confidence", "last_reviewed", "aliases", "url", "json_url", "evidence"}
required_attack_fields = {
    "id", "technique_id", "technique", "technique_slug", "tactics", "mapping_status", "confidence",
    "campaign", "first_observed", "last_observed", "notes", "uncertainty", "attack_url",
    "apt_notes_url", "sources",
}
evidence_ids = []
for actor in attack_actors:
    missing_actor_fields = required_actor_fields - actor.keys()
    if missing_actor_fields:
        errors.append(f"ATT&CK actor {actor.get('id', '<unknown>')} is missing: {', '.join(sorted(missing_actor_fields))}")
    if urlparse(actor.get("url", "")).hostname != "apt.hecavex.com":
        errors.append(f"ATT&CK actor profile must link to APT Notes: {actor.get('id')}")
    for record in actor.get("evidence", []):
        evidence_ids.append(record.get("id"))
        record_name = f"{actor.get('id')}/{record.get('technique_id', '<unknown>')}"
        missing_attack_fields = required_attack_fields - record.keys()
        if missing_attack_fields:
            errors.append(f"ATT&CK record {record_name} is missing: {', '.join(sorted(missing_attack_fields))}")
        technique_id = record.get("technique_id", "")
        if not technique_id.startswith("T") or not technique_id[1:].replace(".", "").isdigit():
            errors.append(f"Invalid ATT&CK technique id in {record_name}")
        if not record.get("tactics") or not set(record.get("tactics", [])).issubset(valid_attack_tactics):
            errors.append(f"Invalid tactic mapping in {record_name}: {record.get('tactics')}")
        if record.get("mapping_status") not in {"reported", "observed", "assessed", "inferred", "disputed", "rejected"}:
            errors.append(f"Invalid evidence status in {record_name}: {record.get('mapping_status')}")
        if record.get("confidence") not in {"high", "moderate", "low"}:
            errors.append(f"Invalid ATT&CK confidence in {record_name}: {record.get('confidence')}")
        if urlparse(record.get("attack_url", "")).hostname != "attack.mitre.org":
            errors.append(f"Invalid MITRE ATT&CK URL in {record_name}")
        if not record.get("sources"):
            errors.append(f"ATT&CK record has no public source: {record_name}")
        for source in record.get("sources", []):
            if not {"id", "title", "publisher", "published", "source_type", "url", "apt_notes_url"}.issubset(source):
                errors.append(f"Incomplete ATT&CK source in {record_name}")
            if urlparse(source.get("url", "")).scheme != "https":
                errors.append(f"ATT&CK source must use HTTPS in {record_name}: {source.get('url')}")
            if urlparse(source.get("apt_notes_url", "")).hostname != "apt.hecavex.com":
                errors.append(f"ATT&CK source must preserve its APT Notes record in {record_name}")
if len(evidence_ids) != len(set(evidence_ids)) or None in evidence_ids:
    errors.append("ATT&CK evidence record ids must be present and unique")

attack_html = (root / "attack-map/index.html").read_text(encoding="utf-8")
required_explorer_ids = {
    "evidence-index", "evidence-controls", "evidence-results", "result-count", "actor-filter",
    "campaign-filter", "tactic-filter", "confidence-filter", "status-filter", "comparison",
    "comparison-grid", "mapping-dialog", "mapping-dialog-body", "export-json", "export-csv",
    "export-navigator",
}
missing_explorer_ids = {item for item in required_explorer_ids if f'id="{item}"' not in attack_html}
if missing_explorer_ids or "/assets/attack-map.js" not in attack_html or "/assets/attack-evidence.css" not in attack_html:
    errors.append(f"ATT&CK Evidence Explorer is incomplete: {', '.join(sorted(missing_explorer_ids))}")
sitemap_text = (root / "sitemap.xml").read_text(encoding="utf-8")
if "https://labs.hecavex.com/attack-map/guide/" in sitemap_text:
    errors.append("Retired ATT&CK workbench guide remains in sitemap.xml")
for required_public_page in ("changes", "methodology", "about", "licence", "security"):
    if f"https://labs.hecavex.com/{required_public_page}/" not in sitemap_text:
        errors.append(f"{required_public_page} page is missing from sitemap.xml")
attack_javascript = (root / "assets/attack-map.js").read_text(encoding="utf-8")
for required_explorer_contract in (
    "/data/attack/intelligence/reviewed-evidence.json", "showModal", "textContent",
    "exportNavigator", "MAX_COMPARISON", "reconcileDependentControls", "matchesFacet",
):
    if required_explorer_contract not in attack_javascript:
        errors.append(f"ATT&CK Evidence Explorer is missing its client contract: {required_explorer_contract}")
attack_styles = (root / "assets/attack-evidence.css").read_text(encoding="utf-8")
if not re.search(r"\.evidence-controls \.button\s*\{[^}]*grid-column:\s*1\s*/\s*-1\s*;", attack_styles):
    errors.append("ATT&CK filter reset control must span the complete grid without an exposed filler row")
for forbidden_surface in (
    "Assess defensive coverage", "Incident timeline mapper", "Phishing investigation model",
    "Detection engineering package", "Technique reference catalogue", "localStorage", "FileReader",
    "/data/attack/catalogue/enterprise.json", "/data/attack/operations/guides.json",
    "/data/attack/detections/packages.json",
):
    if forbidden_surface in attack_html or forbidden_surface in attack_javascript:
        errors.append(f"Retired ATT&CK workbench surface remains public: {forbidden_surface}")

retired_attack_paths = {
    "attack-map/guide/index.html",
    "data/attack/catalogue/enterprise.json",
    "data/attack/intelligence/official-actor-procedures.json",
    "data/attack/operations/guides.json",
    "data/attack/detections/packages.json",
    "data/attack/governance/governance.json",
}
remaining_retired_paths = sorted(path for path in retired_attack_paths if (root / path).exists())
if remaining_retired_paths:
    errors.append("Retired ATT&CK public payload remains: " + ", ".join(remaining_retired_paths))

attack_generator = (root / "scripts/build_reviewed_attack_evidence.py").read_text(encoding="utf-8")
for generator_contract in ("technique_evidence", "--check", "APT_NOTES_DIST", "validate_payload"):
    if generator_contract not in attack_generator:
        errors.append(f"ATT&CK evidence generator is missing its drift contract: {generator_contract}")
for path in html_files:
    if path.name == "index.html" and path.parent in {root, root / "baltic-threat-atlas", root / "pivot-graph", root / "osint-workbench", root / "attack-map"}:
        if "/attack-map/" not in path.read_text(encoding="utf-8"):
            errors.append(f"ATT&CK Evidence Explorer is missing from navigation in {path.relative_to(root)}")

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
    f"{len(attack_actors)} reviewed ATT&CK actors, {len(attack_records)} source-backed evidence mappings and {len(tool_ids)} OSINT tools "
    f"across {len(osint_sections)} sections."
)
