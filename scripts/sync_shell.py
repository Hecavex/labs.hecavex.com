#!/usr/bin/env python3
"""Keep the rendered Labs portfolio shell identical across static routes."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Route:
    path: str
    active: str | None
    utility: str
    utility_label: str = ""
    utility_placeholder: str = ""
    utility_href: str = ""
    utility_text: str = ""
    portfolio_active: str = "labs"


ROUTES = (
    Route("index.html", "overview", "search", "Filter Labs workspaces", "Filter"),
    Route("baltic-threat-atlas/index.html", "atlas", "search", "Search Baltic Threat Atlas", "Search"),
    Route("pivot-graph/index.html", "pivots", "search", "Search case claims", "Search"),
    Route("attack-map/index.html", "attack", "search", "Search actors or techniques", "Search"),
    Route("osint-workbench/index.html", None, "search", "Search archived OSINT resources", "Search"),
    Route("data/index.html", None, "link", utility_href="/data/catalogue.json", utility_text="Catalogue JSON"),
    Route("changes/index.html", "changes", "link", utility_href="/changes/feed.json", utility_text="JSON feed"),
    Route("methodology/index.html", "methodology", "link", utility_href="https://github.com/Hecavex/labs.hecavex.com", utility_text="Source"),
    Route("about/index.html", "about", "link", utility_href="https://github.com/Hecavex/labs.hecavex.com", utility_text="Source"),
    Route("licence/index.html", None, "link", utility_href="/methodology/", utility_text="Methodology"),
    Route("security/index.html", None, "link", utility_href="/.well-known/security.txt", utility_text="security.txt"),
)

LOCAL_NAVIGATION = (
    ("overview", "Overview", "/"),
    ("atlas", "Baltic Atlas", "/baltic-threat-atlas/"),
    ("pivots", "Pivots", "/pivot-graph/"),
    ("attack", "ATT&amp;CK Evidence", "/attack-map/"),
    ("changes", "Changes", "/changes/"),
    ("methodology", "Methodology", "/methodology/"),
    ("about", "About", "/about/"),
)

PORTFOLIO_NAVIGATION = (
    ("research", "Research", "https://hecavex.com/en/research/"),
    ("radar", "Radar", "https://radar.hecavex.com/"),
    ("apt", "APT Notes", "https://apt.hecavex.com/"),
    ("labs", "Labs", "https://labs.hecavex.com/"),
)

HEADER_RE = re.compile(r'<header class="site-header"(?:\s[^>]*)?>.*?</header>', re.DOTALL)
FOOTER_RE = re.compile(r'<footer class="(?:footer|site-footer)"(?:\s[^>]*)?>.*?</footer>', re.DOTALL)


def attributes(current: bool) -> str:
    return ' aria-current="page"' if current else ""


def render_local_navigation(active: str | None, *, mobile: bool) -> str:
    links = "".join(
        f'<a href="{href}"{attributes(key == active)}>{label}</a>'
        for key, label, href in LOCAL_NAVIGATION
    )
    if mobile:
        return f'<nav class="mobile-product-navigation" aria-label="Labs sections"><span class="navigation-label">Labs</span>{links}</nav>'
    return f'<nav class="product-navigation" aria-label="Labs sections">{links}</nav>'


def render_portfolio_navigation(active: str, *, mobile: bool) -> str:
    links = "".join(
        f'<a href="{href}"{attributes(key == active)}>{label}</a>'
        for key, label, href in PORTFOLIO_NAVIGATION
    )
    if mobile:
        return f'<nav class="mobile-portfolio-navigation" aria-label="HECAVEX projects"><span class="navigation-label">HECAVEX network</span>{links}</nav>'
    return f'<nav class="portfolio-navigation" aria-label="HECAVEX projects">{links}</nav>'


def render_utility(route: Route, *, mobile: bool) -> str:
    if route.utility == "link":
        class_name = "mobile-header-utility" if mobile else "header-utility"
        return f'<a class="{class_name}" href="{route.utility_href}">{route.utility_text}</a>'

    suffix = "mobile" if mobile else "desktop"
    class_name = "mobile-header-search" if mobile else "header-search"
    return (
        f'<form class="{class_name}" action="/" role="search">'
        f'<label class="sr-only" for="global-q-{suffix}">{route.utility_label}</label>'
        '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>'
        f'<input id="global-q-{suffix}" name="q" type="search" placeholder="{route.utility_placeholder}" autocomplete="off" data-shell-search>'
        '</form>'
    )


def render_header(route: Route) -> str:
    desktop_portfolio = render_portfolio_navigation(route.portfolio_active, mobile=False)
    mobile_portfolio = render_portfolio_navigation(route.portfolio_active, mobile=True)
    desktop_local = render_local_navigation(route.active, mobile=False)
    mobile_local = render_local_navigation(route.active, mobile=True)
    desktop_utility = render_utility(route, mobile=False)
    mobile_utility = render_utility(route, mobile=True)
    return f'''<header class="site-header" data-portfolio-shell="v1">
    <div class="network-bar">
      <a class="brand" href="https://hecavex.com/en/" aria-label="HECAVEX Research">
        <img src="/assets/hecavex-mark.svg" alt="" width="36" height="36">
        <span class="brand-copy"><strong>HECAVEX</strong><small>Labs / open CTI workspaces</small></span>
      </a>
      {desktop_portfolio}
      <details class="mobile-navigation" data-mobile-navigation>
        <summary aria-label="Open navigation menu">
          <svg class="menu-open-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
          <svg class="menu-close-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>
          <span>Menu</span>
        </summary>
        <div class="mobile-navigation-panel">
          {mobile_local}
          <div class="mobile-navigation-utility">{mobile_utility}</div>
          {mobile_portfolio}
        </div>
      </details>
    </div>
    <div class="product-bar">
      <a class="product-identity" href="/"><strong>Labs</strong><span>Open CTI workspaces</span></a>
      {desktop_local}
      {desktop_utility}
    </div>
  </header>'''


def render_footer() -> str:
    return '''<footer class="site-footer">
    <div class="footer-inner">
      <div class="footer-brand"><strong>HECAVEX LABS</strong><span>Inspectable public CTI workspaces by <a href="https://hecavex.com/en/">HECAVEX</a>.</span></div>
      <nav aria-label="Footer"><a href="https://hecavex.com/en/research/">Research</a><a href="https://radar.hecavex.com/">Radar</a><a href="https://apt.hecavex.com/">APT Notes</a><a href="https://labs.hecavex.com/">Labs</a><a href="https://hecavex.com/data/">Data</a><a href="/changes/">Changes</a><a href="/methodology/">Methodology</a><a href="/about/">About</a><a href="/licence/">Licence</a><a href="https://hecavex.com/en/privacy/">Privacy</a><a href="/security/">Security</a></nav>
    </div>
  </footer>'''


def transform(text: str, route: Route) -> str:
    header_matches = HEADER_RE.findall(text)
    footer_matches = FOOTER_RE.findall(text)
    if len(header_matches) != 1 or len(footer_matches) != 1:
        raise ValueError(
            f"{route.path}: expected one site header and one site footer; "
            f"found {len(header_matches)} header(s), {len(footer_matches)} footer(s)"
        )
    text = HEADER_RE.sub(render_header(route), text, count=1)
    return FOOTER_RE.sub(render_footer(), text, count=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail if a page shell is stale")
    mode.add_argument("--write", action="store_true", help="synchronize every page shell")
    args = parser.parse_args()

    stale: list[str] = []
    for route in ROUTES:
        path = ROOT / route.path
        original = path.read_text(encoding="utf-8")
        rendered = transform(original, route)
        if rendered == original:
            continue
        stale.append(route.path)
        if args.write:
            path.write_text(rendered, encoding="utf-8", newline="\n")

    if stale and args.check:
        print("Stale Labs portfolio shell: " + ", ".join(stale), file=sys.stderr)
        print("Run: python scripts/sync_shell.py --write", file=sys.stderr)
        return 1
    if args.write:
        print(f"Synchronized Labs portfolio shell across {len(ROUTES)} routes ({len(stale)} updated).")
    else:
        print(f"Labs portfolio shell is current across {len(ROUTES)} routes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
