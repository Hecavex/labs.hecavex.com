"""Canonical public-route and navigation contract for HECAVEX Labs.

The static pages, shared shell, sitemap and validation all consume this file.
Keeping the route metadata here prevents a page from being published in one
surface while silently disappearing from another.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    path: str
    public_path: str
    active: str | None
    utility: str
    utility_label: str = ""
    utility_placeholder: str = ""
    utility_href: str = ""
    utility_text: str = ""
    portfolio_active: str = "labs"
    sitemap_lastmod: str | None = None

    @property
    def canonical_url(self) -> str:
        return f"https://labs.hecavex.com{self.public_path}"


ROUTES = (
    Route("index.html", "/", "overview", "search", "Filter Labs workspaces", "Filter", sitemap_lastmod="2026-09-01"),
    Route("baltic-threat-atlas/index.html", "/baltic-threat-atlas/", "atlas", "search", "Search Baltic Threat Atlas", "Search", sitemap_lastmod="2026-09-01"),
    Route("pivot-graph/index.html", "/pivot-graph/", "pivots", "search", "Search case claims", "Search", sitemap_lastmod="2026-09-01"),
    Route("attack-map/index.html", "/attack-map/", "attack", "search", "Search actors or techniques", "Search", sitemap_lastmod="2026-09-01"),
    Route("osint-workbench/index.html", "/osint-workbench/", None, "link", utility_href="/data/osint/resources.json", utility_text="Archive JSON", sitemap_lastmod="2026-08-26"),
    Route("data/index.html", "/data/", None, "link", utility_href="/data/catalogue.json", utility_text="Catalogue JSON"),
    Route("changes/index.html", "/changes/", "changes", "link", utility_href="/changes/feed.json", utility_text="JSON feed", sitemap_lastmod="2026-09-01"),
    Route("methodology/index.html", "/methodology/", "methodology", "link", utility_href="https://github.com/Hecavex/labs.hecavex.com", utility_text="Source", sitemap_lastmod="2026-08-26"),
    Route("about/index.html", "/about/", "about", "link", utility_href="https://github.com/Hecavex/labs.hecavex.com", utility_text="Source", sitemap_lastmod="2026-08-26"),
    Route("licence/index.html", "/licence/", None, "link", utility_href="/methodology/", utility_text="Methodology", sitemap_lastmod="2026-08-26"),
    Route("security/index.html", "/security/", None, "link", utility_href="/.well-known/security.txt", utility_text="security.txt", sitemap_lastmod="2026-08-26"),
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
