#!/usr/bin/env python3
"""Browser-level responsive, navigation and focus checks for public Labs pages."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "test-results" / "responsive.json"
VISUAL_RESULTS = ROOT / "test-results" / "visual"
WIDTHS = (320, 360, 390, 768, 1024, 1160, 1161, 1440, 1600)
HEIGHT = 900
ROUTES = (
    "/",
    "/baltic-threat-atlas/",
    "/pivot-graph/",
    "/attack-map/",
    "/attack-map/guide/",
    "/osint-workbench/",
    "/data/",
    "/methodology/",
    "/licence/",
    "/security/",
)
WORKSPACE_SUMMARIES = {
    "/baltic-threat-atlas/": {"first_control": ".country-button", "max_control_y": 1240},
    "/pivot-graph/": {"first_control": ".case-card", "max_control_y": 1150},
    "/osint-workbench/": {"first_control": "#section-filter", "max_control_y": 1350},
}
NETWORK_LINKS = (
    "https://hecavex.com/en/research/",
    "https://radar.hecavex.com/",
    "https://apt.hecavex.com/",
    "https://labs.hecavex.com/",
    "https://labs.hecavex.com/data/",
)
ACCESSIBLE_NAME_AUDIT = """elements => elements.filter(element => {
  const style = getComputedStyle(element);
  const closedDetails = element.closest('details:not([open])');
  const hiddenByDetails = closedDetails && !element.matches('summary') && !element.closest('summary');
  if (style.display === 'none' || style.visibility === 'hidden' || !element.getClientRects().length || element.closest('[inert], [aria-hidden="true"]') || hiddenByDetails) return false;
  const labelledBy = (element.getAttribute('aria-labelledby') || '').split(/\\s+/).filter(Boolean).map(id => document.getElementById(id)?.textContent || '').join(' ');
  const explicitLabel = element.id ? document.querySelector(`label[for="${CSS.escape(element.id)}"]`)?.textContent || '' : '';
  const wrappedLabel = element.closest('label')?.textContent || '';
  const ariaLabel = element.getAttribute('aria-label');
  const name = ariaLabel !== null ? ariaLabel : labelledBy || explicitLabel || wrappedLabel || element.innerText || element.getAttribute('title') || element.querySelector('img')?.getAttribute('alt') || '';
  return !name.trim();
}).map(element => `${element.tagName.toLowerCase()}#${element.id || '(no-id)'}${element.className ? '.' + String(element.className).trim().replace(/\\s+/g, '.') : ''}[href=${element.getAttribute('href') || ''}]`)"""
FOCUS_INDICATOR_AUDIT = """element => {
  if (document.activeElement !== element) return false;
  const candidates = [element, element.parentElement, element.closest('form')].filter(Boolean);
  return candidates.some(candidate => {
    const style = getComputedStyle(candidate);
    const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) >= 2;
    const shadow = style.boxShadow && style.boxShadow !== 'none';
    return outline || shadow;
  });
}"""
SCROLL_CONTAINMENT_AUDIT = """() => {
  const problems = [];
  const selector = element => `${element.tagName.toLowerCase()}${element.id ? '#' + element.id : ''}${element.className && typeof element.className === 'string' ? '.' + element.className.trim().replace(/\\s+/g, '.') : ''}`;
  for (const container of document.querySelectorAll('.table-wrap, .attack-matrix-wrap, .phishing-flow, .journey-steps, pre')) {
    if (!container.getClientRects().length || container.scrollWidth <= container.clientWidth + 1) continue;
    if (!['auto', 'scroll'].includes(getComputedStyle(container).overflowX)) problems.push(`${selector(container)} does not contain horizontal scrolling`);
  }
  for (const table of document.querySelectorAll('table')) {
    if (!table.getClientRects().length) continue;
    const container = table.closest('.table-wrap, .attack-matrix-wrap');
    if (container && table.getBoundingClientRect().width > container.clientWidth + 1 && !['auto', 'scroll'].includes(getComputedStyle(container).overflowX)) problems.push(`${selector(table)} is clipped instead of scrolling`);
    if (!container && table.getBoundingClientRect().right > innerWidth + 1) problems.push(`${selector(table)} escapes the viewport without a scroll container`);
  }
  return problems;
}"""


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def assert_focus_visible(locator, context):
    locator.focus()
    assert locator.evaluate(FOCUS_INDICATOR_AUDIT), f"focus indicator missing: {context}"


handler = partial(QuietHandler, directory=ROOT)
server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base_url = f"http://127.0.0.1:{server.server_port}"
results = []

try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        for width in WIDTHS:
            page = browser.new_page(viewport={"width": width, "height": HEIGHT})
            page_errors = []
            page.on("pageerror", lambda error, bucket=page_errors: bucket.append(str(error)))
            for route in ROUTES:
                page.goto(base_url + route, wait_until="domcontentloaded")
                page.wait_for_timeout(100)
                first_control_y = None

                fonts_ready = page.evaluate("""async () => {
                  await Promise.all([document.fonts.load('400 16px Inter'), document.fonts.load('400 12px "IBM Plex Mono"')]);
                  await document.fonts.ready;
                  const faces = [...document.fonts];
                  return {
                    status: document.fonts.status,
                    inter: faces.some(face => face.family.replace(/[\"']/g, '') === 'Inter' && face.status === 'loaded'),
                    mono: faces.some(face => face.family.replace(/[\"']/g, '') === 'IBM Plex Mono' && face.status === 'loaded'),
                    body: getComputedStyle(document.body).fontFamily,
                    label: getComputedStyle(document.querySelector('.eyebrow')).fontFamily,
                  };
                }""")
                assert fonts_ready["status"] == "loaded" and fonts_ready["inter"] and fonts_ready["mono"], f"self-hosted fonts failed: {route} at {width}px: {fonts_ready}"
                assert "Inter" in fonts_ready["body"] and "IBM Plex Mono" in fonts_ready["label"], f"Cold Signal font roles differ: {route} at {width}px: {fonts_ready}"

                assert page.locator("h1").count() == 1, f"{route} at {width}px must have one h1"
                theme_colour = page.locator('meta[name="theme-color"]')
                assert theme_colour.count() == 1 and theme_colour.get_attribute("content").lower() == "#05080b", f"Cold Signal theme colour metadata differs: {route} at {width}px"
                assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), f"page overflow: {route} at {width}px"
                heading = page.locator("h1")
                heading_height = heading.bounding_box()["height"]
                assert heading_height < HEIGHT * 0.55, f"heading consumes the viewport: {route} at {width}px"
                heading_size = heading.evaluate("element => parseFloat(getComputedStyle(element).fontSize)")
                heading_limit = 64 if heading.locator("xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '), ' brand-hero ')]").count() else 56
                assert heading_size <= heading_limit + 0.1, f"heading exceeds the portfolio scale: {route} at {width}px ({heading_size}px > {heading_limit}px)"
                containment = page.evaluate(SCROLL_CONTAINMENT_AUDIT)
                assert not containment, f"wide content is not contained: {route} at {width}px: {containment}"

                site_header = page.locator('.site-header[data-portfolio-shell="v1"]')
                network_bar = page.locator(".network-bar")
                product_bar = page.locator(".product-bar")
                assert site_header.count() == 1, f"versioned portfolio shell missing: {route} at {width}px"
                assert abs(network_bar.bounding_box()["height"] - 64) <= 1, f"network row is not 64px: {route} at {width}px"
                assert network_bar.bounding_box()["width"] <= 1504.5, f"network shell exceeds 94rem: {route} at {width}px"
                mark_size = page.locator(".brand img").bounding_box()["width"]
                expected_mark_size = 34 if width <= 480 else 36
                assert abs(mark_size - expected_mark_size) <= 1, f"identity mark differs: {route} at {width}px ({mark_size}px)"
                if width <= 1160:
                    assert abs(site_header.bounding_box()["height"] - 64) <= 1, f"mobile header is not one 64px row: {route} at {width}px"
                    assert product_bar.is_hidden() and page.locator(".portfolio-navigation").is_hidden(), f"desktop shell remains visible at mobile collapse: {route} at {width}px"
                    assert page.locator(".mobile-navigation summary").is_visible(), f"mobile menu is unavailable: {route} at {width}px"
                else:
                    assert abs(product_bar.bounding_box()["height"] - 52) <= 1, f"product row is not 52px: {route} at {width}px"
                    assert 116 <= site_header.bounding_box()["height"] <= 120, f"desktop shell rows plus dividers exceed their geometry: {route} at {width}px"
                    assert page.locator(".portfolio-navigation").is_visible() and page.locator(".mobile-navigation").is_hidden(), f"desktop shell visibility differs: {route} at {width}px"

                hero = page.locator(".brand-hero, .page-head, .task-hero").first
                hero_box = hero.bounding_box()
                header_box = site_header.bounding_box()
                start_gap = hero_box["y"] - (header_box["y"] + header_box["height"])
                if width <= 1160:
                    assert 39 <= start_gap <= 57, f"mobile content start differs: {route} at {width}px ({start_gap}px)"
                else:
                    assert 63 <= start_gap <= 81, f"desktop content start differs: {route} at {width}px ({start_gap}px)"
                    if hero.evaluate("element => element.matches('.brand-hero, .page-head')"):
                        assert hero_box["height"] <= 430, f"hero exceeds 430px: {route} at {width}px ({hero_box['height']}px)"

                if route == "/" and width <= 650:
                    hero = page.locator(".brand-hero")
                    marker = hero.evaluate("element => ({ display: getComputedStyle(element, '::after').display, content: getComputedStyle(element, '::after').content })")
                    assert marker["display"] == "none" and marker["content"] == "none", f"decorative hero marker remains exposed on mobile at {width}px: {marker}"
                    meta_box = page.locator(".hero-meta").bounding_box()
                    hero_box = hero.bounding_box()
                    assert meta_box and hero_box, f"home hero metadata is not measurable at {width}px"
                    assert meta_box["x"] >= hero_box["x"] and meta_box["x"] + meta_box["width"] <= hero_box["x"] + hero_box["width"] + 1, f"home hero metadata escapes its panel at {width}px"
                    if width == 390:
                        VISUAL_RESULTS.mkdir(parents=True, exist_ok=True)
                        page.screenshot(path=str(VISUAL_RESULTS / "home-mobile.png"), full_page=True)
                elif route == "/" and width == 1440:
                    VISUAL_RESULTS.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(VISUAL_RESULTS / "home-desktop.png"), full_page=True)

                if route in WORKSPACE_SUMMARIES and width <= 480:
                    metric_grid = page.locator(".stat-grid")
                    metrics = metric_grid.locator(".stat")
                    assert metrics.count() == 4, f"workspace summary must retain four metrics: {route} at {width}px"
                    tracks = metric_grid.evaluate("element => getComputedStyle(element).gridTemplateColumns.split(/\\s+/).filter(Boolean)")
                    assert len(tracks) == 2, f"workspace summary must use two phone columns: {route} at {width}px: {tracks}"
                    positions = metrics.evaluate_all("elements => elements.map(element => { const box = element.getBoundingClientRect(); return { top: box.top, left: box.left }; })")
                    assert abs(positions[0]["top"] - positions[1]["top"]) <= 1, f"first metric row is not aligned: {route} at {width}px"
                    assert abs(positions[2]["top"] - positions[3]["top"]) <= 1, f"second metric row is not aligned: {route} at {width}px"
                    assert positions[2]["top"] > positions[0]["top"], f"workspace summary is not a 2x2 grid: {route} at {width}px"
                    summary = WORKSPACE_SUMMARIES[route]
                    first_control = page.locator(summary["first_control"]).first
                    first_control.wait_for(state="visible")
                    assert first_control.is_visible(), f"first operational control is missing: {route} at {width}px"
                    first_control_y = first_control.bounding_box()["y"]
                    assert first_control_y <= summary["max_control_y"], f"first operational control is too far below the fold: {route} at {width}px ({first_control_y:.1f}px)"

                assert_focus_visible(page.locator(".skip-link"), f"skip link on {route} at {width}px")
                page.locator(".skip-link").evaluate("element => element.blur()")
                unnamed = page.locator("a[href], button, summary, input:not([type=hidden]), select, textarea").evaluate_all(ACCESSIBLE_NAME_AUDIT)
                assert not unnamed, f"visible controls without accessible names: {route} at {width}px: {unnamed}"

                if width <= 1160:
                    menu = page.locator(".mobile-navigation summary")
                    assert menu.is_visible(), f"mobile menu missing: {route} at {width}px"
                    assert_focus_visible(menu, f"menu control on {route} at {width}px")
                    page.keyboard.press("Enter")
                    assert page.locator(".mobile-navigation").evaluate("element => element.open"), f"mobile menu did not open: {route} at {width}px"
                    page.wait_for_function("document.querySelector('.mobile-navigation summary')?.getAttribute('aria-label') === 'Close navigation menu'")
                    assert menu.get_attribute("aria-label") == "Close navigation menu", f"mobile menu state is not announced: {route} at {width}px"
                    assert page.locator(".mobile-navigation-panel").is_visible(), f"navigation hidden after opening: {route} at {width}px"
                    page.wait_for_timeout(50)
                    project_navigation = page.locator(".mobile-portfolio-navigation")
                else:
                    project_navigation = page.locator(".portfolio-navigation")

                links = project_navigation.locator("a").evaluate_all("links => links.map(link => link.href)")
                links = tuple(links)
                assert links == NETWORK_LINKS, f"project navigation differs: {route} at {width}px: {links}"
                expected_current = "https://labs.hecavex.com/data/" if route == "/data/" else "https://labs.hecavex.com/"
                current_links = tuple(project_navigation.locator('a[aria-current="page"]').evaluate_all("links => links.map(link => link.href)"))
                assert current_links == (expected_current,), f"portfolio current state differs: {route} at {width}px: {current_links}"
                assert_focus_visible(project_navigation.locator("a").first, f"project link on {route} at {width}px")
                footer_links = tuple(page.locator(".site-footer nav a").evaluate_all("links => links.slice(0, 5).map(link => link.href)"))
                assert footer_links == NETWORK_LINKS, f"footer project order differs: {route} at {width}px: {footer_links}"

                if width <= 1160:
                    page.keyboard.press("Escape")
                    assert not page.locator(".mobile-navigation").evaluate("element => element.open"), f"Escape did not close navigation: {route} at {width}px"
                    page.wait_for_function("document.querySelector('.mobile-navigation summary')?.getAttribute('aria-label') === 'Open navigation menu'")
                    assert menu.get_attribute("aria-label") == "Open navigation menu", f"closed mobile menu state is not announced: {route} at {width}px"
                    assert menu.evaluate("element => document.activeElement === element"), f"menu focus was not restored: {route} at {width}px"
                    assert menu.evaluate(FOCUS_INDICATOR_AUDIT), f"restored menu focus is invisible: {route} at {width}px"

                results.append({"route": route, "width": width, "overflow": False, "scroll_containment": "pass", "keyboard_navigation": "pass", "accessibility_names": "pass", "focus": "pass", "compact_metrics": "pass" if route in WORKSPACE_SUMMARIES and width <= 480 else "not-applicable", "first_operational_control_y": round(first_control_y, 1) if first_control_y is not None else None})

            assert not page_errors, f"browser errors at {width}px: {page_errors}"
            page.close()

        no_script_context = browser.new_context(viewport={"width": 390, "height": HEIGHT}, java_script_enabled=False)
        no_script_page = no_script_context.new_page()
        for route in ROUTES:
            no_script_page.goto(base_url + route, wait_until="domcontentloaded")
            menu = no_script_page.locator(".mobile-navigation summary")
            assert menu.is_visible(), f"native navigation control is unavailable without JavaScript: {route}"
            menu.click()
            assert no_script_page.locator(".mobile-navigation").evaluate("element => element.open"), f"native navigation cannot open without JavaScript: {route}"
            assert no_script_page.locator(".mobile-navigation-panel").is_visible(), f"navigation panel is unavailable without JavaScript: {route}"
            assert no_script_page.locator(".mobile-navigation-panel a[href]").count() >= 11, f"navigation fallback is incomplete: {route}"
            assert no_script_page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), f"no-JavaScript page overflow: {route}"
        no_script_context.close()
        browser.close()
finally:
    server.shutdown()
    server.server_close()

RESULTS.parent.mkdir(exist_ok=True)
RESULTS.write_text(json.dumps({"checked_widths": WIDTHS, "routes": ROUTES, "no_javascript_navigation": "pass", "results": results}, indent=2) + "\n", encoding="utf-8")
print(f"Responsive checks passed for {len(ROUTES)} routes at {len(WIDTHS)} widths plus no-JavaScript navigation; evidence: {RESULTS.relative_to(ROOT)}")
