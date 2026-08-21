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
WIDTHS = (320, 360, 390, 768, 1024)
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
PROJECT_LINKS = (
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


def normalise_project_link(value):
    if value.startswith("http://127.0.0.1:"):
        path = value.split("/", 3)[-1]
        return "https://labs.hecavex.com/" + path
    return value


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

                assert page.locator("h1").count() == 1, f"{route} at {width}px must have one h1"
                assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), f"page overflow: {route} at {width}px"
                heading_height = page.locator("h1").bounding_box()["height"]
                assert heading_height < HEIGHT * 0.55, f"heading consumes the viewport: {route} at {width}px"
                containment = page.evaluate(SCROLL_CONTAINMENT_AUDIT)
                assert not containment, f"wide content is not contained: {route} at {width}px: {containment}"

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

                if width <= 849:
                    menu = page.locator(".menu-toggle")
                    assert menu.is_visible(), f"mobile menu missing: {route} at {width}px"
                    assert_focus_visible(menu, f"menu control on {route} at {width}px")
                    page.keyboard.press("Enter")
                    assert menu.get_attribute("aria-expanded") == "true", f"mobile menu did not open: {route} at {width}px"
                    assert page.locator("#site-nav").is_visible(), f"navigation hidden after opening: {route} at {width}px"
                    page.wait_for_timeout(50)
                    close_button = page.locator(".mobile-nav-close")
                    assert close_button.evaluate("element => document.activeElement === element"), f"drawer did not receive focus: {route} at {width}px"
                    assert close_button.evaluate(FOCUS_INDICATOR_AUDIT), f"drawer close focus is invisible: {route} at {width}px"
                    page.keyboard.press("Shift+Tab")
                    assert page.evaluate("document.querySelector('#site-nav').contains(document.activeElement)"), f"drawer focus trap failed: {route} at {width}px"

                project_summary = page.locator(".edition-switcher summary")
                assert_focus_visible(project_summary, f"project switcher on {route} at {width}px")
                page.keyboard.press("Enter")
                assert page.locator(".edition-switcher").evaluate("element => element.open"), f"project switcher did not open by keyboard: {route} at {width}px"
                links = page.locator(".edition-menu a").evaluate_all("links => links.map(link => link.href)")
                links = tuple(normalise_project_link(value) for value in links)
                assert links == PROJECT_LINKS, f"project navigation differs: {route} at {width}px: {links}"
                current = page.locator('.edition-menu a[aria-current="true"]')
                assert current.count() == 1, f"project switcher must identify one current project: {route} at {width}px"
                assert_focus_visible(page.locator(".edition-menu a").first, f"project link on {route} at {width}px")
                unnamed = page.locator("#site-nav a[href], #site-nav button, #site-nav summary").evaluate_all(ACCESSIBLE_NAME_AUDIT)
                assert not unnamed, f"open navigation controls without accessible names: {route} at {width}px: {unnamed}"

                if width <= 849:
                    page.keyboard.press("Escape")
                    assert page.locator(".menu-toggle").get_attribute("aria-expanded") == "false", f"Escape did not close navigation: {route} at {width}px"
                    assert page.locator(".menu-toggle").evaluate("element => document.activeElement === element"), f"menu focus was not restored: {route} at {width}px"
                    assert page.locator(".menu-toggle").evaluate(FOCUS_INDICATOR_AUDIT), f"restored menu focus is invisible: {route} at {width}px"

                results.append({"route": route, "width": width, "overflow": False, "scroll_containment": "pass", "keyboard_navigation": "pass", "accessibility_names": "pass", "focus": "pass", "compact_metrics": "pass" if route in WORKSPACE_SUMMARIES and width <= 480 else "not-applicable", "first_operational_control_y": round(first_control_y, 1) if first_control_y is not None else None})

            assert not page_errors, f"browser errors at {width}px: {page_errors}"
            page.close()
        browser.close()
finally:
    server.shutdown()
    server.server_close()

RESULTS.parent.mkdir(exist_ok=True)
RESULTS.write_text(json.dumps({"checked_widths": WIDTHS, "routes": ROUTES, "results": results}, indent=2) + "\n", encoding="utf-8")
print(f"Responsive checks passed for {len(ROUTES)} routes at {len(WIDTHS)} widths; evidence: {RESULTS.relative_to(ROOT)}")
