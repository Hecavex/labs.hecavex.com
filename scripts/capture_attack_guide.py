#!/usr/bin/env python3
"""Capture the ATT&CK Workbench screenshots used by the first-use guide."""

import os
from pathlib import Path

from playwright.sync_api import sync_playwright


ROOT = os.environ.get("HECAVEX_CAPTURE_ROOT", "http://127.0.0.1:4174/attack-map/")
OUTPUT = Path(__file__).resolve().parent.parent / "assets" / "img" / "attack-workbench-guide"


def clear_marks(page):
    page.evaluate(
        """
        document.querySelectorAll('.capture-marker').forEach((node) => node.remove());
        document.querySelectorAll('.capture-target').forEach((node) => node.classList.remove('capture-target'));
        """
    )


def mark(page, targets):
    page.evaluate(
        """
        (targets) => {
          let style = document.querySelector('#capture-guide-style');
          if (!style) {
            style = document.createElement('style');
            style.id = 'capture-guide-style';
            style.textContent = `
              .capture-target { outline: 3px solid #44c7dc !important; outline-offset: 4px !important; }
              .capture-marker { position: fixed; z-index: 100000; display: grid; width: 36px; height: 36px;
                place-items: center; border: 3px solid #f2f8fb; border-radius: 50%; background: #44c7dc;
                color: #05080b; font: 800 17px/1 "IBM Plex Mono", monospace; box-shadow: 0 5px 18px rgb(0 0 0 / 70%); }
            `;
            document.head.append(style);
          }
          targets.forEach(({selector, number, anchor = 'top-right'}) => {
            const target = document.querySelector(selector);
            if (!target) throw new Error(`Capture target not found: ${selector}`);
            target.classList.add('capture-target');
            const rect = target.getBoundingClientRect();
            const marker = document.createElement('span');
            marker.className = 'capture-marker';
            marker.textContent = String(number);
            marker.setAttribute('aria-hidden', 'true');
            const x = anchor.includes('left') ? rect.left + 8 : anchor.includes('center') ? rect.left + rect.width / 2 : rect.right - 8;
            const y = anchor.includes('bottom') ? rect.bottom - 8 : anchor.includes('middle') ? rect.top + rect.height / 2 : rect.top + 8;
            marker.style.left = `${Math.max(8, Math.min(innerWidth - 44, x - 18))}px`;
            marker.style.top = `${Math.max(8, Math.min(innerHeight - 44, y - 18))}px`;
            document.body.append(marker);
          });
        }
        """,
        targets,
    )


def capture(page, name, focus, targets):
    clear_marks(page)
    page.locator(focus).evaluate("node => node.scrollIntoView({block: 'start', behavior: 'instant'})")
    page.evaluate("window.scrollBy(0, -72)")
    page.wait_for_timeout(250)
    mark(page, targets)
    page.screenshot(path=str(OUTPUT / name), full_page=False)


def new_page(browser):
    page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
    page.goto(ROOT, wait_until="networkidle")
    page.evaluate("document.documentElement.style.scrollBehavior = 'auto'")
    page.locator("#workspace-mode").wait_for(state="visible")
    page.locator("#workspace-mode").wait_for(state="attached")
    page.wait_for_function("!document.querySelector('#workspace-mode').disabled")
    return page


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        page = new_page(browser)
        capture(
            page,
            "01-choose-workflow.png",
            ".journey-picker",
            [
                {"selector": '[data-open-workflow="observation"]', "number": 1},
                {"selector": '[data-open-workflow="readiness"]', "number": 2},
                {"selector": '[data-open-workflow="intelligence"]', "number": 3},
            ],
        )
        page.close()

        page = new_page(browser)
        page.get_by_role("button", name="Smishing link").click()
        page.locator('[data-observation-stage="1"]').wait_for(state="visible")
        capture(
            page,
            "02-review-evidence-candidates.png",
            "#workbench",
            [
                {"selector": "#journey-steps li:nth-child(2)", "number": 1},
                {"selector": ".candidate-card:first-of-type", "number": 2},
                {"selector": ".candidate-card:first-of-type .candidate-actions", "number": 3},
            ],
        )
        page.close()

        page = new_page(browser)
        page.get_by_role("button", name="Assess defensive coverage", exact=False).click()
        page.get_by_role("button", name="02 Inspect telemetry", exact=False).click()
        page.locator(".readiness-card").first.wait_for(state="visible")
        capture(
            page,
            "03-assess-coverage.png",
            ".readiness-controls",
            [
                {"selector": "#readiness-focus", "number": 1, "anchor": "top-left"},
                {"selector": "#readiness-summary", "number": 2},
                {"selector": ".readiness-card:first-of-type", "number": 3},
                {"selector": ".readiness-card:first-of-type .button.small", "number": 4},
            ],
        )
        page.locator(".readiness-card:first-of-type .button.small").click()
        page.locator("#capability-editor").wait_for(state="visible")
        capture(
            page,
            "04-record-capability.png",
            "#capability-editor",
            [
                {"selector": "#capability-progress", "number": 1},
                {"selector": "#capability-telemetry", "number": 2, "anchor": "top-left"},
                {"selector": "#capability-sensors", "number": 3, "anchor": "top-left"},
                {"selector": "#capability-fields-required", "number": 4, "anchor": "top-left"},
            ],
        )
        page.close()

        page = new_page(browser)
        page.get_by_role("button", name="Explore threat intelligence", exact=False).click()
        page.locator("#group-search").fill("APT29")
        page.get_by_role("button", name="Inspect APT29 aliases, sources and techniques").wait_for(state="visible")
        page.locator(".group-card:first-of-type .group-description").evaluate("node => node.style.display = 'none'")
        capture(
            page,
            "05-find-threat-actor.png",
            ".group-directory-controls",
            [
                {"selector": "#group-search", "number": 1, "anchor": "top-left"},
                {"selector": ".group-card:first-of-type", "number": 2},
                {"selector": ".group-card:first-of-type .text-button", "number": 3},
            ],
        )
        page.get_by_role("button", name="Inspect APT29 aliases, sources and techniques").click()
        page.get_by_role("button", name="03 Review procedures").click()
        page.locator(".official-procedure").first.wait_for(state="visible")
        page.locator(".official-procedure").evaluate_all("nodes => nodes.forEach((node, index) => { if (index > 0) node.hidden = true; })")
        page.locator("#group-procedures > .load-more").evaluate("node => node.hidden = true")
        capture(
            page,
            "06-use-actor-procedures.png",
            "#group-procedures",
            [
                {"selector": "#group-procedures", "number": 1},
                {"selector": ".official-procedure:first-of-type", "number": 2},
                {"selector": ".official-procedure:first-of-type .inline-sources", "number": 3},
                {"selector": ".group-use .button.primary", "number": 4},
            ],
        )
        page.close()
        browser.close()

    print(f"Captured six guide screenshots in {OUTPUT}")


if __name__ == "__main__":
    main()
