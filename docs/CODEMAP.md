# Labs source map

Use the responsibility below to find a change's source. Do not edit a deployed artifact or turn a UI change into a dataset revision.

## Pages and interface

| Responsibility | Source | Contract / check |
| --- | --- | --- |
| EN / LT workspace discovery | `index.html`, `lt/index.html`, `assets/workspace-discovery.css` | `scripts/smoke_workspace_discovery.mjs` checks layout, filters, empty recovery, local query privacy, keyboard and no-JS access |
| Shared palette, type, shell and general analytical UI | `assets/styles.css` | `scripts/validate.py` checks the coordinated design tokens; `scripts/audit_performance.py` enforces transfer budgets |
| Self-hosted font subsets and provenance | `assets/fonts.css`, `assets/fonts/README.md` | Font loading is explicit in the generated shell; every expected binary must be referenced locally and accompanied by its license |
| Generated navigation / footer / asset version | `scripts/site_contract.py`, `scripts/sync_shell.py` | Edit the generator, then `python scripts/sync_shell.py --write`; `--check` rejects drift across all routes |
| Browser navigation, shell search and copied views | `assets/site.js` | `updateWorkspaceFeedback` owns only overview state; `bindShellSearch` hands dataset filtering to the responsible workspace. `scripts/test_copied_view.js` preserves opt-in sharing |
| Atlas records and observation permalinks | `baltic-threat-atlas/index.html`, `assets/atlas.js` | `scripts/test_atlas_initial_query.js`, served-release smoke; source metadata and unknown actor links must remain explicit |
| Pivot selection, evidence graph and claim drawer | `pivot-graph/index.html`, `assets/pivot-graph.js` | `scripts/test_pivot_race.js`; latest selected case wins, claim type and reproduction limits stay attached |
| ATT&CK evidence / filters / comparisons | `attack-map/index.html`, `assets/attack-map.js`, `assets/attack-evidence.css` | `scripts/smoke-release.mjs`; comparisons never silently change export selection |
| Evidence handoff serialization | `assets/evidence-export.js` | `scripts/test_evidence_export.js`; CSV retains lossless JSON and spreadsheet-safe display fields |
| Synthetic analytical exercise | `assets/analytical-exercise.js`, `data/attack/exercises/source-to-hypothesis.json` | `scripts/test_analytical_exercise.js`; fixture is fictional, not telemetry or a detection rule |
| Methodology / changes / rights | Named route `index.html` files and `changes/feed.json` | HTML/feed IDs and dates must agree; claims and legal boundaries must not be rewritten for a visual change |

## Data and release boundary

- `data/public-manifest.json` is the exact public-data allowlist. `scripts/stage_public_data.py` stages only its entries and injects non-executable evidence context.
- `scripts/upstream-release.json` pins the approved APT source. The generators and `scripts/check_upstream_contract.py` enforce reproducibility. A new visual release does not require changing the analytical pin.
- `scripts/validate.py`, `scripts/test_provenance.py` and `scripts/test_analytical_contract.py` preserve schema, source wording, provenance and analytical limitations.
- `.github/workflows/pages.yml` validates, stages, tests CSP and interactive data, creates a release manifest, deploys, then verifies the live revision and artifact hashes.
- `scripts/release.mjs` verifies publication. `scripts/smoke-release.mjs` tests the served data interactions; `scripts/smoke_workspace_discovery.mjs` isolates the overview/portfolio geometry checks.

## September 2026 design decision

The owner retained the HECAVEX logo and teal identity, asked for a substantial layout/type redesign and selected research first. Labs keeps the coordinated 94rem shell, 64px network row, 52px product row and 1160px mobile collapse. The updated system uses self-hosted Space Grotesk headings, 16px Inter reading text, 12px minimum interface metadata, and IBM Plex Mono for technical identifiers. Heroes are open, content-aligned compositions with a 320px desktop minimum, natural mobile height and no decorative top stripe. Workspace previews show actual scope and limitations, not invented telemetry or generic AI images.

Overview styles are a separate route-specific module. Font declarations are isolated from the shared tokens/layout skin, and evidence-specific styles stay with the evidence explorer. `scripts/browser_support.mjs` supplies one shared temporary loopback server and browser launcher to both browser suites. The static HTML architecture, stable routes, native no-JS navigation, exports and source data remain intact.
