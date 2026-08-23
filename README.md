# HECAVEX Labs

This repository is the publication source for [labs.hecavex.com](https://labs.hecavex.com/), the HECAVEX collection of small, inspectable cyber-threat-intelligence workspaces and public datasets.

The canonical product is the deployed website. This repository is public to make its evidence boundaries, transformations and publication controls inspectable; it is not maintained as a starter kit, distributable application or supported self-hosting package.

HECAVEX Labs is maintained on a best-effort basis by Deividas Lis / HECAVEX. It provides neither comprehensive monitoring nor an operational, notification, response or support SLA.

## Published workspaces

- [Baltic Threat Atlas](https://labs.hecavex.com/baltic-threat-atlas/) presents selected, source-linked public observations concerning Lithuania, Latvia and Estonia. Links to APT Notes appear only where the evidence supports them.
- [Pivot Workspace](https://labs.hecavex.com/pivot-graph/) separates observations, reproducible derivations, analytical assessments and limitations across selected HECAVEX investigations.
- [ATT&CK Operations Workbench](https://labs.hecavex.com/attack-map/) supports evidence triage, defensive-capability assessment and source-aware actor research. Browser-local workspaces are not uploaded to HECAVEX.
- [ATT&CK first-use guide](https://labs.hecavex.com/attack-map/guide/) documents the workbench's status model and analytical boundaries using captures from the published interface.
- [OSINT Workbench](https://labs.hecavex.com/osint-workbench/) is an annotated selection of public tools with use cases and evidential cautions.
- [Data catalogue](https://labs.hecavex.com/data/) records the public datasets, update state, provenance and reuse boundary.

The [methodology and limitations](https://labs.hecavex.com/methodology/), [licensing boundary](https://labs.hecavex.com/licence/) and [security policy](https://labs.hecavex.com/security/) are part of the published service and should be read alongside the interfaces.

## Repository role

The site is purpose-built static HTML, CSS and browser JavaScript. It shares the Cold Signal portfolio shell with the other HECAVEX properties, uses self-hosted Inter and IBM Plex Mono fonts, and does not depend on a remote font or icon service.

Production staging enables one Do Not Track-aware Cloudflare Web Analytics loader on each HTML page. The source pages and pull-request checks remain keyless; the Pages gate supplies the public site token and verifies the staged artifact without printing it. Analytics does not read the ATT&amp;CK workbench's browser-local readiness, incident or observation records. The published methodology describes that boundary and links to the portfolio privacy policy.

Files in this repository fall into four operational groups:

| Area | Purpose |
| --- | --- |
| Public routes and `assets/` | The interface delivered at `labs.hecavex.com` |
| `data/` | Deliberately published source, generated and curated datasets |
| `scripts/` | Maintainer tooling for generation, shell synchronisation, publication staging and validation |
| `.github/workflows/pages.yml` | The reviewed build and GitHub Pages deployment path |

Private notes, submissions, credentials, victim data, malware samples and quarantined observations do not belong in this repository. A file committed under `data/` is not automatically public: `data/public-manifest.json` is the exact publication allowlist, and deployment rejects or omits material outside that boundary.

## Data and editorial maintenance

Curated changes should preserve source URLs, dates, review state, confidence or status language, and explicit limitations. Observations, derivations and analytical assessments remain separate record types. Technical similarity, a common ATT&CK technique or shared infrastructure does not independently establish attribution.

The principal maintained data areas are:

- `data/atlas/` for selected Baltic observations;
- `data/pivots/` for HECAVEX case graphs;
- `data/osint/` for the annotated resource catalogue;
- `data/attack/catalogue/` and `data/attack/intelligence/official-actor-procedures.json` for generated MITRE ATT&CK reference material;
- `data/attack/intelligence/reviewed-evidence.json` for the smaller HECAVEX-reviewed evidence layer;
- `data/attack/operations/`, `data/attack/detections/` and `data/attack/governance/` for curated operational guidance, engineering packages and lifecycle metadata.

`scripts/update_attack_catalog.py` refreshes the compact official catalogue from MITRE's Enterprise ATT&CK STIX bundle. `scripts/build_attack_content.py` materialises the dependent public layers, and CI fails if running that build changes committed ATT&CK output. Guide captures are maintained through `scripts/capture_attack_guide.py`; their source images remain part of the published guide and are not decorative repository screenshots.

Detection packages are reference material, not claims of deployed coverage. Candidate packages still require local schemas, testing, tuning, ownership and lifecycle controls before operational use.

## Validation and deployment

Every pull request and push to `main` runs the publication checks in `.github/workflows/pages.yml`. The workflow:

1. verifies that the shared portfolio shell is synchronized across every route;
2. rebuilds ATT&CK-derived content and rejects uncommitted generated changes;
3. validates links, metadata, structured data, dataset schemas, font provenance and the public-data allowlist;
4. enforces deterministic raw and compressed performance budgets;
5. checks browser layout, keyboard operation, focus visibility, no-JavaScript navigation and overflow from 320 through 1600 pixels;
6. stages only the approved public site and deploys it to GitHub Pages after a successful build.

The validation entry points are `scripts/sync_shell.py`, `scripts/validate.py`, `scripts/audit_performance.py` and `scripts/test_responsive.py`. `requirements-checks.txt` is limited to the browser tooling required by that CI gate. Generated validation evidence is retained by GitHub Actions and is intentionally excluded from the repository.

Production is served through the custom domain declared in `CNAME`. GitHub Pages must remain configured to use GitHub Actions as its source; direct branch publishing would bypass the staging allowlist.

## Corrections, security and rights

Corrections should identify the affected page or record and include supporting evidence. They can be sent through the [HECAVEX contact channel](https://hecavex.com/en/contact/). Website vulnerabilities or accidental publication should follow the [Labs security policy](https://labs.hecavex.com/security/); sensitive material must not be posted in a public issue.

HECAVEX-authored software is covered by the [MIT License](LICENSE). Original HECAVEX data is CC BY 4.0 only where the [data licensing and attribution notice](DATA-LICENSE.md) says so. MITRE ATT&CK records, cited publications, trademarks and external services retain their respective terms. The public [licensing page](https://labs.hecavex.com/licence/) is the human-readable summary of that boundary.
