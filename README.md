# HECAVEX Labs

This repository is the publication source for [labs.hecavex.com](https://labs.hecavex.com/), the HECAVEX collection of small, inspectable cyber-threat-intelligence workspaces and public datasets.

The canonical product is the deployed website. This repository is public to make its evidence boundaries, transformations and publication controls inspectable; it is not maintained as a starter kit, distributable application or supported self-hosting package.

HECAVEX Labs is maintained on a best-effort basis by Deividas Lis / HECAVEX. It provides neither comprehensive monitoring nor an operational, notification, response or support SLA.

## Published workspaces

- [Baltic Threat Atlas](https://labs.hecavex.com/baltic-threat-atlas/) presents selected, source-linked public observations concerning Lithuania, Latvia and Estonia alongside a separately labelled Europe-context actor index. Baltic links appear only where an explicit observation supports them.
- [Pivot Workspace](https://labs.hecavex.com/pivot-graph/) separates observations, reproducible derivations, analytical assessments and limitations across selected HECAVEX investigations.
- [ATT&CK Evidence](https://labs.hecavex.com/attack-map/) exposes source-backed behavior mappings generated from reviewed APT Notes evidence. It supports filters, bounded comparisons and selected exports without claiming defensive coverage.
- [HECAVEX Data](https://hecavex.com/data/) records portfolio-wide public datasets, update state, provenance and reuse boundaries. Labs continues to host its established machine-readable distributions under `/data/`.

The former generic [OSINT directory](https://labs.hecavex.com/osint-workbench/) is retained as a dated archive, not advertised as a maintained product. The [changes journal](https://labs.hecavex.com/changes/), [methodology and limitations](https://labs.hecavex.com/methodology/), [about page](https://labs.hecavex.com/about/), [licensing boundary](https://labs.hecavex.com/licence/) and [security policy](https://labs.hecavex.com/security/) are part of the published service.

## Repository role

The site is purpose-built static HTML, CSS and browser JavaScript. It shares the Cold Signal portfolio shell with the other HECAVEX properties, uses self-hosted Inter and IBM Plex Mono fonts, and does not depend on a remote font or icon service.

Production staging enables one Do Not Track-aware Cloudflare Web Analytics loader on each HTML page. Source pages and pull-request checks remain keyless; the Pages gate supplies the public site token and verifies the staged artifact without printing it. The published methodology describes that boundary and links to the portfolio privacy policy.

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

- `data/atlas/` for selected Baltic observations and explicitly bounded Europe-context actors;
- `data/pivots/` for HECAVEX case graphs;
- `data/attack/intelligence/reviewed-evidence.json` for source-linked HECAVEX evidence generated from APT Notes;
- `data/osint/` for the frozen resource snapshot retained by the archived compatibility page.

`scripts/build_reviewed_attack_evidence.py` rebuilds the public ATT&CK evidence layer from the APT Notes release when that checkout is available and validates the frozen public copy in isolated CI. Generic ATT&CK mirrors, browser-local coverage scoring, detection packages, incident authoring and the old guide are not part of the public product.

## Validation and deployment

Every pull request and push to `main` runs the publication checks in `.github/workflows/pages.yml`. The workflow:

1. verifies that the shared portfolio shell is synchronized across every route;
2. validates the APT Notes-derived ATT&CK evidence contract and rejects uncommitted generated changes;
3. validates links, metadata, structured data, dataset schemas, font provenance and the public-data allowlist;
4. enforces deterministic raw and compressed performance budgets;
5. stages only the approved public site and deploys it to GitHub Pages after a successful build.

The validation entry points are `scripts/sync_shell.py`, `scripts/validate.py` and `scripts/audit_performance.py`.

Production is served through the custom domain declared in `CNAME`. GitHub Pages must remain configured to use GitHub Actions as its source; direct branch publishing would bypass the staging allowlist.

## Corrections, security and rights

Corrections should identify the affected page or record and include supporting evidence. They can be sent through the [HECAVEX contact channel](https://hecavex.com/en/contact/). Website vulnerabilities or accidental publication should follow the [Labs security policy](https://labs.hecavex.com/security/); sensitive material must not be posted in a public issue.

HECAVEX-authored software is covered by the [MIT License](LICENSE). Original HECAVEX data is CC BY 4.0 only where the [data licensing and attribution notice](DATA-LICENSE.md) says so. MITRE ATT&CK records, cited publications, trademarks and external services retain their respective terms. The public [licensing page](https://labs.hecavex.com/licence/) is the human-readable summary of that boundary.
