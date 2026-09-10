# HECAVEX Labs

## Source-linked evidence handoff

The ATT&CK explorer exports the current filtered records, independently of the actor comparison panel. JSON retains every public record field and source snapshot metadata. CSV keeps its existing display columns and appends exact IDs, provenance, lossless `record_json`, `source_metadata_json` and build context. Formula-sensitive display cells are apostrophe-prefixed. Parse the JSON cells for original values.

The Markdown evidence brief is a readable subset, not a comprehensive actor profile, detection rule or defensive coverage measure. It distinguishes the frozen dataset release, pinned APT build revision, source SHA-256, actual recorded review dates and export time. Staging injects non-executable context from `scripts/upstream-release.json`, without changing the evidence dataset. The browser verifies the downloaded source hash before enabling the handoff. Unstaged previews retain browsing and canonical JSON access but cannot claim verified export provenance.

Regression gates: `node scripts/test_evidence_export.js`, `python scripts/test_evidence_context.py`, and the served-release browser smoke at 320/1440 pixels.

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

The site is purpose-built static HTML, CSS and browser JavaScript. It shares the HECAVEX operational portfolio shell with the other HECAVEX properties, uses self-hosted Inter and IBM Plex Mono fonts, and does not depend on a remote font or icon service.

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

`scripts/build_reviewed_attack_evidence.py` rebuilds the public ATT&CK evidence layer from the APT Notes release. CI checks out the exact source revision declared in `scripts/upstream-release.json`, builds it, and requires both projection parity and the catalogue/framework contract. A new upstream release requires a reviewed proposal, not automatic new analytical claims. Generic ATT&CK mirrors, browser-local coverage scoring, detection packages, incident authoring and the old guide are not part of the public product.

The `/lt/` overview and `/lt/metodika/` route provide bounded Lithuanian access summaries. Canonical workspaces and evidence remain English and retain stable IDs. Atlas records declare period precision, source metadata and claim-review gaps without inventing historical dates. A source locator check is distinct from a substantive analytical review.

Atlas and ATT&CK expose an explicit "Copy filtered view" action. Search text stays local during normal use and is included in a share link only when requested. The fragment preserves filters without sending the text in the HTTP request. Recipients can still read the shared search text, so users must review links before sharing.

Each Atlas observation also has a stable-ID permalink. A direct observation link is resolved after the dataset loads, visibly clears conflicting filters and focuses the exact record with its source, period precision and review limitations intact. Browser Back restores a locally filtered view when a permalink was opened from it. Unknown IDs are reported, never guessed or substituted. Without JavaScript, the source JSON and published research remain the explicit fallback.

## Validation and deployment

Every pull request and push to `main` runs the publication checks in `.github/workflows/pages.yml`. The workflow:

1. verifies that the shared portfolio shell is synchronized across every route;
2. validates the APT Notes-derived ATT&CK evidence contract and rejects uncommitted generated changes;
3. validates links, metadata, structured data, dataset schemas, font provenance and the public-data allowlist;
4. enforces deterministic raw and compressed performance budgets;
5. stages only the approved public site and deploys it to GitHub Pages after a successful build.

The validation entry points are `scripts/sync_shell.py`, `scripts/validate.py` and `scripts/audit_performance.py`.

`scripts/audit_external_links.py` performs the separate remote-destination review. A weekly GitHub workflow publishes its JSON report and warnings without blocking deployment for rate limits, bot protection or transient network failures; only a maintainer-invoked `--strict` run treats confirmed HTTP 404/410 responses as failures.

Production is served through the custom domain declared in `CNAME`. GitHub Pages must remain configured to use GitHub Actions as its source; direct branch publishing would bypass the staging allowlist.

## Corrections, security and rights

Corrections should identify the affected page or record and include supporting evidence. They can be sent through the [HECAVEX contact channel](https://hecavex.com/en/contact/). Website vulnerabilities or accidental publication should follow the [Labs security policy](https://labs.hecavex.com/security/); sensitive material must not be posted in a public issue.

HECAVEX-authored software is covered by the [MIT License](LICENSE). Original HECAVEX data is CC BY 4.0 only where the [data licensing and attribution notice](DATA-LICENSE.md) says so. MITRE ATT&CK records, cited publications, trademarks and external services retain their respective terms. The public [licensing page](https://labs.hecavex.com/licence/) is the human-readable summary of that boundary.
