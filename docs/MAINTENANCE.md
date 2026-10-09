# Labs maintenance

Maintainer guide for this operated HECAVEX publication. [The repository README](../README.md) is the product entrypoint. Detailed field or legal rules stay in their existing owning documents.

## Local preparation and checks

The site source needs no application server or package installation. Serve a staged site over loopback for browser validation; the Pages workflow records the exact upstream checkout, projection, source validation, staging, CSP, interaction and release steps. Start feature changes from [CODEMAP.md](CODEMAP.md). Source preview is useful for layout, but export provenance is verified only after staging.

## Source-linked evidence handoff

The ATT&CK explorer exports the current filtered records, independently of the actor comparison panel. JSON retains every public record field and source snapshot metadata. CSV keeps its existing display columns and appends exact IDs, provenance, lossless `record_json`, `source_metadata_json` and build context. Formula-sensitive display cells are apostrophe-prefixed. Parse the JSON cells for original values.

The Markdown evidence brief is a readable subset, not a comprehensive actor profile, detection rule or defensive coverage measure. It distinguishes the frozen dataset release, pinned APT build revision, source SHA-256, actual recorded review dates and export time. Staging injects non-executable context from `scripts/upstream-release.json`, without changing the evidence dataset. The browser verifies the downloaded source hash before enabling the handoff. Unstaged previews retain browsing and canonical JSON access but cannot claim verified export provenance.

Regression gates: `node scripts/test_evidence_export.js`, `python scripts/test_evidence_context.py`, and the served-release browser smoke at 320/1440 pixels.

This repository is the publication source for [labs.hecavex.com](https://labs.hecavex.com/), the HECAVEX collection of small, inspectable cyber-threat-intelligence workspaces and public datasets.

The canonical product is the deployed website. This repository is public to make its evidence boundaries, transformations and publication controls inspectable; it is not maintained as a starter kit, distributable application or supported self-hosting package.

HECAVEX Labs is maintained on a best-effort basis by Deividas Lis / HECAVEX. It provides neither comprehensive monitoring nor an operational, notification, response or support SLA.

## Data and editorial maintenance

Curated changes should preserve source URLs, dates, review state, confidence or status language, and explicit limitations. Observations, derivations and analytical assessments remain separate record types. Technical similarity, a common ATT&CK technique or shared infrastructure does not independently establish attribution.

Private pivot proposals stay outside this public repository. Exclusion from the Pages staging copy list does not make a tracked GitHub file private. After actual owner approval, promote only sanitized data: update the graph and catalogue record together with the exact public manifest, metadata/counts and normal publication checks. Record `publication_approved: true` and the actual approval date; do not change approval values merely to make a preview or validator pass.

The AI tooling case is approved for publication on 2026-10-09. Its graph links the canonical English and Lithuanian investigation and published sanitized support. The fixed 174-byte replay is a bounded constant relation, not a complete sample reproduction. Five independently checked original source pairings remain separate from 539 independently recomputed arithmetic outputs. Run `python scripts/test_ai_tooling_pivot.py` before the unchanged staged release gate. Original samples, withheld candidates and private research receipts are excluded.

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
