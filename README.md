# HECAVEX Labs

Source for [labs.hecavex.com](https://labs.hecavex.com/), a collection of inspectable cyber threat intelligence workspaces and bounded public datasets. Static HTML, CSS and browser JavaScript make evidence and transformations accessible without an account.

## Read and explore

- [Baltic Threat Atlas](https://labs.hecavex.com/baltic-threat-atlas/): selected Baltic observations and a separately labelled Europe-context actor index.
- [Pivot Workspace](https://labs.hecavex.com/pivot-graph/): observations, reproducible derivations, assessments and limitations from selected investigations.
- [ATT&CK Evidence](https://labs.hecavex.com/attack-map/): reviewed, source-backed behavior records with filters, comparisons and explicit exports.
- [Lietuviškai](https://labs.hecavex.com/lt/): Lithuanian orientation to the canonical English workspaces.
- [Changes](https://labs.hecavex.com/changes/), [methodology](https://labs.hecavex.com/methodology/) and [public data catalogue](https://hecavex.com/data/): release state, limits and reuse.

## Find and change the source

Start with [the code map](docs/CODEMAP.md). Route HTML and `assets/` own presentation; `data/` holds deliberately published records; `scripts/` owns shell generation, reviewed projections, staging and validation.

| Task | Authoritative guide |
| --- | --- |
| Local preview, release checks, staging and upstream evidence | [Maintenance](docs/MAINTENANCE.md) |
| Interface, data ownership and focused regressions | [Code map](docs/CODEMAP.md) |
| Publication allowlist | `data/public-manifest.json` |
| Exact APT source revision | `scripts/upstream-release.json` |
| Rights and attribution | [Data licence](DATA-LICENSE.md) and [published summary](https://labs.hecavex.com/licence/) |

Begin with `python scripts/sync_shell.py --check`, `python scripts/validate.py` and `python scripts/audit_performance.py`; the complete staged release gate is [the Pages workflow](.github/workflows/pages.yml). Source pages alone cannot claim a verified export provenance; staging supplies the exact context before CSP and release checks.

## Evidence, privacy and service boundaries

Observations, derivations and assessments remain distinct. Shared infrastructure or an ATT&CK mapping alone does not establish attribution or defensive coverage. Search stays local; a shared filter link includes search text only after explicit copying. Preserve unknown dates and review gaps.

The website is maintained on a best-effort basis by Deividas Lis / HECAVEX with no monitoring, response or support SLA. The former [OSINT directory](https://labs.hecavex.com/osint-workbench/) remains a dated archive. A committed data file is not automatically deployable: the exact default-deny publication manifest controls staging.

Original software is [MIT](LICENSE). Original data is CC BY 4.0 only where [DATA-LICENSE.md](DATA-LICENSE.md) says so; MITRE, cited works, fonts and third-party material keep their terms. [Font provenance](assets/fonts/README.md) stays beside the binaries. Corrections use [HECAVEX contact](https://hecavex.com/en/contact/); vulnerabilities use the [private security policy](https://labs.hecavex.com/security/). Keep private cases, credentials, victim data and malware samples outside this repository.
