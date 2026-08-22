# HECAVEX Labs

[HECAVEX Labs](https://labs.hecavex.com) contains the small tools and datasets that sit next to HECAVEX research. They are intentionally simple, inspectable and usable without an account.

Project status: **maintained on a best-effort basis** by Deividas Lis / HECAVEX. Labs is intended for CTI analysts, defenders, investigators, journalists and researchers; it is not a monitoring service or an operational SLA. The public site carries the current [methodology and limitations](https://labs.hecavex.com/methodology/), [data catalogue](https://labs.hecavex.com/data/) and [security policy](https://labs.hecavex.com/security/).

The interface is purpose-built static HTML, CSS and browser JavaScript. Its Cold Signal design system uses a fixed dark analyst palette shared across the HECAVEX portfolio, Inter for interface and reading text, and IBM Plex Mono for labels, states and technical metadata. Both font families are self-hosted under `assets/fonts/`; their OFL notices are stored alongside the files. No remote font or icon service is required.

Current projects:

- **Baltic Threat Atlas** collects source-linked public observations and maps them to APT Notes only when the evidence supports the link.
- **Pivot Workspace** contains separate case graphs for the UniPark smishing infrastructure, the Adform JavaScript clipper and a malicious Python loader found on GitHub. Each graph keeps observations, derivations, assessments and limitations distinct.
- **ATT&CK Operations Workbench** starts with three clear jobs: analyse evidence, assess defensive coverage or explore threat intelligence. Evidence analysis ends in a recorded, exportable assessment rather than a candidate list. Coverage separates scope, telemetry, analytic, validation and operational ownership in one inline record. Intelligence exposes the official procedure descriptions and available citations for every active Enterprise ATT&CK group, while the smaller HECAVEX-reviewed evidence layer remains visibly separate. Capability and incident workspaces stay in the browser and can be exported; the site accepts no file imports or uploads.
- **ATT&CK first-use guide** documents those workflows with marked screenshots from the actual interface. It explains the status model and the boundaries between a candidate and a finding, reference data and attribution, and an engineering package and deployed coverage.
- **OSINT Workbench** is an annotated selection of free and free-tier tools from three established Awesome OSINT collections. It explains where, when and why to use each source, plus the evidential limits.

## Run it locally

There is no application framework or package install.

```powershell
python -m http.server 4173
```

Open `http://localhost:4173/` and run the repository checks with:

```powershell
python scripts/validate.py
```

The validator checks the HTML, local links, metadata, structured data, self-hosted font inventory, absence of remote font loading and the expected shape of each dataset. `python scripts/audit_performance.py` separately enforces deterministic raw and gzip size limits for the page shell, static assets and route-specific data bundles. Thresholds are recorded in that script and should only be raised after reviewing the affected user experience.

Deployment also checks every public workspace at 320, 360, 390, 768, 1024 and 1440 pixels. The browser suite covers actual font loading, keyboard navigation, focus restoration, scroll containment, page overflow and usable navigation without JavaScript; a successful CI run retains its JSON result as a 30-day workflow artifact. To reproduce the checks locally:

```powershell
python -m pip install -r requirements-checks.txt
python -m playwright install chromium
python scripts/test_responsive.py
```

The workbench-guide screenshots are reproducible. With the local server running on port 4174 and Playwright installed, refresh them with:

```powershell
python scripts/capture_attack_guide.py
```

Refresh the compact catalogue from MITRE's official Enterprise ATT&CK STIX bundle with:

```powershell
python scripts/update_attack_catalog.py
python scripts/build_attack_content.py
```

ATT&CK material lives under `data/attack/`:

- `catalogue/enterprise.json` is the generated official technique and group catalogue.
- `intelligence/official-actor-procedures.json` contains every official group-to-technique procedure description and available public citations.
- `intelligence/reviewed-evidence.json` is the much smaller HECAVEX-reviewed procedure layer maintained alongside APT Notes.
- `operations/guides.json` contains curated collection, pivot and response guidance.
- `detections/packages.json` contains one materialised engineering package for every operational guide.
- `governance/governance.json` publishes counts, boundaries, review triggers and change history for each layer.

The other Labs datasets are separated under `data/atlas/`, `data/osint/` and `data/pivots/`.

`data/catalogue.json` is the machine-readable inventory of deliberately public Labs datasets and related HECAVEX APIs. Publication is default-deny: `data/public-manifest.json` is an exact allowlist, validation rejects unlisted files, and deployment stages only paths in that manifest. Private notes, submissions, credentials, malware samples, victim data and quarantined observations do not belong in this repository.

Detection engineering is deliberately separate from ATT&CK reference data:

- One PowerShell package is validation-ready reference material. The remaining packages are explicitly labelled engineering candidates requiring local schema design and testing.
- Candidate packages still provide a hypothesis, minimum data contract, product-independent logic, positive/negative/resilience tests, triage and lifecycle fields. They are not silently generated by the browser.
- A package is validation-ready reference material, not a deployable rule or evidence of coverage in a reader's environment.

## Publishing

GitHub Pages deploys the site through `.github/workflows/pages.yml`. Keep `CNAME` and use GitHub Actions as the Pages source.

## Licensing

HECAVEX-authored software uses the full [MIT License](LICENSE). Original HECAVEX data is CC BY 4.0 only where the [data licensing and attribution notice](DATA-LICENSE.md) identifies it as covered. MITRE ATT&CK records, cited publications, trademarks and external services retain their respective terms; the public [licensing page](https://labs.hecavex.com/licence/) summarizes the boundary.

## Evidence

An observation, a reproducible derivation and an analytical assessment are different things. The interfaces label them separately. Public claims keep their source links, unsupported actor mappings remain empty, and known limitations stay visible.

Corrections can be sent to `info@hecavex.com`. The accompanying long-form research lives at [hecavex.com](https://hecavex.com), and structured actor records live at [apt.hecavex.com](https://apt.hecavex.com).
