# HECAVEX Labs

[HECAVEX Labs](https://labs.hecavex.com) contains the small tools and datasets that sit next to HECAVEX research. They are intentionally simple, inspectable and usable without an account.

Current projects:

- **Baltic Threat Atlas** collects source-linked public observations and maps them to APT Notes only when the evidence supports the link.
- **Pivot Workspace** contains separate case graphs for the UniPark smishing infrastructure, the Adform JavaScript clipper and a malicious Python loader found on GitHub. Each graph keeps observations, derivations, assessments and limitations distinct.
- **ATT&CK Explorer** includes the complete active Enterprise ATT&CK catalogue, its official group, campaign, software, mitigation and detection relationships, a bounded phishing behaviour model, and reviewed APT28/APT44 evidence. Views export to CSV and ATT&CK Navigator.
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

The validator checks the HTML, local links, metadata, structured data and the expected shape of each dataset.

Refresh the compact catalogue from MITRE's official Enterprise ATT&CK STIX bundle with:

```powershell
python scripts/update_attack_catalog.py
```

The ATT&amp;CK map is a generated publication layer over reviewed `technique_evidence` relationships maintained in APT Notes. Update the actor record and its source references first, then refresh `data/attack-evidence.json`; do not add an unsupported cell directly for visual completeness.

## Publishing

GitHub Pages deploys the site through `.github/workflows/pages.yml`. Keep `CNAME` and use GitHub Actions as the Pages source.

Optional aggregate measurement is enabled with the Actions variable `HECAVEX_ANALYTICS_TOKEN`. Without it, the measurement tag is removed from the deployed files.

## Evidence

An observation, a reproducible derivation and an analytical assessment are different things. The interfaces label them separately. Public claims keep their source links, unsupported actor mappings remain empty, and known limitations stay visible.

Corrections can be sent to `info@hecavex.com`. The accompanying long-form research lives at [hecavex.com](https://hecavex.com), and structured actor records live at [apt.hecavex.com](https://apt.hecavex.com).
