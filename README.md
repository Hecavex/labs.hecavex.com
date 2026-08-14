# HECAVEX Labs

[HECAVEX Labs](https://labs.hecavex.com) contains the small tools and datasets that sit next to HECAVEX research. They are intentionally simple, inspectable and usable without an account.

Current projects:

- **Baltic Threat Atlas** collects source-linked public observations and maps them to APT Notes only when the evidence supports the link.
- **Pivot Workspace** shows how an investigation moves from an observed artefact to a derivation or assessment.
- **CRA Article 14 Triage** helps prepare an incident record in the browser. Entered data stays in the browser unless the user exports it.

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

## Publishing

GitHub Pages deploys the site through `.github/workflows/pages.yml`. Keep `CNAME` and use GitHub Actions as the Pages source.

Optional aggregate measurement is enabled with the Actions variable `HECAVEX_ANALYTICS_TOKEN`. Without it, the measurement tag is removed from the deployed files.

## Evidence

An observation, a reproducible derivation and an analytical assessment are different things. The interfaces label them separately. Public claims keep their source links, unsupported actor mappings remain empty, and known limitations stay visible.

Corrections can be sent to `info@hecavex.com`. The accompanying long-form research lives at [hecavex.com](https://hecavex.com), and structured actor records live at [apt.hecavex.com](https://apt.hecavex.com).
