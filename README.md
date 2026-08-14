# HECAVEX Labs

Static, dependency-free research interfaces for `labs.hecavex.com`.

## Projects

- **Baltic Threat Atlas** — selected primary-source observations concerning Lithuania, Latvia and Estonia.
- **Pivot Graph** — an evidence-aware view of the published Adform supply-chain case.
- **CRA reporting triage** — a conservative educational assistant for Regulation (EU) 2024/2847 Article 14.

## Local preview

From this directory:

```powershell
python -m http.server 4173
```

Then open `http://localhost:4173/`. The site has no package dependencies, accounts, analytics or external runtime requests.

Run the dependency-free structural check with:

```powershell
python scripts/validate.py
```

## Publishing

The repository is suitable for GitHub Pages. Add the repository to the HECAVEX organisation, keep `CNAME`, and deploy the repository root. DNS configuration is intentionally not automated here.

## Evidence policy

Interfaces distinguish observations from assessments, link claims to their sources and state material limitations. Corrections can be sent to `info@hecavex.com`.
