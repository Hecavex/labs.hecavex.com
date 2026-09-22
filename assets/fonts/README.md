# Self-hosted fonts

HECAVEX Labs serves its typography locally and does not contact a font CDN.

The WOFF2 files in this directory were obtained from Fontsource 5.3.0 packages for Inter and IBM Plex Mono. The stylesheet uses Latin and Latin Extended subsets: Inter normal weights 400–700 plus 400 italic, and IBM Plex Mono normal weights 400–700.

Both families are distributed under the SIL Open Font License 1.1. The bundled licence texts are:

- `INTER-OFL.txt`
- `IBM-PLEX-MONO-OFL.txt`
- `SPACE-GROTESK-OFL.txt`

The September 2026 portfolio redesign adds the Latin and Latin Extended variable WOFF2 subsets from `@fontsource-variable/space-grotesk` 5.3.0 for display headings (weights 300–700). They are also SIL Open Font License 1.1. Inter remains the reading and interface family; IBM Plex Mono is reserved for identifiers and technical data. All three families remain self-hosted.

When updating the files, retain the same subset and weight naming convention, update the Fontsource version recorded here, and keep the corresponding OFL texts with the binaries.
