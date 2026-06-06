# archive/ — repo-root archive for blog-post sources and historical artifacts

This directory holds files that should not be picked up by the Docusaurus blog plugin (anything under `docs/blog/` becomes a current blog post on the docs site) but **do** belong in the repo as either canonical sources for external publications or historical preservation per ADR-020 §13 (repo structure) §11 + master-checklist §4.3a.

## Contents

- `devto-lazy-discovery-tokenomics.md` — externally-published dev.to post from the pre-reset era (moved from `dogfood/` per PR 3 / ADR-020 §13 (repo structure) §11). Historical record only; do not edit.

## How to read this directory

All files here are read-only historical artifacts (do not edit; do not link adopters here as current docs). The current canonical *docs* surfaces (where adopters should be linked) are:

- [`README.md`](../README.md) — repo entry point
- [`CHANGELOG.md`](../CHANGELOG.md) — current changelog
- [`ROADMAP.md`](../ROADMAP.md) — public roadmap
- [`docs/docs/`](../docs/docs/) — Docusaurus content (canonical docs site)
- [`docs/archive/`](../docs/archive/) — Docusaurus-tree archive (snapshots, superseded, placeholder pages)
