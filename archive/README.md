# archive/ — repo-root archive for blog-post sources and historical artifacts

This directory holds files that should not be picked up by the Docusaurus blog plugin (anything under `docs/blog/` becomes a current blog post on the docs site) but **do** belong in the repo as either canonical sources for external publications or historical preservation per ADR-020 §13 (repo structure) §11 + master-checklist §4.3a.

## Contents

- `devto-lazy-discovery-tokenomics.md` — externally-published dev.to post from the pre-reset era (moved from `dogfood/` per PR 3 / ADR-020 §13 (repo structure) §11). Historical record only; do not edit.
- `devto-stigmem-v0.9.0a1-retraction.md` — **canonical source** of the dev.to retraction post that announces the v1.0 retraction and the v0.9.0a1 reset. The stigmem repo is the authoritative home for this post; the dev.to publication mirrors this content. After publish, fill in `canonical_url` in the frontmatter; corrections ship as follow-up posts or PEP 440 `.post1` errata per `docs/internal/release-cadence.md` §Rule 3, not as in-place edits.

## How to read this directory

Most files here are read-only historical artifacts (do not edit; do not link adopters here as current docs). The exception is canonical sources for external publications (e.g., the retraction post) which are editable until the external publication goes live, then frozen. Each file's header banner declares which mode it's in. The current canonical *docs* surfaces (where adopters should be linked) are:

- [`README.md`](../README.md) — repo entry point
- [`CHANGELOG.md`](../CHANGELOG.md) — current changelog
- [`ROADMAP.md`](../ROADMAP.md) — public roadmap
- [`docs/docs/`](../docs/docs/) — Docusaurus content (canonical docs site)
- [`docs/archive/`](../docs/archive/) — Docusaurus-tree archive (snapshots, superseded, placeholder pages)
