# <Feature name> — Status

> Per ADR-008, gate status for `experimental/<feature>/`.
> Drop in at `experimental/<feature>/STATUS.md`.

**Status:** Dormant | Active | Blocked | Withdrawn
**Active version:** vX.Y.Z (the version of stigmem this feature was last tested against)
**Last updated:** YYYY-MM-DD
**Owner:** name(s) or `unowned` if no one is currently progressing this feature
**Buildable:** yes | no — does the experimental code currently compile and pass its own tests?

---

## Summary

One paragraph: what this feature is, what problem it solves, why it's experimental rather than v1.0.

## Why deferred

One paragraph: the reasoning from ADR-002 or a subsequent amendment for why this feature is not in v1.0.0 critical-path scope. Reference the relevant ADRs and risk-register entries.

---

## Gate progress

| Gate | Description | Status | Date | Artifact |
|---|---|---|---|---|
| 1 | Threat-model delta | `Open` / `Done` | YYYY-MM-DD | `experimental/<feature>/security.md` |
| 2 | ADR | `Open` / `Done` | YYYY-MM-DD | `docs/adr/NNN-<feature>.md` |
| 3 | Conformance vectors | `Open` / `Done` | YYYY-MM-DD | `data/conformance/<feature>/` |
| 4 | 30-day external operator soak | `Open` / `Done` | YYYY-MM-DD | LOG.md entry; closed soak issues |
| 5 | Documentation parity | `Open` / `Done` | YYYY-MM-DD | Learn / Build / Operate / Secure pages |

When all five are `Done`, the feature is ready for promotion via an ADR-002 amendment.

---

## Notes per gate

### Gate 1 — Threat-model delta

What new trust boundaries does this feature introduce? What new STRIDE entries? What new risks (R-XX)? Which existing risks does it widen or narrow? Per ADR-020 §11 (security taxonomy), draft and maintain this analysis in `experimental/<feature>/security.md`; when the delta is merged into the unified threat model, link both artifacts here.

### Gate 2 — ADR

Open questions that need design resolution before the ADR can be drafted. Once the ADR is merged, link it here.

### Gate 3 — Conformance vectors

What positive, negative, and adversarial vectors does this feature need? When vectors land in CI, link the directory here.

### Gate 4 — Operator soak

Candidate operators identified. Soak start date, planned duration, public-issue tag. Link the soak findings issue here when soak begins.

### Gate 5 — Documentation parity

Per ADR-020 §12 (docs IA), identify which of Learn / Build / Operate / Secure tabs the feature touches and what content each tab needs.

---

## Open questions

Material design or scope questions that the feature's reintroduction depends on resolving. Each question becomes either a Gate 2 ADR section or a follow-up ADR.

---

## History

Append-only log of significant status changes. Newest entries first.

- **YYYY-MM-DD** — <event>: <one-line description>
- **YYYY-MM-DD** — created in `experimental/` per ADR-002.

---

*Per ADR-008, gate transitions require sign-off (two contributors or the founder alone, per ADR-001 §Contributor approval rule).*
