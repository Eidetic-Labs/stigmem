# Security Evidence Registry — 2026-05-17 Internal Node Security Audit

**Scope:** `stigmem-node` v0.9.0a1 source review, completing in v0.9.0a2 release prep.
**Method:** source review of authentication/identity, input validation, federation, plugins, cryptography, storage, filesystem permissions, and logging/secrets behavior.
**Reviewer:** internal review with automated investigation agents and maintainer follow-up.
**Release target:** `stigmem-node 0.9.0a2` (advisory disclosures + hardening).

This page lists each audit finding, the code paths that implement the fix, the resolution PR, the regression evidence, and the disposition. Per the [Security Evidence Registry best-practices guide](./security-evidence-registry.md), a finding moves to **Closed** only when implementation, tests, version-introduced, and documentation evidence all agree.

## Critical / High findings (published as GHSAs)

**Advisory range correction (2026-06-03):** The six published GHSA records in
this table were narrowed from `<0.9.0a2` to `==0.9.0a1` after Dependabot
reopened alerts against the `uv.lock` editable workspace entry for
`stigmem-node 0.9.0a10`. The a2 patch disposition did not change: `0.9.0a1`
is the reset-line vulnerable artifact, and `0.9.0a2` is the first patched
artifact. Alerts #53-#58 were dismissed as inaccurate after the advisory
metadata read back with the exact affected range.

| Finding | GHSA | Evidence path(s) | Resolution PR | Regression evidence | Disposition |
| --- | --- | --- | ---: | --- | --- |
| C1 — Federation peer token timestamp handling | [GHSA-xh5j-xjfq-qvvx](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-xh5j-xjfq-qvvx) | `node/src/stigmem_node/federation/peer_auth.py`; `node/src/stigmem_node/federation/peer_token.py` | #487 | Peer-token epoch tests | Closed |
| C2 — Non-loopback insecure federation startup | [GHSA-jmfc-hfjq-pxcp](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-jmfc-hfjq-pxcp) | `node/src/stigmem_node/main.py` startup validation | #484 | Startup-configuration tests | Closed |
| H1 — Non-loopback auth-disabled deployment | [GHSA-fp6w-8wpg-74g5](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-fp6w-8wpg-74g5) | `node/src/stigmem_node/auth.py`; `node/src/stigmem_node/main.py` | #484 | Startup-configuration tests | Closed |
| H2 — Federation peer registration approval gate | [GHSA-9vp8-3hmv-8fgh](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9vp8-3hmv-8fgh) | federation peer registration routes and implementation | #490 | Peer-registration tests and 4-node fixture update | Closed |
| H3 — Unsigned plugin override acknowledgement | [GHSA-w7pm-9g55-mxfm](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-w7pm-9g55-mxfm) | plugin lifecycle/signing configuration | #484 | Startup-configuration tests | Closed |
| H5 — Postgres schema identifier handling | [GHSA-9pc9-4crj-mhpj](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9pc9-4crj-mhpj) | `node/src/stigmem_node/storage/postgres_backend.py` | #486 | Postgres backend tests | Closed |

## Medium and Low findings (changelog-documented per the publication policy)

| Finding | Evidence path(s) | Resolution PR | Regression evidence | Disposition |
| --- | --- | ---: | --- | --- |
| M1 — Federation nonce cache lifetime | federation nonce cache handling | #487 | Peer-token nonce lifetime tests | Closed |
| M2 — Federation token issuer validation | federation token issuer validation | #487 | Peer-token validation tests | Closed |
| M3 — Federation token time-claim validation | federation token time claims | #487, #492 | Peer-token epoch tests and Hypothesis fuzz coverage | Closed |
| M4 — Legacy SHA-256 API key acceptance deadline | `node/src/stigmem_node/auth.py` legacy hash path | #172 | Argon2/auth deadline tests | Closed |
| M5 — OIDC ID-token algorithm allowlist | OIDC algorithm handling | #488 | OIDC tests | Closed |
| M6 — SQLite database and sidecar permissions | SQLite file creation and sidecars | #489 | Runtime hygiene tests | Closed |
| M7 — CLI write-out path permissions | CLI write-out paths | #489 | Runtime hygiene tests | Closed |
| M8 — Rate-limit kill-switch acknowledgement | quota-disablement operator acknowledgement | security posture docs | Documentation and operator guidance | Closed |
| M9 — Federation message validation | federation message state-transition validation | security posture docs | Security posture documentation | Closed |
| L1 — Development CORS startup warning | CORS development flag startup posture | #489 | Runtime hygiene tests | Closed |
| L2 — Embedding-provider error redaction | embedding provider error output | #489 | Runtime hygiene tests | Closed |
| L3 — Audit posture documentation by trust mode | audit posture documentation | #491 | Documentation-only; docs build not required by sparse PR | Closed |
| L4 — Federation clock-skew leeway (folded into M2/M3) | federation clock-skew behavior | #487, #492 | Peer-token epoch tests and fuzz coverage | Closed/folded |
| L5 — OIDC discovery URL validation | OIDC discovery URL handling | security posture docs | Security posture documentation | Closed |

## Cross-references

- Public security posture, upgrade command, and audit disposition index: ["Security Posture — v0.9.0a2"](../../SECURITY.md) in `SECURITY.md`.
- Release-impact summary: `[0.9.0a2]` `### Security` block in [`CHANGELOG.md`](../../CHANGELOG.md).
- Architectural risk classes derived from C2, H1, and H2 are registered as R-24, R-25, and R-26 in [`spec/security/threat-model.md`](../../spec/security/threat-model.md).
- Best-practices guide for the registry format: [security-evidence-registry.md](./security-evidence-registry.md).

## Additional Medium / Low dispositions documented in SECURITY.md

Rate-limit kill-switch acknowledgement, federation message validation, and OIDC discovery URL validation are captured in `SECURITY.md` as final Medium/Low dispositions. Per the v0.9.0a2 publication policy, Critical and High findings are disclosed through GHSAs; Medium and Low findings are documented in the public security posture unless their risk profile changes.

C3 federation transport guard / preflight and H6 federation authority verification independent of trust mode did not receive standalone advisories after triage. Their public disposition is captured by the existing federation hardening entries in `CHANGELOG.md`, `SECURITY.md`, and the threat-model evidence for the affected federation risks.
