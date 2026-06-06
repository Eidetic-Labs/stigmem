# Future Release-Candidate and GA Roadmap

**Status:** future gate
**Release owner:** maintainer
**Milestone:** not opened
**Tag / release:** not tagged
**Last updated:** 2026-05-22

## Release Intent

The release-candidate and GA lines are not active. Entry is blocked on
hardened-core exit and a later release-candidate observation window. Do not
create RC or GA milestones until the release-candidate line is explicitly
opened.

## Scope Summary

| Area | In scope | Out of scope | Canonical references |
| --- | --- | --- | --- |
| Supply-chain evidence | Sigstore, reproducible-source evidence, SBOM, Rekor/operator verification | Publishing stable releases before hardened-core exit | #440 |
| External adoption | 3+ external organizations with pairwise federation and review posture | Internal-only validation as GA evidence | #441 |
| Compatibility | Wire-format freeze and v1.x compatibility commitment | Premature v1.0.0 promises | ADR-008 §Deprecation policy, #442 |

## Detailed Scope

### Work

- Sigstore-signed releases, reproducible-source evidence, SBOM publication, and Rekor/operator verification evidence ([#440](https://github.com/eidetic-labs/stigmem/issues/440)). The publish workflow now signs GHCR images keylessly, attaches SBOM and BuildKit provenance evidence, publishes npm/PyPI provenance, and documents operator verification commands.
- 3+ external organizations running stigmem with pairwise federation and public external-review/bug-bounty posture ([#441](https://github.com/eidetic-labs/stigmem/issues/441)).
- Wire-format freeze; backwards compatibility committed within v1.x ([#442](https://github.com/eidetic-labs/stigmem/issues/442)).

## Artifact Surfaces

| Surface | Expected artifact | Status | Evidence |
| --- | --- | --- | --- |
| PyPI | Future RC/GA package artifacts | Future gate | Not opened |
| npm | Future RC/GA SDK artifacts | Future gate | Not opened |
| GHCR | Future RC/GA image artifacts with supply-chain evidence | Future gate | Not opened |
| Docs | Stable compatibility and operator verification docs | Future gate | Not opened |
| GitHub release | Future RC/GA tags only after gate opens | Not tagged | Not opened |

## Security and Risk Posture

RC/GA entry is blocked on hardened-core exit. Stable release claims require
wire-format commitment, supply-chain evidence, external operator evidence, and
the compatibility commitment required by ADR-008 §Deprecation policy.

## Evidence Gates

| Gate | Required evidence | Status |
| --- | --- | --- |
| Hardened-core exit | Hardened-core gate complete | Future gate |
| v1.0.0 stable shipped | Stable tag and release notes | Future gate |
| Wire format committed | Compatibility commitment doc per ADR-008 §Deprecation policy honored across v1.x | Future gate |
| External organizations | 3+ production external operators | Future gate |

## Release Notes Candidates

- Release-candidate and GA release notes are not drafted until those lines open.

## Deferred / Follow-Up Work

| Item | Disposition | Target |
| --- | --- | --- |
| Post-GA expansion | Blocked until stable v1.0.0 ships | Post-GA roadmap |

## Historical Disposition

Not applicable. This horizon is not active.
