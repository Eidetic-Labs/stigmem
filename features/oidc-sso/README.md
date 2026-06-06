---
feature_id: oidc-sso
title: OIDC SSO
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: core
default_surface: opt-in
canonical_spec: none
implementation_path: node/src/stigmem_node/routes/auth.py
package: stigmem-node
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# OIDC SSO

OIDC SSO is the opt-in bridge that exchanges an identity-provider `id_token`
for a short-lived Stigmem API key. Static bearer-key authentication remains the
default path; OIDC is disabled unless operators configure the OIDC environment
settings.

The implementation validates provider discovery, token issuer, audience,
configured signing algorithms, and optional email-domain allowlists before
minting a scoped API key bound to the OIDC `sub` claim.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `node/src/stigmem_node/routes/auth.py` |
| Primary tests | `node/tests/auth/test_oidc.py` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
