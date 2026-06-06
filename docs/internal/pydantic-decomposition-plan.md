# Pydantic Models — Domain-Specific Decomposition Plan

> Decompose `node/src/stigmem_node/models.py` (652 lines, 45 classes) and ~25 inline route models into domain-specific modules.
> Companion to `stigmem-file-structure-and-size-best-practices.md`; corrects an earlier mis-recommendation that `models.py` should stay as one file.

---

## Why this matters

A 45-class Pydantic file violates the standard Python convention of one-domain-per-module. Concrete consequences:

- **Discoverability:** a contributor adding a new `IntentEnvelope` field has to scroll past 30 unrelated classes to find the right spot.
- **Import scope:** every module that needs `FactRecord` currently imports from `models.py`, which pulls in the symbol table for all 45 classes; minor at runtime, real at import-time and IDE-indexing time.
- **Review velocity:** a PR that adds three fact-related fields and three garden-related fields churns the same file even though they're unrelated changes. Reviewers can't tell at a glance which sections of the diff belong together.
- **Domain boundaries:** the file gives no signal about what's a fact concept vs. a federation concept vs. an experimental concept. Every new class lands wherever the author scrolled to.

The standard Python convention — domain-per-module (e.g., `user.py`, `order.py`, `product.py`) — addresses all four. For stigmem, the domains follow naturally from the protocol surface.

---

## Proposed structure

`node/src/stigmem_node/models/` becomes a sub-package replacing the flat `models.py`:

```
node/src/stigmem_node/models/
├── __init__.py # Re-exports for backwards compatibility (one minor version)
├── _shared.py # VALID_VALUE_TYPES, VALID_SCOPES, VALID_GARDEN_ROLES, etc.
├── facts.py # Fact / FactValue / FactRecord / AssertRequest / QueryResponse / AttestationToken
├── federation.py # PeerRegisterRequest / PeerRecord / PeerRegisterResponse / FederationFactsResponse
├── audit.py # AuditEntry / AuditLogEntry / AuditLogResponse
├── gardens.py # GardenRecord / GardenMemberRecord / GardenCreateRequest / GardenMemberRequest / GardenMemberUpdateRequest
├── quarantine.py # QuarantineRecord / QuarantinePromoteRequest / QuarantineRejectRequest / QuarantineListResponse
├── identity.py # AgentKeyRegisterRequest / AgentKeyRecord
├── intents.py # Constraint / Preference / DeferenceRule / EscalationPolicy / HandoffArtifact / HandoffPayload / IntentEnvelopeRequest / IntentEnvelopeRecord
├── conflict.py # ConflictResolveRequest
└── provenance.py # ProvenanceEntry / ProvenanceResponse
```

Experimental domains move to their `experimental/<feature>/` directories per ADR-020 §13 (repo structure)/011:

```
experimental/23-rtbf-tombstones/src/stigmem_tombstones/models.py
 # TombstoneNotice / TombstoneRecord / TombstoneRevocationRecord
 # TombstoneCreateRequest / TombstoneRevokeRequest / TombstoneStatusResponse
 # FederationTombstonesResponse

experimental/subscriptions/src/stigmem_subscriptions/models.py
 # SubscriptionCreateRequest / SubscriptionRecord / SubscriptionEventRecord
 # SubscriptionListResponse / SubscriptionEventsResponse
```

These move with their features during ADR-011 C2 extractions, not as part of this decomposition.

### Backwards compatibility shim

`node/src/stigmem_node/models/__init__.py` re-exports all classes for one minor version (v0.9.x), so existing imports keep working:

```python
# node/src/stigmem_node/models/__init__.py
"""Re-exports from domain-specific model modules (v0.9.x compat).

Direct imports from this package are deprecated. New code should import
from the specific domain module:

 from stigmem_node.models.facts import FactRecord
 from stigmem_node.models.gardens import GardenRecord

This compat shim ships in v0.9.x and is removed in v1.0.0.
"""
from .facts import FactValue, AttestationToken, AssertRequest, FactRecord, QueryResponse
from .federation import PeerRegisterRequest, PeerRecord, PeerRegisterResponse, FederationFactsResponse
from .audit import AuditEntry, AuditLogEntry, AuditLogResponse
from .gardens import GardenRecord, GardenMemberRecord, GardenCreateRequest, GardenMemberRequest, GardenMemberUpdateRequest
from .quarantine import QuarantineRecord, QuarantinePromoteRequest, QuarantineRejectRequest, QuarantineListResponse
from .identity import AgentKeyRegisterRequest, AgentKeyRecord
from .intents import (
 Constraint, Preference, DeferenceRule, EscalationPolicy,
 HandoffArtifact, HandoffPayload, IntentEnvelopeRequest, IntentEnvelopeRecord,
)
from .conflict import ConflictResolveRequest
from .provenance import ProvenanceEntry, ProvenanceResponse
from ._shared import VALID_VALUE_TYPES, VALID_SCOPES, VALID_GARDEN_ROLES

__all__ = [
 # ... full list
]
```

In v1.0.0, the `models/__init__.py` is reduced to:

```python
"""Domain-specific Pydantic models. Import from submodules:

 from stigmem_node.models.facts import FactRecord
"""
```

No re-exports. Every caller imports from its domain module directly.

### Updating `row_to_record` and similar utilities

`models.py` currently contains a `row_to_record` helper that converts a SQLite row to a `FactRecord`. That belongs with `FactRecord` in the new structure:

```python
# node/src/stigmem_node/models/facts.py
class FactRecord(BaseModel):
 ...

def row_to_record(row: sqlite3.Row) -> FactRecord:
 """Convert a fact-table SQLite row to a FactRecord."""
 ...
```

Same pattern for any other model-specific helpers that currently live in the flat `models.py`.

---

## Inline route models — separate decomposition

There are ~25 Pydantic classes inline in `routes/*.py` files. Each route file holds its own request/response shapes:

| Routes file | Inline classes |
|---|---|
| `routes/aliases.py` | `AliasRequest`, `AliasRecord` |
| `routes/admin_audit.py` | `AdminAuditEntry`, `AdminAuditResponse` |
| `routes/auth.py` | `ExchangeRequest`, `ExchangeResponse`, `KeyInfo` |
| `routes/cid_admin.py` | `CidBackfillStatus` |
| `routes/cards.py` | `MemoryCardResponse` |
| `routes/facts.py` | `_CidVerifyResponse` |
| `routes/graph.py` | `NeighborItem`, `NeighborsResponse` |
| `routes/lint.py` | `LintRequest`, `LintFinding`, `LintResult` |
| `routes/instruction.py` | `LoadTriggers`, `ManifestEntry`, `PublishManifestRequest`, `RecallInstructionRequest`, `AuditSubmitRequest` |
| `routes/recall.py` | `RecallWeights`, `RecallRequest`, `ScoreBreakdown`, `ScoredFact`, `RecallResponse` |

The convention here has two competing pulls:

- **"Models live in `models/`":** every Pydantic class moves to a domain module. Routes import from `models/`.
- **"Route-specific request/response stays inline":** request bodies and response bodies tightly coupled to a single endpoint stay in the route file. Domain entities (Fact, Garden, Peer) live in `models/`.

The right call depends on whether the model is part of the **public wire format** or **route-internal plumbing**:

- `RecallRequest`, `RecallResponse`, `LintRequest`, `LintResult`, `ManifestEntry`, `PublishManifestRequest` — **wire format**; should move to domain modules (`models/recall.py`, `models/lint.py`, `models/instruction.py`).
- `_CidVerifyResponse` (note the underscore prefix) — clearly route-internal; stays inline.
- `KeyInfo`, `MemoryCardResponse`, `NeighborsResponse`, `AdminAuditResponse` — wire format; move to domain modules.

**Rule of thumb:** if it appears in OpenAPI output, it belongs in `models/`. If it's prefixed with an underscore or is purely internal scaffolding, it stays in the route file.

### After the inline-route decomposition

The new `models/` sub-package gains a few more files:

```
node/src/stigmem_node/models/
├── __init__.py
├── _shared.py
├── facts.py
├── federation.py
├── audit.py
├── gardens.py
├── quarantine.py
├── identity.py # + ExchangeRequest / ExchangeResponse / KeyInfo from routes/auth.py
├── intents.py
├── conflict.py
├── provenance.py
├── recall.py # NEW — RecallWeights / RecallRequest / ScoreBreakdown / ScoredFact / RecallResponse
├── lint.py # NEW — LintRequest / LintFinding / LintResult
├── graph.py # NEW — NeighborItem / NeighborsResponse
├── cards.py # NEW — MemoryCardResponse
├── aliases.py # NEW — AliasRequest / AliasRecord
└── admin_audit.py # NEW — AdminAuditEntry / AdminAuditResponse
```

Plus experimental migrations:

```
experimental/21-lazy-instruction-discovery/src/stigmem_instructions/models.py
 # LoadTriggers / ManifestEntry / PublishManifestRequest
 # RecallInstructionRequest / AuditSubmitRequest

experimental/25-cids/src/stigmem_cids/models.py
 # CidBackfillStatus / _CidVerifyResponse (or stays in routes/facts.py if the underscore convention holds)
```

Total `models/` files in v1.0 critical-path: **15 domain modules**, each 30–150 lines. Compared to `models.py` at 652 lines plus inline classes scattered across 10 route files, this is a meaningful navigation improvement.

---

## Domain ownership of cross-domain concepts

A few classes touch multiple domains. Worth being explicit about ownership:

- **`AttestationToken`** is referenced by `AssertRequest` (writes) and federation handshake. It lives in `models/facts.py` because that's its primary use; federation imports it from there.
- **`QuarantineRecord`** is part of the federation flow but conceptually a quarantine concept. It lives in `models/quarantine.py`.
- **`AuditEntry`** is part of fact provenance but conceptually an audit concept. It lives in `models/audit.py`. Its near-cousin `ProvenanceEntry` lives in `models/provenance.py` because provenance is the broader concept (audit is one consumer of provenance data).

When in doubt, the rule: **the class lives in the domain that owns its lifecycle**. A class created during fact assertion lives in `facts.py` even if it's read elsewhere.

---

## Implementation plan

This is **a v0.9.x deliverable, not Phase A.** The decomposition is mechanical but touches every file that imports from `models.py` (which is most of the node module).

Three sequential PRs:

### PR A: Decompose `models.py` into `models/` sub-package

- Create the `models/` directory.
- Move classes per the domain mapping.
- Add the backwards-compat re-export shim in `models/__init__.py`.
- Run the full test suite to confirm imports resolve correctly.
- No changes to imports in any other file (compat shim handles this).

**Effort:** half day.

### PR B: Migrate inline route models

- Move wire-format classes from `routes/*.py` to the appropriate `models/<domain>.py`.
- Update `routes/*.py` to import from `models/<domain>`.
- Underscore-prefixed internal classes stay inline.

**Effort:** 1 day.

### PR C: Sweep imports across the codebase

- Replace `from stigmem_node.models import X` with `from stigmem_node.models.<domain> import X` everywhere.
- The compat shim continues to work; this PR is just preferring the explicit path.
- Add a deprecation warning to the compat shim:
 ```python
 # models/__init__.py
 import warnings
 warnings.warn(
 "Importing from stigmem_node.models directly is deprecated. "
 "Use stigmem_node.models.<domain> instead. The shim will be removed in v1.0.0.",
 DeprecationWarning,
 stacklevel=2,
 )
 ```

**Effort:** half day.

### v1.0.0: remove the compat shim

- `models/__init__.py` becomes a brief module docstring with no re-exports.
- Any remaining direct-import callers get a hard ImportError.

The three PRs total **~2 days of work** spread across v0.9.x. Each PR is independently mergeable; the project is never in a half-decomposed state.

---

## Updates to the file-structure best-practices doc

The earlier `stigmem-file-structure-and-size-best-practices.md` listed `models.py` (652 lines) as "acceptable; splitting would make the schema harder to read in one place." That recommendation was wrong for the same reason this decomposition exists: 45 classes is well past the point where one-place wins.

The corrected guidance for that doc:

> **Pydantic model files specifically:** organize by domain (`models/facts.py`, `models/gardens.py`, etc.), not by data shape (`models.py`, `requests.py`, `responses.py`). Group classes that change together. A flat `models.py` over ~10 classes is a smell; over 20 classes is a hard rule violation regardless of total line count.

I'll apply this update to the best-practices doc in a follow-up edit.

---

## Side effects worth naming

### `__init__.py` for `routes/`

The `routes/` directory currently has an empty `__init__.py`. It can stay empty.

### Test imports

Tests import from `models.py` heavily (e.g., `from stigmem_node.models import FactRecord`). The compat shim handles this for v0.9.x. Tests can be migrated to explicit imports as part of PR C.

### OpenAPI generation

The TypeScript SDK's `generated.ts` is built by `openapi-typescript` from the FastAPI-generated OpenAPI schema. Decomposing `models.py` does not affect the generated output — Pydantic classes appear in the OpenAPI schema by their class name regardless of which file they live in. The generated SDK is unchanged.

### IDE quality-of-life

Splitting `models.py` improves IDE behavior in three ways: faster symbol indexing per file, more relevant "go to definition" navigation (you land in `models/facts.py`, not in a 652-line file), and clearer "find references" results scoped to one domain.

---

## Why I missed this in the first review

Worth being explicit because this is the second time in the strengthening-plan work where I've under-recommended decomposition (the other was when I didn't initially flag the 40 flat `*.py` files in `node/src/stigmem_node/`).

The pattern of error: **defaulting to "leave it alone" for files where the alternative requires real work.** A 652-line file with 45 unrelated classes is not "models in one place" — it's a kitchen drawer. The right test is "would a contributor adding a new domain class find the right home easily?" and `models.py` fails that test.

The corrected default for future reviews: **whenever I see a single file containing more than ~10 classes that span multiple domains, propose decomposition. The discipline cost is low; the navigation benefit is high.**

This applies retroactively to one other place in the project I should re-examine: are there any 5+-class files I marked "fine" earlier that should also decompose? Worth a sweep when this work is sequenced.

---

*This decomposition is independently valuable and should land in v0.9.x regardless of other work. Cross-cutting feature extractions (per ADR-011) build on top of a clean models layer; doing the model decomposition first makes the experimental migrations cleaner.*
