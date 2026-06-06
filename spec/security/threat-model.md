# Stigmem Threat Model

**Revision:** 2.8 — ADR-020 §11 (security taxonomy) per-feature security colocation completion (2026-05-16)
**Status:** Current. Re-versioned from Rev 2.0 to v0.9.0a1 baseline per [ADR-001](../../docs/adr/001-versioning.md) (per-ecosystem version-string convention). pre-reset hardening evidence carried forward; R-19 through R-26 added (R-24/R-25/R-26 capture the v0.9.0a2 audit hardening for non-loopback insecure federation, non-loopback auth-disabled deployment, and federation peer registration trust-on-first-use); STRIDE residual columns refreshed; ADR-003 / [ADR-007](../../docs/adr/archive/007-argon2id.md) / ADR-016 cross-references added. Rev 2.8 completes the ADR-020 §11 (security taxonomy) per-feature security colocation map for the hardened-core documentation pass.
**Previous revisions:** 2.0 (2026-05-05, retracted-label posture preserved as historical context); 1.0 — pre-reset hardening (2026-05-04) — archived.
**Applies to:** Stigmem v0.9.0a1 and reference node implementation.
**Spec cross-reference:** §19 (Federation Trust), §20 (Recall & Graph), §21 (Lazy Instruction Discovery), §22 (Security Hardening), §23 (RTBF Tombstones), §24 (Time-Travel Queries), §25 (Content-Addressed Fact IDs).

### Revision 2.0 change summary

- **Pre-reset hardening closed:** R-01 (mTLS), R-02 (quotas), R-03 (key max-age), R-06 (replay fuzz), R-09 (audit log), R-10 (key-rotation log), R-11 (container), R-12 (agent quota), R-14 (capability token validation) all **Mitigated** — code shipped in the pre-reset hardening PR and verified in `tls.py`, `rate_limit.py`, `auth.py`, `audit_event.py`, `identity/key_rotation.py`, `identity/capability.py`, `Dockerfile`, and corresponding test suites.
- **HLC hardening closed on main for v0.9.0a2:** R-19 is **Mitigated** by bounded inbound remote-HLC skew checks at federation ingest, `peer_hlc_anomaly` audit events, and regression tests for far-future and far-past remote HLC values.
- **Auth storage hardened:** §4 assumption 2 and T1-S1 now reflect [ADR-007](../../docs/adr/archive/007-argon2id.md) Argon2id hashing for new API keys, with dual-mode legacy SHA-256 verification and opportunistic rehash during the v0.9.x migration window.
- **New TB-9 added:** Lazy Instruction Discovery (§21) introduces a new trust boundary between agent runtimes and the instruction recall path.
- **New risks R-15–R-18:** v2.0 sections §21–§25 introduce four new risks: instruction-scope injection (R-15), tombstone-based DoS (R-16), legal-hold historical data exposure (R-17), and CID field-exclusion tampering (R-18).

---

## 1. Purpose and Scope

This document is the formal threat model for the Stigmem reference node and federated protocol. Revision history is in §10. It covers:

- The system architecture and component diagram.
- Trust boundaries and actors.
- STRIDE analysis per trust boundary.
- A risk register linked to spec sections and pre-reset hardening backlog (carried forward to v0.9.0a1).

It does **not** replace the operational [Security & Pen Testing guide](../../docs/docs/security/pen-test.md) or the project's [SECURITY.md](../../SECURITY.md). Those documents address disclosure policy, scope for community pen testing, and the current patched-CVE posture. This document addresses protocol-level and architecture-level threats.

---

## 2. System Architecture

### 2.1 Components

| Component | Description | Trust level |
|---|---|---|
| **Reference node** (Python/FastAPI) | HTTP API, federation layer, recall pipeline, MCP adapter, OpenClaw adapter | Server |
| **Storage backend** | SQLite, libSQL (Turso), or PostgreSQL; persists facts, embeddings, vector index, audit log, nonce cache | Local to node or cloud (libSQL cloud) |
| **Transparency log** | Rekor / Sigstore-equivalent for org manifest rotation events | External, append-only |
| **Org manifest** | Ed25519 keypair, entity-URI list, rotation events; served at `/.well-known/stigmem-manifest.json` | Node-published, public |
| **Capability tokens** | Short-lived signed tokens authorising cross-org writes (Ed25519, max 90 days) | Issued by node admin |
| **Peer node** | Another Stigmem node in a federation; may be operated by a different organisation | External, authenticated via mTLS + manifest |
| **MCP adapter** | Exposes `assert_fact`, `query_facts`, `recall`, `lint_scope` tools to MCP-compatible LLM runtimes | Trusted by node as a caller |
| **OpenClaw / Claude Code adapter** | Read/write memory paths for Claude Code integration | Trusted by node as a caller |
| **Obsidian adapter** | CLI/daemon or Obsidian plugin; bidirectional vault ↔ node sync | Local trusted client |
| **Admin client** | Human operator or automation holding an admin-scope API key | Privileged |
| **Agent / end client** | Automated agent or application holding a scoped API key | Semi-trusted; scope-limited |
| **Quarantine garden** | Isolated fact store for untrusted incoming federation writes pending human review | Internal |
| **Recall pipeline** | Three-stage hybrid (lexical + dense vector + graph) recall; embedding model (local or cloud) | Internal + optional external |
| **Embedding service** | nomic-embed-text-v1.5 (offline default) or cloud provider (opt-in) | External opt-in |

### 2.2 System Diagram

```
                          ┌─────────────────────────────────────────────┐
                          │              PUBLIC INTERNET                 │
                          │                                              │
          ┌───────────────┼──────────────┐      ┌───────────────────────┼────┐
          │  Agent/Client │              │      │  Peer Node B          │    │
          │  (API key)    │              │      │  (mTLS + capability   │    │
          └──────┬────────┘              │      │   token, §19 manifest)│    │
                 │ TB-1                  │      └────────────┬──────────┘    │
                 │ HTTPS (TLS 1.3)       │                   │ TB-2          │
                 ▼                       │                   │ mTLS (§22.1)  │
    ┌────────────────────────────────┐   │                   ▼               │
    │       Stigmem Reference Node  │   │    ┌──────────────────────────┐   │
    │                                │   │    │   Transparency Log       │   │
    │  ┌─────────────────────────┐   │   │    │   (Rekor / Sigstore)     │   │
    │  │   HTTP API (FastAPI)    │◄──┼───┘    │   TB-5 (HTTPS)          │   │
    │  │   /v1/*                 │   │        └──────────────────────────┘   │
    │  └──────────┬──────────────┘   │                                       │
    │             │                  │        ┌──────────────────────────┐   │
    │  ┌──────────▼──────────────┐   │        │  Embedding Service       │   │
    │  │   Recall Pipeline       │   │        │  (cloud opt-in)          │   │
    │  │   (lexical+vec+graph)   │   │        │  TB-8 (HTTPS)            │   │
    │  └──────────┬──────────────┘   │        └──────────────────────────┘   │
    │             │                  │                                        │
    │  ┌──────────▼──────────────┐   │                                        │
    │  │   Storage Backend       │   │  ┌─────────────────────────────────┐  │
    │  │   (SQLite/libSQL/PG)    │   │  │  Obsidian Adapter               │  │
    │  │   TB-4                  │   │  │  (CLI daemon or plugin)         │  │
    │  └─────────────────────────┘   │  │  TB-6 (localhost or HTTPS)      │  │
    │                                │  └────────────────┬────────────────┘  │
    │  ┌─────────────────────────┐   │                   │                   │
    │  │  MCP / OpenClaw Adapter │   │                   │                   │
    │  │  TB-3                   │◄──┼───────────────────┘                   │
    │  └─────────────────────────┘   │                                       │
    │                                │  ┌──────────────────────────────────┐ │
    │  ┌─────────────────────────┐   │  │  Admin Client                    │ │
    │  │  Quarantine Garden      │   │  │  (admin API key)                 │ │
    │  └─────────────────────────┘   │  │  TB-7                            │ │
    └────────────────────────────────┘  └──────────────────────────────────┘ │
                                                                              │
                          └─────────────────────────────────────────────────-┘
```

### 2.3 Trust Boundaries

| ID | Boundary | From | To | Authentication |
|---|---|---|---|---|
| **TB-1** | Internet → Node API | Agents, end clients | Node HTTP API | API key (Argon2id hashed; legacy SHA-256 rows migrate on use) + TLS 1.3 |
| **TB-2** | Node ↔ Peer node | Federation replication | HTTP API on peer | mTLS (§22.1) + Ed25519 capability tokens (§19.3) |
| **TB-3** | Agent tool → Node | MCP / OpenClaw adapter | Node HTTP API | API key; tool call may carry adversarial content |
| **TB-4** | Node → Storage | Node process | DB file / libSQL / PG | Local filesystem or network (libSQL cloud) |
| **TB-5** | Node → Transparency log | Node | Rekor / Sigstore | TLS + Rekor API key (when used) |
| **TB-6** | Obsidian adapter → Node | Local plugin or CLI | Node HTTP API | API key stored in plugin config |
| **TB-7** | Admin → Node | Human / automation | Node admin API | Admin-scope API key |
| **TB-8** | Recall pipeline → Embedding | Node | Cloud embedding provider | Provider API key (opt-in only) |
| **TB-9** | Agent runtime → Instruction recall | Agent boot stub (§21.1) | Node `recall_instruction` tool via HTTP API | API key; `instruction:` scope; same transport as TB-1 |

---

## 3. Actors

| Actor | Description | Trust level |
|---|---|---|
| **Authenticated agent** | Holds a scoped API key; may call `assert_fact`, `query_facts`, `recall` within granted scope | Semi-trusted |
| **Admin operator** | Holds an admin API key; full control over keys, manifests, quarantine, quotas | Trusted |
| **Peer node** | Federation partner; authenticated via mTLS + capability token; write authority is scope-limited by the token | Conditionally trusted |
| **Obsidian plugin** | Local process with user-granted API key; same trust as authenticated agent | Semi-trusted |
| **Transparency log** | Append-only external service; provides verifiable audit of manifest rotations | Trusted read-only verifier |
| **LLM runtime** | Consumes recalled facts via MCP / OpenClaw adapter; may be prompt-injected | Untrusted content source |
| **Agent boot stub runtime** | Loads instructions via `recall_instruction` (§21.3); instruction content may be adversarially planted | Untrusted content source |
| **Data subject (RTBF requestor)** | End-user requesting fact erasure via §23 tombstone mechanism | External; interacts via admin |
| **External attacker** | Unauthenticated or credential-holding adversary attempting exploitation | Untrusted |

---

## 4. Assumptions

1. **Key confidentiality:** Ed25519 private signing keys are generated and stored on the operator's infrastructure. If a node signing key is compromised, the adversary can issue arbitrary capability tokens and org manifests. Key rotation (§22.2) and transparency log publication are the recovery mechanisms.
2. **API key storage:** API keys are Argon2id-hashed at rest in the current alpha implementation, using the [ADR-007](../../docs/adr/archive/007-argon2id.md) parameters (`m_cost=19456`, `t_cost=2`, `parallelism=1`). Legacy v0.9.0a1 SHA-256 rows remain accepted during the v0.9.x migration window and are opportunistically rehashed to Argon2id on first successful use with an `api_key_rehashed` audit event. Plaintext API keys are visible only at issuance time. Compromised keys must still be revoked and rotated via the admin API.
3. **mTLS as the federation transport:** TB-2 analysis assumes §22.1 mTLS deployment. Pre-§22.1 deployments (TLS only, no client cert) have a weaker peer-authentication posture; R-01 applies.
4. **SQLite at-rest encryption is opt-in (SQLCipher).** The default deployment does not encrypt the fact store at rest. Operators in regulated environments must enable SQLCipher explicitly.
5. **Recall sanitizer is best-effort:** The recall-time content sanitizer (§19.7) strips known prompt-injection sentinels, but cannot exhaustively detect all injection patterns in stored `value` fields.
6. **Cloud embedding is opt-in:** Fact content is not sent to external embedding services unless `STIGMEM_EMBED_MODEL_PROVIDER=openai` (or equivalent) is explicitly set.
7. **Transparency log availability:** §19.2 requires Rekor / Sigstore for org manifest verification. If the transparency log is unavailable, the node operates in a degraded verification mode (see §19.2.6 failure-closed behavior).
8. **Operator physical security:** The threat model assumes the node host is under operator control and not physically accessible to attackers. Physical access is out of scope.

---

## 5. Out of Scope

- Vulnerabilities in the static documentation site (`docs.stigmem.dev`) — no user data, no dynamic server-side logic.
- Attacks on third-party dependencies (libSQL cloud/Turso, PostgreSQL, Rekor) — report to upstream.
- Social engineering or phishing.
- Operator errors that bypass documented configuration controls (e.g., running as root, disabling TLS).
- Protocol-level weaknesses in Rekor or Sigstore itself.
- Physical server access.
- Rate-limiting / resource exhaustion scenarios with no clear security exploit path (tracked separately as availability concerns).

---

## 6. STRIDE Analysis

### 6.1 TB-1 — Internet / Agent → Node HTTP API

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T1-S1 | API key theft | Spoofing | Attacker obtains a leaked API key and impersonates a legitimate agent | Argon2id hashing at rest for new keys; legacy SHA-256 rows verify during v0.9.x and rehash on successful use; keys visible only at issuance; `expires_at` enforced (R-03 mitigated). | Key revocation must still be performed manually via admin API on suspected compromise. Legacy rows that are never used remain SHA-256-hashed until rotated or migrated explicitly. |
| T1-S2 | Unauthenticated endpoint access | Spoofing | Attacker reaches write endpoints without a valid key | All write endpoints require `Authorization` header | — |
| T1-T1 | Tampered fact payload | Tampering | Attacker replays or modifies a fact assertion with a stolen key | Facts are scoped; replay of old payloads creates duplicate, auditable facts | No per-request integrity seal beyond TLS |
| T1-R1 | Missing read audit trail | Repudiation | Agent reads sensitive-scope facts; no record of what was returned | Audit log (§22.3) — `fact_read` event type | **Mitigated** (R-09). Audit log persists with WAL ordering; 90-day retention. Residual: log retention is a security boundary; operators must monitor for log truncation. |
| T1-I1 | Cross-scope data leak via recall | Info. disclosure | Attacker uses a `public`-scoped key to reach `local` or `team` facts via the recall pipeline | Stage 2 ANN filter enforces scope (§20.3.3); garden ACL pre-filter at Stage 3 (§20.3.3) | Fuzz coverage of scope-isolation paths incomplete |
| T1-D1 | Resource exhaustion via recall | Denial of service | Attacker submits expensive graph-traversal recalls in a tight loop | Per-principal token-bucket quotas (§22.4) | **Mitigated** (R-02). Residual: operators who set `STIGMEM_RATE_LIMIT_*=0` in production silently re-open this risk; loud startup warning recommended. |
| T1-D2 | Vector store disk exhaustion | Denial of service | Attacker asserts millions of facts via a compromised key, filling the embedding index | `fact_write` quota dimension (§22.4.2) | **Mitigated** (R-02). Residual: per-fact quota does not bound aggregate storage; operators must monitor disk usage. |
| T1-E1 | Elevated-scope key misuse | Elevation of privilege | Agent with `team` scope writes to `local` scope or admin scope | Scope enforcement at API layer (§3.5) | — |

### 6.2 TB-2 — Node ↔ Peer Node (Federation)

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T2-S1 | Peer impersonation | Spoofing | Attacker acts as a legitimate peer node, injecting facts | mTLS mutual cert verification (§22.1); SAN ↔ entity_uri binding | Pre-§22.1 deployments lack mTLS (R-01) |
| T2-S2 | Org manifest spoofing | Spoofing | Attacker publishes a fraudulent manifest under a legitimate entity URI | Ed25519 signature on manifest; Rekor inclusion proof check (§19.2.6) | Rekor check is failure-closed but service may be unavailable |
| T2-T1 | Replay attack on capability token | Tampering | Attacker replays a previously valid capability token to write facts | Nonce + timestamp window ±5 min (§22.5.2); persistent nonce cache | Nonce cache survives restarts per §22.5.2; fuzz coverage (R-06) |
| T2-T2 | HLC cursor manipulation | Tampering | Malicious peer sends crafted HLC values to push the local HLC forward | Federation ingest rejects remote HLC wall times outside configured future/past skew bounds and emits `peer_hlc_anomaly` audit events | **Mitigated** (R-19). Residual: operators can widen/disable the past-skew bound for archival backfills and must monitor anomaly events. |
| T2-R1 | Unreported federation events | Repudiation | Federation connect/disconnect events not logged | `federation_connect` audit event (§22.3.1) | **Mitigated** (R-09). `federation_connect` audit event fires on every connect/disconnect. |
| T2-I1 | Cross-org scope leakage | Info. disclosure | Peer node reads facts beyond its capability token scope | Capability token verb/object validation (§19.3.3) | Partial: §22 amendments strengthen admission checks |
| T2-D1 | Replication queue flooding | Denial of service | Malicious peer sends a flood of replication requests | `federation_pull` quota (§22.4.2) | **Mitigated** (R-02). Per-peer `federation_pull` quota enforced. |
| T2-E1 | Excessive-scope capability token | Elevation of privilege | Token with wildcard or overly broad scope grants unwanted write authority | Token verb/object validation at admission; `subscribe` verb added to enum (§19.3.2) | Validator must reject scope claims not in token body (R-14) |

### 6.3 TB-3 — Agent Tool → Node (MCP / OpenClaw Adapter)

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T3-S1 | Indirect prompt injection | Spoofing | Adversarial content stored as a fact value is recalled and injects instructions into the LLM's context | ADR-003 capability model on `main`: `FactValue.interpret_as`, default content interpretation, `instruction:write` enforcement, instruction-channel separation in recall, federation-inbound instruction quarantine, and adapter directives for channel-separated consumers. Sanitizer (§19.7) remains defense-in-depth, not the primary control. | R-05 is in review while ADR-015 certification results and operator validation prove the L4-L6 consumer boundary. Novel injection patterns can still expose adapter/model behavior gaps. |
| T3-E2 | Instruction-channel promotion by adapter | Elevation of privilege | An adapter or agent runtime mistakenly treats untrusted content-channel facts as instruction-channel material, giving attacker-authored facts operational authority | Channel-separated recall output, `interpret_as` metadata, `instruction:write` for local instruction facts, and federation quarantine for inbound instruction-typed facts. Supported adapters must preserve channel separation and include `SYSTEM_PROMPT_DIRECTIVE`. | R-15 remains open until lazy-instruction admission/promotion policy and adapter conformance evidence cover all supported consumers. |
| T3-T1 | Entity URI injection | Tampering | Agent passes an unvalidated entity URI that triggers unexpected scope resolution | Pydantic validation at the API layer; URI format enforced | No semantic validation of URI namespace against agent's scope |
| T3-R1 | Tool calls unattributed | Repudiation | MCP tool calls not tied to a specific agent identity in the audit log | `fact_write` and `fact_read` audit events include `actor_entity` | API key must correctly identify the agent; shared keys lose attribution |
| T3-I1 | Cross-scope recall via tool | Info. disclosure | Agent exploits the recall pipeline to retrieve facts outside its granted scope | Scope enforcement at recall pipeline (§20.3.3) | Same as T1-I1 |
| T3-D1 | Recall loop via tool | Denial of service | Agent triggers expensive recalls in a loop (e.g., via prompt injection instructing it to recall repeatedly) | Per-agent token-bucket quotas (§22.4) | **Mitigated** (R-02, R-12). Per-agent quota dimension enforced. |
| T3-E1 | Tool surface exposed to admin scope | Elevation of privilege | Agent tool configured with an admin-scope API key, giving the LLM full admin authority | No technical control — requires operator configuration discipline | Operator education; least-privilege key issuance |

### 6.4 TB-4 — Node → Storage Backend

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T4-T1 | SQLite WAL corruption | Tampering | Attacker with filesystem access corrupts the WAL to alter facts silently | WAL checkpointing integrity; signed snapshots (§22 backup) | Node process must detect and refuse to serve corrupted data |
| T4-T2 | libSQL cloud MITM | Tampering | MITM on the Turso/libSQL cloud connection alters stored facts | TLS to libSQL cloud endpoint | No additional integrity seal beyond TLS at the application layer |
| T4-I1 | At-rest data exposure | Info. disclosure | Attacker with disk access reads the unencrypted SQLite file | SQLCipher at-rest encryption (opt-in only) | Default deployment stores facts in plaintext at rest (R-04) |
| T4-I2 | Cloud backend data residency | Info. disclosure | Facts stored in libSQL cloud may be subject to cloud provider data access | Operator-configured Turso account; Turso's data residency controls apply | No additional Stigmem-layer encryption of fact payloads |
| T4-D1 | Vector store growth (no cap) | Denial of service | Unbounded embedding index growth exhausts disk | `fact_write` quotas (§22.4.2) | pre-reset hardening; no eviction policy in the pre-reset v1.0-rc snapshot |

### 6.5 TB-5 — Node → Transparency Log (Rekor)

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T5-S1 | TLS cert spoofing on Rekor endpoint | Spoofing | Attacker intercepts the Rekor HTTPS connection to serve a fraudulent log | Standard TLS cert validation; Rekor log consistency checks (Merkle tree) | — |
| T5-T1 | Tampered log entry | Tampering | Attacker alters a submitted Rekor entry | Rekor's Merkle tree and inclusion proofs; `inclusion_proof_invalid` error (§19.2.6) | — |
| T5-R1 | Rotation events not logged | Repudiation | Node rotates org manifest without submitting a transparency log entry | §22.2.3 requires a `key_rotation` log entry on every rotation | Not enforced in the pre-reset v1.0-rc snapshot; pre-reset hardening delivery (R-10) |
| T5-D1 | Rekor unavailability blocks operations | Denial of service | Rekor outage prevents manifest verification, blocking federation | Failure-closed behavior in §19.2.6 (`transparency_log_unavailable` 503) | Operational; operators should monitor Rekor availability |

### 6.6 TB-6 — Obsidian Adapter → Node

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T6-S1 | API key in plaintext settings | Spoofing | Obsidian plugin settings file contains the API key in plaintext; other plugins may read it | Obsidian settings are local to the user's device | Key compromise requires local filesystem access (R-07) |
| T6-T1 | Vault file tampering via adapter | Tampering | Adapter writes unexpected changes back to vault files without user awareness | Conflict surfacing via Obsidian markdown comments; user reviews conflicts | Automated sync may overwrite user edits if conflict detection fails |
| T6-R1 | Sync operations not fully logged | Repudiation | Adapter performs bulk sync without recording which facts were written | `fact_write` audit events on the node side | Adapter itself has no persistent sync log |
| T6-I1 | Plugin reads full vault | Info. disclosure | Plugin holds read access to all vault notes, not just those in the configured sync folder | Scope configuration in plugin settings; enforcement is local | No technical scope enforcement at the filesystem level |
| T6-D1 | Retry storms on partition | Denial of service | Network partition causes adapter to flood the node with retry requests | Exponential backoff in adapter | No per-adapter quota dimension; covered by `fact_write` quota |
| T6-E1 | Plugin settings exposed to other plugins | Elevation of privilege | Malicious Obsidian plugin reads the Stigmem API key from settings | Obsidian settings are user-local; no cross-plugin isolation guarantee | Operator education; rotate key if another plugin is suspected |

### 6.7 TB-7 — Admin → Node

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T7-S1 | Admin key compromise | Spoofing | Attacker obtains an admin API key, gaining full node control | Admin keys use the same Argon2id-at-rest and legacy rehash path as agent keys; enforced `expires_at` (R-03 mitigated); admin key max-age 90 days default. | Key rotation not yet automated; admin must rotate manually via admin API. Legacy admin rows that are never used remain SHA-256-hashed until rotated or migrated explicitly. |
| T7-T1 | Malicious manifest publish | Tampering | Admin key used to publish a fraudulent org manifest | Manifest signature checked before publish | Compromised admin key can produce a validly-signed fraudulent manifest |
| T7-R1 | Admin operations not separately logged | Repudiation | Admin API calls not in a separate audit trail | `admin_action` audit event type (§22.3.1) | **Mitigated** (R-09). `admin_action` audit event fires on every admin-API call. |
| T7-D1 | Quota abuse via admin key | Denial of service | Admin key bypasses principal quotas, enabling self-DoS | Admin quota dimension ceilings apply (§22.4) | Admin may override quota policies by design |

### 6.8 TB-8 — Node → Cloud Embedding Service (opt-in)

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T8-S1 | Embedding provider API key exposed | Spoofing | Provider API key in environment config is leaked | Key stored in env var (not committed to source) | Rotation requires redeployment (R-13) |
| T8-T1 | Poisoned embeddings | Tampering | Cloud provider returns adversarially crafted embeddings to manipulate recall ranking | Not controlled at the node layer | No integrity check on returned embedding vectors |
| T8-I1 | Fact content sent to external service | Info. disclosure | Every `"{entity} {relation} {value}"` string is sent to the cloud embedding API | Opt-in only; default is offline nomic-embed-text-v1.5 | Operators must understand data flows before enabling cloud embed |
| T8-D1 | Provider rate limits block recall | Denial of service | Cloud embedding rate limit causes recall failures | Per-provider retry with backoff; local fallback if configured | No automatic local fallback in pre-reset draft |

### 6.9 TB-9 — Agent Runtime → Instruction Recall (§21 Lazy Instruction Discovery)

*Added in Rev 2.0. §21 is Normative in v2.0.*

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T9-S1 | Instruction manifest spoofing | Spoofing | Attacker with `instruction:` scope write access stores a fraudulent instruction manifest that overrides the agent's heartbeat contract | Scope enforcement at API layer (§3.5); only keys with `write` on `instruction:` scope can write | Any agent or system holding `write` on `instruction:` scope is a potential vector — least-privilege key issuance is critical |
| T9-T1 | Adversarial instruction injection | Tampering | Attacker plants adversarial content in an `instruction:` scope fact that the agent loads as operational instruction via `recall_instruction`; unlike T3-S1 (prompt injection in recalled data), injection here lands in the system/instruction context before task processing begins | Local instruction-typed writes require `instruction:write`; instruction facts are returned in the `instructions` channel; federation-inbound instruction-typed facts fail closed into quarantine until operator promotion. Sanitizer (§19.7) remains defense-in-depth. | R-15 remains open because instruction admission/promotion policy and complete supported-adapter conformance evidence are still required before treating instruction-authoring authority as fully controlled. |
| T9-R1 | Instruction loads unattributed | Repudiation | `recall_instruction` calls not tied to agent identity in audit log if a shared API key is used | `instruction_audit` event type in §22.3.1 audit log | Shared keys lose per-agent attribution |
| T9-I1 | Cross-agent instruction leakage | Info. disclosure | Agent with `instruction:` read scope may retrieve instruction documents intended for a different agent | Scope namespacing (e.g., `instruction:acme/agent/cto/` vs `instruction:acme/agent/engineer/`) | Namespace isolation is by convention, not enforced by the protocol; misconfigured key scope allows cross-agent reads |
| T9-D1 | Instruction manifest flooding | Denial of service | Attacker floods the `instruction:` scope with large manifests, exhausting storage or degrading recall latency | Per-principal write quotas (§22.4, R-02 mitigated) | Quota applies but instruction: scope writes share the `fact_write` bucket with regular writes |
| T9-E1 | Instruction-scope key with effective admin power | Elevation of privilege | An agent holding `write` on `instruction:` scope can inject directives that cause other agents to perform privileged operations (e.g., "escalate everything to done", "ignore approval gates") | Boot stub MUST embed unconditional prohibitions directly (§21.1.1 guidance: always-applicable rules bypass lazy-load) | Operators must audit which agents hold `instruction:` write scope — this permission is functionally equivalent to agent instruction authoring |

---

### 6.10 TB-7 additions — Tombstones and Time-Travel (§23, §24)

*Added in Rev 2.0. These threats extend TB-7 (Admin → Node) with new v2.0 admin API surfaces.*

| # | Threat | Class | Description | Existing control | Residual risk |
|---|---|---|---|---|---|
| T7-T2 | Tombstone forgery | Tampering | Attacker forges a tombstone record (§23) to suppress legitimate facts by crafting a plausible `TombstoneRecord` without a valid Ed25519 signature | Ed25519 signature on tombstone (§23.2.4); `signed_by` must hold admin API key | Requires admin key compromise (T7-S1); if compromised, attacker can issue validly-signed tombstones |
| T7-T3 | Tombstone `valid_until` extension via CID bypass | Tampering | Federated peer extends a fact's `valid_until` field without changing its CID (§25.2.1 known limitation), keeping tombstoned facts alive past their expiry in peers that accept the extended timestamp | Spec §25.2.1 mandates local rejection of `valid_until` extensions beyond observed values | Implementation must enforce this check; see R-18 |
| T7-I1 | Legal-hold historical data exposure | Info. disclosure | After RTBF tombstone with `legal_hold: true`, admin key compromise leaks pre-tombstone historical facts via `as_of` time-travel queries (§24.3.2) | Legal-hold `as_of` responses restricted to admin API keys; `rtbf_legal_hold_issued` audit event required | Admin key compromise post-tombstone retroactively exposes erased data — see R-17 |
| T7-D2 | Tombstone DoS | Denial of service | Attacker with compromised admin key issues tombstones for key entity URIs, permanently suppressing facts and disrupting dependent agents | Tombstone requires admin key (`signed_by` MUST hold active admin API key at issuance); `admin_action` audit event | Tombstone is irreversible without a `TombstoneRevocation` record — blast radius is high for any entity tombstoned (R-16) |

---

## 7. Risk Register

Each risk is rated on:
- **Likelihood**: High / Medium / Low (given the current deployment baseline, not worst-case)
- **Impact**: Critical / High / Medium / Low
- **Priority**: product of the two

Machine-readable evidence for risks marked **Mitigated** lives in
[`evidence-registry.json`](evidence-registry.json). CI validates that each
mitigated risk has implementation files, test files, docs/reference files,
version-introduced metadata, and a review decision.

| ID | Threat refs | Finding | Likelihood | Impact | Priority | Spec ref | Status | Closed by |
|---|---|---|---|---|---|---|---|---|
| R-01 | T2-S1 | No mTLS: federation peer impersonation possible without client cert verification | Medium | High | High | §22.1 | **Mitigated** | pre-reset hardening: `tls.py` (TLS 1.3 floor, `CERT_REQUIRED`), `test_mtls.py` (491 lines) |
| R-02 | T1-D1, T1-D2, T3-D1 | No per-principal rate limits on writes and recalls | High | Medium | High | §22.4 | **Mitigated** | pre-reset hardening: `rate_limit.py` token-bucket quotas, migration `022_quota_buckets.sql`, `test_quota.py`. Kill-switch at both limits=0 (dev only). |
| R-03 | T1-S1, T7-S1 | No enforced API key max-age; keys do not expire | Medium | High | High | §22.2 | **Mitigated** | pre-reset hardening: `expires_at` enforced in `auth.py:113`; `key_rotation.py`; `test_phase12_key_rotation.py` (799 lines). |
| R-04 | T4-I1 | At-rest encryption (SQLCipher) opt-in; default deployment stores facts in plaintext | Medium | High | High | §3 | **Accepted** | Deliberate tradeoff for deployment simplicity; operators in regulated environments must enable SQLCipher. |
| R-05 | T3-S1, T9-T1 | Prompt injection via adversarial facts recalled into agent context; now also via `instruction:` scope (§21) | High | High | Critical | §19.7, §22.5, [ADR-003](../../docs/adr/003-prompt-injection.md), [ADR-015](../../docs/adr/015-adversarial-conformance-and-model-certification.md) | **In review** | Mitigated by capability model in progress: ADR-003 controls now exist on `main` (`interpret_as`, `instruction:write`, channel-separated recall, instruction quarantine, supported-adapter directive framing), and sanitizer remains defense-in-depth. ADR-015 now provides the 80-pattern corpus plus offline and provider-backed runner paths. R-05 stays in review until live certification evidence and operator validation close the L4-L6 consumer boundary. R-15 is the instruction-scope variant; R-21 is the write-side feedback-loop variant. |
| R-06 | T2-T1 | Federation replay protection fuzz test coverage incomplete | Low | High | Medium | §22.5 | **Mitigated** | pre-reset hardening: `test_phase12_replay_fuzz.py` (394 lines); nonce cache survival test. |
| R-07 | T6-S1 | Obsidian plugin API key stored in plaintext settings | Low | Medium | Low | — | **Accepted** | Requires local filesystem access; rotate key if another plugin suspected. |
| R-08 | T4-T2, T4-I2 | libSQL cloud backend: facts in transit to Turso without additional app-layer encryption | Medium | Medium | Medium | §3.2 | **Accepted** | Operator TLS; Turso data residency controls apply. |
| R-09 | T1-R1, T7-R1 | No general-purpose audit log for sensitive scope reads or admin actions | High | Medium | High | §22.3 | **Mitigated** | pre-reset hardening: `audit_event.py` (14 event types including `api_key_rehashed`, WAL semantics, `fact_audit_log` table); `routes/admin_audit.py`; `test_admin_audit.py` (205 lines). |
| R-10 | T5-R1 | Org manifest rotation events not consistently submitted to transparency log | Low | Medium | Low | §19.2.6, §22.2.3 | **Mitigated** | pre-reset hardening: `key_rotation.py` emits `KeyRotationLogEntry` before activation; `key_rotation` audit event (§22.3.1). |
| R-11 | — | Container not distroless; Linux capabilities not fully dropped | Low | Low | Low | §22.6 | **Mitigated** | pre-reset hardening: `Dockerfile` updated to distroless base, non-root UID 1000, `readOnlyRootFilesystem`, seccomp; Helm chart updated. |
| R-12 | T3-D1, T3-E1 | Agent tool surface: no per-agent budget or rate limit without §22.4 | High | Medium | High | §22.4 | **Mitigated** | Same as R-02; per-agent quota dimension in §22.4. |
| R-13 | T8-I1 | Cloud embedding opt-in: fact content sent to external provider when enabled | Low | Medium | Low | §20.2 | **Accepted** | Opt-in only; default is offline nomic-embed-text-v1.5. Operators must review data classification before enabling. |
| R-14 | T2-E1 | Capability token scope/verb not fully validated at federation admission in the pre-reset v1.0-rc snapshot | Low | High | Medium | §19.3.3 | **Mitigated** | pre-reset hardening: normative verb/object validation in `identity/capability.py`; §22 amendments shipped. |
| R-15 | T3-E2, T9-T1, T9-E1 | Instruction-scope write confers effective instruction-authoring authority over any agent using §21 lazy discovery | Low | Critical | High | §21.1, §3.5 | **Open** | Canonical feature analysis: [`features/lazy-instruction-discovery/security.md`](../../features/lazy-instruction-discovery/security.md). Partial mitigation shipped in #373/#375/#377: facts now carry `value.interpret_as`, local instruction-typed writes require `instruction:write`, recall returns instruction-typed facts through the `instructions` channel, federation-inbound instruction-typed facts fail closed into quarantine, and protocol adversarial vectors cover forged instruction capability and inbound instruction quarantine. R-15 remains open until lazy-instruction admission/promotion policy and supported-adapter conformance evidence cover all consumers. |
| R-16 | T7-D2 | Admin key compromise enables tombstone DoS: irreversible entity suppression (§23) | Low | High | Medium | §23.2 | **Open** | Canonical feature analysis: [`features/tombstones/security.md`](../../features/tombstones/security.md). Protocol summary: tombstones are admin-only and auditable, but compromised admin credentials can still suppress critical entities until revocation and recovery procedures land. |
| R-17 | T7-I1 | Legal-hold tombstone + admin key compromise leaks pre-tombstone historical facts via `as_of` (§24) | Low | High | Medium | §24.3.2 | **Open** | Canonical feature analysis: [`features/tombstones/security.md`](../../features/tombstones/security.md). Protocol summary: `legal_hold: true` preserves historical data for admin-only time-travel reads, so legal-hold access needs narrower capability and regression coverage. |
| R-18 | T7-T3 | Federated peer can extend `valid_until` or supply inflated `source_trust` without changing CID (§25.2.1 exclusion) | Low | Medium | Low | §25.2.1 | **Open** | Spec §25.2.1 mandates local `valid_until` extension rejection and local `source_trust` recomputation. Implementation compliance should be verified in integration tests; no regression test currently covers this path. |
| R-19 | T2-T2 | Malicious peer manipulates HLC values to push local clock forward; no current normative bound on accepted skew across the federation | Medium | Medium | Medium | §22.5 | **Mitigated** | Alpha-line hardening: `HLC.receive()` accepts configured future/past skew bounds; federation ingest rejects out-of-bound remote HLC values before fact insertion, emits `peer_hlc_anomaly`, and increments `stigmem_peer_hlc_anomaly_total`. Default future bound: 300s. Default past bound: 30d; set to 0 only for explicit archival backfill. |
| R-20 | T8-T1 | Cloud embedding provider returns adversarially-crafted embedding vectors to manipulate recall ranking | Low | Medium | Low | §20.2 | **Accepted** | Operator opt-in only; node layer does not check returned vectors. Operators must classify data and review provider terms before enabling. Periodic local re-embed sampling for divergence detection is a v2.0+ follow-up. |
| R-21 | T3-S1 (write-side) | Agent feedback-loop worm: an LLM-driven agent compromised via prompt injection (T3-S1) uses its own writer key to assert attacker-chosen facts; those facts replicate across the federation, infecting peer agents and propagating compromise | Medium | High | High | ADR-003, §22 (proposed) | **In review** | Structural controls shipped across #371 and #394: callers that set `Stigmem-Session` get per-session read/write graph isolation; same-scope writes after reads are rejected unless `write_mode="summarize_with_provenance"` carries source-fact provenance; supported MCP/OpenClaw/Python/TypeScript surfaces now propagate sessions and provenance; outbound federation pull excludes provenance-derived facts. R-21 stays in review until release certification and operator validation cover these controls. |
| R-22 | T10-S1, T10-T1, T10-R1 | Compromised build pipeline produces a backdoored stigmem release; operators install and run malicious code without an attestation path | Low | Critical | High | §22.7 (proposed) | **Open** | Mitigation pending: Sigstore-signed releases, reproducible builds, SBOM publication, Rekor entries for every release. Future stable-readiness deliverable. |
| R-23 | T2-T1, T3-T1, T8-T2 (storage layer) | **Admin-level storage tampering / fact mutation attack.** Attacker with admin privileges on a stigmem node (via supply-chain compromise, credential theft, insider threat, or operator error) overwrites existing facts in storage. By mutating `value_v` and/or `interpret_as`, the attacker bypasses ADR-003's structural defenses: a fact mutated to `interpret_as = "instruction"` flows through the recall pipeline's `instructions` channel, is rendered as legitimate instruction by the adapter, and is executed by the consuming LLM. Outcome: data exfiltration, host compromise via downstream agent actions, federation-propagated worm behavior. | Low (requires admin compromise) | **Critical** (bypasses ADR-003 trust boundary; can lead to RCE on host infrastructure via downstream agents) | High | ADR-016, ADR-003 § Trust boundary | **Open** | Mitigation: ADR-016 storage immutability stack — L1 (architectural append-only journal + projection tables), L2 (SQLite triggers blocking UPDATE/DELETE on `facts`), L3 (CIDs covering `interpret_as` per ADR-011), L4 (local hash chain), L5 (Sigstore Rekor external transparency log anchor). Without L5, no local enforcement defeats an admin-level attacker; with L5 plus client/peer verification, tampering becomes detectable by anyone comparing local state to the witness. Targeted: future hardened-core work. Default install ships with all five layers; verification on cross-org reads is on by default. WORM storage and TEE execution are documented deployment options for higher-assurance threat models. |
| R-24 | T2-S1 | **Non-loopback insecure federation deployment.** Federation could be deployed without transport security via operator override outside loopback. | Medium | **Critical** | Critical | §22.1 | **Mitigated** | v0.9.0a2 hardening: startup refuses insecure federation mode when `node_url` is non-loopback; regression coverage in startup-configuration tests. Closed by [GHSA-jmfc-hfjq-pxcp](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-jmfc-hfjq-pxcp). Residual: an operator who edits the startup guard can re-open the risk; that is outside Stigmem's supported deployment posture. |
| R-25 | T1-S1, T7-S1 | **Non-loopback auth-disabled deployment.** Anonymous full-permission identity could be exposed if authentication is disabled outside loopback. | Medium | **Critical** | Critical | §22.2 | **Mitigated** | v0.9.0a2 hardening: startup refuses `STIGMEM_AUTH_REQUIRED=false` when `node_url` is non-loopback; regression coverage in startup-configuration tests. Closed by [GHSA-fp6w-8wpg-74g5](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-fp6w-8wpg-74g5). Residual: local development mode remains supported on loopback only. |
| R-26 | T2-S1 | **Federation peer registration trust on first use.** Federation peer public keys were trust-on-first-use without out-of-band confirmation. | Medium | **High** | High | §6 federation registration | **Mitigated** | v0.9.0a2 hardening: peer registration creates `pending_approval`; admin approval is required before the peer becomes active; peer tokens for pending peers are rejected. Closed by [GHSA-9vp8-3hmv-8fgh](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9vp8-3hmv-8fgh). Residual: an admin can still approve the wrong fingerprint; operator docs should direct admins to compare the presented fingerprint out of band. |

### Risk register key

- **Open** — not yet mitigated; requires design decision or implementation work.
- **In review** — structural controls have landed, but certification, operator
  validation, or rollout evidence is still required before marking mitigated.
- **Mitigated** — control implemented and verified (code and test exist); no residual risk beyond stated notes.
- **Residual** — partially mitigated; residual risk documented and accepted.
- **Accepted** — risk acknowledged; no planned mitigation for the stated reason.

### Risk ownership and colocation queue

Upstream validation F-09 specifically checked R-19 through R-22. Their current
ownership is:

| Risk | Current status | Ownership / colocation |
|---|---|---|
| R-19 | Mitigated | Protocol-level, cross-cutting federation risk. Evidence is recorded in `spec/security/evidence-registry.json`; no per-feature `security.md` owner. |
| R-20 | Accepted | Protocol-level operator opt-in risk for cloud embedding. Tracked in the unified register and experimental feature index; no v0.9.x mitigation planned. |
| R-21 | In review | Protocol-level cross-cutting risk. Contributor notes now live in [`features/lazy-instruction-discovery/security.md`](../../features/lazy-instruction-discovery/security.md), [`features/memory-garden-acl/security.md`](../../features/memory-garden-acl/security.md), and [`features/multi-tenant/security.md`](../../features/multi-tenant/security.md). |
| R-22 | Open | Protocol-level release-engineering risk. Stays in this register until the future signed-release pipeline lands. |

Per-feature owned risks are colocated under the owning feature record or, for
unmigrated features, under the owning experimental feature:
R-15 in [`features/lazy-instruction-discovery/security.md`](../../features/lazy-instruction-discovery/security.md)
and R-16/R-17 in [`features/tombstones/security.md`](../../features/tombstones/security.md).
R-18 and R-21 are intentionally protocol-level per ADR-020 §11 (security taxonomy) because CIDs are
core and the worm vector is structurally cross-cutting.

Feature-local security analysis also exists for material contributors without
owned risks: [`features/time-travel/security.md`](../../features/time-travel/security.md)
records R-17/R-18 contributions, [`features/source-attestation/security.md`](../../features/source-attestation/security.md)
records the R-22 release-supply-chain boundary, and
[`features/multi-tenant/security.md`](../../features/multi-tenant/security.md)
records tenant-boundary contributions to R-01, R-02, and R-21. Adapter,
deployment, SDK, dashboard, and workbench directories under `experimental/`
remain covered by their `STATUS.md` files and this protocol-level register
until they own or materially contribute to a numbered R-XX risk.

---

## 8. Mitigations Summary

### 8.1 Hardening shipped and verified (pre-reset baseline carried forward to v0.9.0a1)

| Risk | Mitigation | Spec section | Evidence |
|---|---|---|---|
| R-01 | mTLS on all federation ports; TLS 1.3 floor; SAN/entity_uri binding | §22.1 | `tls.py`; `test_mtls.py` (491 lines) |
| R-02 | Per-principal token-bucket quotas on 7 dimensions | §22.4 | `rate_limit.py`; `test_quota.py`; migration `022_quota_buckets.sql` |
| R-03 | Enforced key max-age (`expires_at`); rotation runbook | §22.2 | `auth.py:113`; `key_rotation.py`; `test_phase12_key_rotation.py` (799 lines) |
| R-05 | Capability-model prompt-injection controls in review: `FactValue.interpret_as`, `instruction:write`, channel-separated recall, federation instruction quarantine, and sanitizer defense-in-depth | §19.7, §22.5, ADR-003, ADR-015 | `test_phase12_replay_fuzz.py`; protocol adversarial vectors; ADR-015 corpus and runner |
| R-06 | Fuzz tests on federation replay protection; nonce cache survival test | §22.5 | `test_phase12_replay_fuzz.py` |
| R-09 | 14-event-type audit log with WAL ordering and 90-day retention | §22.3 | `audit_event.py`; `routes/admin_audit.py`; `test_admin_audit.py` (205 lines) |
| R-10 | `key_rotation` log entry mandatory on every rotation; logged before activation | §22.2.3 | `key_rotation.py` |
| R-11 | Distroless base image; non-root UID 1000; read-only fs; seccomp | §22.6 | `Dockerfile`; Helm chart |
| R-12 | Per-agent quota dimension (same as R-02) | §22.4 | Same as R-02 |
| R-14 | Normative verb/object validation at capability token admission | §19.3.3 | `identity/capability.py` |
| R-19 | Bounded inbound remote-HLC skew with `peer_hlc_anomaly` audit evidence | §22.5 | `hlc.py`; `federation_ingest.py`; `test_failure_modes.py` |

### 8.2 Open risks — require follow-up

| Risk | Recommended mitigation | Priority |
|---|---|---|
| R-15 | Finish the instruction admission boundary: require explicit promotion policy for lazy-instruction use and supported-adapter conformance evidence. Local writes require `instruction:write` as of #373; federation-inbound instruction-typed facts quarantine or fail closed as of #375; protocol adversarial vectors now cover forged instruction capability and inbound instruction quarantine. | High |
| R-16 | Document tombstone-DoS runbook; require second admin approval for tombstone issuance on entity URIs with >N dependent agents | Medium |
| R-17 | Add integration test asserting that non-admin keys cannot access legal-hold `as_of` facts; add operator runbook for legal-hold management | Medium |
| R-18 | Add integration test: assert federation ingest rejects `valid_until` extension and local `source_trust` re-computation; link to §25.2.1 | Low |
| R-22 | Ship Sigstore-signed releases, reproducible builds, SBOM publication, and Rekor entries for every release artifact | High |
| R-23 | Implement ADR-016 storage immutability stack and verification on cross-org reads | High |

---

## 9. In-Review, Residual, and Open Risk — v0.9.0a1 baseline

Pre-reset hardening is complete. The following risks remain in the v0.9.0a1 baseline (carried forward from pre-reset). R-05 is no longer tracked as sanitizer-only residual risk: structural capability controls have landed and the risk is in review until certification evidence and operator validation close the L4-L6 consumer boundary.

> **Static-analysis triage note (Rev 2.2):** The CodeQL alerts surfaced on 2026-05-11 (8 high-severity findings against `node/src/stigmem_node/routes/` and `storage/postgres_backend.py`) were reviewed against this residual register and produced **no new R-XX entries**. All 8 were taint-analyzer precision-gap false positives, not vulnerabilities. Structural remediation landed in [PR #117](https://github.com/eidetic-labs/stigmem/pull/117); permanent rationale lives in [`SECURITY.md`](../../SECURITY.md#group-c--codeql-static-analysis-alerts-8-alerts-closed-by-structural-refactor) Group C and [`audit-triage.md`](audit-triage.md).

### 9.1 Carried from pre-reset (unchanged)

1. **Prompt injection (R-05)** is in review. ADR-003 structural controls now separate content from instruction material (`FactValue.interpret_as`, `instruction:write`, channel-separated recall, and federation instruction quarantine), while the sanitizer (§19.7) remains defense-in-depth. ADR-015 now provides the corpus and offline/provider-backed runner paths; R-05 cannot move to mitigated until live certification evidence and operator validation close the L4-L6 consumer boundary. See R-15 for the distinct instruction-admission risk.

2. **At-rest encryption (R-04)** is operator-configurable but not default-on. Operators handling regulated data must explicitly enable SQLCipher. This is a deliberate tradeoff for deployment simplicity.

3. **Obsidian plugin key storage (R-07)** depends on OS keychain or Obsidian's own plugin isolation. Rotate keys promptly if another plugin is suspected of access.

4. **Cloud embedding data residency (R-13)** is accepted for opt-in cloud embedding. Operators must review data classification before enabling.

### 9.2 New residual risks from v2.0 features

5. **Instruction-scope write authority (R-15)** remains the highest-priority instruction-admission risk. Local instruction-typed writes now require `instruction:write`, inbound federation instruction facts quarantine or fail closed, and protocol adversarial vectors cover forged instruction capability plus inbound instruction quarantine. R-15 remains open until lazy-instruction admission/promotion policy and supported-adapter conformance evidence cover all consumers. Operators must keep `instruction:write` grants rare and audit them as instruction-authoring authority.

6. **Tombstone DoS (R-16)** is irreversible without a `TombstoneRevocation` record. Admin key compromise that leads to tombstone issuance cannot be automatically remediated. Operators must rotate admin keys immediately on suspected compromise.

7. **Legal-hold data exposure (R-17)** means RTBF-tombstoned data with `legal_hold: true` remains accessible via time-travel queries to admin key holders. Data subjects should be informed that legal holds preserve historical data for lawful purposes.

8. **CID field-exclusion tampering (R-18)** is a protocol-level correctness concern: `valid_until` extension and `source_trust` inflation by federation peers must be rejected locally per §25.2.1. Integration test coverage is needed to confirm this invariant holds in the implementation.

9. **Embedding poisoning (R-20)** is accepted for cloud-embedding deployments. Local nomic-embed (default) is not affected. Operators enabling cloud embedding accept that adversarial vector manipulation cannot be detected at the node layer in v0.9.0a1.

10. **Agent feedback-loop worm (R-21)** is in review. Stigmem now exposes `Stigmem-Session` read/write graph isolation: writes into scopes read earlier in the same session require `write_mode="summarize_with_provenance"` with source-fact provenance. Supported MCP/OpenClaw/Python/TypeScript surfaces propagate sessions and provenance, and outbound federation pull excludes provenance-derived facts. R-21 remains in review until release certification and operator validation cover these controls.

11. **Release supply-chain integrity (R-22)** is unmitigated. v0.9.0a1 releases are unsigned; operators cannot cryptographically verify that an installed binary corresponds to a published commit. Sigstore-signed releases are a future stable-readiness deliverable.

12. **Admin-level storage tampering (R-23)** is the most severe new structural risk identified in v0.9.0a1. An attacker with admin privileges on a stigmem node can — without ADR-016's mitigations — overwrite stored facts, bypassing ADR-003's prompt-injection trust boundary by silently changing `interpret_as` from `content` to `instruction` at the storage layer. Mitigation is the ADR-016 stack (L1-L5: architectural append-only journal, SQLite triggers, CIDs, local hash chain, Sigstore Rekor anchor). Targeted: future hardened-core work. Until ADR-016 lands, operators MUST treat the stigmem node host as a high-trust environment; admin compromise of the host is a critical-severity incident with no architectural mitigation.

---

## 10. Review and Maintenance

- This threat model is reviewed on every spec revision that introduces a new trust boundary or modifies an existing one.
- **Rev 2.8 (2026-05-16):** Completed the hardened-core documentation map: added feature-local security files for time-travel, source-attestation, and multi-tenant; documented why other experimental adapter/deployment/SDK/workbench directories do not receive `security.md` until they own or materially contribute to a numbered risk; and added the operator-facing navigation page for where security analysis lives.
- **Rev 2.7 (2026-05-16):** Moved R-21 from **Open** to **In review** after #394 closed the remaining structural worm-boundary gaps: supported adapter/session propagation for MCP and OpenClaw, Python/TypeScript SDK session/provenance options, and outbound pull-replication exclusion for provenance-derived facts. R-21 still requires release certification and operator validation before mitigation status.
- **Rev 2.6 (2026-05-16):** Closed the hardened-core prompt-injection status pass. R-05 moved from sanitizer-only residual framing to **In review** after ADR-003 structural controls and ADR-015 corpus/runner infrastructure landed; R-15 gained a TB-3 adapter-promotion STRIDE row and now records the remaining admission/promotion-policy and adapter-conformance evidence; R-21 status now separates landed same-session provenance controls and OpenClaw handoff allowlisting from remaining adapter/session propagation plus outbound replication exclusion work.
- **Rev 2.5 (2026-05-15):** Implemented ADR-020 §11 (security taxonomy) colocation for feature-owned security analysis. R-15 canonical analysis moved to `experimental/lazy-instruction-discovery/security.md`; R-16/R-17 canonical analysis moved to `experimental/tombstones/security.md`; R-21 contributor notes added for lazy instruction discovery and memory garden ACLs. Added CI validation for per-feature security frontmatter, risk IDs, cross-references, and public-doc isolation from private planning paths.
- **Rev 2.4 (2026-05-13):** Upstream-validation F-09 status review. Confirmed R-19, R-20, R-21, and R-22 exist in the unified risk register; updated stale rendered-status surfaces after R-19's mitigation landed; recorded R-20 through R-22 in `spec/security/evidence-registry.json`; added explicit risk ownership / per-feature colocation queue notes per ADR-020 §11 (security taxonomy).
- **Rev 2.3 (2026-05-13):** Acknowledged-risk triage for CodeQL [alert #34](https://github.com/eidetic-labs/stigmem/security/code-scanning/34) (`py/weak-sensitive-data-hashing`) on `auth.py:67`'s `_legacy_sha256` function. The alert is **not a false positive** — SHA-256 is computationally weak for password hashing — but the function is the legacy verification path of [ADR-007](../../docs/adr/archive/007-argon2id.md)'s dual-mode migration window, deliberately retained so v0.9.0a1-issued API keys remain verifiable while opportunistically re-hashing to Argon2id (`api_key_rehashed` audit event). No new R-XX risk entry: the residual is already captured in §4 Assumption 2 and the T1-S1 / T7-S1 STRIDE rows. Disposition: dismissed in GitHub UI with reason `won't fix`; retirement milestone is v1.0.0 GA (bulk re-hash migration deletes the function). Full rationale in [`audit-triage.md`](audit-triage.md) § "CodeQL — acknowledged risks (ADR-tracked remediation)" and [`SECURITY.md`](../../SECURITY.md) Group C sub-category.
- **Rev 2.2 (2026-05-11):** CodeQL code-scanning alert triage. 8 open high-severity alerts (7× `py/sql-injection` in conditional SQL-fragment builders within `node/src/stigmem_node/routes/`; 1× `py/polynomial-redos` in `node/src/stigmem_node/storage/postgres_backend.py`) classified as **false positives**. Root cause: taint-analyzer precision gap on Python's conditional-string-fragment assembly and transitive taint into `_pg_translate`'s regex. No new R-XX risk entries — the conditions for exploitation do not exist: every user-supplied value is parameter-bound, every interpolated SQL fragment is a string literal, and the regex inputs are developer-authored migration SQL (not user-flowable). Structural remediation (refactor to constant-SQL pattern; `(? IS NULL OR col = ?)` gating) landed in [PR #117](https://github.com/eidetic-labs/stigmem/pull/117); full per-alert rationale persisted in [`SECURITY.md`](../../SECURITY.md#group-c--codeql-static-analysis-alerts-8-alerts-closed-by-structural-refactor) Group C and [`audit-triage.md`](audit-triage.md). The Audit Tooling table in `SECURITY.md` is updated to include CodeQL alongside `pip-audit` / `pnpm audit` / `bandit`.
- **Rev 2.1 (2026-05-09):** Re-versioned to v0.9.0a1 baseline per ADR-001 + ADR-001; risk register expanded with R-19 (HLC manipulation), R-20 (embedding poisoning), R-21 (agent feedback-loop worm), R-22 (release supply-chain), R-23 (admin-level storage tampering, per ADR-016); §9.2 residual list updated; the pre-reset v1.0-rc snapshot retracted-label posture preserved as historical context. STRIDE residual columns and §1 opening line edits per master-checklist §4.3 P0-3 are staged for follow-up.
- **Rev 2.0 (2026-05-05) [retracted label]:** pre-reset hardening items closed; spec sections §21–§25 modeled; SHA-256/Argon2id documentation corrected; R-15–R-18 added. Per ADR-001, the v2.0 announcement was withdrawn; the substantive work in this revision (pre-reset hardening closure evidence, R-15–R-18 entries) carries forward to v0.9.0a1.
- R-05 and R-21 are In review; R-15, R-16, R-17, R-18, R-22, and R-23 are Open and require implementation or documentation follow-up — see §8.2 for recommended mitigations.
- Community pen-test findings that fall outside this model's scope should be submitted via the [Community Pen-Test Handbook](../../docs/docs/security/pen-test.md).
