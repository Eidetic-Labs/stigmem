---
title: Security
sidebar_label: Overview
description: Stigmem security posture — threat model risk register, scenarios, security architecture, hardening, and disclosure policy.
audience: Security
sidebar_position: 1
---

# Security

<p className="stigmem-meta"><span>4 min read</span><span>Entry point for evaluators, integrators, operators, security engineers</span><span>v0.9.0a2</span></p>

<div className="stigmem-lead">

**What this page is**

Per [ADR-020](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/020-feature-owned-product-structure.md) §12 (docs IA):
"Lead Secure with the risk register." This page is the entry point to
stigmem's security posture. The threat model and scenarios are the
most important artifacts, surfaced first.

</div>

## Risk register status (v0.9.0a2)

<div className="stigmem-fields">

<div>
<dt>Status</dt>
<dt><span className="stigmem-fields__type">Count</span></dt>
<dd>Description</dd>
</div>

<div>
<dt><strong>Mitigated</strong></dt>
<dt><span className="stigmem-fields__type">10</span></dt>
<dd>mTLS, quotas, key max-age, audit log, replay fuzz, capability tokens, container hardening, and R-19 HLC skew bounds — see the <a href="https://github.com/eidetic-labs/stigmem/blob/main/spec/security/threat-model.md">threat model risk register</a>.</dd>
</div>

<div>
<dt><strong>In review</strong></dt>
<dt><span className="stigmem-fields__type">2</span></dt>
<dd>Prompt injection (R-05) and agent feedback-loop worm (R-21); structural controls now exist on <code>main</code>, sanitizer remains defense-in-depth, and live certification plus operator validation evidence are still required before marking the risks mitigated.</dd>
</div>

<div>
<dt><strong>Residual</strong></dt>
<dt><span className="stigmem-fields__type">0</span></dt>
<dd>No risks are currently tracked as sanitizer-only residual risk in the v0.9.0a2 register.</dd>
</div>

<div>
<dt><strong>Open</strong></dt>
<dt><span className="stigmem-fields__type">6</span></dt>
<dd>R-15 instruction-scope injection, R-16 RTBF DoS, R-17 legal-hold exposure, R-18 CID field-exclusion, R-22 release supply-chain, R-23 admin-level storage tampering.</dd>
</div>

<div>
<dt><strong>Accepted</strong></dt>
<dt><span className="stigmem-fields__type">5</span></dt>
<dd>R-04 at-rest encryption default-off, R-07 Obsidian plugin key storage, R-08 libSQL cloud backend, R-13 cloud embedding data residency, R-20 cloud embedding poisoning.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Most-severe structural risk: R-23 (admin-level storage tampering).**

An attacker with admin privileges on a stigmem node can — without
[ADR-016](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/016-storage-immutability-enforcement.md)'s
mitigations — overwrite stored facts, bypassing
[ADR-003](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/003-prompt-injection.md)'s
prompt-injection trust boundary by silently changing
<code>interpret_as</code> from <code>content</code> to
<code>instruction</code> at the storage layer. Mitigation is the
ADR-016 stack (L1–L5: append-only journal, SQLite triggers, CIDs per
[ADR-011](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/011-cross-cutting-extraction.md),
local hash chain, Sigstore Rekor anchor). Targeted: future hardened-core work.

</div>

The second-priority new risk is **R-21 (agent feedback-loop worm)**.
Main now has same-session read/write provenance controls, OpenClaw
handoff-target allowlisting, supported adapter/session propagation,
and outbound replication exclusion for provenance-derived facts.
R-21 remains in review until release certification and operator
validation cover those controls. The OpenClaw adapter remains an
experimental alpha connector until that validation is complete.

For the full risk register: see the **[Threat Model](https://github.com/eidetic-labs/stigmem/blob/main/spec/security/threat-model.md)** (`spec/security/threat-model.md`).
For operator-facing scenarios: see the **[Security Scenarios](./scenarios)**.
For the trust boundary against prompt injection (L1–L6): see [ADR-003](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/003-prompt-injection.md) § Trust boundary.

## v0.9.0a2 architectural posture

Per [LIMITATIONS.md §11](https://github.com/eidetic-labs/stigmem/blob/main/LIMITATIONS.md):
the default install of v0.9.0a2 ships with feature-specific code in
`node/src/stigmem_node/` for features deferred from v1.0 critical-path
scope per [ADR-002](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/002-v1-scope.md).
The routes are mounted but the features are dormant unless explicitly
configured (capability tokens, migrations, manifests). Per
[ADR-001](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/001-versioning.md)
iteration semantics, each v0.9.0aN extracts one cross-cutting feature
into a plugin per [ADR-011](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/011-cross-cutting-extraction.md).

<div className="stigmem-keypoint">

**For v0.9.0a2 evaluators**

The user-visible default behavior matches v1.0 critical-path scope
(single-tenant, no tombstones, no time-travel, no advanced ACL).
Cross-cutting experimental behavior is being extracted into opt-in
source packages across the v0.9.0aN line; signed/published plugin
artifacts remain deferred until all planned plugins are built.

</div>

Main now includes the 22-hook registry foundation and plugin test
harness needed for extraction work. The landed foundation includes
typed hook semantics, deterministic manual/core registration, minimum
manifest/context/capability APIs, hook-site wiring across assertion,
recall, federation, auth, migration, and audit paths, registry
audit/metrics plumbing, benchmark coverage, startup package discovery,
production plugin signing enforcement, and operator CLI inspection.
Per-feature plugin packages remain future alpha-series work.

## Published advisories

Stigmem publishes GitHub Security Advisories for Critical and High
CVSS 4.0 findings that affect a supported published artifact. The
v0.9.0a2 hardening release patches the following advisory batch.

<div className="stigmem-fields">

<div>
<dt>GHSA</dt>
<dt><span className="stigmem-fields__type">Severity · CVSS 4.0</span></dt>
<dd>Patched version</dd>
</div>

<div>
<dt><a href="https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-jmfc-hfjq-pxcp">GHSA-jmfc-hfjq-pxcp</a></dt>
<dt><span className="stigmem-fields__type">Critical · 9.1</span></dt>
<dd><code>stigmem-node 0.9.0a2</code></dd>
</div>

<div>
<dt><a href="https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-fp6w-8wpg-74g5">GHSA-fp6w-8wpg-74g5</a></dt>
<dt><span className="stigmem-fields__type">Critical · 9.2</span></dt>
<dd><code>stigmem-node 0.9.0a2</code></dd>
</div>

<div>
<dt><a href="https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9vp8-3hmv-8fgh">GHSA-9vp8-3hmv-8fgh</a></dt>
<dt><span className="stigmem-fields__type">Critical · 9.1</span></dt>
<dd><code>stigmem-node 0.9.0a2</code></dd>
</div>

<div>
<dt><a href="https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-xh5j-xjfq-qvvx">GHSA-xh5j-xjfq-qvvx</a></dt>
<dt><span className="stigmem-fields__type">High · 7.1</span></dt>
<dd><code>stigmem-node 0.9.0a2</code></dd>
</div>

<div>
<dt><a href="https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-w7pm-9g55-mxfm">GHSA-w7pm-9g55-mxfm</a></dt>
<dt><span className="stigmem-fields__type">High · 7.3</span></dt>
<dd><code>stigmem-node 0.9.0a2</code></dd>
</div>

<div>
<dt><a href="https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9pc9-4crj-mhpj">GHSA-9pc9-4crj-mhpj</a></dt>
<dt><span className="stigmem-fields__type">High · 7.5</span></dt>
<dd><code>stigmem-node 0.9.0a2</code></dd>
</div>

</div>

## Security architecture

<div className="stigmem-fields">

<div>
<dt>Page</dt>
<dt><span className="stigmem-fields__type">Scope</span></dt>
<dd>Topic</dd>
</div>

<div>
<dt><a href="./authentication">Authentication</a></dt>
<dt><span className="stigmem-fields__type">access</span></dt>
<dd>API key auth (Argon2id for new keys; v0.9.0a1 SHA-256 rows rehash on successful use per <a href="../../../docs/adr/archive/007-argon2id.md">ADR-007</a>), local-agent <code>entity_uri</code> naming, expires_at enforcement, session model.</dd>
</div>

<div>
<dt><a href="./agent-keypairs">Agent keypairs</a></dt>
<dt><span className="stigmem-fields__type">identity</span></dt>
<dd>Ed25519 keypair generation, storage, rotation.</dd>
</div>

<div>
<dt><a href="./audit-log">Audit log</a></dt>
<dt><span className="stigmem-fields__type">accountability</span></dt>
<dd>WAL-ordered audit log, 14 event types, 90-day retention (Spec-09-Audit-Log).</dd>
</div>

<div>
<dt><a href="./audit-and-quotas">Audit & quotas</a></dt>
<dt><span className="stigmem-fields__type">rate limits</span></dt>
<dd>Per-principal token-bucket quotas, 7 dimensions (Spec-10-Hardening).</dd>
</div>

<div>
<dt><a href="./key-rotation">Key rotation</a></dt>
<dt><span className="stigmem-fields__type">lifecycle</span></dt>
<dd>Enforced API key max-age (90d default), Ed25519 rotation runbook (Spec-10-Hardening).</dd>
</div>

<div>
<dt><a href="./mtls">mTLS</a></dt>
<dt><span className="stigmem-fields__type">transport</span></dt>
<dd>Federation transport: TLS 1.3 floor, SAN ↔ entity_uri binding (Spec-10-Hardening).</dd>
</div>

<div>
<dt><a href="./encryption-at-rest">Encryption at rest</a></dt>
<dt><span className="stigmem-fields__type">storage</span></dt>
<dd>SQLCipher (opt-in for regulated data).</dd>
</div>

<div>
<dt><a href="./container-hardening">Container hardening</a></dt>
<dt><span className="stigmem-fields__type">runtime</span></dt>
<dd>Distroless, non-root UID 1000, read-only fs, seccomp (Spec-10-Hardening container baseline).</dd>
</div>

<div>
<dt><a href="./immutability-and-attestation">Immutability & attestation</a></dt>
<dt><span className="stigmem-fields__type">integrity</span></dt>
<dd>ADR-016 R-23 mitigation stack, fact-chain checkpoints, WORM storage, and TEE deployment options.</dd>
</div>

<div>
<dt><a href="./where-security-analysis-lives">Where security analysis lives</a></dt>
<dt><span className="stigmem-fields__type">navigation</span></dt>
<dd>ADR-020 §11 (security taxonomy) split between the protocol-level threat model and feature-local <code>experimental/&lt;feature&gt;/security.md</code> files.</dd>
</div>

</div>

The federation-hardening control review lives with the
canonical security evidence at
[`spec/security/federation-control-review.md`](https://github.com/eidetic-labs/stigmem/blob/main/spec/security/federation-control-review.md).

## Operator surfaces

<div className="stigmem-grid">

<div><h4><a href="./human-key-issuance">Human key issuance</a></h4><p>Operator UX for issuing API keys.</p></div>
<div><h4><a href="./human-surface">Human surface</a></h4><p>Human-facing operator concerns.</p></div>
<div><h4><a href="./pen-test">Pen-test handbook</a></h4><p>Community pen-testing process and reproducer template.</p></div>

</div>

## Disclosure & policy

<div className="stigmem-grid">

<div><h4><a href="./compatibility-commitment">Compatibility commitment</a></h4><p>Written commitment per ADR-008 §Deprecation policy.</p></div>
<div><h4><a href="../community/security-disclosure">Security disclosure policy</a></h4><p>How to report a vulnerability.</p></div>
<div><h4><a href="https://github.com/eidetic-labs/stigmem/blob/main/SECURITY.md">SECURITY.md</a></h4><p>Supported versions, dependency posture.</p></div>

</div>

## Specification

The protocol specification is the contract security depends on. It
lives under Secure per ADR-020 §12 (docs IA).

<div className="stigmem-grid">

<div><h4><a href="../spec/index">Specification index</a></h4><p>Section navigator with disposition table (which sections are stable in v0.9.0a2, which are deferred to <code>experimental/&lt;feature&gt;/</code>).</p></div>
<div><h4><a href="https://github.com/eidetic-labs/stigmem/blob/main/spec/stigmem-spec-v0.9.0a1.md">Canonical spec source</a></h4><p><code>spec/stigmem-spec-v0.9.0a1.md</code>. Section-by-section content review against the <code>node/</code> implementation is ongoing.</p></div>

</div>

## Experimental & deferred features

Many features documented in earlier checkpoints are deferred from
v0.9.0a2's default install. They live in
[`experimental/<feature>/`](https://github.com/eidetic-labs/stigmem/tree/main/experimental).
Alpha-series extraction may package some of them as opt-in
experimental plugins; promotion into the supported surface requires
the [ADR-008](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/008-experimental-gates.md)
gate process. See **[Experimental & Deferred Features](../reference/experimental-features)** for the canonical list.

## Quick-start for security researchers

<ol className="stigmem-steps">
<li>Read the <a href="https://github.com/eidetic-labs/stigmem/blob/main/spec/security/threat-model.md">Threat Model</a> to understand the trust boundaries and current risk register.</li>
<li>Read the <a href="./scenarios">Security Scenarios</a> for operator-facing narratives.</li>
<li>Read the <a href="./pen-test">Pen-test handbook</a> for the engagement process and reproducer template.</li>
<li>Set up a local node via the <a href="../get-started/quickstart-tutorial">quickstart tutorial</a>.</li>
<li>File private advisories at <a href="https://github.com/eidetic-labs/stigmem/security/advisories">github.com/eidetic-labs/stigmem/security/advisories</a>.</li>
</ol>
