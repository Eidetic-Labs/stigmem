---
title: Where Security Analysis Lives
sidebar_label: Where Analysis Lives
description: How Stigmem splits cross-cutting threat-model risks from feature-local security analysis.
audience: Security
sidebar_position: 11
---

# Where Security Analysis Lives

<p className="stigmem-meta"><span>2 min read</span><span>Navigation</span><span>Per ADR-020 §11 (security taxonomy)</span></p>

<div className="stigmem-lead">

**What this page is**

Stigmem uses one protocol-level threat model plus feature-local
security files for features. This page tells you where
to look.

</div>

## Canonical risk register

The numbered R-XX risk register lives in
[`spec/security/threat-model.md`](https://github.com/eidetic-labs/stigmem/blob/main/spec/security/threat-model.md).
Cross-cutting protocol risks stay there.

<div className="stigmem-grid">

<div><h4>Transport security</h4></div>
<div><h4>Quota enforcement</h4></div>
<div><h4>Prompt-injection controls</h4></div>
<div><h4>CID integrity</h4></div>
<div><h4>Release supply-chain integrity</h4></div>
<div><h4>Storage immutability</h4></div>

</div>

## Feature-local security files

Per ADR-020 §11 (security taxonomy) and ADR-020, a feature that owns or materially contributes
to a numbered risk keeps its feature analysis in its feature record.
Legacy experimental security files may remain as compatibility
pointers during migration.

<div className="stigmem-fields">

<div>
<dt>Feature</dt>
<dt><span className="stigmem-fields__type">Risk relationship</span></dt>
<dd>Security analysis location</dd>
</div>

<div>
<dt>Lazy instruction discovery</dt>
<dt><span className="stigmem-fields__type">owns R-15; contributes to R-21</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/blob/main/features/lazy-instruction-discovery/security.md"><code>features/lazy-instruction-discovery/security.md</code></a></dd>
</div>

<div>
<dt>RTBF tombstones</dt>
<dt><span className="stigmem-fields__type">owns R-16 and R-17</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/blob/main/features/tombstones/security.md"><code>features/tombstones/security.md</code></a></dd>
</div>

<div>
<dt>Time-travel queries</dt>
<dt><span className="stigmem-fields__type">contributes to R-17 and R-18</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/blob/main/features/time-travel/security.md"><code>features/time-travel/security.md</code></a></dd>
</div>

<div>
<dt>Memory garden ACL</dt>
<dt><span className="stigmem-fields__type">contributes to R-21</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/blob/main/features/memory-garden-acl/security.md"><code>features/memory-garden-acl/security.md</code></a></dd>
</div>

<div>
<dt>Source attestation</dt>
<dt><span className="stigmem-fields__type">contributes to R-22</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/blob/main/features/source-attestation/security.md"><code>features/source-attestation/security.md</code></a></dd>
</div>

<div>
<dt>Multi-tenant scoping</dt>
<dt><span className="stigmem-fields__type">contributes to R-01, R-02, R-21</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/blob/main/features/multi-tenant/security.md"><code>features/multi-tenant/security.md</code></a></dd>
</div>

</div>

<div className="stigmem-keypoint">

**Feature-local files do not replace the risk register.**

They give operators and contributors the local threat-model delta,
operator scenarios, conformance pointers, and ADR-008 reintroduction
gates for the feature.

</div>

## Features without security files

Not every directory under `experimental/` receives a `security.md`
automatically. Adapter, deployment, SDK, dashboard, and workbench
directories remain covered by their `STATUS.md`, contributor checks,
and the protocol-level threat model until they own or materially
contribute to a numbered risk. When that happens, the same PR must
add or update the feature-local `security.md` and cross-link the risk
register.

## Contributor rule

When adding a feature-owned R-XX risk:

<ol className="stigmem-steps">
<li>Add the risk to the unified threat model.</li>
<li>Add or update <code>features/&lt;feature&gt;/security.md</code>.</li>
<li>Link the risk row in the threat model to the feature-local file.</li>
<li>Run the security documentation validator.</li>
</ol>

```bash
python scripts/check_security_documentation.py
```
