# ADR-004: Federation observability and incident response

<p className="stigmem-meta"><span>5 min read</span><span>Accepted</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

The observability and incident-response surface for v1.0 federation,
defined as three layers: signals (what we record), alerts (what fires
when), runbooks (what to do). Separate from the threat model (what
could go wrong) and §22.3 (what we record at the event-type level).

</div>

<div className="stigmem-keypoint">

**Status: Accepted.**

The threat model says what could go wrong. §22.3 says what we record.
This ADR says **what we monitor, alert on, and respond to**.

Scope note: this is federation-future (roadmap Wave 3) work — it lands
with cross-organizational federation, not the single-node wedge.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** threat model §22.3, R-19; `OPERATING.md`; [ADR-002](./002-v1-scope)

## Context

In a federated system, the worst incidents are the ones that happen
*between* nodes — a malicious peer pushing crafted HLC values, a
compromised peer's signed manifest leaking, a worm propagating through
cross-org handoffs. These incidents are not visible inside any single
node's logs in a useful way; they are visible only when an operator
can see the *federation graph* — what's flowing between nodes, who's
writing how often, what the per-peer drift looks like.

The retracted v1.0 shipped with audit-event types defined in §22.3,
but with several gaps relevant to federation:

<div className="stigmem-grid">

<div><h4>No per-peer rate aggregation</h4><p>Which peer is writing how much, of what relation type.</p></div>
<div><h4>No drift-tracking events</h4><p>For HLC, capability-token timestamp, or quarantine-promotion latency.</p></div>
<div><h4>No defined severity / alert taxonomy</h4><p>Every event is at the same level.</p></div>
<div><h4>No incident-response runbooks</h4><p>Naming what to do when specific signals fire.</p></div>

</div>

<div className="stigmem-keypoint">

**Forensics is not enough.**

Without defined signals, alert thresholds, and responses, the audit
log is forensics — you can reconstruct what happened after the fact,
but you can't act in time.

</div>

## Decision

We define three layers: signals, alerts, and runbooks.

### Layer 1 · Signals (what we record)

Federation signals are a subset of audit events, plus derived metrics,
named explicitly and emitted with structured fields suitable for SIEM
ingestion.

#### Per-peer connection signals

<div className="stigmem-grid">

<div><h4><code>federation_connect</code></h4><p>Peer entity URI · mTLS verification result · capability token presented.</p></div>
<div><h4><code>federation_disconnect</code></h4><p>Peer entity URI · reason (clean / abrupt / timeout).</p></div>
<div><h4><code>federation_handshake_failed</code></h4><p>Peer entity URI · failure reason (cert mismatch / expired token / manifest invalid).</p></div>

</div>

#### Per-peer activity signals

<div className="stigmem-grid">

<div><h4><code>peer_fact_write</code></h4><p>Peer entity URI · scope · relation · count (aggregated per minute).</p></div>
<div><h4><code>peer_fact_read</code></h4><p>Peer entity URI · scope · count (aggregated per minute).</p></div>
<div><h4><code>peer_quarantine_admit</code></h4><p>Peer entity URI · fact id · reason.</p></div>

</div>

#### Drift signals

<div className="stigmem-grid">

<div><h4><code>peer_hlc_anomaly</code></h4><p>Peer entity URI · observed HLC · local HLC · drift seconds · threshold breached.</p></div>
<div><h4><code>peer_replay_rejected</code></h4><p>Peer entity URI · nonce · reason.</p></div>
<div><h4><code>peer_capability_violation</code></h4><p>Peer entity URI · attempted verb+object · granted scope.</p></div>

</div>

#### Quarantine signals

<div className="stigmem-grid">

<div><h4><code>instruction_quarantined</code></h4><p>Peer entity URI · fact id · age in queue.</p></div>
<div><h4><code>instruction_promoted</code></h4><p>Admin entity URI · fact id · time-to-promote.</p></div>
<div><h4><code>quarantine_aged_out</code></h4><p>Fact id — a fact that sat in quarantine longer than the configured retention.</p></div>

</div>

#### Manifest and key signals

<div className="stigmem-grid">

<div><h4><code>manifest_rotation_observed</code></h4><p>Peer entity URI · new key id · Rekor inclusion proof status.</p></div>
<div><h4><code>manifest_rotation_failed</code></h4><p>Peer entity URI · failure reason.</p></div>
<div><h4><code>key_expiring_soon</code></h4><p>Key id · days remaining (emitted at 30 / 14 / 7 / 1 day thresholds).</p></div>
<div><h4><code>key_expired_blocked</code></h4><p>Key id · attempted operation.</p></div>

</div>

### Layer 2 · Alerts (what fires when)

Each alert is defined with name, severity, condition, default
threshold, and recommended response. Operators can tune thresholds in
their deployment config.

<div className="stigmem-fields">

<div>
<dt>Alert</dt>
<dt><span className="stigmem-fields__type">Severity</span></dt>
<dd>Default threshold</dd>
</div>

<div>
<dt><code>peer_hlc_drift_high</code></dt>
<dt><span className="stigmem-fields__type">Warning</span></dt>
<dd><code>peer_hlc_anomaly</code> events from a single peer · &gt;5/hour.</dd>
</div>

<div>
<dt><code>peer_hlc_drift_critical</code></dt>
<dt><span className="stigmem-fields__type">Critical</span></dt>
<dd>Drift in seconds · &gt;300s in a single event.</dd>
</div>

<div>
<dt><code>peer_handshake_failure_burst</code></dt>
<dt><span className="stigmem-fields__type">Warning</span></dt>
<dd><code>federation_handshake_failed</code> from a single peer · &gt;3/minute.</dd>
</div>

<div>
<dt><code>peer_replay_burst</code></dt>
<dt><span className="stigmem-fields__type">Critical</span></dt>
<dd><code>peer_replay_rejected</code> from a single peer · &gt;5/hour.</dd>
</div>

<div>
<dt><code>peer_capability_violation</code></dt>
<dt><span className="stigmem-fields__type">Critical</span></dt>
<dd>Any <code>peer_capability_violation</code> event · 1.</dd>
</div>

<div>
<dt><code>quarantine_backlog</code></dt>
<dt><span className="stigmem-fields__type">Warning</span></dt>
<dd>Facts in quarantine waiting for promotion · &gt;50 facts or any aged &gt;24h.</dd>
</div>

<div>
<dt><code>instruction_quarantined_unprecedented</code></dt>
<dt><span className="stigmem-fields__type">Warning</span></dt>
<dd><code>instruction_quarantined</code> from a peer that has never written instruction-typed facts before · 1.</dd>
</div>

<div>
<dt><code>manifest_rotation_failed</code></dt>
<dt><span className="stigmem-fields__type">Critical</span></dt>
<dd>Any <code>manifest_rotation_failed</code> event · 1.</dd>
</div>

<div>
<dt><code>key_expired_blocked</code></dt>
<dt><span className="stigmem-fields__type">Critical</span></dt>
<dd>Any <code>key_expired_blocked</code> event · 1.</dd>
</div>

<div>
<dt><code>worm_pattern_detected</code></dt>
<dt><span className="stigmem-fields__type">Critical</span></dt>
<dd>Per-peer agent-write graph mirrors agent-read graph beyond baseline · pattern-defined.</dd>
</div>

</div>

Each alert maps to a runbook (Layer 3).

### Layer 3 · Runbooks (what to do)

Every Critical alert must have a named runbook in `OPERATING.md`
covering:

<ol className="stigmem-steps">
<li><strong>Identify</strong> — what data to gather first, what queries to run.</li>
<li><strong>Contain</strong> — what to disable or revoke immediately to stop the bleeding.</li>
<li><strong>Investigate</strong> — what audit-log queries reveal the scope of impact.</li>
<li><strong>Recover</strong> — what to retract, rotate, or republish.</li>
<li><strong>Communicate</strong> — federation peers to notify, what to post publicly if the project's reputation is implicated.</li>
</ol>

Initial runbooks shipped in v0.9.x:

<div className="stigmem-grid">

<div><h4><code>R-PEER-COMPROMISE</code></h4><p>For <code>peer_capability_violation</code>, <code>peer_replay_burst</code>, suspicious manifest rotation.</p></div>
<div><h4><code>R-WORM-DETECTED</code></h4><p>For <code>worm_pattern_detected</code>. Coordinates with the OpenClaw allowlist defense and ADR-003 channel separation.</p></div>
<div><h4><code>R-MANIFEST-FAILURE</code></h4><p>For <code>manifest_rotation_failed</code>. Covers Rekor unavailability and signing-key compromise scenarios.</p></div>
<div><h4><code>R-HLC-DRIFT</code></h4><p>For <code>peer_hlc_drift_critical</code>. Covers honest-clock-skew vs malicious-peer disambiguation.</p></div>
<div><h4><code>R-KEY-EXPIRY</code></h4><p>For <code>key_expired_blocked</code>. Recovery from a missed rotation.</p></div>

</div>

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Rely entirely on the existing audit log; let operators wire their own dashboards</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>"Roll your own observability" is a non-answer for the operator evaluating whether stigmem is deployable. The defining question for federation infrastructure is "how do I know when it's going wrong?" — the answer needs to be in our docs.</dd>
</div>

<div>
<dt>Ship a Grafana dashboard</dt>
<dt><span className="stigmem-fields__type">considered, deferred</span></dt>
<dd>Per ADR-002, Grafana is an <code>experimental/</code> deferred feature. We define the signals and alerts in v1.0 and ship the dashboard in v2.0.0-experimental once one external operator has actually used it.</dd>
</div>

<div>
<dt>Define richer ML-driven anomaly detection</dt>
<dt><span className="stigmem-fields__type">rejected for v1.0</span></dt>
<dd>Threshold-based alerts are tractable, debuggable, and operator-tunable. Anomaly-detection ML is none of those things until you have enough deployment data to train against — which we don't.</dd>
</div>

<div>
<dt>Skip runbooks; let operators figure it out</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The most credible signal stigmem can give a prospective operator is "we've thought about what to do when X happens." Runbooks are that signal in concrete form.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Defined operational posture</h4><p>"Subscribe to these alerts; follow these runbooks" is the answer to "how do I run this safely?"</p></div>
<div><h4>Phase B operator soak has structured feedback</h4><p>The 30-day external operator runs against a known set of signals; their bug reports can reference signal names.</p></div>
<div><h4>Threat-model risks have observability mappings</h4><p>R-19 (HLC manipulation) is observable via <code>peer_hlc_drift_critical</code>; R-21 (worm vector) via <code>worm_pattern_detected</code>.</p></div>
<div><h4>Public retro posts have telemetry</h4><p>When a real incident happens, the retro can name the signal that fired, the runbook that ran, and the time-to-recovery.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Signal stability is a contract</h4><p>Once we name <code>peer_hlc_anomaly</code>, we can't rename it without breaking operator dashboards. Wire format applies to telemetry too.</p></div>
<div><h4>Runbook maintenance is ongoing work</h4><p>Each runbook needs to be updated as the underlying mitigations evolve; out-of-date runbooks are worse than no runbooks.</p></div>
<div><h4>Per-peer aggregation storage cost</h4><p>Peer rate aggregation needs sliding-window counters; configurable retention.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-OBS-1</code> · alert fatigue</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Default thresholds tuned too sensitive will produce noise; operators stop reading alerts. Mitigation: ship defaults that produce zero alerts on a healthy single-org single-peer demo; document tuning guidance per deployment shape.</dd>
</div>

<div>
<dt><code>R-OBS-2</code> · runbook drift from reality</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A runbook that says "rotate the org signing key" when the procedure changes is worse than no runbook. Mitigation: every runbook is dated and linked from the corresponding code paths; updates are required as part of the PR that changes the code.</dd>
</div>

</div>

## Implementation plan

This ADR's implementation is split across multiple PR cycles in the
strengthening plan, lower priority than the security-critical work:

<div className="stigmem-fields">

<div>
<dt>Phase</dt>
<dt><span className="stigmem-fields__type">Output</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Phase B (federation hardening)</dt>
<dt><span className="stigmem-fields__type">signals layer</span></dt>
<dd>Emit all named events with the defined structured fields, alongside audit-log work.</dd>
</div>

<div>
<dt>Phase B (operator-facing work)</dt>
<dt><span className="stigmem-fields__type">runbooks drafted</span></dt>
<dd>Runbook documents drafted with placeholder thresholds, alongside OPERATING.md.</dd>
</div>

<div>
<dt>Phase B (operator soak begins)</dt>
<dt><span className="stigmem-fields__type">tune thresholds</span></dt>
<dd>Refine runbooks with real incident data during operator soak.</dd>
</div>

</div>

Alerts (Layer 2) are operator-side configuration; we publish
recommended thresholds and example Prometheus alerting rules in
`OPERATING.md`, but we don't run an alert pipeline as part of the
node.

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
