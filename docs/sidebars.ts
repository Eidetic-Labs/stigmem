import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';
import apisidebar from './docs/reference/api/generated/sidebar';

/**
 * Sidebars for v0.9.0a1 — four-tab IA per ADR-020 (docs IA).
 *
 * Tab structure (Learn / Build / Operate / Secure) replaces the pre-reset
 * five-tab structure (Learn / Build / Operate / Reference / Community).
 * Reference dissolves: API → Build, Specification → Secure, Architecture
 * splits into Build (data-flow) + Operate (deployment topology), Glossary
 * → footer utility, Experimental Features → auto-generated index per
 * ADR-008 (version exposure). Community dissolves: security-disclosure → Secure,
 * project-resources → footer.
 *
 * Per founder direction (plan §13, 2026-05-09): "Concepts" + "How It Works"
 * merge into a single flat "Key concepts" category in Learn — Option (a).
 *
 * Pages for deferred features (lazy-instruction-discovery, RTBF tombstones,
 * time-travel, memory-garden ACL, source attestation, multi-tenant, recall-
 * graph advanced features, MCP-host connectors, non-OpenClaw adapters,
 * Helm/Fly/etc deploy targets, Go SDK) live at experimental/<feature>/
 * per ADR-020 + ADR-011 — they appear in the Reference → Experimental &
 * Deferred index, not in the operating tabs.
 *
 */
const sidebars: SidebarsConfig = {
  // ─────────────────────────────────────────────────────────────────────
  // LEARN — "What is stigmem and why would I use it?"
  // ─────────────────────────────────────────────────────────────────────
  learnSidebar: [
    { type: 'doc', id: 'concepts/index', label: 'Overview' },
    { type: 'doc', id: 'concepts/features', label: 'Features' },
    {
      type: 'category',
      label: 'Key concepts',
      collapsed: false,
      items: [
        'concepts/facts/immutable-typed-facts',
        'concepts/hybrid-logical-clocks',
        'concepts/facts/conflict-semantics',
        'concepts/federation/federation-handshake',
        'concepts/federation/source-trust-and-quarantine',
        'concepts/facts/content-addressing',
        'concepts/memory-garden',
      ],
    },
    {
      type: 'category',
      label: 'Quickstart',
      link: { type: 'doc', id: 'get-started/index' },
      items: [
        'get-started/installation',
        'get-started/quickstart-tutorial',
      ],
    },
  ],

  // ─────────────────────────────────────────────────────────────────────
  // BUILD — "How do I integrate with stigmem from my code?"
  // ─────────────────────────────────────────────────────────────────────
  buildSidebar: [
    {
      type: 'category',
      label: 'Guides',
      link: { type: 'generated-index', title: 'Guides', description: 'Step-by-step guides for building with Stigmem.' },
      items: [
        {
          type: 'category',
          label: 'Facts',
          collapsed: true,
          items: [
            'concepts/facts/asserting-facts',
            'concepts/facts/querying-facts',
            'concepts/facts/conflict-resolution',
            'concepts/facts/content-addressing-guide',
          ],
        },
        {
          type: 'category',
          label: 'Recall',
          collapsed: true,
          items: [
            'concepts/recall/recall',
          ],
        },
        {
          type: 'category',
          label: 'Federation',
          collapsed: true,
          items: [
            'concepts/federation/federation',
            'concepts/federation/federation-trust',
            'concepts/federation/federation-4node',
            'concepts/federation/scope-propagation',
            'concepts/federation/relay-backpressure',
          ],
        },
        {
          type: 'category',
          label: 'Plugins',
          collapsed: true,
          items: [
            'guides/plugins/author-guide',
            'guides/plugins/alpha-tester-migration',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      link: { type: 'doc', id: 'reference/api/index' },
      collapsed: false,
      items: apisidebar,
    },
    {
      type: 'category',
      label: 'Plugin API',
      collapsed: true,
      items: [
        'reference/plugin-api/capabilities',
        'reference/plugin-api/hooks',
      ],
    },
    {
      type: 'category',
      label: 'SDKs',
      collapsed: false,
      items: [
        'sdks/python',
        'sdks/typescript',
      ],
    },
    {
      type: 'category',
      label: 'Connectors',
      link: { type: 'doc', id: 'sdks/connectors/index' },
      items: [
        'sdks/connectors/openclaw',
        {
          type: 'category',
          label: 'MCP integrations',
          link: { type: 'doc', id: 'integrations/mcp/index' },
          collapsed: true,
          items: [
            'integrations/mcp/codex-cli',
            'integrations/mcp/claude-code',
            'integrations/mcp/gemini-cli',
            'integrations/mcp/continue-dev',
            'integrations/mcp/cursor',
            'integrations/mcp/zed',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Architecture',
      collapsed: true,
      items: [
        'reference/architecture/recall-pipeline',
      ],
    },
    {
      type: 'category',
      label: 'Tutorials',
      collapsed: true,
      items: [
        'get-started/sdk-quickstart',
        'sdks/tutorial-two-org-federation',
        'operators/tutorial-hardening',
      ],
    },
  ],

  // ─────────────────────────────────────────────────────────────────────
  // OPERATE — "How do I run a stigmem node in production?"
  // ─────────────────────────────────────────────────────────────────────
  operateSidebar: [
    { type: 'doc', id: 'operators/index', label: 'Overview' },
    {
      type: 'category',
      label: 'Deployment',
      collapsed: true,
      items: [
        'operators/deployment/install',
        'operators/release-readiness',
        'operators/release-verification',
        'operators/validation-soak',
      ],
    },
    {
      type: 'category',
      label: 'Runbooks',
      collapsed: true,
      items: [
        'operators/runbooks/deploy-runbooks',
        'operators/runbooks/federation-setup',
        'operators/runbooks/backup-restore',
        'operators/runbooks/cursor-reset-recovery',
        'operators/runbooks/r-peer-compromise',
        'operators/runbooks/r-worm-detected',
        'operators/runbooks/r-manifest-failure',
        'operators/runbooks/r-rekor-unavailable',
        'operators/runbooks/r-hlc-drift',
        'operators/runbooks/r-key-expiry',
      ],
    },
    {
      type: 'category',
      label: 'Observability',
      link: { type: 'doc', id: 'operators/observability/index' },
      collapsed: true,
      items: [
        'operators/observability/monitoring',
      ],
    },
    {
      type: 'category',
      label: 'Plugins',
      link: { type: 'doc', id: 'plugins/index' },
      collapsed: true,
      items: [
        'plugins/index',
        'plugins/lazy-instruction-discovery',
        'plugins/time-travel',
        'plugins/tombstones',
        'plugins/memory-garden-acl',
        'plugins/source-attestation',
        'plugins/multi-tenant',
        'operators/plugins/management',
      ],
    },
    {
      type: 'category',
      label: 'Architecture',
      collapsed: true,
      items: [
        'reference/architecture/single-host-node',
        'reference/architecture/federated-network',
      ],
    },
    {
      type: 'category',
      label: 'CLI',
      link: { type: 'doc', id: 'reference/cli/index' },
      collapsed: true,
      items: [
        'reference/cli/stigmem',
        'reference/cli/stigmem-node',
      ],
    },
    'operators/conformance',
    'operators/prompt-injection-hardening',
    'operators/compatibility',
    'operators/design-partner-notes',
  ],

  // ─────────────────────────────────────────────────────────────────────
  // SECURE — "Can I trust this with my data and my federation peers?"
  // ─────────────────────────────────────────────────────────────────────
  secureSidebar: [
    { type: 'doc', id: 'security/index', label: 'Overview' },
    {
      type: 'category',
      label: 'Security architecture',
      collapsed: false,
      items: [
        'security/authentication',
        'security/agent-keypairs',
        'security/audit-log',
        'security/audit-and-quotas',
        'security/key-rotation',
        'security/mtls',
        'security/encryption-at-rest',
        'security/container-hardening',
        'security/immutability-and-attestation',
        'security/where-security-analysis-lives',
        'concepts/security-model',
      ],
    },
    {
      type: 'category',
      label: 'Operator surfaces',
      collapsed: true,
      items: [
        'security/human-key-issuance',
        'security/human-surface',
        'security/pen-test',
        'security/model-certification',
      ],
    },
    {
      type: 'category',
      label: 'Specification',
      link: { type: 'doc', id: 'spec/index' },
      collapsed: true,
      items: [
        {
          type: 'category',
          label: 'Component specs',
          link: {
            type: 'generated-index',
            title: 'Component Specs',
            description: 'ADR-020 modular component specs in protocol order.',
          },
          collapsed: false,
          items: [
            'spec/specs/fact-model',
            'spec/specs/scopes-and-acl',
            'spec/specs/http-api',
            'spec/specs/manifests',
            'spec/specs/federation-trust',
            'spec/specs/capability-tokens',
            'spec/specs/recall-pipeline',
            'spec/specs/quarantine-garden',
            'spec/specs/audit-log',
            'spec/specs/hardening',
            'spec/specs/replay-protection',
            'spec/specs/hlc-bounded-skew',
            'spec/specs/capability-based-instructions',
            'spec/specs/batch-assert',
            'spec/specs/fact-semantics',
            'spec/specs/namespace-registry',
            'spec/specs/schema-and-migration',
            'spec/specs/conformance-and-failure-modes',
            'spec/specs/adapter-abi',
            'spec/specs/lint-semantics',
            'spec/specs/content-addressed-ids',
          ],
        },
        {
          type: 'category',
          label: 'Experimental specs',
          link: {
            type: 'generated-index',
            title: 'Experimental Specs',
            description: 'Colocated experimental specs in Spec-X order.',
          },
          collapsed: true,
          items: [
            'spec/experimental/lazy-instruction-discovery',
            'spec/experimental/rtbf-tombstones',
            'spec/experimental/time-travel-queries',
            'spec/experimental/memory-garden-advanced-acl',
            'spec/experimental/source-attestation',
            'spec/experimental/subscriptions',
            'spec/experimental/intent-envelope',
            'spec/experimental/decay-semantics',
            'spec/experimental/synthesis',
            'spec/experimental/recall-graph',
          ],
        },
        {
          type: 'category',
          label: 'Legacy rendered section pages',
          link: {
            type: 'generated-index',
            title: 'Legacy Rendered Section Pages',
            description: 'Compatibility pages retained for older section-based links and anchors.',
          },
          collapsed: true,
          items: [
            'spec/motivation',
            'spec/atomic-fact-shape',
            'spec/fact-semantics',
            'spec/wire-format',
            'spec/federation',
            'spec/design-decisions-log',
            'spec/open-questions',
            'spec/namespace-registry',
            'spec/schema-and-migration',
            'spec/failure-mode-scenarios',
            'spec/adapter-abi',
            'spec/lint-semantics',
            'spec/federation-trust',
            'spec/security-hardening',
            'spec/content-addressed-fact-ids',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Disclosure & policy',
      collapsed: true,
      items: [
        'community/ai-authorship',
        'community/security-disclosure',
        'security/compatibility-commitment',
      ],
    },
    { type: 'doc', id: 'reference/experimental-features', label: 'Experimental & Deferred' },
  ],
};

export default sidebars;
