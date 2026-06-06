// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');
const remarkGlossaryLink = require('./plugins/remark-glossary-link');
const remarkSpecLink = require('./plugins/remark-spec-link');

// RTD serves the site under /<language>/<version>/ in multi-version mode.
// Use injected env vars so asset paths resolve correctly without changing local dev.
const baseUrl = process.env.READTHEDOCS === 'True'
  ? `/${process.env.READTHEDOCS_LANGUAGE}/${process.env.READTHEDOCS_VERSION}/`
  : '/';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Stigmem Protocol',
  tagline: 'Structured, federated knowledge graph for AI agents',
  favicon: 'img/favicon.ico',

  url: 'https://docs.stigmem.dev',
  baseUrl,

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.ts',
          docItemComponent: '@theme/ApiItem',
          remarkPlugins: [remarkGlossaryLink, remarkSpecLink],
          // Single-version mode for the current v0.9.0 alpha line (canonical first build per
          // ADR-001). Pre-reset versioned snapshots (v0.2, v1.1)
          // and the v2.0-draft "current" label labeled internal development
          // checkpoints, not tagged releases. Snapshots preserved at
          // docs/archive/snapshots/. The rendered docs now use ADR-020's
          // Learn / Build / Operate / Secure information architecture.
          //
          // Multi-version configuration will be reintroduced when v0.9.0a2
          // ships and we have an actual prior release to snapshot
          // (docs-structure-review-2026-05-06 §8.1: "every release" snapshot
          // policy).
          versions: {
            current: {
              label: 'v0.9.0a2',
              badge: true,
              // banner: 'none' — v0.9.0a2 is the current preview-alpha docs line
              // (PyPI: stigmem, stigmem-py, stigmem-node, stigmem-openclaw;
              // npm: @eidetic-labs/stigmem-ts; GHCR: stigmem-node).
              // The label remains a preview-alpha (no stability guarantee
              // until v1.0.0 GA per ADR-001), but the docs are no longer
              // describing an unreleased build. The 'unreleased' banner
              // was correct pre-publish and was retired post-publish.
              banner: 'none',
            },
          },
        },
        blog: {
          showReadingTime: true,
          blogTitle: 'Stigmem Blog',
          blogDescription: 'Updates, announcements, and deep-dives from the Stigmem project.',
          postsPerPage: 10,
          blogSidebarTitle: 'Recent posts',
          blogSidebarCount: 5,
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  plugins: [
    [
      'docusaurus-plugin-openapi-docs',
      {
        id: 'api',
        docsPluginId: 'classic',
        config: {
          stigmem: {
            specPath: './openapi/stigmem.json',
            outputDir: 'docs/reference/api/generated',
            downloadUrl: './openapi/stigmem.json',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
        },
      },
    ],
    [
      '@easyops-cn/docusaurus-search-local',
      /** @type {import("@easyops-cn/docusaurus-search-local").PluginOptions} */
      ({
        hashed: true,
        indexPages: true,
      }),
    ],
    require.resolve('./plugins/validate-audience'),
    [
      '@docusaurus/plugin-client-redirects',
      {
        // Redirects under preview-alpha single-version mode. The entries below
        // cover URLs in already-published artifact metadata plus the most
        // likely external-link patterns that survived the v1.0 retraction.
        // Archived version snapshots live in docs/archive/snapshots/ as repo
        // preservation artifacts; public routes redirect to current docs.
        redirects: [
          { from: '/docs/guides/connectors/openclaw',  to: '/docs/sdks/connectors/openclaw' },
          { from: '/docs/guides/federation',           to: '/docs/concepts/federation/' },
          { from: '/docs/about/state-of-stigmem',      to: '/docs/concepts/features' },
          { from: '/docs/getting-started/installation', to: '/docs/get-started/installation' },
          { from: '/docs/getting-started/quickstart',  to: '/docs/get-started/quickstart-tutorial' },
          { from: '/docs/concepts/lifecycle/decay-and-confidence', to: '/docs/spec/experimental/decay-semantics' },
          { from: '/docs/concepts/lifecycle/time-travel-queries', to: '/docs/spec/experimental/time-travel-queries' },
          { from: '/docs/concepts/lifecycle/tombstones-and-rtbf', to: '/docs/spec/experimental/rtbf-tombstones' },
          { from: '/docs/concepts/recall/memory-cards-as-fast-path', to: '/docs/spec/experimental/recall-graph' },
          { from: '/docs/concepts/recall/memory-gardens', to: '/docs/concepts/memory-garden' },
          { from: '/v1.1',                             to: '/docs/concepts/' },
          { from: '/v0.2',                             to: '/docs/concepts/' },
          { from: '/docs/v1.1',                        to: '/docs/concepts/' },
          { from: '/docs/v0.2',                        to: '/docs/concepts/' },
          { from: '/install',                          to: '/docs/operators/deployment/install' },
        ],
      },
    ],
  ],

  themes: [
    'docusaurus-theme-openapi-docs',
    '@docusaurus/theme-live-codeblock',
    '@docusaurus/theme-mermaid',
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/stigmem-logo.svg',
      metadata: [
        { name: 'description', content: 'Open-source federated knowledge graph for AI agents. Immutable (entity, relation, value) facts with provenance, confidence scores, and cryptographic federation across peer nodes.' },
        { property: 'og:type', content: 'website' },
        { name: 'twitter:card', content: 'summary_large_image' },
        { name: 'twitter:site', content: '@stigmem' },
      ],
      navbar: {
        title: 'Stigmem',
        logo: { alt: 'Stigmem by Eidetic Labs', src: 'img/logo.svg' },
        items: [
          // Four-tab IA per ADR-020: Learn / Build / Operate / Secure.
          // Reference dissolves: API → Build, Specification → Secure,
          // Architecture splits Build/Operate, Glossary → footer utility.
          // Community dissolves: security-disclosure → Secure,
          // project-resources → footer.
          {
            type: 'docSidebar',
            sidebarId: 'learnSidebar',
            label: 'Learn',
            position: 'left',
          },
          {
            type: 'docSidebar',
            sidebarId: 'buildSidebar',
            label: 'Build',
            position: 'left',
          },
          {
            type: 'docSidebar',
            sidebarId: 'operateSidebar',
            label: 'Operate',
            position: 'left',
          },
          {
            type: 'docSidebar',
            sidebarId: 'secureSidebar',
            label: 'Secure',
            position: 'left',
          },
          { to: '/blog', label: 'Blog', position: 'left' },
          { type: 'custom-githubButton', position: 'right', variant: 'star' },
          { type: 'custom-githubButton', position: 'right', variant: 'fork' },
        ],
      },
      footer: {
        // No `style` override — let the footer follow the page background
        // (light surface in light mode, logo-canvas dark in dark mode).
        links: [
          {
            title: 'Docs',
            items: [
              { label: 'Learn', to: '/docs/concepts/' },
              { label: 'Build', to: '/docs/concepts/facts/asserting-facts' },
              { label: 'Operate', to: '/docs/operators/' },
              { label: 'Secure', to: '/docs/security/' },
              { label: 'Features', to: '/docs/concepts/features' },
            ],
          },
          {
            title: 'Reference',
            items: [
              { label: 'Glossary', to: '/docs/reference/glossary/' },
              { label: 'Architecture', to: '/docs/reference/architecture/' },
              { label: 'Experimental & Deferred', to: '/docs/reference/experimental-features' },
              { label: 'Project Resources', to: '/docs/community/project-resources' },
            ],
          },
          {
            title: 'Project',
            items: [
              { label: 'GitHub', href: 'https://github.com/eidetic-labs/stigmem' },
              { label: 'License (Apache 2.0)', href: 'https://github.com/eidetic-labs/stigmem/blob/main/LICENSE' },
              { label: 'Security policy', href: 'https://github.com/eidetic-labs/stigmem/blob/main/SECURITY.md' },
              { label: 'Blog', to: '/blog' },
            ],
          },
          {
            title: 'Community',
            items: [
              { label: 'Discord', href: 'https://discord.gg/Z47Re7FjjV' },
              { label: 'Discussions', href: 'https://github.com/eidetic-labs/stigmem/discussions' },
              { label: 'Issues', href: 'https://github.com/eidetic-labs/stigmem/issues' },
            ],
          },
        ],
        copyright: `© ${new Date().getFullYear()} Eidetic Labs · Apache 2.0`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'python', 'json'],
      },
      mermaid: {
        theme: { light: 'neutral', dark: 'dark' },
        options: {
          flowchart: {
            padding: 20,
          },
        },
      },
      liveCodeBlock: {
        playgroundPosition: 'bottom',
      },
    }),
};

module.exports = config;
