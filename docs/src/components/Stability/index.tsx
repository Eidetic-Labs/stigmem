/**
 * <Stability /> — version-aware feature exposure component per ADR-008 (version exposure).
 *
 * Renders an inline alert at the top of feature/concept/SDK/operator pages
 * surfacing the page's stability tier, since-version, and (when applicable)
 * a link to the relevant spec section. Sourced from frontmatter:
 *
 *   ---
 *   stability: stable | beta | experimental | deprecated
 *   since: 0.9.0a1
 *   applies_to_version: 0.9.0a1+
 *   spec_section: §17 (optional)
 *   removed_in: 2.0.0 (only on deprecated entries)
 *   replacement: ./new-feature-page.md (only on deprecated entries)
 *   ---
 *
 * Or used inline:
 *
 *   <Stability level="experimental" since="0.9.0a1" specSection="§21" />
 *
 * Per ADR-008 (version exposure) implementation plan; lands in PR 2.5 sub-phase H. The
 * frontmatter validator extension that enforces stability/since across
 * every page is acknowledged as a follow-up; this component renders
 * what the frontmatter provides.
 */

import React from 'react';
import Admonition from '@theme/Admonition';
import Link from '@docusaurus/Link';

type StabilityLevel = 'stable' | 'beta' | 'experimental' | 'deprecated';

const LEVEL_META: Record<StabilityLevel, { type: 'info' | 'warning' | 'caution' | 'danger'; label: string; description: string }> = {
  stable: {
    type: 'info',
    label: 'Stable',
    description: 'In production. Eval-covered. No breaking changes planned within the major version.',
  },
  beta: {
    type: 'info',
    label: 'Beta',
    description: 'Spec normative. Feature-flagged or in early adopters. Minor breaking changes possible before next major.',
  },
  experimental: {
    type: 'caution',
    label: 'Experimental',
    description: 'Implementation behind a flag. Spec section may be draft. Breaking changes expected. Use behind feature flag in production at your own risk.',
  },
  deprecated: {
    type: 'warning',
    label: 'Deprecated',
    description: 'Marked for removal. Still operational; replacement available.',
  },
};

interface StabilityProps {
  level: StabilityLevel;
  since: string;
  specSection?: string;
  removedIn?: string;
  replacement?: string;
}

export default function Stability({ level, since, specSection, removedIn, replacement }: StabilityProps): JSX.Element | null {
  const meta = LEVEL_META[level];
  if (!meta) return null;

  return (
    <Admonition type={meta.type} title={`${meta.label} — since v${since}`}>
      <p>{meta.description}</p>
      {specSection && (
        <p>
          <strong>Spec:</strong> {specSection}
        </p>
      )}
      {level === 'deprecated' && removedIn && (
        <p>
          <strong>Removed in:</strong> v{removedIn}
          {replacement && (
            <>
              {' '}— see <Link to={replacement}>replacement</Link>.
            </>
          )}
        </p>
      )}
    </Admonition>
  );
}
