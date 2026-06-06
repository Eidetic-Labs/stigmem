// Audience taxonomy per ADR-020 (docs IA) + master-checklist §4.3a:
//   - Evaluator  — first-time visitor assessing whether stigmem fits.
//   - Integrator — developer writing code against stigmem.
//   - Operator   — running a node in production.
//   - Security   — security engineer or compliance team auditing the design.
//   - Spec       — protocol contributor or spec implementer.
//
// Pre-reset taxonomy was 3 values (Operator/Integrator/Spec); extended to 5
// during sub-phase 2.5.I per ADR-020 (docs IA). Per-page backfill against the new
// 5-value vocabulary is acknowledged as a follow-up sweep; this commit
// extends the validator to accept the new values without forcing the
// backfill in one pass.

const VALID_AUDIENCES = ['Evaluator', 'Integrator', 'Operator', 'Security', 'Spec'];
const VALID_STABILITIES = ['stable', 'beta', 'experimental', 'deprecated'];

// Audience badges are only meaningful where the page's audience is non-obvious from
// its top-level section. The Learn section name already implies a general reader, so
// pages under learn/ (and a few catch-all sections) opt out of the audience requirement.
const AUDIENCE_OPTIONAL_PREFIXES = ['get-started/', 'concepts/', 'learn/', 'community/', 'reference/glossary'];

module.exports = function validateAudiencePlugin() {
  return {
    name: 'validate-audience',
    async allContentLoaded({allContent}) {
      const docsPlugin = allContent['docusaurus-plugin-content-docs']?.default;
      if (!docsPlugin) return;

      const errors = [];
      for (const version of docsPlugin.loadedVersions ?? []) {
        for (const doc of version.docs ?? []) {
          if (doc.sourceDirName?.includes('reference/api/generated')) {
            continue;
          }
          const isOptional = AUDIENCE_OPTIONAL_PREFIXES.some(
            (prefix) => doc.sourceDirName?.startsWith(prefix) || doc.id?.startsWith(prefix)
          );
          const audience = doc.frontMatter?.audience;
          if (!audience) {
            if (!isOptional) {
              errors.push(`${doc.id}: missing "audience" frontmatter`);
            }
          } else if (!VALID_AUDIENCES.includes(audience)) {
            errors.push(`${doc.id}: invalid audience "${audience}" (must be one of ${VALID_AUDIENCES.join(', ')})`);
          }

          if (doc.id?.startsWith('spec/experimental/')) {
            const stability = doc.frontMatter?.stability;
            const since = doc.frontMatter?.since;
            if (!stability) {
              errors.push(`${doc.id}: missing "stability" frontmatter`);
            } else if (!VALID_STABILITIES.includes(stability)) {
              errors.push(`${doc.id}: invalid stability "${stability}" (must be one of ${VALID_STABILITIES.join(', ')})`);
            }
            if (!since) {
              errors.push(`${doc.id}: missing "since" frontmatter`);
            } else if (!/^\d+\.\d+\.\d+(?:a\d+|b\d+|rc\d+)?$/.test(String(since))) {
              errors.push(`${doc.id}: invalid since "${since}" (expected e.g. 0.9.0a1)`);
            }
          }
        }
      }

      if (errors.length > 0) {
        throw new Error(
          `[validate-audience] ${errors.length} doc(s) missing or invalid "audience" frontmatter:\n` +
          errors.map(e => `  - ${e}`).join('\n')
        );
      }
    },
  };
};
