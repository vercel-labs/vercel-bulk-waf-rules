/**
 * Terminal-friendly rendering of an {@link ImportResult}.
 *
 * These strings get pasted verbatim into customer tickets and Slack threads, so
 * they are plain ASCII-structured text with no colour codes and no box drawing:
 * whatever the operator copies is what the customer reads.
 */

import type { ImportProblem, ImportResult, ProblemKind } from './normalize.js';
import { PROBLEM_KIND_ORDER, isAllowlistWildcardProblem } from './normalize.js';

/** How many collapsible problems to list per group before summarising the rest. */
export const COLLAPSE_LIMIT = 10;

const KIND_TITLES: Readonly<Record<ProblemKind, string>> = {
  'invalid-address': 'Invalid addresses (must be fixed)',
  'row-shape': 'Malformed rows (must be fixed)',
  'suspicious-range': 'Suspiciously broad ranges',
  'private-address': 'Non-routable / private addresses',
  'normalized-host-bits': 'CIDRs normalized (host bits were set)',
  duplicate: 'Duplicate entries (ignored)',
  'covered-by-cidr': 'Redundant entries (already covered)',
};

/**
 * Problems that are never abbreviated, no matter how many there are.
 *
 * `invalid-address` because the operator needs the complete fix list in one
 * pass, and the allowlist-`/0` case because hiding "this rule admits the entire
 * internet" behind an "... and 47 more" is precisely the silent failure the
 * diagnostic exists to prevent.
 */
function isAlwaysListed(problem: ImportProblem): boolean {
  return problem.kind === 'invalid-address' || isAllowlistWildcardProblem(problem);
}

function formatLine(problem: ImportProblem): string {
  const raw = problem.raw === '' ? '(empty)' : JSON.stringify(problem.raw);
  return `  line ${problem.lineNumber}: ${raw} — ${problem.message}`;
}

function formatGroup(kind: ProblemKind, problems: readonly ImportProblem[]): string[] {
  const pinned = problems.filter(isAlwaysListed);
  const collapsible = problems.filter((problem) => !isAlwaysListed(problem));
  const shown = collapsible.slice(0, COLLAPSE_LIMIT);
  const hidden = collapsible.length - shown.length;

  const lines = [`${KIND_TITLES[kind]} (${problems.length})`];
  for (const problem of [...pinned, ...shown]) lines.push(formatLine(problem));
  if (hidden > 0) lines.push(`  ... and ${hidden} more`);
  return lines;
}

/**
 * Render every problem, grouped by kind in {@link PROBLEM_KIND_ORDER}.
 *
 * Within a group, problems keep the canonical (line, kind) ordering
 * `normalizeEntries` established, so the same CSV always produces the same
 * report text.
 */
export function formatProblemReport(result: ImportResult): string {
  const { problems, stats } = result;
  if (problems.length === 0) {
    return `No import problems found (${stats.rowsRead} rows read, ${stats.valid} valid).`;
  }

  const groups = PROBLEM_KIND_ORDER.map(
    (kind) => [kind, problems.filter((problem) => problem.kind === kind)] as const,
  ).filter(([, group]) => group.length > 0);

  const header =
    `Import problems: ${problems.length} across ${groups.length} ` +
    `${groups.length === 1 ? 'category' : 'categories'} ` +
    `(${stats.rowsRead} rows read, ${stats.valid} valid, ${stats.invalid} invalid).`;

  const body = groups.map(([kind, group]) => formatGroup(kind, group).join('\n'));
  return [header, '', ...intersperse(body)].join('\n');
}

function intersperse(blocks: readonly string[]): string[] {
  return blocks.flatMap((block, index) => (index === 0 ? [block] : ['', block]));
}

const STAT_LABELS: readonly (readonly [string, (result: ImportResult) => string])[] = [
  ['Rows read', (r) => String(r.stats.rowsRead)],
  ['Valid entries', (r) => String(r.stats.valid)],
  ['Invalid', (r) => String(r.stats.invalid)],
  ['Duplicates', (r) => String(r.stats.duplicates)],
  ['Normalized', (r) => String(r.stats.normalized)],
  ['Addresses covered', (r) => r.stats.addressesCovered.toString()],
  ['After aggregation', (r) => String(r.stats.afterAggregation)],
  ['Distinct vendors', (r) => String(r.stats.vendorCount)],
];

/** One aligned key/value block summarising the import, for the end of a run. */
export function formatStatsSummary(result: ImportResult): string {
  const width = Math.max(...STAT_LABELS.map(([label]) => label.length));
  return STAT_LABELS.map(([label, read]) => `${`${label}:`.padEnd(width + 3)}${read(result)}`).join(
    '\n',
  );
}
