/**
 * Turn raw CSV rows into a canonical, deduplicated, fully-diagnosed IP list.
 *
 * Three policies here are deliberate reversals of the legacy bash tool, and
 * each is load-bearing enough to justify the prose:
 *
 * 1. **IPv6 is accepted.** The old script hard-rejected any address containing
 *    a colon and printed "IPv6 not supported". That was a self-imposed limit of
 *    its integer arithmetic, not a platform limit — the Vercel firewall's
 *    validator accepts IPv4 and IPv6 with prefixes /0–/128. Rejecting v6 here
 *    would silently drop the half of a dual-stack vendor's egress that is
 *    increasingly the default, producing an allowlist that locks out the very
 *    partner it was written for.
 *
 * 2. **Bad rows are collected, never thrown.** A fail-on-first parser turns a
 *    500-row list into 500 sequential edit-run cycles. Every invalid address
 *    becomes an {@link ImportProblem} so a single pass reports everything an
 *    operator must fix. Fatality is a *caller* policy: see
 *    {@link hasFatalProblems}.
 *
 * 3. **Provenance survives.** `vendor_name` and `notes` were parsed and then
 *    discarded by the old tool. They are kept per-entry because downstream
 *    consumers need them — Security Lists carry a per-value `note`, and a
 *    human-readable rule description wants to say "12 vendors", not "417 IPs".
 */

import { aggregateCidrs, countAddresses } from '../core/aggregate.js';
import type { Intent } from '../core/decompose.js';
import type { Cidr, IpVersion } from '../core/ip.js';
import { cidrToRange, compareRanges, formatCidr, parseCidr, parseCidrLoose } from '../core/ip.js';
import type { ColumnMap, CsvRow } from './csv.js';
import { cellAt, resolveColumns } from './csv.js';

/** A valid, canonicalized address plus the provenance of the row it came from. */
export interface ImportEntry {
  readonly cidr: Cidr;
  /** The address cell exactly as written, for diagnostics and round-tripping. */
  readonly raw: string;
  readonly vendor?: string;
  readonly note?: string;
  readonly lineNumber: number;
}

/** Categories of import diagnostic, roughly ordered from fatal-ish to advisory. */
export type ProblemKind =
  | 'invalid-address'
  | 'normalized-host-bits'
  | 'duplicate'
  | 'covered-by-cidr'
  | 'suspicious-range'
  | 'private-address'
  | 'row-shape';

/** One diagnostic, always citing the source line and the offending raw text. */
export interface ImportProblem {
  readonly lineNumber: number;
  readonly raw: string;
  readonly kind: ProblemKind;
  readonly message: string;
}

/** Aggregate counters for the summary block and for CI thresholds. */
export interface ImportStats {
  readonly rowsRead: number;
  readonly valid: number;
  readonly invalid: number;
  readonly duplicates: number;
  readonly normalized: number;
  readonly addressesCovered: bigint;
  readonly afterAggregation: number;
  readonly vendorCount: number;
}

/** Everything {@link normalizeEntries} learned about a CSV. */
export interface ImportResult {
  readonly entries: ImportEntry[];
  readonly aggregated: Cidr[];
  readonly problems: ImportProblem[];
  readonly stats: ImportStats;
}

/** Tuning knobs for {@link normalizeEntries}. All have safe defaults. */
export interface NormalizeOptions {
  /** Drives the default suspicious-prefix thresholds. Defaults to `allowlist`. */
  readonly intent?: Intent;
  /** When true, `invalid-address` and `row-shape` make the result fatal. */
  readonly strict?: boolean;
  /** Warn when an IPv4 prefix is shorter than this. Overrides the intent default. */
  readonly suspiciousPrefixV4?: number;
  /** Warn when an IPv6 prefix is shorter than this. Overrides the intent default. */
  readonly suspiciousPrefixV6?: number;
  /** Set false to suppress `private-address` diagnostics entirely. Defaults to true. */
  readonly flagPrivate?: boolean;
}

/**
 * Marker embedded in the message for a `/0` on an allowlist.
 *
 * A `/0` in an allowlist is not "a broad range" — it is the entire internet, so
 * the rule that was supposed to restrict access to twelve vendors now admits
 * everyone while still *looking* like a restriction in the dashboard. That
 * failure is silent, total, and security-critical, so it gets a distinct marker
 * that {@link ImportProblem} consumers can match on and the report layer
 * refuses to collapse.
 */
export const ALLOWLIST_WILDCARD_MARKER = 'ALLOWS EVERY IP ON THE INTERNET';

/** True when this problem is the allowlist-`/0` hazard described above. */
export function isAllowlistWildcardProblem(problem: ImportProblem): boolean {
  return problem.kind === 'suspicious-range' && problem.message.includes(ALLOWLIST_WILDCARD_MARKER);
}

/**
 * Non-public address space, flagged as `private-address`.
 *
 * Covers RFC 1918, loopback, link-local, unique-local (RFC 4193) and the
 * documentation prefixes. On an allowlist these are harmless but useless — a
 * client's public source IP can never be one of them, so the entry is dead
 * weight that hides a copy-paste mistake. On a bypass list they are worse: they
 * suggest an internal range was exported into an internet-facing rule.
 */
const PRIVATE_RANGES: readonly { readonly label: string; readonly cidr: string }[] = [
  { label: 'RFC1918 private', cidr: '10.0.0.0/8' },
  { label: 'RFC1918 private', cidr: '172.16.0.0/12' },
  { label: 'RFC1918 private', cidr: '192.168.0.0/16' },
  { label: 'loopback', cidr: '127.0.0.0/8' },
  { label: 'link-local', cidr: '169.254.0.0/16' },
  { label: 'documentation (TEST-NET-1)', cidr: '192.0.2.0/24' },
  { label: 'documentation (TEST-NET-2)', cidr: '198.51.100.0/24' },
  { label: 'documentation (TEST-NET-3)', cidr: '203.0.113.0/24' },
  { label: 'loopback', cidr: '::1/128' },
  { label: 'unique-local (ULA)', cidr: 'fc00::/7' },
  { label: 'link-local', cidr: 'fe80::/10' },
  { label: 'documentation', cidr: '2001:db8::/32' },
];

interface LabelledRange {
  readonly label: string;
  readonly text: string;
  readonly version: IpVersion;
  readonly start: bigint;
  readonly end: bigint;
}

const PRIVATE_LOOKUP: readonly LabelledRange[] = PRIVATE_RANGES.map(({ label, cidr }) => {
  const parsed = parseCidr(cidr);
  const range = cidrToRange(parsed);
  return { label, text: cidr, version: parsed.version, start: range.start, end: range.end };
});

function privateLabelFor(cidr: Cidr): LabelledRange | undefined {
  const range = cidrToRange(cidr);
  return PRIVATE_LOOKUP.find(
    (candidate) =>
      candidate.version === cidr.version &&
      range.start >= candidate.start &&
      range.end <= candidate.end,
  );
}

/**
 * Prefix lengths below which a block is flagged as suspiciously broad.
 *
 * An allowlist is an *exception* list, so a genuine entry is a handful of
 * vendor egress addresses; anything wider than a /8 (v4) or /32 (v6) is far
 * more likely a typo or a misunderstood export than a real requirement. For a
 * blocklist or bypass list a broad range can be legitimate, so only `/0` — the
 * degenerate "everything" case — is flagged there.
 */
function defaultThresholds(intent: Intent): { v4: number; v6: number } {
  return intent.kind === 'allowlist' ? { v4: 8, v6: 32 } : { v4: 0, v6: 0 };
}

function describeVersion(version: IpVersion): string {
  return `IPv${version}`;
}

function describeIntent(intent: Intent): string {
  switch (intent.kind) {
    case 'allowlist':
      return 'an allowlist';
    case 'blocklist':
      return 'a blocklist';
    case 'bypass':
      return 'a bypass list';
  }
}

function addressCount(cidr: Cidr): bigint {
  const range = cidrToRange(cidr);
  return range.end - range.start + 1n;
}

/** Stable presentation order for problem groups: most actionable first. */
export const PROBLEM_KIND_ORDER: readonly ProblemKind[] = [
  'invalid-address',
  'row-shape',
  'suspicious-range',
  'private-address',
  'normalized-host-bits',
  'duplicate',
  'covered-by-cidr',
];

function kindRank(kind: ProblemKind): number {
  const index = PROBLEM_KIND_ORDER.indexOf(kind);
  return index === -1 ? PROBLEM_KIND_ORDER.length : index;
}

function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface PendingEntry {
  readonly cidr: Cidr;
  readonly raw: string;
  readonly vendor: string;
  readonly note: string;
  readonly lineNumber: number;
}

function toEntry(pending: PendingEntry): ImportEntry {
  return {
    cidr: pending.cidr,
    raw: pending.raw,
    lineNumber: pending.lineNumber,
    ...(pending.vendor === '' ? {} : { vendor: pending.vendor }),
    ...(pending.note === '' ? {} : { note: pending.note }),
  };
}

function collectRowProblems(
  rows: readonly CsvRow[],
  header: readonly string[],
  columns: ColumnMap,
  problems: ImportProblem[],
): PendingEntry[] {
  const accepted: PendingEntry[] = [];
  const firstSeen = new Map<string, PendingEntry>();

  for (const row of rows) {
    const raw = cellAt(row.values, columns.address);

    if (row.values.length > header.length) {
      problems.push({
        lineNumber: row.lineNumber,
        raw: row.values.join(','),
        kind: 'row-shape',
        message:
          `row has ${row.values.length} values but the header declares ${header.length} columns ` +
          '— most likely an unquoted comma inside a value; quote the field or remove the comma',
      });
      continue;
    }

    if (raw === '') {
      problems.push({
        lineNumber: row.lineNumber,
        raw: '',
        kind: 'invalid-address',
        message: 'address cell is empty',
      });
      continue;
    }

    let cidr: Cidr;
    let normalized: boolean;
    try {
      ({ cidr, normalized } = parseCidrLoose(raw));
    } catch (error) {
      problems.push({
        lineNumber: row.lineNumber,
        raw,
        kind: 'invalid-address',
        message: reasonOf(error),
      });
      continue;
    }

    if (normalized) {
      problems.push({
        lineNumber: row.lineNumber,
        raw,
        kind: 'normalized-host-bits',
        message:
          `host bits were set; ${raw} was normalized to ${formatCidr(cidr)} ` +
          `(${addressCount(cidr)} addresses). Confirm this is the range you intended`,
      });
    }

    const key = formatCidr(cidr);
    const previous = firstSeen.get(key);
    if (previous !== undefined) {
      problems.push({
        lineNumber: row.lineNumber,
        raw,
        kind: 'duplicate',
        message: `${key} was already listed on line ${previous.lineNumber} (as ${JSON.stringify(previous.raw)}); this repeat is ignored`,
      });
      continue;
    }

    const pending: PendingEntry = {
      cidr,
      raw,
      vendor: cellAt(row.values, columns.vendor),
      note: cellAt(row.values, columns.note),
      lineNumber: row.lineNumber,
    };
    firstSeen.set(key, pending);
    accepted.push(pending);
  }

  return accepted;
}

/**
 * Flag entries wholly contained in another listed block.
 *
 * The entry is kept — aggregation removes the redundancy losslessly — but it is
 * reported, because a list containing both `10.0.0.0/8` and `10.0.0.5` almost
 * always means the operator believes the /8 is narrower than it is.
 */
function collectCoverage(entries: readonly ImportEntry[], problems: ImportProblem[]): void {
  const byVersion = new Map<IpVersion, ImportEntry[]>();
  for (const entry of entries) {
    const bucket = byVersion.get(entry.cidr.version);
    if (bucket === undefined) byVersion.set(entry.cidr.version, [entry]);
    else bucket.push(entry);
  }

  for (const bucket of byVersion.values()) {
    const sorted = [...bucket].sort((a, b) => {
      const ra = cidrToRange(a.cidr);
      const rb = cidrToRange(b.cidr);
      if (ra.start !== rb.start) return ra.start < rb.start ? -1 : 1;
      return a.cidr.prefixLen - b.cidr.prefixLen;
    });

    const open: ImportEntry[] = [];
    for (const entry of sorted) {
      const range = cidrToRange(entry.cidr);
      while (open.length > 0) {
        const top = open[open.length - 1];
        if (top !== undefined && cidrToRange(top.cidr).end >= range.start) break;
        open.pop();
      }
      const enclosing = open[open.length - 1];
      if (enclosing !== undefined && range.end <= cidrToRange(enclosing.cidr).end) {
        problems.push({
          lineNumber: entry.lineNumber,
          raw: entry.raw,
          kind: 'covered-by-cidr',
          message:
            `${formatCidr(entry.cidr)} is already inside ${formatCidr(enclosing.cidr)} ` +
            `from line ${enclosing.lineNumber}; it adds no coverage`,
        });
        continue;
      }
      open.push(entry);
    }
  }
}

function collectBreadthProblems(
  entries: readonly ImportEntry[],
  intent: Intent,
  options: NormalizeOptions,
  problems: ImportProblem[],
): void {
  const defaults = defaultThresholds(intent);
  const v4 = options.suspiciousPrefixV4 ?? defaults.v4;
  const v6 = options.suspiciousPrefixV6 ?? defaults.v6;
  const flagPrivate = options.flagPrivate ?? true;

  for (const entry of entries) {
    const { cidr } = entry;
    const threshold = cidr.version === 4 ? v4 : v6;

    if (cidr.prefixLen === 0) {
      const message =
        intent.kind === 'allowlist'
          ? `${formatCidr(cidr)} ${ALLOWLIST_WILDCARD_MARKER}. On an allowlist this defeats the rule ` +
            'entirely: every client matches, so nothing is actually restricted. Remove it or replace ' +
            'it with the specific ranges you meant.'
          : `${formatCidr(cidr)} covers the entire ${describeVersion(cidr.version)} address space`;
      problems.push({ lineNumber: entry.lineNumber, raw: entry.raw, kind: 'suspicious-range', message });
    } else if (cidr.prefixLen < threshold) {
      problems.push({
        lineNumber: entry.lineNumber,
        raw: entry.raw,
        kind: 'suspicious-range',
        message:
          `${formatCidr(cidr)} spans ${addressCount(cidr)} addresses, wider than the ` +
          `/${threshold} ${describeVersion(cidr.version)} threshold for ${describeIntent(intent)}`,
      });
    }

    if (flagPrivate) {
      const label = privateLabelFor(cidr);
      if (label !== undefined) {
        problems.push({
          lineNumber: entry.lineNumber,
          raw: entry.raw,
          kind: 'private-address',
          message:
            `${formatCidr(cidr)} is in ${label.text} (${label.label}) and can never be a public ` +
            `client source address; it has no effect on ${describeIntent(intent)}`,
        });
      }
    }
  }
}

function countVendors(entries: readonly ImportEntry[]): number {
  const vendors = new Set<string>();
  for (const entry of entries) {
    const vendor = entry.vendor?.trim() ?? '';
    if (vendor !== '') vendors.add(vendor);
  }
  return vendors.size;
}

/**
 * Normalize CSV rows into a canonical import result.
 *
 * Output is order-independent: entries are sorted by {@link compareRanges} and
 * problems by (line, kind), so shuffling the rows of a CSV produces the same
 * entries, the same aggregation and the same stats. That determinism is what
 * makes a generated WAF payload diffable between runs.
 *
 * @throws {CsvParseError} only when the header has no resolvable address column.
 */
export function normalizeEntries(
  rows: readonly CsvRow[],
  header: readonly string[],
  options: NormalizeOptions = {},
): ImportResult {
  const columns = resolveColumns(header);
  const intent: Intent = options.intent ?? { kind: 'allowlist' };
  const problems: ImportProblem[] = [];

  const accepted = collectRowProblems(rows, header, columns, problems);
  const entries = accepted
    .map(toEntry)
    .sort((a, b) => compareRanges(cidrToRange(a.cidr), cidrToRange(b.cidr)));

  collectCoverage(entries, problems);
  collectBreadthProblems(entries, intent, options, problems);

  problems.sort((a, b) => {
    if (a.lineNumber !== b.lineNumber) return a.lineNumber - b.lineNumber;
    const rank = kindRank(a.kind) - kindRank(b.kind);
    if (rank !== 0) return rank;
    return a.message < b.message ? -1 : a.message > b.message ? 1 : 0;
  });

  const cidrs = entries.map((entry) => entry.cidr);
  const aggregated = aggregateCidrs([...cidrs]);

  return {
    entries,
    aggregated,
    problems,
    stats: {
      rowsRead: rows.length,
      valid: entries.length,
      invalid: problems.filter((problem) => problem.kind === 'invalid-address').length,
      duplicates: problems.filter((problem) => problem.kind === 'duplicate').length,
      normalized: problems.filter((problem) => problem.kind === 'normalized-host-bits').length,
      addressesCovered: countAddresses([...cidrs]),
      afterAggregation: aggregated.length,
      vendorCount: countVendors(entries),
    },
  };
}

/**
 * Decide whether a result should stop the pipeline.
 *
 * Exposed as a predicate instead of being thrown from the parser so the caller
 * owns the policy: a CI job wants `strict` and a hard stop, while an engineer
 * triaging a customer's export wants the whole problem list first and will
 * decide for themselves. Only `invalid-address` and `row-shape` qualify —
 * everything else is advisory by construction.
 */
export function hasFatalProblems(result: ImportResult, strict = true): boolean {
  if (!strict) return false;
  return result.problems.some(
    (problem) => problem.kind === 'invalid-address' || problem.kind === 'row-shape',
  );
}
