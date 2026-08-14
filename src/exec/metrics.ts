/**
 * `vercel metrics` reader, used by the post-apply verify step.
 *
 * WHY THIS MODULE NEVER THROWS ON A FAILED QUERY
 * ----------------------------------------------
 * Verify is advisory. It runs *after* rules have been applied, and the operator's
 * next decision is usually "keep this or roll it back". If metrics are
 * unreadable — the project has no Observability Plus, the envelope changed, the
 * query 500s — the correct outcome is "I could not read this, here is the
 * dashboard URL", never an exception that aborts the run. An exception thrown
 * here would propagate out of verify and could prevent the operator from
 * reaching the rollback path, which is precisely backwards: the moment metrics
 * fail is the moment rollback matters most. Every failure is therefore modelled
 * as a value ({@link MetricsResult}), not as control flow.
 *
 * The one exception is {@link InvalidDurationError}, which fires *before* any
 * spawn on a malformed `--since`. A bad window is not a degraded read, it is a
 * read of the wrong thing — a silently-wrong time range makes the verify step
 * lie, and a verify step that lies is worse than one that is absent.
 *
 * FLAG SPELLING — TRANSCRIBED, NOT GUESSED
 * ----------------------------------------
 * From `packages/cli/src/commands/metrics/command.ts`: positional `metric-id`
 * (command.ts:30), `--group-by DIM` repeatable (command.ts:56-63),
 * `--since TIME` (command.ts:105-113), `--granularity SIZE` (command.ts:122-129),
 * and `formatOption` (command.ts:151) which is `--format FORMAT` with
 * `FORMAT=json` (`util/arg-common.ts:217-224`).
 */

import { truncate } from './errors.js';
import type { Scope } from './firewall.js';
import type { CliResult } from './spawn.js';
import { parseJsonStdout, runVercel } from './spawn.js';

export const FIREWALL_ACTION_METRIC = 'vercel.firewall_action.count';

export const DEFAULT_FIREWALL_GROUP_BY = ['waf_rule_id', 'waf_action'] as const;

export interface FirewallMetricsOptions {
  since: string;
  granularity?: string;
  groupBy?: readonly string[];
}

export interface FirewallMetricRow {
  ruleId?: string;
  action?: string;
  count: number;
}

/**
 * Outcome of a metrics read.
 *
 * `shapeUnrecognized` rides on the success arm rather than being a third
 * failure reason: the command ran, we have the raw payload, we simply could not
 * find rows in it. A caller can still print the raw response or fall back to the
 * dashboard, and does not have to treat it as an error.
 */
export type MetricsResult =
  | { ok: true; rows: FirewallMetricRow[]; raw: unknown; shapeUnrecognized?: true }
  | { ok: false; reason: 'not-enabled' | 'unavailable'; detail: string };

/**
 * A duration string did not match the accepted grammar.
 *
 * Extends `RangeError` rather than `ExecError` because it is pre-spawn argument
 * validation, not an execution failure — the same call this module is wrapping
 * has not happened yet. `firewall.ts` sets this precedent in `positionFlags`,
 * which throws a plain `RangeError` for an out-of-range `--position`.
 */
export class InvalidDurationError extends RangeError {
  readonly field: string;
  readonly received: string;

  constructor(field: string, received: string) {
    super(
      [
        `invalid ${field} duration ${JSON.stringify(received)}.`,
        'Accepted form is <number><unit> where unit is m (minutes), h (hours) or d (days)',
        '— for example 30m, 6h, 3d.',
        '',
        'Rejecting rather than passing this through: a window the CLI silently',
        'reinterprets would make the verify step report on the wrong time range.',
      ].join('\n'),
    );
    this.name = 'InvalidDurationError';
    this.field = field;
    this.received = received;
  }
}

const DURATION = /^\d+[mhd]$/;

function assertDuration(field: string, value: string): string {
  if (!DURATION.test(value)) throw new InvalidDurationError(field, value);
  return value;
}

export function firewallActionMetricsArgv(opts: FirewallMetricsOptions): string[] {
  const groupBy = opts.groupBy ?? DEFAULT_FIREWALL_GROUP_BY;
  const since = assertDuration('--since', opts.since);

  const argv = ['metrics', FIREWALL_ACTION_METRIC];
  for (const dimension of groupBy) argv.push('--group-by', dimension);
  argv.push('--since', since);
  if (opts.granularity !== undefined) {
    argv.push('--granularity', assertDuration('--granularity', opts.granularity));
  }
  argv.push('--format', 'json');
  return argv;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Does this failure mean "the project has no Observability Plus"?
 *
 * Matched loosely and case-insensitively on purpose. The exact wording is not a
 * stable contract, and over-matching here is cheap — both arms of the union
 * degrade to the same dashboard-URL fallback, they differ only in the sentence
 * we print. Under-matching is the expensive direction, because it turns a known,
 * explainable limitation into an opaque "unavailable".
 */
function looksLikeNotEnabled(text: string): boolean {
  if (/not\s+enabled/i.test(text)) return true;
  if (/observability\s*plus/i.test(text)) return true;
  return /observability/i.test(text) && /metrics/i.test(text);
}

const RULE_KEYS = ['waf_rule_id', 'wafRuleId', 'rule_id', 'ruleId'] as const;
const ACTION_KEYS = ['waf_action', 'wafAction', 'action'] as const;
const COUNT_KEYS = ['count', 'value', 'total'] as const;
const NON_VALUE_KEYS = new Set<string>([...RULE_KEYS, ...ACTION_KEYS, 'timestamp']);

function readString(row: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  return undefined;
}

/**
 * Resolve the numeric value of a grouped row.
 *
 * The named keys are tried first, then any remaining numeric column. The
 * fallback is the branch that actually fires against the real CLI: it names the
 * value column `<metric>_<aggregation>` with dots flattened to underscores
 * (`commands/metrics/output.ts:5-12`), so `vercel.firewall_action.count`
 * summed arrives as `vercel_firewall_action_count_sum` — a name we cannot
 * hardcode without also hardcoding the aggregation the CLI chose for us.
 */
function readCount(row: Record<string, unknown>): number | undefined {
  for (const key of COUNT_KEYS) {
    const value = row[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  for (const [key, value] of Object.entries(row)) {
    if (NON_VALUE_KEYS.has(key)) continue;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return undefined;
}

function toRow(entry: unknown): FirewallMetricRow | undefined {
  if (!isRecord(entry)) return undefined;
  const count = readCount(entry);
  if (count === undefined) return undefined;
  const ruleId = readString(entry, RULE_KEYS);
  const action = readString(entry, ACTION_KEYS);
  return {
    ...(ruleId === undefined ? {} : { ruleId }),
    ...(action === undefined ? {} : { action }),
    count,
  };
}

/**
 * Find the row array in an envelope whose exact shape we do not control.
 *
 * The CLI currently emits `{ query, summary, data, statistics }`
 * (`commands/metrics/output.ts:36-46`), so `data` is the expected hit; `rows`
 * and `series` are tolerated because the JSON envelope is not a documented
 * stability contract and a bare array is the other plausible form.
 */
function findRowArray(payload: unknown): unknown[] | undefined {
  if (Array.isArray(payload)) return payload;
  if (!isRecord(payload)) return undefined;
  for (const key of ['data', 'series', 'rows']) {
    const candidate = payload[key];
    if (Array.isArray(candidate)) return candidate;
  }
  return undefined;
}

export async function getFirewallActionMetrics(
  opts: FirewallMetricsOptions,
  scope: Scope,
  timeoutMs?: number,
): Promise<MetricsResult> {
  const argv = firewallActionMetricsArgv(opts);

  let result;
  try {
    result = await runVercel(
      argv,
      timeoutMs === undefined ? { cwd: scope.cwd } : { cwd: scope.cwd, timeoutMs },
    );
  } catch (err) {
    return {
      ok: false,
      reason: 'unavailable',
      detail: truncate(err instanceof Error ? err.message : String(err)),
    };
  }

  if (result.exitCode !== 0) {
    const detail = truncate((result.stderr.trim() || result.stdout.trim()) || '(no output)');
    return {
      ok: false,
      reason: looksLikeNotEnabled(`${result.stderr}\n${result.stdout}`) ? 'not-enabled' : 'unavailable',
      detail,
    };
  }

  let parsed: unknown;
  try {
    parsed = parseJsonStdout(result);
  } catch (err) {
    return {
      ok: false,
      reason: 'unavailable',
      detail: truncate(err instanceof Error ? err.message : String(err)),
    };
  }

  const entries = findRowArray(parsed);
  if (entries === undefined) {
    return { ok: true, rows: [], raw: parsed, shapeUnrecognized: true };
  }

  const rows: FirewallMetricRow[] = [];
  for (const entry of entries) {
    const row = toRow(entry);
    if (row !== undefined) rows.push(row);
  }
  return { ok: true, rows, raw: parsed };
}

export interface DashboardUrlParams {
  team: string;
  project: string;
  ruleId?: string;
}

/** The documented fallback surface when {@link getFirewallActionMetrics} cannot read anything. */
export function firewallTrafficDashboardUrl(params: DashboardUrlParams): string {
  const team = encodeURIComponent(params.team);
  const project = encodeURIComponent(params.project);
  const base = `https://vercel.com/${team}/${project}/firewall/traffic`;
  if (params.ruleId === undefined || params.ruleId === '') return base;
  return `${base}?filter=${encodeURIComponent(params.ruleId)}`;
}

export interface MetricSummaryEntry {
  key: string;
  count: number;
}

export const UNKNOWN_KEY = '(unknown)';

/**
 * Sorted by descending count, then by key ascending.
 *
 * The tiebreaker is not cosmetic: these aggregates are rendered into a report
 * that operators diff between runs, so two identical datasets must produce
 * byte-identical output regardless of the order rows arrived in.
 */
function summarize(
  rows: readonly FirewallMetricRow[],
  pick: (row: FirewallMetricRow) => string | undefined,
): MetricSummaryEntry[] {
  const totals = new Map<string, number>();
  for (const row of rows) {
    const key = pick(row) ?? UNKNOWN_KEY;
    totals.set(key, (totals.get(key) ?? 0) + row.count);
  }
  return [...totals.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => (b.count - a.count) || a.key.localeCompare(b.key));
}

export function summarizeByAction(rows: readonly FirewallMetricRow[]): MetricSummaryEntry[] {
  return summarize(rows, (row) => row.action);
}

export function summarizeByRule(rows: readonly FirewallMetricRow[]): MetricSummaryEntry[] {
  return summarize(rows, (row) => row.ruleId);
}
