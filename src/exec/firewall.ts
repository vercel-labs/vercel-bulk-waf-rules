/**
 * Typed wrappers over `vercel firewall`.
 *
 * Flag names and JSON shapes here are transcribed from the CLI source, not
 * guessed — see `packages/cli/src/commands/firewall/command.ts` for the option
 * definitions and `util/firewall/types.ts` for the payload types. Two
 * consequences worth knowing before editing:
 *
 *   - `--json` means two different things. On read commands (`overview`,
 *     `diff`, `rules list`, `rules inspect`) it is a Boolean output-format
 *     flag. On `rules add` / `rules edit` it is a **String** carrying the rule
 *     payload (command.ts:437, command.ts:584). Never conflate them.
 *   - `rules` and `ip-blocks` mutations only stage a draft; nothing reaches
 *     production until `publish`. `system-bypass`, `attack-mode` and
 *     `system-mitigations` are immediate — and the latter two are severity-gated
 *     incident controls, so this module deliberately provides no wrapper for
 *     them at all. Same for `rules add --ai` and the interactive wizard, which
 *     the CLI hard-blocks for non-TTY callers anyway (rules/add.ts:66-96).
 */

import { ExecError } from './errors.js';
import type { CliResult } from './spawn.js';
import { formatArgvForAudit, parseJsonStdout, runVercelOrThrow } from './spawn.js';

/**
 * Which firewall config to operate on.
 *
 * `teamLevel` switches the CLI onto the team-scoped config that applies to
 * every project in the team. It requires a newer CLI — see
 * `MIN_VERCEL_MAJOR_TEAM_LEVEL` in `preflight.ts`.
 */
export interface Scope {
  teamLevel: boolean;
  cwd: string;
}

export interface MutationOptions {
  dryRun: boolean;
  timeoutMs?: number;
}

/**
 * Result of a mutating call. Discriminated on `dryRun` so a caller cannot read
 * `.result` without first proving a spawn actually happened.
 */
export type MutationOutcome =
  | { dryRun: true; argv: string[]; audit: string }
  | { dryRun: false; argv: string[]; audit: string; result: CliResult };

/** Thrown when a subcommand does not support the requested scope. */
export class ScopeUnsupportedError extends ExecError {
  override readonly kind = 'scope-unsupported' as const;

  constructor(subcommand: string) {
    super(
      [
        `\`vercel firewall ${subcommand}\` does not support --team-level.`,
        '',
        'Silently falling back to project scope would show you project data while you',
        'believe you are looking at team-level config, so this is a hard error.',
      ].join('\n'),
    );
  }
}

/**
 * Verbatim from `util/firewall/types.ts`. Fields the CLI marks optional stay
 * optional here — asserting presence on data we do not own is how a wrapper
 * starts throwing on a customer's machine after a CLI patch release.
 */
export interface FirewallCondition {
  type: string;
  op: string;
  neg?: boolean;
  key?: string;
  value?: string | string[] | number;
}

export interface FirewallConditionGroup {
  conditions: FirewallCondition[];
}

export interface FirewallMitigateAction {
  action: string;
  rateLimit?: unknown;
  redirect?: unknown;
  actionDuration?: string | null;
}

export interface FirewallRuleAction {
  mitigate?: FirewallMitigateAction;
}

export interface FirewallRule {
  id: string;
  name: string;
  description?: string;
  active: boolean;
  conditionGroup: FirewallConditionGroup[];
  action: FirewallRuleAction;
  valid?: boolean;
  validationErrors?: string[];
  /** Injected by `rules list --json` only (rules/list.ts:46), not a server field. */
  _status?: string;
}

/** Shape of `rules list --json` (rules/list.ts:43-52). */
export interface RulesListOutput {
  rules: FirewallRule[];
  hasDraft?: boolean;
  pendingChanges?: number;
}

/** One staged change. `action` is an open string union in the CLI's own types. */
export interface FirewallConfigChange {
  action: string;
  id?: string | null;
  value?: unknown;
}

/** Shape of `diff --json` (diff.ts:28-40): always `{ changes }`, `[]` when clean. */
export interface DiffOutput {
  changes: FirewallConfigChange[];
}

/** Shape of `overview --json` (overview.ts:50-58). */
export interface OverviewOutput {
  active?: unknown;
  draft?: unknown;
  bypass?: unknown;
  attackMode?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFirewallRule(value: unknown): value is FirewallRule {
  if (!isRecord(value)) return false;
  return (
    typeof value['id'] === 'string' &&
    typeof value['name'] === 'string' &&
    typeof value['active'] === 'boolean' &&
    Array.isArray(value['conditionGroup']) &&
    isRecord(value['action'])
  );
}

function isFirewallConfigChange(value: unknown): value is FirewallConfigChange {
  return isRecord(value) && typeof value['action'] === 'string';
}

class ShapeError extends ExecError {
  override readonly kind = 'cli-json-parse' as const;

  constructor(what: string, got: unknown) {
    super(
      `unexpected shape for ${what}: ${JSON.stringify(got)?.slice(0, 300) ?? String(got)}`,
    );
  }
}

/**
 * Scope flags for one subcommand.
 *
 * Throws rather than dropping the flag when the subcommand cannot honour it —
 * `overview` notably has no `--team-level` (command.ts:13-35), unlike `diff`,
 * `publish`, `discard` and every `rules` subcommand.
 */
function scopeFlags(scope: Scope, subcommand: string, supportsTeamLevel: boolean): string[] {
  if (!scope.teamLevel) return [];
  if (!supportsTeamLevel) throw new ScopeUnsupportedError(subcommand);
  return ['--team-level'];
}

async function readJson(argv: string[], scope: Scope, timeoutMs?: number): Promise<unknown> {
  const result = await runVercelOrThrow(
    argv,
    timeoutMs === undefined ? { cwd: scope.cwd } : { cwd: scope.cwd, timeoutMs },
  );
  return parseJsonStdout(result);
}

/**
 * Run or, under `dryRun`, describe a mutation.
 *
 * A dry run must not spawn anything — the returned argv is exactly what a real
 * run would execute, which is what makes `--dry-run` output trustworthy as a
 * review artifact.
 */
async function mutate(
  argv: string[],
  scope: Scope,
  opts: MutationOptions,
): Promise<MutationOutcome> {
  const audit = formatArgvForAudit(argv);
  if (opts.dryRun) return { dryRun: true, argv, audit };

  const result = await runVercelOrThrow(
    argv,
    opts.timeoutMs === undefined ? { cwd: scope.cwd } : { cwd: scope.cwd, timeoutMs: opts.timeoutMs },
  );
  return { dryRun: false, argv, audit, result };
}

export function listRulesArgv(scope: Scope): string[] {
  return ['firewall', 'rules', 'list', ...scopeFlags(scope, 'rules list', true), '--json'];
}

export async function listRules(scope: Scope): Promise<RulesListOutput> {
  const parsed = await readJson(listRulesArgv(scope), scope);
  if (!isRecord(parsed) || !Array.isArray(parsed['rules'])) {
    throw new ShapeError('rules list --json', parsed);
  }
  const rules = parsed['rules'].filter(isFirewallRule);
  const hasDraft = parsed['hasDraft'];
  const pendingChanges = parsed['pendingChanges'];
  return {
    rules,
    ...(typeof hasDraft === 'boolean' ? { hasDraft } : {}),
    ...(typeof pendingChanges === 'number' ? { pendingChanges } : {}),
  };
}

export function inspectRuleArgv(nameOrId: string, scope: Scope): string[] {
  return [
    'firewall',
    'rules',
    'inspect',
    nameOrId,
    ...scopeFlags(scope, 'rules inspect', true),
    '--json',
  ];
}

/** `rules inspect --json` emits the bare rule object, not a wrapper (rules/inspect.ts:142-145). */
export async function inspectRule(nameOrId: string, scope: Scope): Promise<FirewallRule> {
  const parsed = await readJson(inspectRuleArgv(nameOrId, scope), scope);
  if (!isFirewallRule(parsed)) throw new ShapeError('rules inspect --json', parsed);
  return parsed;
}

/**
 * The rule payload is passed as a single argv element containing JSON.
 *
 * The rule name lives inside the payload (`add.ts:227`), so the optional
 * positional `name` argument is deliberately omitted — supplying both invites a
 * disagreement between two sources of truth for the same field.
 */
export function addRuleArgv(ruleJson: unknown, scope: Scope): string[] {
  return [
    'firewall',
    'rules',
    'add',
    ...scopeFlags(scope, 'rules add', true),
    '--json',
    JSON.stringify(ruleJson),
    '--yes',
  ];
}

export function addRule(
  ruleJson: unknown,
  scope: Scope,
  opts: MutationOptions,
): Promise<MutationOutcome> {
  return mutate(addRuleArgv(ruleJson, scope), scope, opts);
}

export function editRuleArgv(nameOrId: string, ruleJson: unknown, scope: Scope): string[] {
  return [
    'firewall',
    'rules',
    'edit',
    nameOrId,
    ...scopeFlags(scope, 'rules edit', true),
    '--json',
    JSON.stringify(ruleJson),
    '--yes',
  ];
}

export function editRule(
  nameOrId: string,
  ruleJson: unknown,
  scope: Scope,
  opts: MutationOptions,
): Promise<MutationOutcome> {
  return mutate(editRuleArgv(nameOrId, ruleJson, scope), scope, opts);
}

export function removeRuleArgv(nameOrId: string, scope: Scope): string[] {
  return [
    'firewall',
    'rules',
    'remove',
    nameOrId,
    ...scopeFlags(scope, 'rules remove', true),
    '--yes',
  ];
}

export function removeRule(
  nameOrId: string,
  scope: Scope,
  opts: MutationOptions,
): Promise<MutationOutcome> {
  return mutate(removeRuleArgv(nameOrId, scope), scope, opts);
}

/**
 * Target slot for `rules reorder`.
 *
 * `--position` is **1-based** (command.ts:784-789, converted to a 0-based index
 * at reorder.ts:185) and is mutually exclusive with `--first` / `--last`
 * (reorder.ts:158-166), so this is modelled as a union rather than three flags.
 */
export type ReorderPosition =
  | { kind: 'first' }
  | { kind: 'last' }
  | { kind: 'position'; value: number };

function positionFlags(position: ReorderPosition): string[] {
  switch (position.kind) {
    case 'first':
      return ['--first'];
    case 'last':
      return ['--last'];
    case 'position': {
      if (!Number.isInteger(position.value) || position.value < 1) {
        throw new RangeError(
          `reorder position must be a 1-based integer >= 1, got ${String(position.value)}`,
        );
      }
      return ['--position', String(position.value)];
    }
  }
}

export function reorderRuleArgv(
  nameOrId: string,
  position: ReorderPosition,
  scope: Scope,
): string[] {
  return [
    'firewall',
    'rules',
    'reorder',
    nameOrId,
    ...scopeFlags(scope, 'rules reorder', true),
    ...positionFlags(position),
    '--yes',
  ];
}

export function reorderRule(
  nameOrId: string,
  position: ReorderPosition,
  scope: Scope,
  opts: MutationOptions,
): Promise<MutationOutcome> {
  return mutate(reorderRuleArgv(nameOrId, position, scope), scope, opts);
}

/** `overview` has no `--team-level` (command.ts:13-35); team scope is rejected. */
export function getOverviewArgv(scope: Scope): string[] {
  return ['firewall', 'overview', ...scopeFlags(scope, 'overview', false), '--json'];
}

export async function getOverview(scope: Scope): Promise<OverviewOutput> {
  const parsed = await readJson(getOverviewArgv(scope), scope);
  if (!isRecord(parsed)) throw new ShapeError('overview --json', parsed);
  return parsed;
}

export function getDiffArgv(scope: Scope): string[] {
  return ['firewall', 'diff', ...scopeFlags(scope, 'diff', true), '--json'];
}

export async function getDiff(scope: Scope): Promise<DiffOutput> {
  const parsed = await readJson(getDiffArgv(scope), scope);
  if (!isRecord(parsed) || !Array.isArray(parsed['changes'])) {
    throw new ShapeError('diff --json', parsed);
  }
  return { changes: parsed['changes'].filter(isFirewallConfigChange) };
}

export function publishArgv(scope: Scope): string[] {
  return ['firewall', 'publish', ...scopeFlags(scope, 'publish', true), '--yes'];
}

/** Promotes the staged draft to production. Irreversible from this tool's side. */
export function publish(scope: Scope, opts: MutationOptions): Promise<MutationOutcome> {
  return mutate(publishArgv(scope), scope, opts);
}

export function discardArgv(scope: Scope): string[] {
  return ['firewall', 'discard', ...scopeFlags(scope, 'discard', true), '--yes'];
}

/** Drops the staged draft. Discards ANY draft on the config, including a colleague's. */
export function discard(scope: Scope, opts: MutationOptions): Promise<MutationOutcome> {
  return mutate(discardArgv(scope), scope, opts);
}
