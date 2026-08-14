/**
 * Firewall **config version** access: read the current version, and promote
 * (roll back to) a previous one.
 *
 * WHY THIS GOES THROUGH `vercel api` AND NOT `vercel firewall`
 * ------------------------------------------------------------
 * `vercel firewall` has no config-version surface. Its command tree is exactly
 * `overview | diff | publish | discard | rules | ip-blocks | system-bypass |
 * attack-mode | system-mitigations` — there is no `versions`, no `history`, no
 * `rollback`. So the only way to capture a restore point before a bulk import,
 * and the only way to restore it afterwards, is the REST endpoint.
 *
 * WHY THAT DOES NOT BREAK THE NO-TOKEN RULE
 * -----------------------------------------
 * `vercel api <endpoint>` is a passthrough subcommand: the CLI performs the
 * HTTP call itself, authenticated with the operator's existing `vercel login`
 * session. We still only ever *spawn a binary*. This module therefore keeps the
 * architectural constraint stated in `spawn.ts` intact — it never reads
 * `VERCEL_TOKEN`, never builds an `Authorization` header, and never calls
 * `fetch` or `node:https`. Reaching a REST endpoint is not the same thing as
 * holding a REST credential, and that distinction is the whole point.
 *
 * FLAG SPELLING — TRANSCRIBED, NOT GUESSED
 * ----------------------------------------
 * From `packages/cli/src/commands/api/command.ts`:
 *   - positional `endpoint` (command.ts:51-56)
 *   - `--method` / `-X METHOD`, "Defaults to GET, or POST if body is provided"
 *     (command.ts:59-67)
 *   - `--raw`, "Output raw JSON without pretty-printing" (command.ts:129-135)
 *   - `--input FILE` ("use - for stdin") for request bodies (command.ts:93-100)
 *   - documented example form: `vercel api /v10/projects -X POST` (command.ts:173)
 * We pass `-X` explicitly even where it matches the CLI default, because the
 * argv is an audit artifact a customer may read months later and "GET" written
 * down beats "GET by convention". Neither call here sends a body, so `--input`
 * is deliberately unused.
 */

import { ExecError } from './errors.js';
import { ScopeUnsupportedError, type MutationOptions, type MutationOutcome, type Scope } from './firewall.js';
import { formatArgvForAudit, parseJsonStdout, runVercelOrThrow } from './spawn.js';

/**
 * Identifies which firewall config to address.
 *
 * `teamId` is how the REST endpoints express team scope — there is no
 * `--team-level` flag on `vercel api`, since the flag belongs to
 * `vercel firewall`, not to the passthrough.
 */
export interface FirewallConfigParams {
  projectId: string;
  teamId?: string;
}

/**
 * What we record before mutating, and what we assert against afterwards.
 *
 * `version` is a **string** on purpose. It is used as a URL path segment and as
 * an opaque restore handle; nothing in this tool ever does arithmetic on it, and
 * modelling it as a number would invite exactly that.
 */
export interface FirewallConfigSnapshot {
  version: string;
  hasDraft: boolean;
  activeRuleCount: number;
  raw: unknown;
}

/**
 * The config payload was not shaped the way we need it to be.
 *
 * Reuses the `cli-json-parse` discriminator because `ExecErrorKind` in
 * `errors.ts` is a closed union and this module is not permitted to extend it.
 * `firewall.ts` sets the same precedent with its local `ShapeError`.
 */
class ConfigShapeError extends ExecError {
  override readonly kind = 'cli-json-parse' as const;

  constructor(message: string) {
    super(message);
  }
}

/**
 * We could not extract a trustworthy config version.
 *
 * Deliberately an error and not a sentinel. A caller that receives `''` or `-1`
 * and stores it as `preImportConfigVersion` has handed the operator a restore
 * point that does not exist — they will import a few hundred rules believing
 * they can undo it. Failing here, before anything is mutated, is strictly
 * better than failing at rollback time.
 */
export class ConfigVersionUnavailableError extends ExecError {
  override readonly kind = 'cli-json-parse' as const;
  readonly received: unknown;

  constructor(received: unknown) {
    super(
      [
        'could not read a usable firewall config version from the API response.',
        `  got: ${describe(received)}`,
        '',
        'Refusing to continue: this value would be recorded as the rollback point,',
        'and a restore point we cannot trust is worse than none — you would believe',
        'the import is reversible when it is not.',
        '',
        'Check the response by hand:',
        '  vercel api /v1/security/firewall/config?projectId=<id> -X GET',
      ].join('\n'),
    );
    this.received = received;
  }
}

function describe(value: unknown): string {
  if (value === undefined) return '(field absent)';
  try {
    return JSON.stringify(value)?.slice(0, 200) ?? String(value);
  } catch {
    return String(value);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Normalise a config version to its canonical string form.
 *
 * Accepts a non-negative integer, expressed either as a JSON number or as a
 * digit-only string, and rejects everything else — including fractional and
 * non-finite numbers, empty strings, and free-form text. The endpoint documents
 * this field as numeric; accepting `"latest"` or `"v3"` on the theory that it is
 * "just an opaque handle" would let a typo travel all the way to a rollback URL.
 */
function normalizeVersion(value: unknown): string | undefined {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) return undefined;
    return String(value);
  }
  if (typeof value === 'string') {
    return /^\d+$/.test(value) ? value : undefined;
  }
  return undefined;
}

/**
 * Locate the version field.
 *
 * Checked at the top level first, then inside `active`, because the endpoint
 * documentation describes a payload containing `active`, `draft` and `version`
 * without pinning the nesting. Both placements are read; neither is asserted.
 */
function readVersion(payload: Record<string, unknown>): unknown {
  const top = payload['version'];
  if (top !== undefined) return top;
  const active = payload['active'];
  return isRecord(active) ? active['version'] : undefined;
}

function countActiveRules(payload: Record<string, unknown>): number {
  const active = payload['active'];
  if (isRecord(active) && Array.isArray(active['rules'])) return active['rules'].length;
  if (Array.isArray(payload['rules'])) return payload['rules'].length;
  return 0;
}

function readHasDraft(payload: Record<string, unknown>): boolean {
  const flag = payload['hasDraft'];
  if (typeof flag === 'boolean') return flag;
  const draft = payload['draft'];
  if (draft === undefined || draft === null) return false;
  if (isRecord(draft)) return Object.keys(draft).length > 0;
  return Boolean(draft);
}

function query(params: FirewallConfigParams): string {
  const qs = new URLSearchParams({ projectId: params.projectId });
  if (params.teamId !== undefined && params.teamId !== '') qs.set('teamId', params.teamId);
  return qs.toString();
}

/**
 * `vercel api` addresses the project by id in the query string, so team-level
 * firewall config — which has no project id — is not reachable here. Say so
 * rather than silently returning the project's config under a team-level label.
 */
function assertProjectScope(scope: Scope): void {
  if (scope.teamLevel) throw new ScopeUnsupportedError('api /v1/security/firewall/config');
}

export function getFirewallConfigArgv(params: FirewallConfigParams): string[] {
  return ['api', `/v1/security/firewall/config?${query(params)}`, '-X', 'GET', '--raw'];
}

/**
 * Promote a config version — the rollback call.
 *
 * ⚠️ THE ENDPOINT IS UNVERIFIED AGAINST A LIVE ACCOUNT. ⚠️
 *
 * Two documentation sources disagree on how promotion is expressed: one
 * describes `POST /v1/security/firewall/config/{configVersion}/activate`, the
 * other `DELETE /v1/security/firewall/config/{configVersion}`. The generated SDK
 * muddies it further — its method is named
 * `deleteSecurityFirewallConfigByConfigVersion`, which contradicts the
 * promote-a-version behaviour its own docs ascribe to it. We use the POST form:
 * a `DELETE` whose documented effect is "make this version live" is far likelier
 * to be a naming artifact than a real destructive delete, and guessing wrong on
 * POST costs an error while guessing wrong on DELETE could cost a config.
 *
 * This is the one call in the tool whose failure mode is "rollback silently
 * does nothing". Callers MUST inspect the returned {@link MutationOutcome},
 * surface a non-success loudly, and never wrap this in a swallowing try/catch —
 * an operator who is told the rollback succeeded when it did not will stop
 * looking for the problem.
 */
export function activateConfigVersionArgv(
  configVersion: string,
  params: FirewallConfigParams,
): string[] {
  const version = normalizeVersion(configVersion);
  if (version === undefined) {
    throw new RangeError(
      `config version must be a non-negative integer, got ${JSON.stringify(configVersion)}`,
    );
  }
  return [
    'api',
    `/v1/security/firewall/config/${version}/activate?${query(params)}`,
    '-X',
    'POST',
    '--raw',
  ];
}

/** Read the firewall config and narrow it into a {@link FirewallConfigSnapshot}. */
export async function getFirewallConfig(
  params: FirewallConfigParams,
  scope: Scope,
  timeoutMs?: number,
): Promise<FirewallConfigSnapshot> {
  assertProjectScope(scope);

  const argv = getFirewallConfigArgv(params);
  const result = await runVercelOrThrow(
    argv,
    timeoutMs === undefined ? { cwd: scope.cwd } : { cwd: scope.cwd, timeoutMs },
  );
  const parsed = parseJsonStdout(result);

  if (!isRecord(parsed)) {
    throw new ConfigShapeError(
      `firewall config response was not a JSON object: ${describe(parsed)}`,
    );
  }

  const version = normalizeVersion(readVersion(parsed));
  if (version === undefined) throw new ConfigVersionUnavailableError(readVersion(parsed));

  return {
    version,
    hasDraft: readHasDraft(parsed),
    activeRuleCount: countActiveRules(parsed),
    raw: parsed,
  };
}

/**
 * Record the pre-import restore point.
 *
 * Thin by design: the value it returns is the only thing standing between a bad
 * bulk import and an unrecoverable one, so it does exactly one thing and throws
 * rather than degrading.
 */
export async function captureConfigVersion(
  params: FirewallConfigParams,
  scope: Scope,
  timeoutMs?: number,
): Promise<string> {
  const snapshot = await getFirewallConfig(params, scope, timeoutMs);
  return snapshot.version;
}

/**
 * Roll back to `configVersion`.
 *
 * See {@link activateConfigVersionArgv} for the endpoint caveat — read it before
 * relying on this. Honours `dryRun` by returning the argv without spawning, so
 * the rollback command can be shown to an operator for approval.
 */
export async function activateConfigVersion(
  configVersion: string,
  params: FirewallConfigParams,
  scope: Scope,
  opts: MutationOptions,
): Promise<MutationOutcome> {
  assertProjectScope(scope);

  const argv = activateConfigVersionArgv(configVersion, params);
  const audit = formatArgvForAudit(argv);
  if (opts.dryRun) return { dryRun: true, argv, audit };

  const result = await runVercelOrThrow(
    argv,
    opts.timeoutMs === undefined ? { cwd: scope.cwd } : { cwd: scope.cwd, timeoutMs: opts.timeoutMs },
  );
  return { dryRun: false, argv, audit, result };
}
