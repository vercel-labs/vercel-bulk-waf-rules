/**
 * Safety preflights that run before any mutation is attempted.
 *
 * Two independent checks, because each catches something the other cannot:
 * a version gate (cheap, coarse) and a capability probe against the real
 * `--help` output (authoritative). A version number is only a proxy for what a
 * binary can do — a customer may have a patched build, a stale global install
 * shadowed by a local one, or a canary. The probe reads what is actually there.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { ExecError } from './errors.js';
import type { CliResult } from './spawn.js';
import { runVercel } from './spawn.js';

/**
 * Baseline: `vercel firewall` with `rules add --json`, `--condition`, `diff`,
 * `publish` and `discard` all exist in 56.1.0 (verified empirically).
 */
export const MIN_VERCEL_MAJOR = 56;

/**
 * `--team-level` is NOT present in 56.1.0 — `vercel firewall rules list --help`
 * on that version shows no such flag. It landed later, so team-scoped runs
 * require a higher floor.
 */
export const MIN_VERCEL_MAJOR_TEAM_LEVEL = 59;

export interface VercelVersion {
  major: number;
  minor: number;
  patch: number;
  raw: string;
}

export class VercelVersionError extends ExecError {
  override readonly kind = 'vercel-version' as const;
  readonly detected: string;
  readonly requiredMajor: number;

  constructor(args: { detected: string; requiredMajor: number; because: string }) {
    super(
      [
        `Vercel CLI ${args.detected} is too old: ${args.because}`,
        `  detected: ${args.detected}`,
        `  required: >= ${String(args.requiredMajor)}.0.0`,
        '',
        'Upgrade with:',
        '  npm i -g vercel@latest',
      ].join('\n'),
    );
    this.detected = args.detected;
    this.requiredMajor = args.requiredMajor;
  }
}

/**
 * `59`, `.0`, `.0`, then an optional `-canary.1` style prerelease tail that we
 * capture into `raw` but otherwise ignore for gating purposes.
 */
const VERSION_RE = /(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?/;

/**
 * Extract a semver from `vercel --version` output.
 *
 * Tolerates both the bare `56.1.0` form and the banner form
 * `Vercel CLI 59.0.0`, since which one you get depends on version and TTY.
 */
export function parseVercelVersion(stdout: string): VercelVersion {
  const match = VERSION_RE.exec(stdout);
  const major = match?.[1];
  const minor = match?.[2];
  const patch = match?.[3];

  if (match === null || major === undefined || minor === undefined || patch === undefined) {
    throw new VercelVersionError({
      detected: stdout.trim() === '' ? '(empty output)' : stdout.trim().split('\n')[0] ?? '(unknown)',
      requiredMajor: MIN_VERCEL_MAJOR,
      because: 'could not parse a version number from `vercel --version` output',
    });
  }

  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    raw: match[0],
  };
}

export interface VersionRequirement {
  requireTeamLevel?: boolean;
}

/**
 * Fail loudly if the installed CLI predates the flags we depend on.
 *
 * Never silently degrades to a fallback code path: a wrapper that quietly
 * stops passing `--team-level` would apply project-scoped rules while the
 * operator believes they are editing team-scoped config.
 */
export function assertVercelVersion(
  result: CliResult,
  opts: VersionRequirement = {},
): VercelVersion {
  const version = parseVercelVersion(result.stdout || result.stderr);
  const requireTeamLevel = opts.requireTeamLevel === true;
  const required = requireTeamLevel ? MIN_VERCEL_MAJOR_TEAM_LEVEL : MIN_VERCEL_MAJOR;

  if (version.major < required) {
    throw new VercelVersionError({
      detected: version.raw,
      requiredMajor: required,
      because: requireTeamLevel
        ? '`--team-level` is not available on this version'
        : '`vercel firewall` lacks the subcommands this tool requires',
    });
  }

  return version;
}

/** Fetch and validate the CLI version in one step. */
export async function checkVercelVersion(
  opts: VersionRequirement & { cwd?: string } = {},
): Promise<VercelVersion> {
  const result = await runVercel(
    ['--version'],
    opts.cwd === undefined ? {} : { cwd: opts.cwd },
  );
  return assertVercelVersion(
    result,
    opts.requireTeamLevel === undefined ? {} : { requireTeamLevel: opts.requireTeamLevel },
  );
}

export class CapabilityError extends ExecError {
  override readonly kind = 'capability' as const;
  readonly missing: readonly string[];

  constructor(missing: readonly string[]) {
    super(
      [
        'The installed Vercel CLI is missing firewall features this tool requires:',
        ...missing.map((m) => `  - ${m}`),
        '',
        'Upgrade with:',
        '  npm i -g vercel@latest',
      ].join('\n'),
    );
    this.missing = [...missing];
  }
}

export interface FirewallCapabilities {
  subcommands: { rules: boolean; diff: boolean; publish: boolean; discard: boolean; overview: boolean };
  rulesAddFlags: { json: boolean; condition: boolean; action: boolean; yes: boolean };
  teamLevel: boolean;
}

/**
 * Word-boundary match so `--json` does not also match `--jsonl`, and so a flag
 * mentioned in prose ("output as json") does not count as present.
 */
function hasFlag(help: string, flag: string): boolean {
  return new RegExp(`${flag.replaceAll('-', '\\-')}(?![A-Za-z0-9-])`).test(help);
}

function hasSubcommand(help: string, name: string): boolean {
  return new RegExp(`(?:^|\\s)${name}(?![A-Za-z0-9-])`, 'm').test(help);
}

export interface ProbeOptions {
  cwd?: string;
  requireTeamLevel?: boolean;
}

/**
 * Read the CLI's own `--help` and assert the surface we depend on is present.
 *
 * Authoritative in a way a version comparison is not: this is the binary that
 * will actually run. Throws {@link CapabilityError} listing every missing
 * piece at once rather than failing on the first, so an operator gets one
 * upgrade instruction instead of a sequence of them.
 */
export async function probeFirewallCapabilities(
  opts: ProbeOptions = {},
): Promise<FirewallCapabilities> {
  const runOpts = opts.cwd === undefined ? {} : { cwd: opts.cwd };
  const [firewallHelp, addHelp] = await Promise.all([
    runVercel(['firewall', '--help'], runOpts),
    runVercel(['firewall', 'rules', 'add', '--help'], runOpts),
  ]);

  const fwText = `${firewallHelp.stdout}\n${firewallHelp.stderr}`;
  const addText = `${addHelp.stdout}\n${addHelp.stderr}`;

  const capabilities: FirewallCapabilities = {
    subcommands: {
      rules: hasSubcommand(fwText, 'rules'),
      diff: hasSubcommand(fwText, 'diff'),
      publish: hasSubcommand(fwText, 'publish'),
      discard: hasSubcommand(fwText, 'discard'),
      overview: hasSubcommand(fwText, 'overview'),
    },
    rulesAddFlags: {
      json: hasFlag(addText, '--json'),
      condition: hasFlag(addText, '--condition'),
      action: hasFlag(addText, '--action'),
      yes: hasFlag(addText, '--yes'),
    },
    teamLevel: hasFlag(fwText, '--team-level') || hasFlag(addText, '--team-level'),
  };

  const missing: string[] = [];
  for (const [name, present] of Object.entries(capabilities.subcommands)) {
    if (!present) missing.push(`\`vercel firewall ${name}\` subcommand`);
  }
  for (const [name, present] of Object.entries(capabilities.rulesAddFlags)) {
    if (!present) missing.push(`\`vercel firewall rules add --${name}\` flag`);
  }
  if (opts.requireTeamLevel === true && !capabilities.teamLevel) {
    missing.push('`--team-level` flag (team-scoped operation was requested)');
  }

  if (missing.length > 0) throw new CapabilityError(missing);
  return capabilities;
}

export class NotLinkedError extends ExecError {
  override readonly kind = 'not-linked' as const;
  readonly cwd: string;

  constructor(args: { cwd: string; because: string }) {
    super(
      [
        `No usable Vercel project link in ${args.cwd}: ${args.because}`,
        '',
        'Link the directory first:',
        '  vercel link',
      ].join('\n'),
    );
    this.cwd = args.cwd;
  }
}

export interface LinkedProject {
  projectId: string;
  orgId: string;
}

function readStringField(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * Resolve `{ projectId, orgId }` from `.vercel/project.json`.
 *
 * We read the file rather than shelling out because it is the same artifact
 * `vercel link` writes and the CLI itself consumes; an unreadable or partial
 * file means every subsequent firewall call would fail with a much less
 * actionable error deep inside the CLI.
 */
export async function assertLinkedProject(cwd: string): Promise<LinkedProject> {
  const file = path.join(cwd, '.vercel', 'project.json');

  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    throw new NotLinkedError({ cwd, because: `${file} does not exist or is unreadable` });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (err) {
    throw new NotLinkedError({
      cwd,
      because: `${file} is not valid JSON (${err instanceof Error ? err.message : String(err)})`,
    });
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new NotLinkedError({ cwd, because: `${file} does not contain a JSON object` });
  }

  const record: Record<string, unknown> = { ...parsed };
  const projectId = readStringField(record, 'projectId');
  const orgId = readStringField(record, 'orgId');

  if (projectId === undefined) {
    throw new NotLinkedError({ cwd, because: `${file} has no "projectId" string` });
  }
  if (orgId === undefined) {
    throw new NotLinkedError({ cwd, because: `${file} has no "orgId" string` });
  }

  return { projectId, orgId };
}
