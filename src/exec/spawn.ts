/**
 * The single place this tool talks to Vercel: by spawning the real `vercel`
 * binary. Nothing else in the codebase may import `node:child_process`.
 *
 * WHY THE CLI AND NOT `@vercel/sdk` / REST — this is a deliberate architectural
 * constraint, not an accident of convenience. Do not "modernize" it:
 *
 *   1. Credentials. This tool runs on customer-adjacent laptops operated by
 *      Vercel field engineers. `vercel login` mints a short-lived, team-scoped
 *      credential managed by the CLI. The SDK/REST path would instead require a
 *      long-lived Personal Access Token sitting in an env var or dotfile on
 *      those same machines. That is a security downgrade we are explicitly
 *      refusing. Consequently this module NEVER reads `VERCEL_TOKEN`, never
 *      constructs an `Authorization` header, and never calls `fetch`/`https`.
 *   2. Stability. `@vercel/sdk` is beta and ships breaking changes without a
 *      major version bump. The CLI's flag surface is comparatively stable and,
 *      more importantly, we can *probe* it at runtime (see `preflight.ts`).
 *   3. Auditability. The artifact we hand a customer is the literal argv plus
 *      captured stdout/stderr. That is reproducible by hand and reviewable by
 *      someone who does not read TypeScript.
 *
 * WHY AN ARGV ARRAY AND NEVER A SHELL STRING — rule names, hostnames and IPs
 * arrive from customer-supplied CSV files and flow straight into these
 * arguments. `spawn` with an argv array and `shell: false` means a rule named
 * `foo; rm -rf /` is one opaque argument, not two commands. There is a test
 * asserting exactly that. Never set `shell: true`, never build a command
 * string, never pass user input through a template literal into an exec call.
 */

import { spawn } from 'node:child_process';

import { CliError, CliJsonParseError, CliTimeoutError } from './errors.js';

/** Everything a caller (or an audit log) needs to know about one invocation. */
export interface CliResult {
  argv: string[];
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export interface RunVercelOptions {
  cwd?: string;
  timeoutMs?: number;
  input?: string;
}

/**
 * Two minutes. Firewall reads are sub-second; the ceiling exists to stop a
 * hung child from wedging an unattended migration forever.
 */
export const DEFAULT_TIMEOUT_MS = 120_000;

/** The binary we drive. Resolved from PATH by `spawn`, never through a shell. */
export const VERCEL_BIN = 'vercel';

/**
 * Environment forced onto every child.
 *
 * `CI=1` plus the Vercel-specific non-interactive hints keep the CLI from ever
 * blocking on a TTY prompt — a prompt in a non-TTY child is indistinguishable
 * from a hang, and would burn the full timeout. Callers must additionally pass
 * `--yes` on any subcommand that supports it; the env alone is not a contract.
 */
function nonInteractiveEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    CI: '1',
    VERCEL_CLI_NON_INTERACTIVE: '1',
    NO_COLOR: '1',
    FORCE_COLOR: '0',
  };
}

/** POSIX shell quoting, for the audit log only — never fed back into a shell. */
function shellQuote(arg: string): string {
  if (arg.length > 0 && /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) return arg;
  return `'${arg.replaceAll("'", `'\\''`)}'`;
}

/**
 * Render an argv as a copy-pasteable command for the audit artifact.
 *
 * Presentation only. The real invocation always uses the array form; this
 * string exists so a customer can reproduce what we ran by hand.
 */
export function formatArgvForAudit(argv: readonly string[]): string {
  return [VERCEL_BIN, ...argv].map(shellQuote).join(' ');
}

/**
 * Run `vercel <args>` and resolve with the outcome.
 *
 * Resolves for ANY exit code — a non-zero exit is data, not an exception, and
 * several callers legitimately expect one. Rejects only when the process could
 * not be run at all, or when it blew the timeout.
 */
export function runVercel(args: string[], opts: RunVercelOptions = {}): Promise<CliResult> {
  const argv = [...args];
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const startedAt = Date.now();

  return new Promise<CliResult>((resolve, reject) => {
    const child = spawn(VERCEL_BIN, argv, {
      cwd: opts.cwd ?? process.cwd(),
      env: nonInteractiveEnv(),
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const timer = setTimeout(() => {
      finish(() => {
        child.kill('SIGKILL');
        reject(new CliTimeoutError({ argv, timeoutMs, stdout, stderr }));
      });
    }, timeoutMs);
    timer.unref?.();

    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => {
      stderr += chunk;
    });

    child.on('error', (err) => {
      finish(() => reject(err));
    });

    child.on('close', (code, signal) => {
      finish(() =>
        resolve({
          argv,
          // A signalled death has a null code; surface it as a conventional 128+n.
          exitCode: code ?? (signal === null ? 1 : 128),
          stdout,
          stderr,
          durationMs: Date.now() - startedAt,
        }),
      );
    });

    if (opts.input !== undefined) {
      child.stdin?.end(opts.input);
    } else {
      child.stdin?.end();
    }
  });
}

/** `runVercel`, but a non-zero exit throws a {@link CliError}. */
export async function runVercelOrThrow(
  args: string[],
  opts: RunVercelOptions = {},
): Promise<CliResult> {
  const result = await runVercel(args, opts);
  if (result.exitCode !== 0) {
    throw new CliError({
      argv: result.argv,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }
  return result;
}

/**
 * Locate the start of the JSON body in CLI stdout.
 *
 * The CLI prints human banners ("Vercel CLI 59.0.0", "Retrieving project…")
 * before the payload even under `--json`, so we cannot just `JSON.parse` the
 * whole buffer. We scan for the first line that *begins* with `{` or `[` —
 * anchoring to line start avoids matching a brace inside a banner sentence.
 */
function findJsonStart(stdout: string): number {
  const lines = stdout.split('\n');
  let offset = 0;
  for (const line of lines) {
    const trimmed = line.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      return offset + (line.length - trimmed.length);
    }
    offset += line.length + 1;
  }
  return -1;
}

/**
 * Parse the JSON body out of a `--json` invocation.
 *
 * Returns `unknown` by design: the CLI's output shape is not ours to assert,
 * so callers narrow it with real type guards rather than a cast. Throws a
 * {@link CliJsonParseError} carrying a snippet of what we actually received —
 * silently returning `undefined` here would turn a CLI change into a
 * mysterious downstream null-deref on a customer's machine.
 */
export function parseJsonStdout(result: CliResult): unknown {
  const { stdout, argv } = result;

  if (stdout.trim() === '') {
    throw new CliJsonParseError({ argv, stdout, reason: 'stdout was empty' });
  }

  const start = findJsonStart(stdout);
  if (start === -1) {
    throw new CliJsonParseError({
      argv,
      stdout,
      reason: 'no line beginning with "{" or "[" was found',
    });
  }

  const body = stdout.slice(start);
  try {
    return JSON.parse(body) as unknown;
  } catch (cause) {
    throw new CliJsonParseError({
      argv,
      stdout: body,
      reason: cause instanceof Error ? cause.message : 'JSON.parse failed',
      cause,
    });
  }
}
