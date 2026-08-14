/**
 * Typed error hierarchy for the execution layer.
 *
 * Every error carries enough context to debug from nothing but a customer's
 * terminal transcript: the argv we ran, the exit code, and whatever the CLI
 * wrote to stderr. Field engineers frequently paste a scrollback into Slack and
 * nothing else, so an error that only says "command failed" costs a round trip.
 *
 * There are deliberately no secrets to redact — see the module doc-comment in
 * `spawn.ts` for why this tool never handles a token.
 */

/** Discriminator for narrowing execution-layer errors without `instanceof` chains. */
export type ExecErrorKind =
  | 'cli-error'
  | 'cli-timeout'
  | 'cli-json-parse'
  | 'vercel-version'
  | 'capability'
  | 'scope-unsupported'
  | 'not-linked'
  | 'foreign-draft'
  | 'lockout';

/** Base class for everything thrown by `src/exec`. */
export abstract class ExecError extends Error {
  abstract readonly kind: ExecErrorKind;

  protected constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Truncate long CLI output so an error message stays pasteable. */
export function truncate(text: string, max = 500): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}… (${text.length - max} more chars)`;
}

/**
 * A `vercel` invocation exited non-zero.
 *
 * Only thrown by `runVercelOrThrow` — the plain `runVercel` returns the result
 * so callers can inspect a non-zero exit without exception control flow.
 */
export class CliError extends ExecError {
  override readonly kind = 'cli-error' as const;
  readonly argv: readonly string[];
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(args: {
    argv: readonly string[];
    exitCode: number;
    stdout: string;
    stderr: string;
  }) {
    super(
      [
        `vercel exited with code ${args.exitCode}`,
        `  argv:   ${args.argv.join(' ')}`,
        `  stderr: ${truncate(args.stderr.trim()) || '(empty)'}`,
      ].join('\n'),
    );
    this.argv = [...args.argv];
    this.exitCode = args.exitCode;
    this.stdout = args.stdout;
    this.stderr = args.stderr;
  }
}

/** The child process exceeded its timeout and was killed. */
export class CliTimeoutError extends ExecError {
  override readonly kind = 'cli-timeout' as const;
  readonly argv: readonly string[];
  readonly timeoutMs: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(args: {
    argv: readonly string[];
    timeoutMs: number;
    stdout: string;
    stderr: string;
  }) {
    super(
      [
        `vercel timed out after ${args.timeoutMs}ms and was killed`,
        `  argv:   ${args.argv.join(' ')}`,
        `  stdout: ${truncate(args.stdout.trim(), 200) || '(empty)'}`,
        `  stderr: ${truncate(args.stderr.trim(), 200) || '(empty)'}`,
      ].join('\n'),
    );
    this.argv = [...args.argv];
    this.timeoutMs = args.timeoutMs;
    this.stdout = args.stdout;
    this.stderr = args.stderr;
  }
}

/** `--json` output could not be parsed. Never swallowed into `undefined`. */
export class CliJsonParseError extends ExecError {
  override readonly kind = 'cli-json-parse' as const;
  readonly argv: readonly string[];
  readonly snippet: string;
  override readonly cause: unknown;

  constructor(args: { argv: readonly string[]; stdout: string; reason: string; cause?: unknown }) {
    super(
      [
        `could not parse JSON from vercel stdout: ${args.reason}`,
        `  argv: ${args.argv.join(' ')}`,
        `  got:  ${truncate(args.stdout.trim(), 400) || '(empty stdout)'}`,
      ].join('\n'),
    );
    this.argv = [...args.argv];
    this.snippet = truncate(args.stdout.trim(), 400);
    this.cause = args.cause;
  }
}
