import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CliError, CliJsonParseError, CliTimeoutError } from './errors.js';
import {
  DEFAULT_TIMEOUT_MS,
  formatArgvForAudit,
  parseJsonStdout,
  runVercel,
  runVercelOrThrow,
} from './spawn.js';

vi.mock('node:child_process', () => ({ spawn: vi.fn() }));

const spawnMock = vi.mocked(spawn);

interface FakeChild extends EventEmitter {
  stdout: PassThrough;
  stderr: PassThrough;
  stdin: PassThrough;
  kill: ReturnType<typeof vi.fn>;
}

function makeChild(): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  child.kill = vi.fn();
  return child;
}

/**
 * Queue a child that emits the given output then closes. Emission is deferred
 * until `spawn` is actually invoked so a queued stub survives a conditional
 * second call.
 */
function stubRun(opts: { stdout?: string; stderr?: string; exitCode?: number }): void {
  spawnMock.mockImplementationOnce(() => {
    const child = makeChild();
    queueMicrotask(() => {
      if (opts.stdout !== undefined) child.stdout.write(opts.stdout);
      if (opts.stderr !== undefined) child.stderr.write(opts.stderr);
      child.emit('close', opts.exitCode ?? 0, null);
    });
    return child as unknown as ReturnType<typeof spawn>;
  });
}

function result(stdout: string, argv: string[] = ['firewall', 'rules', 'list', '--json']) {
  return { argv, exitCode: 0, stdout, stderr: '', durationMs: 1 };
}

beforeEach(() => {
  spawnMock.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('runVercel', () => {
  it('spawns the vercel binary with an argv array and never a shell', async () => {
    stubRun({ stdout: 'ok' });
    await runVercel(['firewall', 'rules', 'list']);

    const call = spawnMock.mock.calls[0];
    expect(call).toBeDefined();
    expect(call?.[0]).toBe('vercel');
    expect(call?.[1]).toEqual(['firewall', 'rules', 'list']);
    const options = call?.[2] as { shell?: boolean } | undefined;
    expect(options?.shell).toBe(false);
  });

  it('injects a non-interactive environment so the CLI never prompts', async () => {
    stubRun({ stdout: 'ok' });
    await runVercel(['whoami']);

    const options = spawnMock.mock.calls[0]?.[2] as
      | { env?: NodeJS.ProcessEnv }
      | undefined;
    expect(options?.env?.['CI']).toBe('1');
    expect(options?.env?.['VERCEL_CLI_NON_INTERACTIVE']).toBe('1');
  });

  it('never reads VERCEL_TOKEN or forwards an injected one as an auth argument', async () => {
    stubRun({ stdout: 'ok' });
    await runVercel(['firewall', 'diff', '--json']);

    const argv = spawnMock.mock.calls[0]?.[1];
    expect(argv?.some((a) => /token/i.test(a))).toBe(false);
  });

  it('returns the result on non-zero exit instead of throwing', async () => {
    stubRun({ stdout: 'partial', stderr: 'boom', exitCode: 3 });
    const res = await runVercel(['firewall', 'publish', '--yes']);

    expect(res.exitCode).toBe(3);
    expect(res.stderr).toBe('boom');
    expect(res.argv).toEqual(['firewall', 'publish', '--yes']);
  });

  it('reports a signalled death as a 128 exit code', async () => {
    const child = makeChild();
    spawnMock.mockReturnValueOnce(child as unknown as ReturnType<typeof spawn>);
    queueMicrotask(() => child.emit('close', null, 'SIGTERM'));

    await expect(runVercel(['whoami'])).resolves.toMatchObject({ exitCode: 128 });
  });

  it('rejects when the binary cannot be spawned at all', async () => {
    const child = makeChild();
    spawnMock.mockReturnValueOnce(child as unknown as ReturnType<typeof spawn>);
    queueMicrotask(() => child.emit('error', new Error('ENOENT')));

    await expect(runVercel(['whoami'])).rejects.toThrow('ENOENT');
  });

  it('kills the child and rejects with CliTimeoutError when it never exits', async () => {
    vi.useFakeTimers();
    const child = makeChild();
    spawnMock.mockReturnValueOnce(child as unknown as ReturnType<typeof spawn>);

    const promise = runVercel(['firewall', 'diff'], { timeoutMs: 50 });
    const assertion = expect(promise).rejects.toBeInstanceOf(CliTimeoutError);
    await vi.advanceTimersByTimeAsync(60);
    await assertion;

    expect(child.kill).toHaveBeenCalledWith('SIGKILL');
  });

  it('defaults to a 120s timeout', () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(120_000);
  });
});

describe('runVercelOrThrow', () => {
  it('resolves on exit code 0', async () => {
    stubRun({ stdout: 'fine' });
    await expect(runVercelOrThrow(['whoami'])).resolves.toMatchObject({ exitCode: 0 });
  });

  it('throws a CliError carrying argv, exit code and stderr', async () => {
    stubRun({ stderr: 'not authenticated', exitCode: 1 });

    await expect(runVercelOrThrow(['firewall', 'publish', '--yes'])).rejects.toSatisfy(
      (err: unknown) =>
        err instanceof CliError &&
        err.exitCode === 1 &&
        err.stderr === 'not authenticated' &&
        err.argv.join(' ') === 'firewall publish --yes' &&
        err.message.includes('not authenticated'),
    );
  });
});

describe('formatArgvForAudit', () => {
  it('renders a plain command unquoted', () => {
    expect(formatArgvForAudit(['firewall', 'rules', 'list', '--json'])).toBe(
      'vercel firewall rules list --json',
    );
  });

  it('quotes arguments containing shell metacharacters', () => {
    expect(formatArgvForAudit(['firewall', 'rules', 'remove', 'evil; rm -rf /'])).toBe(
      "vercel firewall rules remove 'evil; rm -rf /'",
    );
  });

  it('escapes embedded single quotes', () => {
    expect(formatArgvForAudit(["it's"])).toBe(`vercel 'it'\\''s'`);
  });
});

describe('argv safety', () => {
  it('passes a hostile rule name as one opaque argv element', async () => {
    const hostile = `evil"; rm -rf / #\n$(whoami) 'quoted'`;
    stubRun({ stdout: '{}' });

    await runVercel(['firewall', 'rules', 'remove', hostile, '--yes']);

    const argv = spawnMock.mock.calls[0]?.[1];
    expect(argv).toEqual(['firewall', 'rules', 'remove', hostile, '--yes']);
    expect(argv?.[3]).toBe(hostile);
    expect(argv).toHaveLength(5);
  });

  it('never enables shell mode even for hostile input', async () => {
    stubRun({ stdout: '{}' });
    await runVercel(['firewall', 'rules', 'add', '`id`', '--yes']);

    const options = spawnMock.mock.calls[0]?.[2] as { shell?: boolean } | undefined;
    expect(options?.shell).toBe(false);
  });
});

describe('parseJsonStdout', () => {
  it('parses clean JSON', () => {
    expect(parseJsonStdout(result('{"rules":[]}'))).toEqual({ rules: [] });
  });

  it('parses JSON preceded by CLI banner lines', () => {
    const stdout = ['Vercel CLI 59.0.0', 'Retrieving firewall config…', '{"ok":true}'].join('\n');
    expect(parseJsonStdout(result(stdout))).toEqual({ ok: true });
  });

  it('parses an array payload', () => {
    expect(parseJsonStdout(result('Vercel CLI 59.0.0\n[1,2,3]'))).toEqual([1, 2, 3]);
  });

  it('parses indented JSON after a banner', () => {
    expect(parseJsonStdout(result('banner\n  {"a":1}'))).toEqual({ a: 1 });
  });

  it('ignores a brace appearing mid-sentence in a banner', () => {
    const stdout = ['Using scope {team-alpha} for this run', '{"real":true}'].join('\n');
    expect(parseJsonStdout(result(stdout))).toEqual({ real: true });
  });

  it('throws a typed error with a snippet on malformed JSON', () => {
    try {
      parseJsonStdout(result('{"broken": '));
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CliJsonParseError);
      expect((err as CliJsonParseError).snippet).toContain('{"broken"');
      expect((err as CliJsonParseError).message).toContain('firewall rules list --json');
    }
  });

  it('throws a typed error on empty stdout rather than returning undefined', () => {
    try {
      parseJsonStdout(result('   \n  '));
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CliJsonParseError);
      expect((err as CliJsonParseError).message).toContain('stdout was empty');
    }
  });

  it('throws when stdout contains no JSON body at all', () => {
    try {
      parseJsonStdout(result('Error: not authenticated\nRun `vercel login`'));
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CliJsonParseError);
      expect((err as CliJsonParseError).message).toContain('no line beginning with');
    }
  });
});
