import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CapabilityError,
  MIN_VERCEL_MAJOR,
  MIN_VERCEL_MAJOR_TEAM_LEVEL,
  NotLinkedError,
  VercelVersionError,
  assertLinkedProject,
  assertVercelVersion,
  checkVercelVersion,
  parseVercelVersion,
  probeFirewallCapabilities,
} from './preflight.js';

vi.mock('node:child_process', () => ({ spawn: vi.fn() }));

const spawnMock = vi.mocked(spawn);

function stubRun(stdout: string, exitCode = 0): void {
  spawnMock.mockImplementationOnce(() => {
    const child = new EventEmitter() as EventEmitter & {
      stdout: PassThrough;
      stderr: PassThrough;
      stdin: PassThrough;
      kill: () => void;
    };
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.kill = () => undefined;
    queueMicrotask(() => {
      child.stdout.write(stdout);
      child.emit('close', exitCode, null);
    });
    return child as unknown as ReturnType<typeof spawn>;
  });
}

function versionResult(stdout: string) {
  return { argv: ['--version'], exitCode: 0, stdout, stderr: '', durationMs: 1 };
}

beforeEach(() => {
  spawnMock.mockReset();
});

describe('version floors', () => {
  it('pins the documented baseline and team-level minimums', () => {
    expect(MIN_VERCEL_MAJOR).toBe(56);
    expect(MIN_VERCEL_MAJOR_TEAM_LEVEL).toBe(59);
  });
});

describe('parseVercelVersion', () => {
  it('parses the banner form', () => {
    expect(parseVercelVersion('Vercel CLI 59.0.0')).toEqual({
      major: 59,
      minor: 0,
      patch: 0,
      raw: '59.0.0',
    });
  });

  it('parses a bare version', () => {
    expect(parseVercelVersion('56.1.0')).toMatchObject({ major: 56, minor: 1, patch: 0 });
  });

  it('parses a prerelease and keeps the full raw string', () => {
    expect(parseVercelVersion('60.0.0-canary.1')).toEqual({
      major: 60,
      minor: 0,
      patch: 0,
      raw: '60.0.0-canary.1',
    });
  });

  it('tolerates trailing newlines and surrounding noise', () => {
    expect(parseVercelVersion('  Vercel CLI 59.12.3 \n')).toMatchObject({
      major: 59,
      minor: 12,
      patch: 3,
    });
  });

  it('throws on garbage', () => {
    expect(() => parseVercelVersion('command not found: vercel')).toThrow(VercelVersionError);
  });

  it('throws on empty output', () => {
    expect(() => parseVercelVersion('')).toThrow(VercelVersionError);
  });
});

describe('assertVercelVersion', () => {
  it('accepts 56 for the baseline requirement', () => {
    expect(assertVercelVersion(versionResult('56.1.0'))).toMatchObject({ major: 56 });
  });

  it('rejects 55 for the baseline requirement', () => {
    expect(() => assertVercelVersion(versionResult('55.9.9'))).toThrow(VercelVersionError);
  });

  it('rejects 56 when team-level is required and names 59', () => {
    try {
      assertVercelVersion(versionResult('Vercel CLI 56.1.0'), { requireTeamLevel: true });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VercelVersionError);
      const message = (err as VercelVersionError).message;
      expect(message).toContain('56.1.0');
      expect(message).toContain('>= 59.0.0');
      expect(message).toContain('--team-level');
      expect((err as VercelVersionError).requiredMajor).toBe(59);
    }
  });

  it('accepts 59 for both baseline and team-level', () => {
    expect(assertVercelVersion(versionResult('59.0.0'))).toMatchObject({ major: 59 });
    expect(
      assertVercelVersion(versionResult('59.0.0'), { requireTeamLevel: true }),
    ).toMatchObject({ major: 59 });
  });

  it('includes the exact remediation command in the error message', () => {
    try {
      assertVercelVersion(versionResult('50.0.0'));
      expect.unreachable('should have thrown');
    } catch (err) {
      expect((err as VercelVersionError).message).toContain('npm i -g vercel@latest');
    }
  });

  it('falls back to stderr when the version was printed there', () => {
    const result = { argv: ['--version'], exitCode: 0, stdout: '', stderr: '59.1.0', durationMs: 1 };
    expect(assertVercelVersion(result)).toMatchObject({ major: 59 });
  });
});

describe('checkVercelVersion', () => {
  it('spawns `vercel --version` and validates the result', async () => {
    stubRun('Vercel CLI 59.0.0');
    await expect(checkVercelVersion()).resolves.toMatchObject({ major: 59 });
    expect(spawnMock.mock.calls[0]?.[1]).toEqual(['--version']);
  });
});

const FULL_FIREWALL_HELP = `
vercel firewall

  overview   Show config
  diff       Show pending changes
  publish    Publish draft
  discard    Discard draft
  rules      Manage custom rules
  ip-blocks  Manage IP blocks

Options:
  --team-level
`;

const FULL_ADD_HELP = `
vercel firewall rules add

Options:
  --json <payload>
  --condition <cond>
  --action <action>
  --team-level
  --yes
`;

describe('probeFirewallCapabilities', () => {
  it('reports every capability present on a modern CLI', async () => {
    stubRun(FULL_FIREWALL_HELP);
    stubRun(FULL_ADD_HELP);

    const caps = await probeFirewallCapabilities();

    expect(caps.subcommands).toEqual({
      rules: true,
      diff: true,
      publish: true,
      discard: true,
      overview: true,
    });
    expect(caps.rulesAddFlags).toEqual({ json: true, condition: true, action: true, yes: true });
    expect(caps.teamLevel).toBe(true);
  });

  it('probes both `firewall --help` and `firewall rules add --help`', async () => {
    stubRun(FULL_FIREWALL_HELP);
    stubRun(FULL_ADD_HELP);
    await probeFirewallCapabilities();

    const invoked = spawnMock.mock.calls.map((c) => c[1]);
    expect(invoked).toContainEqual(['firewall', '--help']);
    expect(invoked).toContainEqual(['firewall', 'rules', 'add', '--help']);
  });

  it('throws listing every missing piece at once', async () => {
    stubRun('vercel firewall\n  overview  Show config\n');
    stubRun('vercel firewall rules add\nOptions:\n  --yes\n');

    try {
      await probeFirewallCapabilities();
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CapabilityError);
      const missing = (err as CapabilityError).missing.join('\n');
      expect(missing).toContain('diff');
      expect(missing).toContain('publish');
      expect(missing).toContain('--json');
      expect(missing).toContain('--condition');
      expect((err as CapabilityError).message).toContain('npm i -g vercel@latest');
    }
  });

  it('fails when team-level is required but absent from help output', async () => {
    stubRun(FULL_FIREWALL_HELP.replace('  --team-level\n', ''));
    stubRun(FULL_ADD_HELP.replace('  --team-level\n', ''));

    await expect(probeFirewallCapabilities({ requireTeamLevel: true })).rejects.toBeInstanceOf(
      CapabilityError,
    );
  });

  it('passes when team-level is absent but not required', async () => {
    stubRun(FULL_FIREWALL_HELP.replace('  --team-level\n', ''));
    stubRun(FULL_ADD_HELP.replace('  --team-level\n', ''));

    await expect(probeFirewallCapabilities()).resolves.toMatchObject({ teamLevel: false });
  });
});

async function tempProject(contents?: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'waf-preflight-'));
  if (contents !== undefined) {
    await mkdir(path.join(dir, '.vercel'), { recursive: true });
    await writeFile(path.join(dir, '.vercel', 'project.json'), contents, 'utf8');
  }
  return dir;
}

describe('assertLinkedProject', () => {
  it('returns projectId and orgId from a valid link file', async () => {
    const dir = await tempProject(
      JSON.stringify({ projectId: 'prj_abc', orgId: 'team_xyz', settings: {} }),
    );
    await expect(assertLinkedProject(dir)).resolves.toEqual({
      projectId: 'prj_abc',
      orgId: 'team_xyz',
    });
  });

  it('tells the user to run `vercel link` when the file is missing', async () => {
    const dir = await tempProject();
    try {
      await assertLinkedProject(dir);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NotLinkedError);
      expect((err as NotLinkedError).message).toContain('vercel link');
      expect((err as NotLinkedError).message).toContain('does not exist');
    }
  });

  it('reports malformed JSON specifically', async () => {
    const dir = await tempProject('{ not json');
    try {
      await assertLinkedProject(dir);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NotLinkedError);
      expect((err as NotLinkedError).message).toContain('not valid JSON');
    }
  });

  it('rejects a JSON array', async () => {
    const dir = await tempProject('[]');
    await expect(assertLinkedProject(dir)).rejects.toThrow(/does not contain a JSON object/);
  });

  it('reports a missing projectId specifically', async () => {
    const dir = await tempProject(JSON.stringify({ orgId: 'team_xyz' }));
    await expect(assertLinkedProject(dir)).rejects.toThrow(/no "projectId" string/);
  });

  it('reports a missing orgId specifically', async () => {
    const dir = await tempProject(JSON.stringify({ projectId: 'prj_abc' }));
    await expect(assertLinkedProject(dir)).rejects.toThrow(/no "orgId" string/);
  });

  it('treats an empty-string projectId as missing', async () => {
    const dir = await tempProject(JSON.stringify({ projectId: '', orgId: 'team_xyz' }));
    await expect(assertLinkedProject(dir)).rejects.toThrow(/no "projectId" string/);
  });
});
