import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as fw from './firewall.js';

vi.mock('node:child_process', () => ({ spawn: vi.fn() }));

const spawnMock = vi.mocked(spawn);

const PROJECT: fw.Scope = { teamLevel: false, cwd: '/tmp/proj' };
const TEAM: fw.Scope = { teamLevel: true, cwd: '/tmp/proj' };
const DRY = { dryRun: true } as const;
const LIVE = { dryRun: false } as const;

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

const RULE = {
  name: 'IP Allowlist - Auto-managed',
  active: true,
  conditionGroup: [{ conditions: [{ type: 'ip_address', op: 'ninc', value: ['1.2.3.4'] }] }],
  action: { mitigate: { action: 'deny' } },
};

const RULE_JSON = JSON.stringify(RULE);

beforeEach(() => {
  spawnMock.mockReset();
});

describe('read argv construction', () => {
  it('listRules', () => {
    expect(fw.listRulesArgv(PROJECT)).toEqual(['firewall', 'rules', 'list', '--json']);
    expect(fw.listRulesArgv(TEAM)).toEqual([
      'firewall',
      'rules',
      'list',
      '--team-level',
      '--json',
    ]);
  });

  it('inspectRule places the identifier before the flags', () => {
    expect(fw.inspectRuleArgv('rule_123', PROJECT)).toEqual([
      'firewall',
      'rules',
      'inspect',
      'rule_123',
      '--json',
    ]);
    expect(fw.inspectRuleArgv('rule_123', TEAM)).toEqual([
      'firewall',
      'rules',
      'inspect',
      'rule_123',
      '--team-level',
      '--json',
    ]);
  });

  it('getDiff', () => {
    expect(fw.getDiffArgv(PROJECT)).toEqual(['firewall', 'diff', '--json']);
    expect(fw.getDiffArgv(TEAM)).toEqual(['firewall', 'diff', '--team-level', '--json']);
  });

  it('getOverview at project scope', () => {
    expect(fw.getOverviewArgv(PROJECT)).toEqual(['firewall', 'overview', '--json']);
  });

  it('getOverview refuses team scope because the CLI has no --team-level there', () => {
    expect(() => fw.getOverviewArgv(TEAM)).toThrow(fw.ScopeUnsupportedError);
  });
});

describe('mutation argv construction', () => {
  it('addRule at project scope', () => {
    expect(fw.addRuleArgv(RULE, PROJECT)).toEqual([
      'firewall',
      'rules',
      'add',
      '--json',
      RULE_JSON,
      '--yes',
    ]);
  });

  it('addRule at team level', () => {
    expect(fw.addRuleArgv(RULE, TEAM)).toEqual([
      'firewall',
      'rules',
      'add',
      '--team-level',
      '--json',
      RULE_JSON,
      '--yes',
    ]);
  });

  it('editRule', () => {
    expect(fw.editRuleArgv('rule_123', RULE, PROJECT)).toEqual([
      'firewall',
      'rules',
      'edit',
      'rule_123',
      '--json',
      RULE_JSON,
      '--yes',
    ]);
  });

  it('removeRule', () => {
    expect(fw.removeRuleArgv('rule_123', PROJECT)).toEqual([
      'firewall',
      'rules',
      'remove',
      'rule_123',
      '--yes',
    ]);
  });

  it('reorderRule --first', () => {
    expect(fw.reorderRuleArgv('rule_123', { kind: 'first' }, PROJECT)).toEqual([
      'firewall',
      'rules',
      'reorder',
      'rule_123',
      '--first',
      '--yes',
    ]);
  });

  it('reorderRule --last', () => {
    expect(fw.reorderRuleArgv('rule_123', { kind: 'last' }, PROJECT)).toEqual([
      'firewall',
      'rules',
      'reorder',
      'rule_123',
      '--last',
      '--yes',
    ]);
  });

  it('reorderRule --position is 1-based and stringified', () => {
    expect(fw.reorderRuleArgv('rule_123', { kind: 'position', value: 3 }, TEAM)).toEqual([
      'firewall',
      'rules',
      'reorder',
      'rule_123',
      '--team-level',
      '--position',
      '3',
      '--yes',
    ]);
  });

  it('reorderRule rejects a 0 or fractional position', () => {
    expect(() => fw.reorderRuleArgv('r', { kind: 'position', value: 0 }, PROJECT)).toThrow(
      RangeError,
    );
    expect(() => fw.reorderRuleArgv('r', { kind: 'position', value: 1.5 }, PROJECT)).toThrow(
      RangeError,
    );
  });

  it('publish', () => {
    expect(fw.publishArgv(PROJECT)).toEqual(['firewall', 'publish', '--yes']);
    expect(fw.publishArgv(TEAM)).toEqual(['firewall', 'publish', '--team-level', '--yes']);
  });

  it('discard', () => {
    expect(fw.discardArgv(PROJECT)).toEqual(['firewall', 'discard', '--yes']);
  });

  it('every mutation carries --yes so the CLI never waits for a prompt', () => {
    const argvs = [
      fw.addRuleArgv(RULE, PROJECT),
      fw.editRuleArgv('r', RULE, PROJECT),
      fw.removeRuleArgv('r', PROJECT),
      fw.reorderRuleArgv('r', { kind: 'first' }, PROJECT),
      fw.publishArgv(PROJECT),
      fw.discardArgv(PROJECT),
    ];
    for (const argv of argvs) expect(argv).toContain('--yes');
  });
});

describe('dryRun', () => {
  it('returns argv without spawning for every mutation', async () => {
    const outcomes = await Promise.all([
      fw.addRule(RULE, PROJECT, DRY),
      fw.editRule('r', RULE, PROJECT, DRY),
      fw.removeRule('r', PROJECT, DRY),
      fw.reorderRule('r', { kind: 'last' }, PROJECT, DRY),
      fw.publish(PROJECT, DRY),
      fw.discard(PROJECT, DRY),
    ]);

    expect(spawnMock).not.toHaveBeenCalled();
    for (const outcome of outcomes) {
      expect(outcome.dryRun).toBe(true);
      expect(outcome.argv.length).toBeGreaterThan(0);
      expect(outcome.audit.startsWith('vercel firewall')).toBe(true);
    }
  });

  it('produces argv identical to what a live run would execute', async () => {
    const dryOutcome = await fw.addRule(RULE, TEAM, DRY);
    stubRun('{}');
    const liveOutcome = await fw.addRule(RULE, TEAM, LIVE);

    expect(dryOutcome.argv).toEqual(liveOutcome.argv);
    expect(spawnMock.mock.calls[0]?.[1]).toEqual(dryOutcome.argv);
  });

  it('spawns when dryRun is false', async () => {
    stubRun('{}');
    const outcome = await fw.publish(PROJECT, LIVE);

    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(outcome.dryRun).toBe(false);
    if (!outcome.dryRun) expect(outcome.result.exitCode).toBe(0);
  });
});

describe('argv safety with hostile identifiers', () => {
  const HOSTILE = `evil; rm -rf / "quoted" 'single'\nnewline $(id)`;

  it('keeps a hostile rule name as a single argv element in removeRule', async () => {
    stubRun('{}');
    await fw.removeRule(HOSTILE, PROJECT, LIVE);

    const argv = spawnMock.mock.calls[0]?.[1];
    expect(argv).toEqual(['firewall', 'rules', 'remove', HOSTILE, '--yes']);
    expect(argv?.[3]).toBe(HOSTILE);
  });

  it('keeps a hostile name inside the JSON payload as a single argv element', async () => {
    const hostileRule = { ...RULE, name: HOSTILE };
    stubRun('{}');
    await fw.addRule(hostileRule, PROJECT, LIVE);

    const argv = spawnMock.mock.calls[0]?.[1];
    expect(argv).toHaveLength(6);
    expect(argv?.[4]).toBe(JSON.stringify(hostileRule));
    const parsed: unknown = JSON.parse(argv?.[4] ?? '');
    expect((parsed as { name: string }).name).toBe(HOSTILE);
  });

  it('never enables shell mode', async () => {
    stubRun('{}');
    await fw.removeRule(HOSTILE, PROJECT, LIVE);
    const options = spawnMock.mock.calls[0]?.[2] as { shell?: boolean } | undefined;
    expect(options?.shell).toBe(false);
  });

  it('runs in the scope cwd', async () => {
    stubRun('{}');
    await fw.publish({ teamLevel: false, cwd: '/tmp/somewhere' }, LIVE);
    const options = spawnMock.mock.calls[0]?.[2] as { cwd?: string } | undefined;
    expect(options?.cwd).toBe('/tmp/somewhere');
  });
});

describe('output parsing', () => {
  it('listRules parses the documented wrapper shape', async () => {
    stubRun(
      JSON.stringify({
        rules: [
          {
            id: 'r1',
            name: 'allow',
            active: true,
            conditionGroup: [],
            action: { mitigate: { action: 'deny' } },
            _status: 'staged',
          },
        ],
        hasDraft: true,
        pendingChanges: 2,
      }),
    );

    const out = await fw.listRules(PROJECT);
    expect(out.rules).toHaveLength(1);
    expect(out.rules[0]?.name).toBe('allow');
    expect(out.hasDraft).toBe(true);
    expect(out.pendingChanges).toBe(2);
  });

  it('listRules tolerates the optional fields being absent', async () => {
    stubRun(JSON.stringify({ rules: [] }));
    const out = await fw.listRules(PROJECT);
    expect(out.rules).toEqual([]);
    expect(out.hasDraft).toBeUndefined();
  });

  it('listRules drops entries that do not look like rules', async () => {
    stubRun(JSON.stringify({ rules: [{ nope: true }, null, 'string'] }));
    await expect(fw.listRules(PROJECT)).resolves.toMatchObject({ rules: [] });
  });

  it('listRules rejects a payload with no rules array', async () => {
    stubRun(JSON.stringify({ unexpected: true }));
    await expect(fw.listRules(PROJECT)).rejects.toThrow(/unexpected shape/);
  });

  it('inspectRule returns the bare rule object', async () => {
    stubRun(
      `Vercel CLI 59.0.0\n${JSON.stringify({
        id: 'r1',
        name: 'allow',
        active: true,
        conditionGroup: [],
        action: {},
      })}`,
    );
    await expect(fw.inspectRule('r1', PROJECT)).resolves.toMatchObject({ id: 'r1' });
  });

  it('inspectRule rejects a wrapped payload', async () => {
    stubRun(JSON.stringify({ rule: { id: 'r1' } }));
    await expect(fw.inspectRule('r1', PROJECT)).rejects.toThrow(/unexpected shape/);
  });

  it('getDiff reads an empty changes array as clean', async () => {
    stubRun(JSON.stringify({ changes: [] }));
    await expect(fw.getDiff(PROJECT)).resolves.toEqual({ changes: [] });
  });

  it('getDiff reads staged changes', async () => {
    stubRun(JSON.stringify({ changes: [{ action: 'rules.insert', id: 'r1' }] }));
    const diff = await fw.getDiff(PROJECT);
    expect(diff.changes).toHaveLength(1);
    expect(diff.changes[0]?.action).toBe('rules.insert');
  });

  it('getOverview returns the record as-is', async () => {
    stubRun(JSON.stringify({ active: {}, draft: null, bypass: [], attackMode: {} }));
    await expect(fw.getOverview(PROJECT)).resolves.toMatchObject({ draft: null });
  });

  it('propagates a CLI failure as a thrown CliError', async () => {
    stubRun('', 1);
    await expect(fw.getDiff(PROJECT)).rejects.toThrow(/exited with code 1/);
  });
});
