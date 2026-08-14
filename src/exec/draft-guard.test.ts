import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ForeignDraftError, assertNoForeignDraft, checkForeignDraft } from './draft-guard.js';
import type { Scope } from './firewall.js';

vi.mock('node:child_process', () => ({ spawn: vi.fn() }));

const spawnMock = vi.mocked(spawn);

const SCOPE: Scope = { teamLevel: false, cwd: '/tmp/proj' };

/**
 * Queue one fake child. The `close` event is emitted only once `spawn` is
 * actually called, so a queued stub still works for a second, conditional
 * invocation such as the non-JSON diff fallback.
 */
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

const DIRTY = JSON.stringify({
  changes: [
    { action: 'rules.insert', id: 'r1' },
    { action: 'rules.insert', id: 'r2' },
    { action: 'ip.insert', id: 'i1' },
  ],
});

beforeEach(() => {
  spawnMock.mockReset();
});

describe('checkForeignDraft', () => {
  it('reports clean via json when changes is empty', async () => {
    stubRun(JSON.stringify({ changes: [] }));
    await expect(checkForeignDraft(SCOPE)).resolves.toEqual({ clean: true, via: 'json' });
  });

  it('reports dirty via json with a per-action summary', async () => {
    stubRun(DIRTY);
    const check = await checkForeignDraft(SCOPE);

    expect(check.clean).toBe(false);
    if (!check.clean) {
      expect(check.via).toBe('json');
      expect(check.summary).toContain('3 staged change(s)');
      expect(check.summary).toContain('rules.insert x2');
      expect(check.summary).toContain('ip.insert x1');
    }
  });

  it('uses diff --json first', async () => {
    stubRun(JSON.stringify({ changes: [] }));
    await checkForeignDraft(SCOPE);
    expect(spawnMock.mock.calls[0]?.[1]).toEqual(['firewall', 'diff', '--json']);
  });

  it('falls back to the text diff when JSON is unusable and reports which path was taken', async () => {
    stubRun('this is not json at all');
    stubRun('No pending changes.');

    const check = await checkForeignDraft(SCOPE);
    expect(check).toEqual({ clean: true, via: 'text' });
    expect(spawnMock.mock.calls[1]?.[1]).toEqual(['firewall', 'diff']);
  });

  it('treats unrecognized text diff output as dirty rather than assuming clean', async () => {
    stubRun('not json');
    stubRun('~ rules.update  Some rule someone else staged');

    const check = await checkForeignDraft(SCOPE);
    expect(check.clean).toBe(false);
    if (!check.clean) expect(check.via).toBe('text');
  });

  it('appends --team-level to the text fallback at team scope', async () => {
    stubRun('not json');
    stubRun('No pending changes.');
    await checkForeignDraft({ teamLevel: true, cwd: '/tmp/proj' });
    expect(spawnMock.mock.calls[1]?.[1]).toEqual(['firewall', 'diff', '--team-level']);
  });
});

describe('assertNoForeignDraft', () => {
  it('passes on a clean diff', async () => {
    stubRun(JSON.stringify({ changes: [] }));
    await expect(assertNoForeignDraft(SCOPE, { adoptDraft: false })).resolves.toMatchObject({
      clean: true,
    });
  });

  it('throws on a non-empty diff, printing the summary and both ways forward', async () => {
    stubRun(DIRTY);

    try {
      await assertNoForeignDraft(SCOPE, { adoptDraft: false });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ForeignDraftError);
      const message = (err as ForeignDraftError).message;
      expect(message).toContain('3 staged change(s)');
      expect(message).toContain('would promote them to production');
      expect(message).toContain('vercel firewall discard --yes');
      expect(message).toContain('--adopt-draft');
      expect(message).toContain('vercel firewall diff --json');
      expect((err as ForeignDraftError).via).toBe('json');
    }
  });

  it('passes on a non-empty diff when adoptDraft is explicitly true', async () => {
    stubRun(DIRTY);
    const check = await assertNoForeignDraft(SCOPE, { adoptDraft: true });
    expect(check.clean).toBe(false);
  });

  it('throws when the text fallback could not confirm a clean draft', async () => {
    stubRun('not json');
    stubRun('+ rules.insert something');
    await expect(assertNoForeignDraft(SCOPE, { adoptDraft: false })).rejects.toBeInstanceOf(
      ForeignDraftError,
    );
  });

  it('carries the raw diff for the audit log', async () => {
    stubRun(DIRTY);
    try {
      await assertNoForeignDraft(SCOPE, { adoptDraft: false });
      expect.unreachable('should have thrown');
    } catch (err) {
      const raw = (err as ForeignDraftError).raw as { changes: { action: string }[] };
      expect(raw.changes).toHaveLength(3);
      expect(raw.changes[0]).toMatchObject({ action: 'rules.insert', id: 'r1' });
    }
  });
});
