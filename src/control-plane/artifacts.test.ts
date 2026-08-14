import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { planIpCsv } from '../cli/plan-ip.js';
import type { MigrationBundle } from './model.js';
import { writeMigrationBundle } from './artifact-store.js';
import { parseMigrationBundle, parseMigrationBundleText } from './artifacts.js';

function bundle(): MigrationBundle {
  const result = planIpCsv(['ip,vendor_name', '8.8.8.8,Example'].join('\n'), {
    inputPath: './addresses.csv',
    sourceProvider: 'csv',
    intent: { kind: 'blocklist' },
    projectId: 'prj_1',
    ruleNamePrefix: 'Imported addresses',
    createdAt: '2026-08-14T12:00:00.000Z',
  });
  if (!result.ok) throw new Error(result.message);
  return result.bundle;
}

describe('migration bundle artifacts', () => {
  it('round-trips a generated bundle through strict runtime validation', () => {
    const original = bundle();
    const parsed = parseMigrationBundleText(JSON.stringify(original));

    expect(parsed).toEqual({ ok: true, bundle: original });
  });

  it('detects content edited without regenerating the plan id', () => {
    const original = bundle();
    const first = original.plan.operations[0];
    if (first === undefined) throw new Error('fixture has no operation');
    const tampered: MigrationBundle = {
      ...original,
      plan: {
        ...original.plan,
        operations: [{ ...first, payload: { changed: true } }],
      },
    };

    expect(parseMigrationBundle(tampered)).toMatchObject({
      ok: false,
      problems: [{ code: 'PLAN_ID_MISMATCH', path: '$.plan.id' }],
    });
  });

  it('rejects missing snapshots and mismatched source references', () => {
    const original = bundle();
    const parsed = parseMigrationBundle({ ...original, snapshots: [] });

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.problems.map(({ code }) => code)).toContain('MISSING_SNAPSHOT');
  });

  it('rejects unknown fields and invalid JSON', () => {
    const original = bundle();
    const unknownField = parseMigrationBundle({ ...original, surprise: true });
    const invalidJson = parseMigrationBundleText('{');

    expect(unknownField).toMatchObject({
      ok: false,
      problems: [{ code: 'SCHEMA_INVALID', path: '$' }],
    });
    expect(invalidJson).toMatchObject({
      ok: false,
      problems: [{ code: 'INVALID_JSON', path: '$' }],
    });
  });

  it('persists bundles below a schema-versioned artifact directory', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vercel-migrate-artifacts-'));
    try {
      const original = bundle();
      const path = await writeMigrationBundle(original, root);
      expect(path).toBe(join(root, 'v1', `${original.plan.id}.json`));

      const parsed = parseMigrationBundleText(await readFile(path, 'utf8'));
      expect(parsed.ok).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
