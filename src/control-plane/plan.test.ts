import { describe, expect, it } from 'vitest';

import type { PlanOperation } from './model.js';
import { buildMigrationPlan } from './plan.js';

function operation(id: string, dependsOn: readonly string[] = []): PlanOperation {
  return {
    id,
    product: 'domains',
    kind: 'create',
    effect: 'staged',
    approval: 'before-publish',
    risk: 'low',
    fidelity: 'exact',
    resource: {
      provider: 'vercel',
      resourceType: 'domain',
      externalId: id,
      scope: { projectId: 'prj_1' },
    },
    sourceRefs: [],
    dependsOn,
    payload: { name: `${id}.example` },
  };
}

describe('buildMigrationPlan', () => {
  it('orders operations by dependency while retaining stable input order', () => {
    const result = buildMigrationPlan({
      createdAt: '2026-08-14T12:00:00.000Z',
      sourceSnapshotIds: ['snapshot-b', 'snapshot-a'],
      target: { provider: 'vercel', scope: { projectId: 'prj_1' } },
      operations: [operation('verify', ['configure']), operation('configure'), operation('unrelated')],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.plan.operations.map(({ id }) => id)).toEqual(['configure', 'verify', 'unrelated']);
    expect(result.plan.sourceSnapshotIds).toEqual(['snapshot-a', 'snapshot-b']);
  });

  it('uses a content id that is independent of creation time', () => {
    const common = {
      sourceSnapshotIds: ['snapshot-a'],
      target: { provider: 'vercel' as const, scope: { projectId: 'prj_1' } },
      operations: [operation('configure')],
    };
    const first = buildMigrationPlan({ ...common, createdAt: '2026-08-14T12:00:00.000Z' });
    const second = buildMigrationPlan({ ...common, createdAt: '2026-08-15T12:00:00.000Z' });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(first.plan.id).toBe(second.plan.id);
    expect(first.plan.createdAt).not.toBe(second.plan.createdAt);
  });

  it('collects missing and self dependencies without emitting a plan', () => {
    const result = buildMigrationPlan({
      createdAt: '2026-08-14T12:00:00.000Z',
      sourceSnapshotIds: [],
      target: { provider: 'vercel', scope: {} },
      operations: [operation('one', ['one']), operation('two', ['missing'])],
    });

    expect(result).toMatchObject({
      ok: false,
      issues: [
        { code: 'SELF_DEPENDENCY', operationIds: ['one'] },
        { code: 'MISSING_DEPENDENCY', operationIds: ['two', 'missing'] },
      ],
    });
  });

  it('detects dependency cycles', () => {
    const result = buildMigrationPlan({
      createdAt: '2026-08-14T12:00:00.000Z',
      sourceSnapshotIds: [],
      target: { provider: 'vercel', scope: {} },
      operations: [operation('one', ['two']), operation('two', ['one'])],
    });

    expect(result).toMatchObject({
      ok: false,
      issues: [{ code: 'DEPENDENCY_CYCLE', operationIds: ['one', 'two'] }],
    });
  });

  it('requires approval for deletes and risky immediate operations', () => {
    const deleting = { ...operation('delete'), kind: 'delete' as const, approval: 'none' as const };
    const immediate = {
      ...operation('cutover'),
      effect: 'immediate' as const,
      risk: 'critical' as const,
      approval: 'none' as const,
    };
    const result = buildMigrationPlan({
      createdAt: '2026-08-14T12:00:00.000Z',
      sourceSnapshotIds: [],
      target: { provider: 'vercel', scope: {} },
      operations: [deleting, immediate],
    });

    expect(result).toMatchObject({
      ok: false,
      issues: [
        { code: 'DELETE_REQUIRES_APPROVAL' },
        { code: 'RISKY_IMMEDIATE_OPERATION_REQUIRES_APPROVAL' },
      ],
    });
  });
});
