import { describe, expect, it } from 'vitest';

import { decompose } from '../../../core/decompose.js';
import { parseCidr } from '../../../core/ip.js';
import type { SourceReference } from '../../../control-plane/model.js';
import { buildMigrationPlan } from '../../../control-plane/plan.js';
import { compileIpRulePlan } from './compile-ip-plan.js';

const sourceRef: SourceReference = {
  snapshotId: 'snapshot_cloudflare_1',
  resource: {
    provider: 'cloudflare',
    resourceType: 'ip-list',
    externalId: 'list_1',
    name: 'Partner addresses',
    scope: { accountId: 'account_1' },
  },
};

describe('compileIpRulePlan', () => {
  it('places the existing IP planner behind one staged reconciliation operation', () => {
    const decomposed = decompose({
      intent: { kind: 'blocklist' },
      cidrs: [parseCidr('192.0.2.4/32'), parseCidr('2001:db8::/48')],
      ruleNamePrefix: 'Imported blocklist',
    });
    expect(decomposed.ok).toBe(true);
    if (!decomposed.ok) return;

    const compiled = compileIpRulePlan({
      plan: decomposed.plan,
      setId: 'set1234',
      targetScope: { projectId: 'prj_1', teamId: 'team_1' },
      sourceRefs: [sourceRef],
    });

    expect(compiled.operations).toHaveLength(1);
    expect(compiled.operations[0]).toMatchObject({
      id: 'vercel:firewall:rule-set:set1234:reconcile',
      product: 'firewall',
      kind: 'reconcile',
      effect: 'staged',
      approval: 'before-publish',
      risk: 'medium',
      fidelity: 'exact',
      payload: {
        schemaVersion: 1,
        strategy: 'positive-packed',
        stats: { addressesCovered: '1208925819614629174706177' },
      },
    });

    const result = buildMigrationPlan({
      createdAt: '2026-08-14T12:00:00.000Z',
      sourceSnapshotIds: [sourceRef.snapshotId],
      target: { provider: 'vercel', scope: { projectId: 'prj_1', teamId: 'team_1' } },
      operations: compiled.operations,
      diagnostics: compiled.diagnostics,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.plan.id).toMatch(/^plan_[0-9a-f]{24}$/);
  });

  it('marks allowlist reconciliation as critical and keeps publish human-owned', () => {
    const decomposed = decompose({
      intent: { kind: 'allowlist' },
      cidrs: [parseCidr('203.0.113.8/32')],
      ruleNamePrefix: 'Private application',
    });
    expect(decomposed.ok).toBe(true);
    if (!decomposed.ok) return;

    const compiled = compileIpRulePlan({
      plan: decomposed.plan,
      setId: 'set5678',
      targetScope: { projectId: 'prj_1' },
      sourceRefs: [sourceRef],
    });

    expect(compiled.operations[0]).toMatchObject({
      effect: 'staged',
      approval: 'before-publish',
      risk: 'critical',
    });
  });
});
