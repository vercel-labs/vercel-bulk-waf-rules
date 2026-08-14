import { describe, expect, it } from 'vitest';

import { planIpCsv, type PlanIpOptions } from './plan-ip.js';

const options: PlanIpOptions = {
  inputPath: './partner-ips.csv',
  sourceProvider: 'cloudflare',
  sourceAccountId: 'account_1',
  sourceResourceId: 'list_1',
  intent: { kind: 'blocklist' },
  projectId: 'prj_1',
  teamId: 'team_1',
  ruleNamePrefix: 'Imported partner policy',
  createdAt: '2026-08-14T12:00:00.000Z',
};

describe('planIpCsv', () => {
  it('emits a self-contained snapshot and deterministic staged plan', () => {
    const result = planIpCsv(
      ['ip,vendor_name,notes', '192.0.2.4,Example,First', '192.0.2.5,Example,Second'].join('\n'),
      options,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bundle).toMatchObject({
      schemaVersion: 1,
      snapshots: [
        {
          provider: 'cloudflare',
          accountId: 'account_1',
          adapterVersion: 'csv-ip/1',
          resources: [
            {
              identity: { externalId: 'list_1' },
              captured: {
                declaredIntent: 'blocklist',
                aggregated: ['192.0.2.4/31'],
              },
            },
          ],
        },
      ],
      plan: {
        target: { provider: 'vercel', scope: { projectId: 'prj_1', teamId: 'team_1' } },
        operations: [
          {
            product: 'firewall',
            effect: 'staged',
            approval: 'before-publish',
            fidelity: 'manual',
          },
        ],
      },
    });
    expect(result.bundle.plan.diagnostics.map(({ code }) => code)).toContain(
      'SOURCE_INTENT_OPERATOR_DECLARED',
    );
  });

  it('keeps content identities stable across capture timestamps', () => {
    const csv = ['ip', '198.51.100.10'].join('\n');
    const first = planIpCsv(csv, options);
    const second = planIpCsv(csv, { ...options, createdAt: '2026-08-15T12:00:00.000Z' });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(first.bundle.snapshots[0]?.id).toBe(second.bundle.snapshots[0]?.id);
    expect(first.bundle.plan.id).toBe(second.bundle.plan.id);
  });

  it('refuses malformed input before producing a migration artifact', () => {
    const result = planIpCsv(['ip', 'not-an-ip'].join('\n'), options);

    expect(result).toMatchObject({
      ok: false,
      kind: 'import',
    });
    if (result.ok) return;
    expect(result.message).toContain('Invalid addresses');
  });
});
