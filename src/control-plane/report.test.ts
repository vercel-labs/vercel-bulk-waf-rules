import { describe, expect, it } from 'vitest';

import { planIpCsv } from '../cli/plan-ip.js';
import { formatMigrationReport, summarizeMigrationBundle } from './report.js';

describe('migration report', () => {
  it('summarizes fidelity, risk, approvals, and diagnostics', () => {
    const planned = planIpCsv(['ip', '8.8.8.8'].join('\n'), {
      inputPath: './addresses.csv',
      sourceProvider: 'cloudflare',
      intent: { kind: 'blocklist' },
      projectId: 'prj_1',
      ruleNamePrefix: 'Imported addresses',
      createdAt: '2026-08-14T12:00:00.000Z',
    });
    if (!planned.ok) throw new Error(planned.message);

    expect(summarizeMigrationBundle(planned.bundle)).toMatchObject({
      sourceProviders: ['cloudflare'],
      snapshotCount: 1,
      operationCount: 1,
      fidelity: { exact: 0, approximate: 0, manual: 1, unsupported: 0 },
      risk: { low: 0, medium: 1, high: 0, critical: 0 },
      approvalsRequired: 1,
    });

    const report = formatMigrationReport(planned.bundle);
    expect(report).toContain('Fidelity: exact=0, approximate=0, manual=1, unsupported=0');
    expect(report).toContain('Approvals required: 1');
    expect(report).toContain('WARNING SOURCE_INTENT_OPERATOR_DECLARED');
  });
});
