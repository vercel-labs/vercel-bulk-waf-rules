import { describe, expect, it } from 'vitest';

import { parseMigrationBundle } from '../control-plane/artifacts.js';
import { planCloudflareRuleset, type PlanCloudflareOptions } from './plan-cloudflare.js';

const options: PlanCloudflareOptions = {
  inputPath: './cloudflare-ruleset.json',
  accountId: 'account_1',
  zoneId: 'zone_1',
  projectId: 'prj_1',
  teamId: 'team_1',
  createdAt: '2026-08-14T12:00:00.000Z',
};

describe('planCloudflareRuleset', () => {
  it('produces a runtime-valid bundle with compiled and manual mappings', () => {
    const result = planCloudflareRuleset(
      JSON.stringify({
        id: 'ruleset_1',
        name: 'Custom rules',
        kind: 'zone',
        phase: 'http_request_firewall_custom',
        rules: [
          {
            id: 'block',
            action: 'block',
            expression: 'ip.src in {8.8.8.8 2001:4860:4860::8888}',
            description: 'Block addresses',
          },
          {
            id: 'manual',
            action: 'skip',
            action_parameters: { phases: ['http_ratelimit'] },
            expression: 'http.host eq "example.com"',
          },
        ],
      }),
      options,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bundle.plan.operations).toMatchObject([
      {
        kind: 'reconcile',
        fidelity: 'exact',
        effect: 'staged',
        payload: { rules: [{ sourceRuleId: 'block' }] },
      },
      {
        kind: 'manual',
        fidelity: 'manual',
        effect: 'external-manual',
      },
    ]);
    expect(parseMigrationBundle(result.bundle).ok).toBe(true);
  });

  it('fails closed for non-Rulesets input', () => {
    const result = planCloudflareRuleset(JSON.stringify({ result: [] }), options);
    expect(result).toMatchObject({ ok: false, kind: 'source' });
  });
});
