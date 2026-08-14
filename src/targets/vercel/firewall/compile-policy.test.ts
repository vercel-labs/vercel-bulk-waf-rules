import { describe, expect, it } from 'vitest';

import type { TranslationBatch, TranslationResult } from '../../../control-plane/model.js';
import type { FirewallRule } from '../../../domains/firewall/model.js';
import { parseCloudflareExpression } from '../../../providers/cloudflare/expression.js';
import {
  parseCloudflareRulesetText,
  snapshotCloudflareRuleset,
  translateCloudflareRuleset,
} from '../../../providers/cloudflare/rulesets.js';
import { compileFirewallTranslation } from './compile-policy.js';

function canonicalRecord(expression: string): TranslationResult<FirewallRule> {
  const sourceRef = {
    snapshotId: 'snapshot_1',
    resource: {
      provider: 'cloudflare',
      resourceType: 'firewall-custom-rule',
      externalId: 'rule_1',
      scope: { zoneId: 'zone_1' },
    },
  } as const;
  return {
    fidelity: 'exact',
    sourceRefs: [sourceRef],
    targetResources: [
      {
        identity: sourceRef.resource,
        sourceRefs: [sourceRef],
        name: 'Compiled rule',
        enabled: true,
        priority: 0,
        condition: parseCloudflareExpression(expression),
        action: { kind: 'deny' },
      },
    ],
    diagnostics: [],
    assumptions: [],
  };
}

function compileRecord(record: TranslationResult<FirewallRule>) {
  const translation: TranslationBatch<FirewallRule> = {
    product: 'firewall',
    records: [record],
    diagnostics: record.diagnostics,
  };
  return compileFirewallTranslation({
    translation,
    ownershipId: 'cloudflare-ruleset-1',
    targetScope: { projectId: 'prj_1' },
  });
}

describe('compileFirewallTranslation', () => {
  it('converts Boolean expressions to Vercel DNF groups without changing order', () => {
    const compiled = compileRecord(
      canonicalRecord(
        'ip.src in {192.0.2.0/24 2001:db8::/48} and (http.host eq "example.com" or http.request.method eq "POST")',
      ),
    );

    expect(compiled.operations).toHaveLength(1);
    expect(compiled.operations[0]).toMatchObject({
      kind: 'reconcile',
      effect: 'staged',
      approval: 'before-publish',
      fidelity: 'exact',
      payload: {
        rules: [
          {
            sourceRuleId: 'rule_1',
            rule: {
              conditionGroup: [
                {
                  conditions: [
                    { type: 'ip_address', op: 'inc', value: ['192.0.2.0/24', '2001:db8::/48'] },
                    { type: 'host', op: 'eq', value: 'example.com' },
                  ],
                },
                {
                  conditions: [
                    { type: 'ip_address', op: 'inc', value: ['192.0.2.0/24', '2001:db8::/48'] },
                    { type: 'method', op: 'eq', value: 'POST' },
                  ],
                },
              ],
            },
          },
        ],
      },
    });
  });

  it('turns unresolved lists and transformations into explicit manual operations', () => {
    const unresolved = compileRecord(canonicalRecord('ip.src in $trusted_ips'));
    const transformed = compileRecord(canonicalRecord('lower(http.host) eq "example.com"'));

    expect(unresolved.operations[0]).toMatchObject({
      kind: 'manual',
      effect: 'external-manual',
      fidelity: 'manual',
      payload: { diagnostics: [{ code: 'UNRESOLVED_LIST_REFERENCE' }] },
    });
    expect(transformed.operations[0]).toMatchObject({
      kind: 'manual',
      fidelity: 'manual',
      payload: { diagnostics: [{ code: 'TRANSFORMATION_UNSUPPORTED' }] },
    });
  });

  it('preserves every Cloudflare rule as compiled or manual work', () => {
    const response = {
      id: 'ruleset_1',
      name: 'Custom rules',
      kind: 'zone',
      phase: 'http_request_firewall_custom',
      rules: [
        { id: 'block', action: 'block', expression: 'ip.src eq 8.8.8.8' },
        {
          id: 'challenge',
          action: 'managed_challenge',
          expression: 'http.request.uri.path eq "/login"',
        },
        {
          id: 'skip',
          action: 'skip',
          expression: 'ip.src eq 1.1.1.1',
          action_parameters: { phases: ['http_ratelimit'] },
        },
        { id: 'manual-expression', action: 'block', expression: 'cf.bot_management.score lt 30' },
        { id: 'unsupported-action', action: 'execute', expression: 'http.host eq "example.com"' },
      ],
    };
    const text = JSON.stringify(response);
    const parsed = parseCloudflareRulesetText(text);
    if (!parsed.ok) throw new Error('fixture did not parse');
    const options = {
      inputPath: './ruleset.json',
      accountId: 'account_1',
      zoneId: 'zone_1',
      capturedAt: '2026-08-14T12:00:00.000Z',
    };
    const snapshot = snapshotCloudflareRuleset(text, parsed.input, options);
    const translated = translateCloudflareRuleset(parsed.input, snapshot, options);
    const compiled = compileFirewallTranslation({
      translation: translated,
      ownershipId: response.id,
      targetScope: { projectId: 'prj_1' },
    });

    expect(compiled.operations.map(({ kind }) => kind)).toEqual([
      'reconcile',
      'manual',
      'manual',
      'manual',
    ]);
    expect(compiled.operations[0]).toMatchObject({
      fidelity: 'approximate',
      payload: { rules: [{ sourceRuleId: 'block' }, { sourceRuleId: 'challenge' }] },
    });
    expect(compiled.operations.slice(1).map(({ fidelity }) => fidelity)).toEqual([
      'manual',
      'manual',
      'unsupported',
    ]);
    expect(compiled.diagnostics.map(({ code }) => code)).toContain(
      'CHALLENGE_IMPLEMENTATION_DIFFERS',
    );
  });
});
