import { describe, expect, it } from 'vitest';

import {
  parseCloudflareRulesetText,
  snapshotCloudflareRuleset,
  translateCloudflareRuleset,
} from './rulesets.js';

const ruleset = {
  success: true,
  result: {
    id: 'ruleset_1',
    name: 'Default custom ruleset',
    kind: 'zone',
    version: '7',
    phase: 'http_request_firewall_custom',
    rules: [
      {
        id: 'rule_block',
        ref: 'block_bad_ips',
        action: 'block',
        expression: 'ip.src in {192.0.2.0/24 2001:db8::/48}',
        description: 'Block known attackers',
        enabled: true,
      },
      {
        id: 'rule_challenge',
        action: 'managed_challenge',
        expression: 'http.request.uri.path eq "/login"',
        description: 'Challenge login',
      },
      {
        id: 'rule_skip',
        action: 'skip',
        action_parameters: { phases: ['http_ratelimit'] },
        expression: 'ip.src in $trusted_ips',
      },
      {
        id: 'rule_manual_expression',
        action: 'block',
        expression: 'cf.bot_management.score lt 30',
      },
      {
        id: 'rule_unknown_action',
        action: 'execute',
        expression: 'http.host eq "example.com"',
      },
    ],
  },
};

const options = {
  inputPath: './cloudflare-ruleset.json',
  accountId: 'account_1',
  zoneId: 'zone_1',
  capturedAt: '2026-08-14T12:00:00.000Z',
};

describe('Cloudflare Rulesets adapter', () => {
  it('validates API envelopes and captures rules with stable provenance', () => {
    const text = JSON.stringify(ruleset);
    const parsed = parseCloudflareRulesetText(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    const snapshot = snapshotCloudflareRuleset(text, parsed.input, options);
    expect(snapshot).toMatchObject({
      provider: 'cloudflare',
      accountId: 'account_1',
      adapterVersion: 'cloudflare-rulesets/1',
    });
    expect(snapshot.resources).toHaveLength(6);
    expect(snapshot.resources[0]).toMatchObject({
      identity: { resourceType: 'firewall-custom-ruleset', externalId: 'ruleset_1' },
    });
    expect(snapshot.resources[1]).toMatchObject({
      identity: { resourceType: 'firewall-custom-rule', externalId: 'rule_block' },
    });
  });

  it('emits per-rule fidelity and never drops unsupported semantics', () => {
    const text = JSON.stringify(ruleset);
    const parsed = parseCloudflareRulesetText(text);
    if (!parsed.ok) throw new Error('fixture did not parse');
    const snapshot = snapshotCloudflareRuleset(text, parsed.input, options);
    const translated = translateCloudflareRuleset(parsed.input, snapshot, options);

    expect(translated.records.map(({ fidelity }) => fidelity)).toEqual([
      'exact',
      'approximate',
      'manual',
      'manual',
      'unsupported',
    ]);
    expect(translated.records.map(({ targetResources }) => targetResources.length)).toEqual([
      1, 1, 0, 0, 0,
    ]);
    expect(translated.records[0]?.targetResources[0]).toMatchObject({
      priority: 0,
      enabled: true,
      action: { kind: 'deny' },
      condition: { kind: 'predicate', field: 'client.ip', operator: 'in' },
    });
    expect(translated.diagnostics.map(({ code }) => code)).toEqual([
      'CLOUDFLARE_SKIP_REQUIRES_MANUAL_MAPPING',
      'CLOUDFLARE_EXPRESSION_REQUIRES_MANUAL_MAPPING',
      'CLOUDFLARE_ACTION_UNSUPPORTED',
    ]);
  });

  it('refuses responses from the wrong Rulesets phase', () => {
    const parsed = parseCloudflareRulesetText(
      JSON.stringify({ ...ruleset.result, phase: 'http_request_transform' }),
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.problems.length).toBeGreaterThan(0);
  });
});
