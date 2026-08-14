import { describe, expect, it } from 'vitest';

import type { DecomposeOptions, PlannedGroup, PlannedRule, RulePlan } from './decompose.js';
import { PlanInvariantError, decompose } from './decompose.js';
import type { Cidr } from './ip.js';
import { formatCidr, parseCidr } from './ip.js';
import {
  ALLOWLIST_MAX_PER_RULE,
  MAX_GROUPS_PER_RULE,
  MAX_VALUES_PER_CONDITION,
  POSITIVE_MATCH_MAX_PER_RULE,
  allowlistMaxPerRule,
} from './limits.js';
import { buildRuleJson, stableStringify } from './rule-builder.js';

/** 10.0.0.0 as a bigint, the base of the synthetic host ranges below. */
const V4_BASE = 167772160n;

/**
 * `count` distinct /32s spaced two addresses apart.
 *
 * The stride matters: aggregation coalesces ranges when
 * `next.start <= last.end + 1`, so consecutive /32s would collapse into a single
 * block and every count-based assertion in this file would be testing the wrong
 * number. A stride of 2 leaves a one-address gap between every pair, which keeps
 * aggregation an identity operation on these fixtures.
 */
function spacedHosts(count: number, base: bigint = V4_BASE): Cidr[] {
  return Array.from({ length: count }, (_, index): Cidr => {
    return { version: 4, addr: base + BigInt(index * 2), prefixLen: 32 };
  });
}

function spacedV6Hosts(count: number): Cidr[] {
  const base = parseCidr('2001:db8::').addr;
  return Array.from({ length: count }, (_, index): Cidr => {
    return { version: 6, addr: base + BigInt(index * 2), prefixLen: 128 };
  });
}

function allowlistOptions(cidrs: Cidr[]): DecomposeOptions {
  return { intent: { kind: 'allowlist' }, cidrs, ruleNamePrefix: 'test' };
}

function blocklistOptions(cidrs: Cidr[]): DecomposeOptions {
  return { intent: { kind: 'blocklist' }, cidrs, ruleNamePrefix: 'test' };
}

function bypassOptions(cidrs: Cidr[]): DecomposeOptions {
  return { intent: { kind: 'bypass' }, cidrs, ruleNamePrefix: 'test' };
}

function planOf(opts: DecomposeOptions): RulePlan {
  const result = decompose(opts);
  if (!result.ok) {
    throw new Error(`expected a plan, got refusal ${result.refusal.code}: ${result.refusal.message}`);
  }
  return result.plan;
}

function refusalOf(opts: DecomposeOptions): { code: string; message: string; remediation: string } {
  const result = decompose(opts);
  if (result.ok) {
    throw new Error(`expected a refusal, got a ${result.plan.strategy} plan`);
  }
  return result.refusal;
}

function groupsOf(rule: PlannedRule): readonly PlannedGroup[] {
  return rule.groups;
}

function ruleAt(plan: RulePlan, index: number): PlannedRule {
  const rule = plan.rules[index];
  if (rule === undefined) {
    throw new Error(`plan has no rule at index ${index} (${plan.rules.length} rules)`);
  }
  return rule;
}

function lastRule(plan: RulePlan): PlannedRule {
  return ruleAt(plan, plan.rules.length - 1);
}

function onlyGroup(rule: PlannedRule): PlannedGroup {
  const groups = groupsOf(rule);
  if (groups.length !== 1) {
    throw new Error(`expected exactly 1 group, got ${groups.length}`);
  }
  return ruleGroup(rule, 0);
}

function ruleGroup(rule: PlannedRule, index: number): PlannedGroup {
  const group = groupsOf(rule)[index];
  if (group === undefined) {
    throw new Error(`rule has no group at index ${index}`);
  }
  return group;
}

/** Every CIDR that appears anywhere in a rule's IP conditions, in emission order. */
function ipValuesOf(rule: PlannedRule): string[] {
  return groupsOf(rule).flatMap((group) =>
    group.ipChunks.flatMap((values) => values.map(formatCidr)),
  );
}

function planFingerprint(plan: RulePlan): string {
  return stableStringify({
    strategy: plan.strategy,
    warnings: plan.warnings,
    stats: plan.stats,
    rules: plan.rules.map(buildRuleJson),
  });
}

/** Lehmer PRNG shuffle: deterministic and exact in IEEE doubles. */
function shuffled<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;
  for (let index = out.length - 1; index > 0; index--) {
    state = (state * 48271) % 2147483647;
    const swap = state % (index + 1);
    const left = out[index];
    const right = out[swap];
    if (left !== undefined && right !== undefined) {
      out[index] = right;
      out[swap] = left;
    }
  }
  return out;
}

describe('decompose — allowlist packing', () => {
  const SIZES = [1, 75, 76, 150, ALLOWLIST_MAX_PER_RULE];

  it.each(SIZES)('packs n=%i into exactly one rule with exactly one group', (size) => {
    const plan = planOf(allowlistOptions(spacedHosts(size)));

    expect(plan.strategy).toBe('single-deny-negated');
    expect(plan.rules).toHaveLength(1);

    const rule = ruleAt(plan, 0);
    expect(rule.kind).toBe('negated-allowlist');
    expect(groupsOf(rule)).toHaveLength(1);
  });

  it.each(SIZES)('splits n=%i into ceil(n/75) conditions', (size) => {
    const plan = planOf(allowlistOptions(spacedHosts(size)));
    const group = onlyGroup(ruleAt(plan, 0));

    expect(group.ipChunks).toHaveLength(Math.ceil(size / MAX_VALUES_PER_CONDITION));
    for (const values of group.ipChunks) {
      expect(values.length).toBeLessThanOrEqual(MAX_VALUES_PER_CONDITION);
    }
  });

  it.each(SIZES)('negates every ip condition for n=%i', (size) => {
    const plan = planOf(allowlistOptions(spacedHosts(size)));
    const json = buildRuleJson(ruleAt(plan, 0));

    const ipConditions = json.conditionGroup.flatMap((group) =>
      group.conditions.filter((condition) => condition.type === 'ip_address'),
    );
    expect(ipConditions.length).toBeGreaterThan(0);
    for (const condition of ipConditions) {
      expect(condition.op).toBe('inc');
      expect(condition.neg).toBe(true);
    }
  });

  it.each(SIZES)('preserves the input set exactly for n=%i, with no loss or duplication', (size) => {
    const input = spacedHosts(size);
    const plan = planOf(allowlistOptions(input));
    const emitted = ipValuesOf(ruleAt(plan, 0));

    expect(emitted).toHaveLength(size);
    expect(new Set(emitted).size).toBe(size);
    expect([...emitted].sort()).toEqual([...input.map(formatCidr)].sort());
  });

  it('reports one condition per chunk plus the aggregation totals in stats', () => {
    const plan = planOf(allowlistOptions(spacedHosts(150)));

    expect(plan.stats).toMatchObject({
      inputCount: 150,
      afterAggregation: 150,
      ruleCount: 1,
      conditionCount: 2,
    });
    expect(plan.stats.addressesCovered).toBe(150n);
  });

  /**
   * REGRESSION GUARD — do not delete or weaken this test.
   *
   * An allowlist is negative matching: "deny unless the IP is in chunk 1 AND not
   * in chunk 2 AND …". Conditions AND only *within* one condition group; sibling
   * groups OR, and so do sibling rules.
   *
   * If the chunks are ever split across groups or across rules, the conjunction
   * becomes `(IP ∉ A) OR (IP ∉ B)`, which is true for every address on the
   * internet — the rule matches all traffic and the action is `deny`. That is the
   * outage this planner exists to prevent, and it only appears once a list grows
   * past 75 entries, so it survives every small fixture.
   *
   * The one-element tuple on NegatedAllowlistRule.groups is the compile-time
   * defence; this test is the behavioural one.
   */
  it('never emits more than one rule or more than one group, at any size', () => {
    for (const size of [76, 150, 1000, 4874, ALLOWLIST_MAX_PER_RULE]) {
      const plan = planOf(allowlistOptions(spacedHosts(size)));

      expect(plan.rules.length).toBe(1);
      for (const rule of plan.rules) {
        expect(groupsOf(rule).length).toBe(1);
      }

      const json = plan.rules.map(buildRuleJson);
      expect(json).toHaveLength(1);
      expect(json[0]?.conditionGroup.length).toBe(1);
    }
  });

  it('warns that traffic of the other IP version is denied', () => {
    const plan = planOf(allowlistOptions(spacedHosts(4)));

    expect(plan.warnings.map((warning) => warning.code)).toContain(
      'ALLOWLIST_COVERS_SINGLE_IP_VERSION',
    );
  });
});

describe('decompose — allowlist ceiling and escalation', () => {
  const OVER_CEILING = ALLOWLIST_MAX_PER_RULE + 1;

  it('refuses above the ceiling when escalation is not opted into', () => {
    const refusal = refusalOf(allowlistOptions(spacedHosts(OVER_CEILING)));

    expect(refusal.code).toBe('EXCEEDS_ALLOWLIST_CEILING');
    expect(refusal.message).toContain(String(ALLOWLIST_MAX_PER_RULE));
    expect(refusal.message).toContain(String(OVER_CEILING));
    expect(refusal.remediation.length).toBeGreaterThan(0);
    expect(refusal.remediation).toContain('allowBypassEscalation');
  });

  it('refuses above the ceiling when escalation is explicitly disabled', () => {
    const refusal = refusalOf({
      ...allowlistOptions(spacedHosts(OVER_CEILING)),
      allowBypassEscalation: false,
    });

    expect(refusal.code).toBe('EXCEEDS_ALLOWLIST_CEILING');
  });

  it('drops the ceiling by one condition slot when a hostname is set', () => {
    const scopedCeiling = allowlistMaxPerRule(true);
    expect(scopedCeiling).toBe(4800);

    const atCeiling = planOf({
      ...allowlistOptions(spacedHosts(scopedCeiling)),
      hostname: 'example.com',
    });
    expect(atCeiling.stats.conditionCount).toBe(65);

    const refusal = refusalOf({
      ...allowlistOptions(spacedHosts(scopedCeiling + 1)),
      hostname: 'example.com',
    });
    expect(refusal.code).toBe('EXCEEDS_ALLOWLIST_CEILING');
    expect(refusal.message).toContain('host condition consumes');
  });

  it('escalates to bypass-then-deny when opted in', () => {
    const plan = planOf({
      ...allowlistOptions(spacedHosts(OVER_CEILING)),
      allowBypassEscalation: true,
    });

    expect(plan.strategy).toBe('bypass-then-deny');
    expect(plan.rules).toHaveLength(
      Math.ceil(OVER_CEILING / POSITIVE_MATCH_MAX_PER_RULE) + 1,
    );
  });

  it('orders every bypass rule before the terminal deny', () => {
    const plan = planOf({
      ...allowlistOptions(spacedHosts(5000)),
      allowBypassEscalation: true,
    });

    const actions = plan.rules.map((rule) => rule.action);
    const firstDeny = actions.indexOf('deny');
    const lastBypass = actions.lastIndexOf('bypass');

    expect(lastBypass).toBeLessThan(firstDeny);
    expect(firstDeny).toBe(plan.rules.length - 1);
    plan.rules.forEach((rule, index) => {
      expect(rule.order).toBe(index);
    });
  });

  it('gives the terminal deny no planned ip chunks so it catches everything remaining', () => {
    const plan = planOf({
      ...allowlistOptions(spacedHosts(5000)),
      allowBypassEscalation: true,
    });

    const terminal = lastRule(plan);
    expect(terminal.kind).toBe('catch-all-deny');
    expect(ipValuesOf(terminal)).toEqual([]);

    const json = buildRuleJson(terminal);
    expect(json.conditionGroup).toHaveLength(1);
    expect(json.conditionGroup[0]?.conditions).toEqual([
      { type: 'ip_address', op: 'inc', value: ['0.0.0.0/0', '::/0'] },
    ]);
  });

  it('scopes the terminal deny to the hostname when one is set', () => {
    const plan = planOf({
      ...allowlistOptions(spacedHosts(5000)),
      allowBypassEscalation: true,
      hostname: 'example.com',
    });

    const json = buildRuleJson(lastRule(plan));
    expect(json.conditionGroup[0]?.conditions).toEqual([
      { type: 'host', op: 'eq', value: 'example.com' },
    ]);
  });

  it('warns that managed rulesets are skipped for allowlisted addresses', () => {
    const plan = planOf({
      ...allowlistOptions(spacedHosts(5000)),
      allowBypassEscalation: true,
    });

    const codes = plan.warnings.map((warning) => warning.code);
    expect(codes).toContain('BYPASS_SKIPS_MANAGED_RULESETS');
    expect(codes).toContain('RULE_ORDER_IS_LOAD_BEARING');

    const bypassWarning = plan.warnings.find(
      (warning) => warning.code === 'BYPASS_SKIPS_MANAGED_RULESETS',
    );
    expect(bypassWarning?.message).toContain('managed rulesets');
    expect(bypassWarning?.message).toContain('no WAF inspection');
  });

  it('covers the whole input set across the bypass rules', () => {
    const input = spacedHosts(5000);
    const plan = planOf({
      ...allowlistOptions(input),
      allowBypassEscalation: true,
    });

    const emitted = plan.rules.flatMap(ipValuesOf);
    expect(emitted).toHaveLength(5000);
    expect(new Set(emitted).size).toBe(5000);
    expect([...emitted].sort()).toEqual([...input.map(formatCidr)].sort());
  });
});

describe('decompose — positive packing', () => {
  it('packs 75 entries into a single group', () => {
    const plan = planOf(blocklistOptions(spacedHosts(MAX_VALUES_PER_CONDITION)));

    expect(plan.strategy).toBe('positive-packed');
    expect(plan.rules).toHaveLength(1);
    expect(groupsOf(ruleAt(plan, 0))).toHaveLength(1);
  });

  it('packs 1875 entries into 25 groups of one rule', () => {
    const plan = planOf(blocklistOptions(spacedHosts(POSITIVE_MATCH_MAX_PER_RULE)));

    expect(plan.rules).toHaveLength(1);
    expect(groupsOf(ruleAt(plan, 0))).toHaveLength(MAX_GROUPS_PER_RULE);
  });

  it('spills 1876 entries into a second rule', () => {
    const plan = planOf(blocklistOptions(spacedHosts(POSITIVE_MATCH_MAX_PER_RULE + 1)));

    expect(plan.rules).toHaveLength(2);
    expect(groupsOf(ruleAt(plan, 0))).toHaveLength(MAX_GROUPS_PER_RULE);
    expect(groupsOf(ruleAt(plan, 1))).toHaveLength(1);
  });

  it('puts exactly one ip condition of at most 75 values in every group', () => {
    const plan = planOf(blocklistOptions(spacedHosts(POSITIVE_MATCH_MAX_PER_RULE + 40)));

    for (const rule of plan.rules) {
      const groups = groupsOf(rule);
      expect(groups.length).toBeLessThanOrEqual(MAX_GROUPS_PER_RULE);
      for (const group of groups) {
        expect(group.ipChunks).toHaveLength(1);
        expect(group.ipChunks[0]?.length).toBeLessThanOrEqual(MAX_VALUES_PER_CONDITION);
      }
    }
  });

  it('never negates a positive match', () => {
    const plan = planOf(blocklistOptions(spacedHosts(200)));
    const json = buildRuleJson(ruleAt(plan, 0));

    for (const group of json.conditionGroup) {
      for (const condition of group.conditions) {
        expect(condition).not.toHaveProperty('neg');
      }
    }
  });

  it('denies for a blocklist and bypasses for a bypass list', () => {
    expect(planOf(blocklistOptions(spacedHosts(10))).rules[0]?.action).toBe('deny');
    expect(planOf(bypassOptions(spacedHosts(10))).rules[0]?.action).toBe('bypass');
  });

  it('covers the whole input set across spilled rules', () => {
    const input = spacedHosts(POSITIVE_MATCH_MAX_PER_RULE + 400);
    const plan = planOf(bypassOptions(input));

    const emitted = plan.rules.flatMap(ipValuesOf);
    expect(emitted).toHaveLength(input.length);
    expect([...emitted].sort()).toEqual([...input.map(formatCidr)].sort());
  });
});

describe('decompose — hostname scoping', () => {
  it('adds the host condition to EVERY group of a multi-group rule', () => {
    const plan = planOf({
      ...bypassOptions(spacedHosts(POSITIVE_MATCH_MAX_PER_RULE)),
      hostname: 'example.com',
    });

    const json = buildRuleJson(ruleAt(plan, 0));
    expect(json.conditionGroup).toHaveLength(MAX_GROUPS_PER_RULE);

    // A host condition in only the first group would leave the other 24 groups
    // matching host-independently, silently bypassing the WAF on every other
    // hostname of the project.
    for (const group of json.conditionGroup) {
      const hostConditions = group.conditions.filter((condition) => condition.type === 'host');
      expect(hostConditions).toEqual([{ type: 'host', op: 'eq', value: 'example.com' }]);
    }
  });

  it('adds the host condition to every group of every spilled rule', () => {
    const plan = planOf({
      ...bypassOptions(spacedHosts(POSITIVE_MATCH_MAX_PER_RULE + 1)),
      hostname: 'shop.example.com',
    });

    expect(plan.rules).toHaveLength(2);
    for (const rule of plan.rules) {
      for (const group of buildRuleJson(rule).conditionGroup) {
        expect(group.conditions.filter((condition) => condition.type === 'host')).toHaveLength(1);
      }
    }
  });

  it('counts the repeated host conditions in stats', () => {
    const plan = planOf({
      ...bypassOptions(spacedHosts(150)),
      hostname: 'example.com',
    });

    expect(plan.stats.conditionCount).toBe(4);
  });
});

describe('decompose — plan tier budget', () => {
  /** 41 rules' worth of entries: ceil(75001/75) = 1001 chunks, ceil(1001/25) = 41 rules. */
  const OVER_PRO_LIMIT = POSITIVE_MATCH_MAX_PER_RULE * 40 + 1;

  it('refuses when the plan needs more rules than the pro tier allows', () => {
    const refusal = refusalOf({
      ...bypassOptions(spacedHosts(OVER_PRO_LIMIT)),
      tier: 'pro',
    });

    expect(refusal.code).toBe('EXCEEDS_PLAN_RULE_LIMIT');
    expect(refusal.message).toContain('pro');
    expect(refusal.message).toContain('41');
    expect(refusal.message).toContain('40');
    expect(refusal.remediation.length).toBeGreaterThan(0);
  });

  it('accepts the same input on the enterprise tier', () => {
    const plan = planOf({
      ...bypassOptions(spacedHosts(OVER_PRO_LIMIT)),
      tier: 'enterprise',
    });

    expect(plan.rules).toHaveLength(41);
  });

  it('defaults to the pro budget when no tier is given', () => {
    const refusal = refusalOf(bypassOptions(spacedHosts(OVER_PRO_LIMIT)));

    expect(refusal.code).toBe('EXCEEDS_PLAN_RULE_LIMIT');
    expect(refusal.message).toContain('pro');
  });

  it('refuses a four-rule plan on the hobby tier', () => {
    const refusal = refusalOf({
      ...bypassOptions(spacedHosts(POSITIVE_MATCH_MAX_PER_RULE * 3 + 1)),
      tier: 'hobby',
    });

    expect(refusal.code).toBe('EXCEEDS_PLAN_RULE_LIMIT');
    expect(refusal.message).toContain('hobby');
  });

  it('honours an explicit team override', () => {
    const cidrs = spacedHosts(POSITIVE_MATCH_MAX_PER_RULE * 3 + 1);

    expect(
      refusalOf({ ...bypassOptions(cidrs), tier: 'hobby', tierRuleOverride: 2 }).code,
    ).toBe('EXCEEDS_PLAN_RULE_LIMIT');
    expect(planOf({ ...bypassOptions(cidrs), tier: 'hobby', tierRuleOverride: 10 }).rules).toHaveLength(4);
  });
});

describe('decompose — input refusals', () => {
  it('refuses empty input for an allowlist', () => {
    const refusal = refusalOf(allowlistOptions([]));

    expect(refusal.code).toBe('EMPTY_INPUT');
    expect(refusal.remediation).toContain('offline');
  });

  it('refuses empty input for a blocklist', () => {
    expect(refusalOf(blocklistOptions([])).code).toBe('EMPTY_INPUT');
  });

  it('refuses empty input for a bypass list', () => {
    expect(refusalOf(bypassOptions([])).code).toBe('EMPTY_INPUT');
  });

  it('never emits a bare deny with no conditions for empty input', () => {
    const result = decompose(allowlistOptions([]));

    expect(result.ok).toBe(false);
  });

  it('refuses an empty rule name prefix', () => {
    const refusal = refusalOf({ ...allowlistOptions(spacedHosts(4)), ruleNamePrefix: '   ' });

    expect(refusal.code).toBe('INVALID_RULE_NAME_PREFIX');
  });

  it('refuses a prefix that pushes the generated name over the limit', () => {
    const refusal = refusalOf({
      ...allowlistOptions(spacedHosts(4)),
      ruleNamePrefix: 'p'.repeat(200),
    });

    expect(refusal.code).toBe('RULE_METADATA_TOO_LONG');
    expect(refusal.remediation).toContain('Shorten');
  });
});

describe('decompose — aggregation', () => {
  it('collapses duplicate and contiguous input, and says so', () => {
    const plan = planOf(
      blocklistOptions([
        parseCidr('1.0.0.0/25'),
        parseCidr('1.0.0.128/25'),
        parseCidr('1.0.0.0/25'),
      ]),
    );

    expect(plan.stats.inputCount).toBe(3);
    expect(plan.stats.afterAggregation).toBe(1);
    expect(ipValuesOf(ruleAt(plan, 0))).toEqual(['1.0.0.0/24']);
    expect(plan.warnings.map((warning) => warning.code)).toContain('AGGREGATION_CHANGED_INPUT');
    expect(plan.stats.addressesCovered).toBe(256n);
  });

  it('does not warn when aggregation changes nothing', () => {
    const plan = planOf(blocklistOptions(spacedHosts(10)));

    expect(plan.warnings.map((warning) => warning.code)).not.toContain(
      'AGGREGATION_CHANGED_INPUT',
    );
  });
});

describe('decompose — IPv6 and mixed families', () => {
  it('plans an IPv6-only allowlist', () => {
    const input = spacedV6Hosts(100);
    const plan = planOf(allowlistOptions(input));

    expect(plan.rules).toHaveLength(1);
    const emitted = ipValuesOf(ruleAt(plan, 0));
    expect(emitted).toHaveLength(100);
    expect(emitted[0]).toBe('2001:db8::/128');
    expect([...emitted].sort()).toEqual([...input.map(formatCidr)].sort());
  });

  it('keeps mixed families separate and orders v4 before v6', () => {
    const v4 = spacedHosts(80);
    const v6 = spacedV6Hosts(80);
    const plan = planOf(allowlistOptions([...v6, ...v4]));

    const emitted = ipValuesOf(ruleAt(plan, 0));
    expect(emitted).toHaveLength(160);

    const firstV6 = emitted.findIndex((text) => text.includes(':'));
    const lastV4 = emitted.reduce(
      (last, text, index) => (text.includes(':') ? last : index),
      -1,
    );
    expect(lastV4).toBeLessThan(firstV6);
    expect(new Set(emitted).size).toBe(160);
  });

  it('does not warn about a single IP version when both are present', () => {
    const plan = planOf(allowlistOptions([...spacedHosts(4), ...spacedV6Hosts(4)]));

    expect(plan.warnings.map((warning) => warning.code)).not.toContain(
      'ALLOWLIST_COVERS_SINGLE_IP_VERSION',
    );
  });

  it('counts v6 address coverage without overflowing', () => {
    const plan = planOf(blocklistOptions([parseCidr('2001:db8::/32')]));

    expect(plan.stats.addressesCovered).toBe(1n << 96n);
  });
});

describe('decompose — determinism', () => {
  it('produces byte-identical output for shuffled input', () => {
    const input = spacedHosts(400);
    const reference = planFingerprint(planOf(allowlistOptions(input)));

    for (const seed of [1, 7, 12345, 999983]) {
      expect(planFingerprint(planOf(allowlistOptions(shuffled(input, seed))))).toBe(reference);
    }
  });

  it('produces byte-identical output for shuffled positive-packed input', () => {
    const input = [...spacedHosts(300), ...spacedV6Hosts(300)];
    const reference = planFingerprint(planOf(bypassOptions(input)));

    for (const seed of [3, 42, 6789]) {
      expect(planFingerprint(planOf(bypassOptions(shuffled(input, seed))))).toBe(reference);
    }
  });

  it('produces byte-identical output for shuffled escalated input', () => {
    const input = spacedHosts(5000);
    const options = { ...allowlistOptions(input), allowBypassEscalation: true };
    const reference = planFingerprint(planOf(options));

    expect(
      planFingerprint(
        planOf({ ...options, cidrs: shuffled(input, 271828) }),
      ),
    ).toBe(reference);
  });
});

describe('PlanInvariantError', () => {
  it('names the invariant it guards', () => {
    const error = new PlanInvariantError('allowlist-is-exactly-one-group', 'produced 2 groups');

    expect(error.name).toBe('PlanInvariantError');
    expect(error.invariant).toBe('allowlist-is-exactly-one-group');
    expect(error.message).toContain('allowlist-is-exactly-one-group');
    expect(error).toBeInstanceOf(Error);
  });
});
