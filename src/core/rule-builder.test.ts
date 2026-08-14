import { describe, expect, it } from 'vitest';

import type {
  CatchAllDenyRule,
  NegatedAllowlistRule,
  PlannedAction,
  PlannedGroup,
  PositiveMatchRule,
} from './decompose.js';
import type { Cidr } from './ip.js';
import {
  MAX_CONDITIONS_PER_GROUP,
  MAX_GROUPS_PER_RULE,
  MAX_RULE_DESCRIPTION_LEN,
  MAX_RULE_NAME_LEN,
  MAX_VALUES_PER_CONDITION,
} from './limits.js';
import type { RuleLimitName } from './rule-builder.js';
import {
  RuleValidationError,
  buildRuleJson,
  normalizeLegacyIpOp,
  stableStringify,
} from './rule-builder.js';

const V4_BASE = 167772160n;

/** `count` distinct /32s, offset so different chunks never share a value. */
function hosts(count: number, offset = 0): Cidr[] {
  return Array.from({ length: count }, (_, index): Cidr => {
    return { version: 4, addr: V4_BASE + BigInt((offset + index) * 2), prefixLen: 32 };
  });
}

interface RuleOverrides {
  readonly name?: string;
  readonly description?: string;
  readonly hostname?: string;
  readonly action?: PlannedAction;
}

function hostPart(hostname: string | undefined): { hostname?: string } {
  return hostname === undefined ? {} : { hostname };
}

function positiveRule(
  groups: readonly PlannedGroup[],
  overrides: RuleOverrides = {},
): PositiveMatchRule {
  return {
    kind: 'positive-match',
    order: 0,
    name: overrides.name ?? 'prefix blocklist 1/1',
    description: overrides.description ?? 'test description',
    active: true,
    action: overrides.action ?? 'deny',
    groups,
    ...hostPart(overrides.hostname),
  };
}

function allowlistRule(
  group: PlannedGroup,
  overrides: RuleOverrides = {},
): NegatedAllowlistRule {
  return {
    kind: 'negated-allowlist',
    order: 0,
    name: overrides.name ?? 'prefix allowlist 1/1',
    description: overrides.description ?? 'test description',
    active: true,
    action: 'deny',
    groups: [group],
    ...hostPart(overrides.hostname),
  };
}

function catchAllRule(overrides: RuleOverrides = {}): CatchAllDenyRule {
  return {
    kind: 'catch-all-deny',
    order: 1,
    name: overrides.name ?? 'prefix allowlist deny (catch-all)',
    description: overrides.description ?? 'test description',
    active: true,
    action: 'deny',
    groups: [{ ipChunks: [] }],
    ...hostPart(overrides.hostname),
  };
}

/** One group per chunk, one chunk each — the shape positive packing produces. */
function oneChunkGroups(chunkCount: number, valuesPerChunk: number): PlannedGroup[] {
  return Array.from({ length: chunkCount }, (_, index): PlannedGroup => {
    return { ipChunks: [hosts(valuesPerChunk, index * valuesPerChunk)] };
  });
}

function expectValidationError(build: () => unknown, limit: RuleLimitName, actual: number): void {
  expect(build).toThrow(RuleValidationError);
  try {
    build();
    expect.unreachable('expected buildRuleJson to throw');
  } catch (error) {
    expect(error).toBeInstanceOf(RuleValidationError);
    if (error instanceof RuleValidationError) {
      expect(error.limit).toBe(limit);
      expect(error.actual).toBe(actual);
      expect(error.message).toContain(limit);
    }
  }
}

describe('buildRuleJson — negated allowlist', () => {
  it('emits neg:true with op:inc and never the deprecated ninc operator', () => {
    const json = buildRuleJson(allowlistRule({ ipChunks: [hosts(75), hosts(5, 75)] }));

    expect(json.conditionGroup).toHaveLength(1);
    expect(json.conditionGroup[0]?.conditions).toHaveLength(2);
    for (const condition of json.conditionGroup[0]?.conditions ?? []) {
      expect(condition.type).toBe('ip_address');
      expect(condition.op).toBe('inc');
      expect(condition).toMatchObject({ neg: true });
    }
    expect(stableStringify(json)).not.toContain('ninc');
  });

  it('emits the full rule envelope', () => {
    const json = buildRuleJson(
      allowlistRule(
        { ipChunks: [hosts(2)] },
        { name: 'vendor allowlist 1/1', description: 'denies all but two hosts' },
      ),
    );

    expect(json).toEqual({
      name: 'vendor allowlist 1/1',
      description: 'denies all but two hosts',
      active: true,
      conditionGroup: [
        {
          conditions: [
            { type: 'ip_address', op: 'inc', neg: true, value: ['10.0.0.0/32', '10.0.0.2/32'] },
          ],
        },
      ],
      action: { mitigate: { action: 'deny' } },
    });
  });
});

describe('buildRuleJson — positive match', () => {
  it('omits neg entirely rather than emitting neg:false', () => {
    const json = buildRuleJson(positiveRule(oneChunkGroups(2, 3)));

    for (const group of json.conditionGroup) {
      for (const condition of group.conditions) {
        expect(condition).not.toHaveProperty('neg');
      }
    }
    expect(stableStringify(json)).not.toContain('neg');
  });

  it('maps the bypass action through', () => {
    const json = buildRuleJson(positiveRule(oneChunkGroups(1, 3), { action: 'bypass' }));

    expect(json.action).toEqual({ mitigate: { action: 'bypass' } });
  });

  it('never emits the API-rejected allow action', () => {
    for (const action of ['deny', 'bypass'] as const) {
      const json = buildRuleJson(positiveRule(oneChunkGroups(1, 3), { action }));
      expect(json.action.mitigate.action).not.toBe('allow');
    }
  });

  it('omits actionDuration for persistent actions', () => {
    const json = buildRuleJson(positiveRule(oneChunkGroups(1, 3)));

    expect(json.action.mitigate).not.toHaveProperty('actionDuration');
  });
});

describe('buildRuleJson — hostname scoping', () => {
  /**
   * Groups OR and conditions AND, so a host condition present in only the first
   * group leaves every other group matching host-independently. For a bypass rule
   * that means the WAF is silently disabled for those addresses on every other
   * hostname of the project. This test exists to catch exactly that shortcut.
   */
  it('repeats the host condition in EVERY group', () => {
    const json = buildRuleJson(
      positiveRule(oneChunkGroups(MAX_GROUPS_PER_RULE, 2), { hostname: 'example.com' }),
    );

    expect(json.conditionGroup).toHaveLength(MAX_GROUPS_PER_RULE);
    for (const group of json.conditionGroup) {
      expect(group.conditions.filter((condition) => condition.type === 'host')).toEqual([
        { type: 'host', op: 'eq', value: 'example.com' },
      ]);
      expect(group.conditions.filter((condition) => condition.type === 'ip_address')).toHaveLength(
        1,
      );
    }
  });

  it('ANDs the host condition with the negated ip conditions in the single group', () => {
    const json = buildRuleJson(
      allowlistRule({ ipChunks: [hosts(2), hosts(2, 2)] }, { hostname: 'example.com' }),
    );

    expect(json.conditionGroup).toHaveLength(1);
    expect(json.conditionGroup[0]?.conditions).toHaveLength(3);
    expect(json.conditionGroup[0]?.conditions[0]).toEqual({
      type: 'host',
      op: 'eq',
      value: 'example.com',
    });
  });

  it('omits the host condition when no hostname is set', () => {
    const json = buildRuleJson(positiveRule(oneChunkGroups(3, 2)));

    for (const group of json.conditionGroup) {
      expect(group.conditions.filter((condition) => condition.type === 'host')).toEqual([]);
    }
  });
});

describe('buildRuleJson — catch-all deny', () => {
  it('emits an explicit match-all ip condition rather than an empty group', () => {
    const json = buildRuleJson(catchAllRule());

    expect(json.conditionGroup).toEqual([
      { conditions: [{ type: 'ip_address', op: 'inc', value: ['0.0.0.0/0', '::/0'] }] },
    ]);
    expect(json.action).toEqual({ mitigate: { action: 'deny' } });
  });

  it('never emits an empty conditions array, which the compiler rejects', () => {
    for (const rule of [catchAllRule(), catchAllRule({ hostname: 'shop.example.com' })]) {
      for (const group of buildRuleJson(rule).conditionGroup) {
        expect(group.conditions.length).toBeGreaterThan(0);
      }
    }
  });

  it('emits only the host condition when scoped to a hostname', () => {
    const json = buildRuleJson(catchAllRule({ hostname: 'shop.example.com' }));

    expect(json.conditionGroup).toEqual([
      { conditions: [{ type: 'host', op: 'eq', value: 'shop.example.com' }] },
    ]);
  });
});

describe('buildRuleJson — limit validation', () => {
  it('rejects a name over 160 characters', () => {
    const name = 'n'.repeat(MAX_RULE_NAME_LEN + 1);
    expectValidationError(
      () => buildRuleJson(positiveRule(oneChunkGroups(1, 1), { name })),
      'name',
      MAX_RULE_NAME_LEN + 1,
    );
  });

  it('accepts a name of exactly 160 characters', () => {
    const name = 'n'.repeat(MAX_RULE_NAME_LEN);
    expect(buildRuleJson(positiveRule(oneChunkGroups(1, 1), { name })).name).toBe(name);
  });

  it('rejects a description over 256 characters', () => {
    const description = 'd'.repeat(MAX_RULE_DESCRIPTION_LEN + 1);
    expectValidationError(
      () => buildRuleJson(positiveRule(oneChunkGroups(1, 1), { description })),
      'description',
      MAX_RULE_DESCRIPTION_LEN + 1,
    );
  });

  it('rejects more than 25 condition groups', () => {
    expectValidationError(
      () => buildRuleJson(positiveRule(oneChunkGroups(MAX_GROUPS_PER_RULE + 1, 1))),
      'groups',
      MAX_GROUPS_PER_RULE + 1,
    );
  });

  it('accepts exactly 25 condition groups', () => {
    expect(
      buildRuleJson(positiveRule(oneChunkGroups(MAX_GROUPS_PER_RULE, 1))).conditionGroup,
    ).toHaveLength(MAX_GROUPS_PER_RULE);
  });

  it('rejects more than 65 conditions in one group', () => {
    // Semantically nonsense for a positive match (the chunks would AND), but the
    // point here is that the validator catches the shape before the server does.
    const chunks = Array.from({ length: MAX_CONDITIONS_PER_GROUP + 1 }, (_, index) =>
      hosts(1, index),
    );
    expectValidationError(
      () => buildRuleJson(positiveRule([{ ipChunks: chunks }])),
      'conditions',
      MAX_CONDITIONS_PER_GROUP + 1,
    );
  });

  it('counts the host condition toward the per-group condition limit', () => {
    const chunks = Array.from({ length: MAX_CONDITIONS_PER_GROUP }, (_, index) => hosts(1, index));
    expectValidationError(
      () => buildRuleJson(positiveRule([{ ipChunks: chunks }], { hostname: 'example.com' })),
      'conditions',
      MAX_CONDITIONS_PER_GROUP + 1,
    );
  });

  it('rejects more than 75 values in one condition', () => {
    expectValidationError(
      () => buildRuleJson(positiveRule([{ ipChunks: [hosts(MAX_VALUES_PER_CONDITION + 1)] }])),
      'values',
      MAX_VALUES_PER_CONDITION + 1,
    );
  });

  it('accepts exactly 75 values in one condition', () => {
    const json = buildRuleJson(positiveRule([{ ipChunks: [hosts(MAX_VALUES_PER_CONDITION)] }]));

    expect(json.conditionGroup[0]?.conditions[0]).toMatchObject({
      value: expect.any(Array),
    });
  });

  it('names the rule in the error so a failed multi-rule apply is traceable', () => {
    try {
      buildRuleJson(positiveRule([{ ipChunks: [hosts(76)] }], { name: 'vendor bypass 7/12' }));
      expect.unreachable('expected buildRuleJson to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(RuleValidationError);
      if (error instanceof RuleValidationError) {
        expect(error.ruleName).toBe('vendor bypass 7/12');
        expect(error.max).toBe(MAX_VALUES_PER_CONDITION);
      }
    }
  });
});

describe('normalizeLegacyIpOp', () => {
  it('treats the deprecated ninc operator as a negated inc', () => {
    expect(normalizeLegacyIpOp('ninc')).toEqual({ op: 'inc', neg: true });
  });

  it('keeps ninc negated even when neg is explicitly false', () => {
    expect(normalizeLegacyIpOp('ninc', false)).toEqual({ op: 'inc', neg: true });
  });

  it('passes inc through unchanged', () => {
    expect(normalizeLegacyIpOp('inc')).toEqual({ op: 'inc', neg: false });
    expect(normalizeLegacyIpOp('inc', false)).toEqual({ op: 'inc', neg: false });
    expect(normalizeLegacyIpOp('inc', true)).toEqual({ op: 'inc', neg: true });
  });
});

describe('stableStringify', () => {
  it('is independent of key insertion order', () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe(stableStringify({ a: 2, b: 1 }));
    expect(stableStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('sorts keys at every nesting level', () => {
    const left = { outer: { z: 1, a: { y: 2, b: 3 } } };
    const right = { outer: { a: { b: 3, y: 2 }, z: 1 } };

    expect(stableStringify(left)).toBe(stableStringify(right));
    expect(stableStringify(left)).toBe('{"outer":{"a":{"b":3,"y":2},"z":1}}');
  });

  it('preserves array order, which is significant for rule ordering', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
    expect(stableStringify([1, 2, 3])).not.toBe(stableStringify([3, 2, 1]));
  });

  it('handles objects nested inside arrays', () => {
    expect(stableStringify([{ b: 1, a: 2 }, { d: 3, c: 4 }])).toBe(
      '[{"a":2,"b":1},{"c":4,"d":3}]',
    );
  });

  it('serializes primitives the way JSON does', () => {
    expect(stableStringify(null)).toBe('null');
    expect(stableStringify(true)).toBe('true');
    expect(stableStringify('a"b')).toBe('"a\\"b"');
    expect(stableStringify(1.5)).toBe('1.5');
  });

  it('serializes bigint as lossless decimal digits in a string', () => {
    expect(stableStringify({ addressesCovered: 1n << 96n })).toBe(
      '{"addressesCovered":"79228162514264337593543950336"}',
    );
  });

  it('omits undefined object properties, matching JSON.stringify', () => {
    expect(stableStringify({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(stableStringify({ a: 1, b: undefined })).toBe(stableStringify({ a: 1 }));
  });

  it('serializes undefined array elements as null, matching JSON.stringify', () => {
    expect(stableStringify([1, undefined, 2])).toBe('[1,null,2]');
  });

  it('handles empty objects and arrays', () => {
    expect(stableStringify({})).toBe('{}');
    expect(stableStringify([])).toBe('[]');
  });

  it('produces identical output for two independently built identical rules', () => {
    const left = buildRuleJson(positiveRule(oneChunkGroups(3, 4), { hostname: 'example.com' }));
    const right = buildRuleJson(positiveRule(oneChunkGroups(3, 4), { hostname: 'example.com' }));

    expect(stableStringify(left)).toBe(stableStringify(right));
  });

  it('throws on circular structures', () => {
    const cyclic: Record<string, unknown> = { name: 'loop' };
    cyclic.self = cyclic;

    expect(() => stableStringify(cyclic)).toThrow(TypeError);
  });

  it('throws on circular arrays', () => {
    const cyclic: unknown[] = [1];
    cyclic.push(cyclic);

    expect(() => stableStringify(cyclic)).toThrow(TypeError);
  });

  it('reuses a shared reference without treating it as a cycle', () => {
    const shared = { a: 1 };

    expect(stableStringify([shared, shared])).toBe('[{"a":1},{"a":1}]');
  });

  it('throws on values JSON cannot represent', () => {
    expect(() => stableStringify(() => 1)).toThrow(TypeError);
    expect(() => stableStringify(Symbol('x'))).toThrow(TypeError);
  });
});
