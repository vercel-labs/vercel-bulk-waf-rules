/**
 * Serialization layer: turn a {@link PlannedRule} into the exact JSON shape the
 * Vercel firewall config API accepts, and hash-stably stringify it.
 *
 * The types in this file are deliberately narrow. Two platform facts are encoded
 * structurally rather than checked at runtime, because both have caused
 * production incidents when left to a reviewer's memory:
 *
 * 1. `op: 'ninc'` is deprecated in favour of `neg: true` + `op: 'inc'`. The
 *    emit-side condition type therefore cannot express `ninc` at all;
 *    {@link normalizeLegacyIpOp} exists to recognize it on the way *in*, when
 *    diffing rules that already exist in a project.
 * 2. `action: 'allow'` is rejected by the API for custom rules — it is only an
 *    "off" sentinel inside team rulesets. It is absent from
 *    {@link MitigateAction}, so no code path can emit it.
 */

import type { PlannedGroup, PlannedRule } from './decompose.js';
import { formatCidr } from './ip.js';
import {
  MAX_CONDITIONS_PER_GROUP,
  MAX_GROUPS_PER_RULE,
  MAX_RULE_DESCRIPTION_LEN,
  MAX_RULE_NAME_LEN,
  MAX_VALUES_PER_CONDITION,
} from './limits.js';

/** The two default routes, covering every possible client address. */
export const MATCH_ALL_CIDRS: readonly string[] = ['0.0.0.0/0', '::/0'];

/**
 * An IP membership condition.
 *
 * `op` is fixed to `'inc'` and negation is expressed with `neg`, which is the
 * current platform syntax. `neg` is `true` or absent — never `false` — so that
 * the serialized form of a positive condition is byte-identical whether or not
 * the builder thought about negation, which keeps content hashes stable.
 */
export interface IpAddressCondition {
  readonly type: 'ip_address';
  readonly op: 'inc';
  readonly value: readonly string[];
  readonly neg?: true;
}

/** An exact-match hostname condition. */
export interface HostCondition {
  readonly type: 'host';
  readonly op: 'eq';
  readonly value: string;
}

/** Any condition this builder is able to emit. */
export type FirewallCondition = IpAddressCondition | HostCondition;

/**
 * One condition group. Conditions inside it are ANDed.
 *
 * An empty `conditions` array is legal and meaningful: the runtime's `every`
 * over an empty match list is vacuously true, so the group matches every
 * request. Only the terminal deny of the `bypass-then-deny` topology is allowed
 * to be shaped that way, and `decompose` is what guarantees it.
 */
export interface FirewallConditionGroup {
  readonly conditions: readonly FirewallCondition[];
}

/**
 * Mitigation actions accepted on a custom rule.
 *
 * `allow` is intentionally missing — see the module doc comment. The full set is
 * kept (rather than narrowed to `deny | bypass`) so that a differ reading
 * existing project rules can be typed with the same union.
 */
export type MitigateAction = 'deny' | 'challenge' | 'log' | 'bypass' | 'rate_limit' | 'redirect';

/** Durations the platform accepts for time-boxed mitigations. */
export type ActionDuration = '1m' | '5m' | '15m' | '30m' | '1h';

/** The `action` envelope of a custom rule. */
export interface FirewallAction {
  readonly mitigate: {
    readonly action: MitigateAction;
    /**
     * Omitted for persistent actions. `deny` and `bypass` are not time-boxed, so
     * the planner never sets it; the field exists for rate limits and for
     * round-tripping rules that already carry one.
     */
    readonly actionDuration?: ActionDuration;
  };
}

/** A complete custom rule, ready to POST. */
export interface FirewallRuleInput {
  readonly name: string;
  readonly description: string;
  readonly active: boolean;
  readonly conditionGroup: readonly FirewallConditionGroup[];
  readonly action: FirewallAction;
}

/**
 * IP operators that may appear on rules already present in a project.
 *
 * `ninc` is deprecated and never emitted by this builder, but a rule created
 * before the migration — or by hand in the dashboard — can still carry it, and a
 * differ that does not recognize it would report a spurious change and rewrite a
 * working rule.
 */
export type RecognizedIpOp = 'inc' | 'ninc';

/** Which server-enforced limit a {@link RuleValidationError} refers to. */
export type RuleLimitName = 'name' | 'description' | 'groups' | 'conditions' | 'values';

/**
 * Thrown when a rule about to be emitted would violate a server-enforced limit.
 *
 * These are invariant violations, not user errors: `decompose` is responsible for
 * producing rules that fit, so reaching this means the planner and the limits
 * have drifted apart. Failing loudly here is much cheaper than an opaque 400
 * halfway through applying a multi-rule plan, which leaves a project in a
 * partially-migrated state.
 */
export class RuleValidationError extends Error {
  readonly limit: RuleLimitName;
  readonly actual: number;
  readonly max: number;
  readonly ruleName: string;

  constructor(ruleName: string, limit: RuleLimitName, actual: number, max: number) {
    super(
      `Rule ${JSON.stringify(ruleName)} violates the WAF ${limit} limit: ${actual} exceeds the maximum of ${max}.`,
    );
    this.name = 'RuleValidationError';
    this.limit = limit;
    this.actual = actual;
    this.max = max;
    this.ruleName = ruleName;
  }
}

/**
 * Collapse a legacy IP operator into the modern `{ op: 'inc', neg }` form.
 *
 * Used when reading pre-existing rules so that a `ninc` condition and a
 * `neg: true` + `inc` condition compare equal. Emitting is one-way: the builder
 * only ever writes the modern form.
 */
export function normalizeLegacyIpOp(op: RecognizedIpOp, neg?: boolean): {
  readonly op: 'inc';
  readonly neg: boolean;
} {
  return { op: 'inc', neg: op === 'ninc' ? true : neg === true };
}

/**
 * Build the conditions for one group.
 *
 * The `host` condition is emitted **per group**, not once per rule. That is not
 * redundancy: conditions AND within a group and groups OR with each other, so a
 * host condition present only in the first group of a positive-packed rule would
 * leave the other 24 groups matching host-independently. The rule would then act
 * on traffic to every hostname on the project, which for a `bypass` rule means
 * silently disabling the WAF for those addresses on domains the operator never
 * mentioned.
 */
function buildGroupConditions(
  group: PlannedGroup,
  hostname: string | undefined,
  negateIp: boolean,
): FirewallCondition[] {
  const conditions: FirewallCondition[] = [];

  if (hostname !== undefined) {
    conditions.push({ type: 'host', op: 'eq', value: hostname });
  }

  for (const values of group.ipChunks) {
    conditions.push({
      type: 'ip_address',
      op: 'inc',
      value: values.map(formatCidr),
      ...(negateIp ? { neg: true } : {}),
    });
  }

  // Do not remove: an empty group is accepted by the PATCH schema (no `minItems`
  // on `conditions`) but then throws `NoConditions()` at compile time
  // (api/packages/edge-firewall/src/config/compile.ts:62-65). That combination
  // strands a half-applied plan -- bypass rules live, terminal deny not.
  // Only reachable for an unscoped `catch-all-deny`, which has no IP chunks and
  // no hostname; this makes its "match everything" intent explicit instead.
  if (conditions.length === 0) {
    conditions.push({
      type: 'ip_address',
      op: 'inc',
      value: [...MATCH_ALL_CIDRS],
    });
  }

  return conditions;
}

function validate(rule: FirewallRuleInput): void {
  if (rule.name.length > MAX_RULE_NAME_LEN) {
    throw new RuleValidationError(rule.name, 'name', rule.name.length, MAX_RULE_NAME_LEN);
  }
  if (rule.description.length > MAX_RULE_DESCRIPTION_LEN) {
    throw new RuleValidationError(
      rule.name,
      'description',
      rule.description.length,
      MAX_RULE_DESCRIPTION_LEN,
    );
  }
  if (rule.conditionGroup.length > MAX_GROUPS_PER_RULE) {
    throw new RuleValidationError(
      rule.name,
      'groups',
      rule.conditionGroup.length,
      MAX_GROUPS_PER_RULE,
    );
  }
  for (const group of rule.conditionGroup) {
    if (group.conditions.length > MAX_CONDITIONS_PER_GROUP) {
      throw new RuleValidationError(
        rule.name,
        'conditions',
        group.conditions.length,
        MAX_CONDITIONS_PER_GROUP,
      );
    }
    for (const condition of group.conditions) {
      if (condition.type === 'ip_address' && condition.value.length > MAX_VALUES_PER_CONDITION) {
        throw new RuleValidationError(
          rule.name,
          'values',
          condition.value.length,
          MAX_VALUES_PER_CONDITION,
        );
      }
    }
  }
}

/**
 * Render a planned rule as the JSON the API accepts, validating every
 * server-enforced limit on the way out.
 *
 * @throws {RuleValidationError} if the rule would be rejected by the server.
 */
export function buildRuleJson(rule: PlannedRule): FirewallRuleInput {
  const negateIp = rule.kind === 'negated-allowlist';
  const groups: readonly PlannedGroup[] = rule.groups;

  const built: FirewallRuleInput = {
    name: rule.name,
    description: rule.description,
    active: rule.active,
    conditionGroup: groups.map((group) => ({
      conditions: buildGroupConditions(group, rule.hostname, negateIp),
    })),
    action: { mitigate: { action: rule.action } },
  };

  validate(built);
  return built;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Narrow to a read-only array without letting `Array.isArray`'s `any[]`
 * signature leak an implicit `any` into the serializer.
 */
function isArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function serialize(value: unknown, seen: Set<object>): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
    case 'number':
    case 'boolean':
      return JSON.stringify(value);
    case 'bigint':
      // JSON has no bigint. Decimal digits in a string are lossless and stable,
      // which is all a content hash needs; plan stats carry address counts that
      // routinely exceed 2^53.
      return JSON.stringify(value.toString());
    case 'undefined':
      return 'null';
    default:
      break;
  }

  if (isArray(value)) {
    if (seen.has(value)) {
      throw new TypeError('stableStringify cannot serialize a circular structure');
    }
    seen.add(value);
    const items = value.map((item) => serialize(item, seen)).join(',');
    seen.delete(value);
    return `[${items}]`;
  }

  if (isRecord(value)) {
    if (seen.has(value)) {
      throw new TypeError('stableStringify cannot serialize a circular structure');
    }
    seen.add(value);
    const entries = Object.keys(value)
      .sort()
      .flatMap((key) => {
        const item = value[key];
        // Match JSON.stringify: an undefined property is absent, not null.
        // Doing otherwise would make `{ neg: undefined }` and `{}` hash
        // differently and defeat idempotent re-application.
        return item === undefined ? [] : [`${JSON.stringify(key)}:${serialize(item, seen)}`];
      })
      .join(',');
    seen.delete(value);
    return `{${entries}}`;
  }

  throw new TypeError(`stableStringify cannot serialize a value of type ${typeof value}`);
}

/**
 * Deterministic JSON serialization with object keys sorted lexicographically.
 *
 * `JSON.stringify` preserves key insertion order, so two structurally identical
 * rules built by different code paths can produce different strings and
 * therefore different content hashes. That would make an idempotent apply
 * rewrite a project's firewall on every run. Array order *is* significant and is
 * preserved, because rule order is load-bearing in a plan.
 *
 * `bigint` serializes as its decimal digits in a string; `undefined` object
 * properties are omitted, matching `JSON.stringify`.
 *
 * @throws {TypeError} on circular structures or non-JSON-able values.
 */
export function stableStringify(value: unknown): string {
  return serialize(value, new Set<object>());
}
