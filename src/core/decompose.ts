/**
 * Decomposition / planning core: turn an operator intent plus a CIDR set into an
 * ordered list of WAF rules that an executor can apply verbatim.
 *
 * Nothing here performs I/O. The plan is a pure value so it can be diffed,
 * content-hashed, printed in a dry run, and reviewed before anything touches a
 * project's firewall config.
 *
 * The whole file exists because of one asymmetry in the platform's evaluation
 * model:
 *
 * - condition GROUPS within a rule are **ORed** (each group compiles to its own
 *   route);
 * - CONDITIONS within one group are **ANDed** (the runtime does `every` over the
 *   compiled route's match entries).
 *
 * Positive matching ("act on these addresses") wants OR, so it packs across
 * groups. Negative matching ("act on everything except these addresses") wants
 * AND, so it must stay inside a single group. Getting that backwards does not
 * produce a slightly-wrong rule; it produces a rule that denies every request.
 */

import { aggregateCidrs, countAddresses } from './aggregate.js';
import type { Cidr } from './ip.js';
import { cidrToRange, compareRanges } from './ip.js';
import {
  MAX_GROUPS_PER_RULE,
  MAX_RULE_DESCRIPTION_LEN,
  MAX_RULE_NAME_LEN,
  MAX_VALUES_PER_CONDITION,
  allowlistMaxPerRule,
  customRuleLimit,
  type PlanTier,
} from './limits.js';

/**
 * What the operator is trying to achieve, which fully determines the matching
 * polarity and therefore the packing strategy.
 *
 * A discriminated union rather than a string enum so `switch` statements over it
 * are exhaustive: adding a fourth intent will fail to compile until every
 * planner branch handles it, which is the only way to be sure a new intent does
 * not silently inherit allowlist packing.
 */
export type Intent =
  /** Deny everything EXCEPT the listed IPs. Negative matching. */
  | { readonly kind: 'allowlist' }
  /** Deny the listed IPs. Positive matching. */
  | { readonly kind: 'blocklist' }
  /** Listed IPs skip WAF checks entirely. Positive matching. */
  | { readonly kind: 'bypass' };

/**
 * Mitigation actions this planner is allowed to emit.
 *
 * Note the absence of `allow`: the API rejects it on custom rules (it exists
 * only as an "off" sentinel inside team rulesets). `bypass` is the correct way
 * to express a positive allow.
 */
export type PlannedAction = 'deny' | 'bypass';

/**
 * One condition group's worth of IP payload.
 *
 * Each entry in `ipChunks` becomes exactly one `ip_address` condition holding at
 * most {@link MAX_VALUES_PER_CONDITION} values. Whether multiple chunks in one
 * group is correct depends entirely on matching polarity — see
 * {@link NegatedAllowlistRule} and {@link PositiveMatchRule}.
 */
export interface PlannedGroup {
  readonly ipChunks: ReadonlyArray<readonly Cidr[]>;
}

/** Fields shared by every planned rule regardless of matching polarity. */
interface PlannedRuleBase {
  /**
   * 0-based position in {@link RulePlan.rules}.
   *
   * Duplicated from the array index on purpose: the executor may create rules
   * one at a time and then issue a reorder, at which point it needs the intended
   * position as data rather than as an implicit property of an array it has
   * already taken apart.
   */
  readonly order: number;
  readonly name: string;
  readonly description: string;
  readonly active: boolean;
  readonly action: PlannedAction;
  /** When set, every group gets a `host eq <hostname>` condition ANDed in. */
  readonly hostname?: string;
}

/**
 * The negated single-group allowlist rule: deny everything except the listed
 * addresses.
 *
 * ## Why `groups` is a one-element tuple, and why that must never change
 *
 * The rule reads "deny if the client IP is NOT in chunk 1 AND NOT in chunk 2 AND
 * … AND NOT in chunk k". That conjunction is only expressible inside a single
 * condition group, because conditions within a group AND.
 *
 * Splitting the chunks across sibling groups — or across sibling rules, which is
 * the same thing since separate rules are evaluated in order and each can match
 * independently — turns the conjunction into a disjunction:
 *
 *     (IP ∉ A) OR (IP ∉ B)
 *
 * For any two disjoint chunks A and B, every address on the internet satisfies
 * at least one side of that OR: an address in A is not in B, an address in B is
 * not in A, and an address in neither is in neither. The rule therefore matches
 * **every request** and the attached action is `deny`. The customer's allowlist
 * becomes a total outage, and it does so only once the list grows past 75
 * entries — so it passes every small-scale test and fails in production on the
 * first big import.
 *
 * This is not hypothetical; it is the exact shape of the bug this planner was
 * written to make unrepresentable. The tuple type is the primary defence, and
 * {@link PlanInvariantError} is the runtime backstop for code paths that
 * construct rules dynamically. If you find yourself wanting to relax the tuple
 * to `PlannedGroup[]` to "support bigger lists", the supported answer is the
 * `bypass-then-deny` escalation below, not more groups.
 */
export interface NegatedAllowlistRule extends PlannedRuleBase {
  readonly kind: 'negated-allowlist';
  readonly action: 'deny';
  readonly groups: readonly [PlannedGroup];
}

/**
 * A positive-matching rule: act on the listed addresses.
 *
 * OR is the desired semantics here, so the payload fans out across up to
 * {@link MAX_GROUPS_PER_RULE} groups with exactly one `ip_address` condition
 * each. Putting two IP chunks in the same group would AND them, and a single
 * client IP cannot be a member of two disjoint chunks, so such a group could
 * never match.
 */
export interface PositiveMatchRule extends PlannedRuleBase {
  readonly kind: 'positive-match';
  readonly groups: readonly PlannedGroup[];
}

/**
 * The terminal deny of the `bypass-then-deny` escalation: matches everything
 * that the preceding bypass rules did not.
 *
 * `ipChunks` is typed as an empty tuple because an IP condition here would
 * defeat the purpose — the rule's job is to be the unconditional catch-all. With
 * no conditions in the group, the runtime's `every` over an empty match list is
 * vacuously true, so the group matches every request. When a hostname is set the
 * group carries only the `host` condition, which usefully narrows the blast
 * radius to that hostname.
 */
export interface CatchAllDenyRule extends PlannedRuleBase {
  readonly kind: 'catch-all-deny';
  readonly action: 'deny';
  readonly groups: readonly [{ readonly ipChunks: readonly [] }];
}

/** A single rule in a plan, discriminated by its matching polarity. */
export type PlannedRule = NegatedAllowlistRule | PositiveMatchRule | CatchAllDenyRule;

/** Non-fatal findings the operator must see before applying a plan. */
export interface PlanWarning {
  readonly code:
    | 'BYPASS_SKIPS_MANAGED_RULESETS'
    | 'RULE_ORDER_IS_LOAD_BEARING'
    | 'AGGREGATION_CHANGED_INPUT'
    | 'ALLOWLIST_COVERS_SINGLE_IP_VERSION';
  readonly message: string;
}

/** Counts that let a reviewer sanity-check a plan without reading every rule. */
export interface PlanStats {
  /** CIDRs handed to {@link decompose}, before aggregation. */
  readonly inputCount: number;
  /** CIDRs remaining after lossless aggregation; this is what gets packed. */
  readonly afterAggregation: number;
  readonly ruleCount: number;
  /**
   * Total conditions the plan will emit, including the repeated `host`
   * conditions. This is the number to compare against the per-group condition
   * budget when reasoning about headroom.
   */
  readonly conditionCount: number;
  /** Distinct addresses covered by the aggregated set, as a union. */
  readonly addressesCovered: bigint;
}

/**
 * Which topology the planner chose.
 *
 * - `single-deny-negated` — one negated allowlist rule (the safe default).
 * - `positive-packed` — one or more positive-matching rules.
 * - `bypass-then-deny` — the allowlist escalation; see
 *   {@link DecomposeOptions.allowBypassEscalation}.
 */
export type PlanStrategy = 'single-deny-negated' | 'positive-packed' | 'bypass-then-deny';

/**
 * A complete, ordered plan.
 *
 * `rules` is **contractually ordered**: index 0 must end up first in the
 * project's rule array. For `bypass-then-deny` this ordering is load-bearing
 * rather than cosmetic, because a bypass registered after a terminal deny has
 * already matched is too late to help.
 */
export interface RulePlan {
  readonly strategy: PlanStrategy;
  readonly rules: readonly PlannedRule[];
  readonly warnings: readonly PlanWarning[];
  readonly stats: PlanStats;
}

/**
 * A typed, actionable "no".
 *
 * Refusals are for inputs the planner cannot serve safely. They are values, not
 * exceptions, because every one of them is something the operator can fix and
 * the CLI should be able to print several at once without unwinding.
 */
export interface Refusal {
  readonly code:
    | 'EMPTY_INPUT'
    | 'EXCEEDS_ALLOWLIST_CEILING'
    | 'EXCEEDS_PLAN_RULE_LIMIT'
    | 'INVALID_RULE_NAME_PREFIX'
    | 'RULE_METADATA_TOO_LONG'
    /**
     * Reserved for the input-normalization layer, which rejects sources that mix
     * address families in a way it cannot attribute (for example a provider
     * export whose rows carry no version column). `decompose` itself never
     * returns this code: mixed v4/v6 input is fully supported here, because
     * `aggregate.ts` keeps the families separate and an `ip_address` condition
     * accepts both.
     */
    | 'MIXED_VERSION_UNSUPPORTED';
  readonly message: string;
  /** Concrete next step. Always non-empty; the CLI prints it verbatim. */
  readonly remediation: string;
}

/** Input to {@link decompose}. */
export interface DecomposeOptions {
  readonly intent: Intent;
  readonly cidrs: Cidr[];
  /** Scope every group to this hostname. Costs one condition slot per group. */
  readonly hostname?: string;
  /** Prepended to every generated rule name; must be non-empty. */
  readonly ruleNamePrefix: string;
  /**
   * Opt in to the `bypass-then-deny` topology when an allowlist exceeds the
   * single-rule ceiling.
   *
   * Defaults to `false`, and that default is deliberate: the escalation trades
   * away managed-ruleset coverage for the allowlisted addresses. Choosing it
   * silently would weaken a customer's security posture without anyone deciding
   * to. See {@link BYPASS_ESCALATION_WARNING}.
   */
  readonly allowBypassEscalation?: boolean;
  /** Defaults to `'pro'`, which is the common case for a paid team project. */
  readonly tier?: PlanTier;
  /** Team-level custom-rule cap, when the caller has read it from the API. */
  readonly tierRuleOverride?: number;
}

/** Result of {@link decompose}: either a plan or a typed refusal. */
export type DecomposeResult =
  | { readonly ok: true; readonly plan: RulePlan }
  | { readonly ok: false; readonly refusal: Refusal };

/**
 * Thrown when the planner produces output that violates one of its own
 * structural invariants.
 *
 * Distinct from {@link Refusal} on purpose: a refusal means "your input cannot
 * be served", whereas this means "the planner has a bug and the rules it just
 * built may be unsafe to apply". It must never be caught and downgraded to a
 * warning.
 */
export class PlanInvariantError extends Error {
  readonly invariant: string;

  constructor(invariant: string, detail: string) {
    super(`WAF plan invariant violated (${invariant}): ${detail}`);
    this.name = 'PlanInvariantError';
    this.invariant = invariant;
  }
}

/**
 * The security caveat attached to every `bypass-then-deny` plan.
 *
 * Spelled out at length because the two allowlist topologies are *not*
 * equivalent, and the difference is invisible in the generated JSON:
 *
 * - The negated form (`neg: true` + `deny`) leaves the allowlisted traffic
 *   subject to everything else in the firewall: managed rulesets (OWASP, Bot
 *   Protection), rate limits, and any later custom rule. The allowlist only
 *   decides *who may reach the app*, not *what they may do once there*.
 * - The escalated form matches allowlisted traffic with `bypass`, which is a
 *   deliberate skip of remaining custom rules *and* managed rulesets. Those
 *   addresses receive no WAF inspection at all. A compromised vendor host in the
 *   list then has a completely unfiltered path to the origin.
 *
 * That is an acceptable trade for some operators and unacceptable for others, so
 * it is theirs to make. This is why the escalation is gated behind an explicit
 * opt-in and why the warning is attached to the plan rather than only logged.
 */
export const BYPASS_ESCALATION_WARNING =
  'Escalated to bypass-then-deny: allowlisted addresses are matched with the "bypass" action, ' +
  'which skips all remaining custom rules AND managed rulesets (OWASP, Bot Protection) for ' +
  'those addresses. They receive no WAF inspection at all. The single-rule negated form keeps ' +
  'managed rulesets active for allowlisted traffic; this topology does not. Confirm that ' +
  'unfiltered origin access for every listed address is acceptable.';

const ORDER_WARNING =
  'Rule order is load-bearing: every bypass rule must be positioned before the terminal deny. ' +
  'A bypass evaluated after the deny has already matched cannot rescue the request, so applying ' +
  'these rules out of order will deny all traffic. Apply in the given order, then verify with a ' +
  'rules reorder.';

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    out.push(items.slice(index, index + size));
  }
  return out;
}

/**
 * Canonical total order over CIDRs: version, then start address, then prefix
 * length.
 *
 * Determinism is a hard requirement, not a nicety: a later layer content-hashes
 * the plan to decide whether a project's rules need updating. If two runs over
 * the same set produced different chunk boundaries, every run would look like a
 * change and the tool would rewrite a customer's firewall on every invocation.
 */
function canonicalSort(cidrs: readonly Cidr[]): Cidr[] {
  return [...cidrs].sort((a, b) => {
    const byRange = compareRanges(cidrToRange(a), cidrToRange(b));
    if (byRange !== 0) return byRange;
    return a.prefixLen - b.prefixLen;
  });
}

function refuse(code: Refusal['code'], message: string, remediation: string): DecomposeResult {
  return { ok: false, refusal: { code, message, remediation } };
}

function plural(count: number): string {
  return count === 1 ? 'entry' : 'entries';
}

/** Everything the per-strategy planners need, resolved once up front. */
interface PlanContext {
  readonly prefix: string;
  readonly hostname?: string;
  readonly aggregated: readonly Cidr[];
  readonly inputCount: number;
  readonly warnings: PlanWarning[];
  readonly tier: PlanTier;
  readonly ruleLimit: number;
}

function hostPart(hostname: string | undefined): { hostname?: string } {
  return hostname === undefined ? {} : { hostname };
}

function countPlannedConditions(rules: readonly PlannedRule[], hasHostname: boolean): number {
  let total = 0;
  for (const rule of rules) {
    const groups: readonly PlannedGroup[] = rule.groups;
    for (const group of groups) {
      total += group.ipChunks.length + (hasHostname ? 1 : 0);
    }
  }
  return total;
}

/**
 * Structural checks that the type system cannot express.
 *
 * The tuple types already forbid a multi-group allowlist rule and an IP-bearing
 * catch-all. What remains is cross-rule shape (only one catch-all, and it is
 * last), the array-index/`order` correspondence, and the numeric limits — none
 * of which are expressible without dependent types.
 */
function assertPlanInvariants(strategy: PlanStrategy, rules: readonly PlannedRule[]): void {
  rules.forEach((rule, index) => {
    if (rule.order !== index) {
      throw new PlanInvariantError(
        'order-matches-index',
        `rule ${JSON.stringify(rule.name)} carries order ${rule.order} at array index ${index}`,
      );
    }
    const groups: readonly PlannedGroup[] = rule.groups;
    if (groups.length > MAX_GROUPS_PER_RULE) {
      throw new PlanInvariantError(
        'groups-within-limit',
        `rule ${JSON.stringify(rule.name)} has ${groups.length} groups`,
      );
    }
    for (const group of groups) {
      for (const values of group.ipChunks) {
        if (values.length > MAX_VALUES_PER_CONDITION) {
          throw new PlanInvariantError(
            'values-within-limit',
            `rule ${JSON.stringify(rule.name)} has a condition with ${values.length} values`,
          );
        }
      }
    }
  });

  if (strategy === 'single-deny-negated') {
    // The allowlist outage guard. See NegatedAllowlistRule for why a second
    // group or a sibling rule inverts the semantics into deny-everything.
    if (rules.length !== 1) {
      throw new PlanInvariantError(
        'allowlist-is-exactly-one-rule',
        `produced ${rules.length} rules; sibling allowlist rules OR into deny-everything`,
      );
    }
    const only = rules[0];
    if (only === undefined || only.kind !== 'negated-allowlist') {
      throw new PlanInvariantError(
        'allowlist-is-negated-kind',
        `expected a negated-allowlist rule, got ${only === undefined ? 'nothing' : only.kind}`,
      );
    }
    if (only.groups.length !== 1) {
      throw new PlanInvariantError(
        'allowlist-is-exactly-one-group',
        `produced ${only.groups.length} groups; sibling groups OR into deny-everything`,
      );
    }
  }

  if (strategy === 'bypass-then-deny') {
    const catchAlls = rules.filter((rule) => rule.kind === 'catch-all-deny');
    if (catchAlls.length !== 1) {
      throw new PlanInvariantError(
        'escalation-has-one-catch-all',
        `expected exactly 1 catch-all deny, got ${catchAlls.length}`,
      );
    }
    const last = rules[rules.length - 1];
    if (last === undefined || last.kind !== 'catch-all-deny') {
      throw new PlanInvariantError(
        'catch-all-is-last',
        'the terminal deny must be the final rule, otherwise it matches before the bypasses',
      );
    }
    for (const rule of rules.slice(0, -1)) {
      if (rule.kind !== 'positive-match' || rule.action !== 'bypass') {
        throw new PlanInvariantError(
          'escalation-preamble-is-bypass',
          `rule ${JSON.stringify(rule.name)} is ${rule.kind}/${rule.action}, expected positive-match/bypass`,
        );
      }
    }
  }
}

function finalize(
  ctx: PlanContext,
  strategy: PlanStrategy,
  rules: readonly PlannedRule[],
): DecomposeResult {
  for (const rule of rules) {
    if (rule.name.length > MAX_RULE_NAME_LEN) {
      return refuse(
        'RULE_METADATA_TOO_LONG',
        `Generated rule name is ${rule.name.length} characters, over the ${MAX_RULE_NAME_LEN}-character limit: ${JSON.stringify(rule.name)}.`,
        `Shorten ruleNamePrefix by at least ${rule.name.length - MAX_RULE_NAME_LEN} characters.`,
      );
    }
    if (rule.description.length > MAX_RULE_DESCRIPTION_LEN) {
      return refuse(
        'RULE_METADATA_TOO_LONG',
        `Generated rule description is ${rule.description.length} characters, over the ${MAX_RULE_DESCRIPTION_LEN}-character limit.`,
        'This is a planner bug: descriptions are generated from fixed templates. Please report it.',
      );
    }
  }

  if (rules.length > ctx.ruleLimit) {
    return refuse(
      'EXCEEDS_PLAN_RULE_LIMIT',
      `Plan needs ${rules.length} custom rules but the ${ctx.tier} tier allows ${ctx.ruleLimit}.`,
      `Reduce the list (CIDR aggregation already ran and left ${ctx.aggregated.length} ${plural(ctx.aggregated.length)}), ` +
        'split it across projects or hostnames, or raise the custom-rule limit for this team.',
    );
  }

  assertPlanInvariants(strategy, rules);

  return {
    ok: true,
    plan: {
      strategy,
      rules,
      warnings: ctx.warnings,
      stats: {
        inputCount: ctx.inputCount,
        afterAggregation: ctx.aggregated.length,
        ruleCount: rules.length,
        conditionCount: countPlannedConditions(rules, ctx.hostname !== undefined),
        addressesCovered: countAddresses([...ctx.aggregated]),
      },
    },
  };
}

function planAllowlist(ctx: PlanContext, allowEscalation: boolean): DecomposeResult {
  const ceiling = allowlistMaxPerRule(ctx.hostname !== undefined);
  const count = ctx.aggregated.length;

  if (count > ceiling) {
    if (!allowEscalation) {
      const scopeNote =
        ctx.hostname === undefined
          ? ''
          : ` (the ceiling is ${ceiling} rather than ${allowlistMaxPerRule(false)} because the host condition consumes one of the condition slots in the single group)`;
      return refuse(
        'EXCEEDS_ALLOWLIST_CEILING',
        `An allowlist must fit in one rule with one condition group, which caps it at ${ceiling} CIDR entries${scopeNote}; this list has ${count} after aggregation. ` +
          'Splitting it across groups or rules would OR the negated conditions together and deny all traffic, so the planner will not do it.',
        `Consolidate the list into fewer blocks — aggregation is already lossless, so the next step is deliberately widening to supernets, which grants access to addresses that were never listed and needs a human decision. ` +
          `Alternatively scope separate allowlists to different hostnames, or set allowBypassEscalation: true to use the bypass-then-deny topology (which skips managed rulesets for allowlisted addresses — read the warning before choosing it).`,
      );
    }
    return planBypassThenDeny(ctx);
  }

  const valueChunks = chunk(ctx.aggregated, MAX_VALUES_PER_CONDITION);
  const rule: NegatedAllowlistRule = {
    kind: 'negated-allowlist',
    order: 0,
    name: `${ctx.prefix} allowlist 1/1`,
    description: `Denies all traffic except the ${count} listed CIDR ${plural(count)}. One condition group whose negated IP conditions all have to match.`,
    active: true,
    action: 'deny',
    groups: [{ ipChunks: valueChunks }],
    ...hostPart(ctx.hostname),
  };

  return finalize(ctx, 'single-deny-negated', [rule]);
}

function packPositiveRules(
  ctx: PlanContext,
  action: PlannedAction,
  name: (index: number, total: number) => string,
  description: (index: number, total: number, count: number) => string,
  startOrder: number,
): PositiveMatchRule[] {
  const valueChunks = chunk(ctx.aggregated, MAX_VALUES_PER_CONDITION);
  const perRule = chunk(valueChunks, MAX_GROUPS_PER_RULE);

  return perRule.map((groupChunks, index) => {
    const count = groupChunks.reduce((sum, values) => sum + values.length, 0);
    return {
      kind: 'positive-match',
      order: startOrder + index,
      name: name(index + 1, perRule.length),
      description: description(index + 1, perRule.length, count),
      active: true,
      action,
      groups: groupChunks.map((values) => ({ ipChunks: [values] })),
      ...hostPart(ctx.hostname),
    };
  });
}

function planPositive(ctx: PlanContext, action: PlannedAction): DecomposeResult {
  const verb = action === 'deny' ? 'Denies' : 'Bypasses WAF checks for';
  const label = action === 'deny' ? 'blocklist' : 'bypass';

  const rules = packPositiveRules(
    ctx,
    action,
    (index, total) => `${ctx.prefix} ${label} ${index}/${total}`,
    (index, total, count) =>
      `${verb} traffic from ${count} listed CIDR ${plural(count)} (part ${index} of ${total}).`,
    0,
  );

  return finalize(ctx, 'positive-packed', rules);
}

/**
 * The allowlist escalation: N positive `bypass` rules followed by exactly one
 * terminal `deny`.
 *
 * This works because `bypass` does not short-circuit rule evaluation, but once a
 * bypass has been registered for a request no later non-bypass mitigation can
 * override it. So the broad deny can sit at the end and catch everything the
 * bypasses did not claim — provided it really is at the end.
 *
 * Read {@link BYPASS_ESCALATION_WARNING} before touching this. The security
 * posture it produces is materially weaker than the single-rule negated form.
 */
function planBypassThenDeny(ctx: PlanContext): DecomposeResult {
  const bypassRules = packPositiveRules(
    ctx,
    'bypass',
    (index, total) => `${ctx.prefix} allowlist bypass ${index}/${total}`,
    (index, total, count) =>
      `Allowlist escalation: bypasses WAF checks for ${count} listed CIDR ${plural(count)} (part ${index} of ${total}). Must be ordered before the catch-all deny.`,
    0,
  );

  const terminal: CatchAllDenyRule = {
    kind: 'catch-all-deny',
    order: bypassRules.length,
    name: `${ctx.prefix} allowlist deny (catch-all)`,
    description:
      ctx.hostname === undefined
        ? 'Denies every request not matched by the preceding allowlist bypass rules. Must be ordered last.'
        : `Denies every request to ${ctx.hostname} not matched by the preceding allowlist bypass rules. Must be ordered last.`,
    active: true,
    action: 'deny',
    groups: [{ ipChunks: [] }],
    ...hostPart(ctx.hostname),
  };

  ctx.warnings.push({ code: 'BYPASS_SKIPS_MANAGED_RULESETS', message: BYPASS_ESCALATION_WARNING });
  ctx.warnings.push({ code: 'RULE_ORDER_IS_LOAD_BEARING', message: ORDER_WARNING });

  return finalize(ctx, 'bypass-then-deny', [...bypassRules, terminal]);
}

/**
 * Plan the WAF rules for an intent over a CIDR set.
 *
 * Runs lossless aggregation first (so `stats.afterAggregation` is what actually
 * gets packed), sorts canonically for byte-stable output, dispatches on intent,
 * then checks the plan against the project's custom-rule budget. Returns a
 * {@link Refusal} rather than throwing for anything the operator can fix, and
 * throws {@link PlanInvariantError} only when the planner itself is wrong.
 */
export function decompose(opts: DecomposeOptions): DecomposeResult {
  const prefix = opts.ruleNamePrefix.trim();
  if (prefix === '') {
    return refuse(
      'INVALID_RULE_NAME_PREFIX',
      'ruleNamePrefix is empty. Generated rule names are how the executor finds the rules it owns, so they cannot be anonymous.',
      'Pass a stable, human-recognizable prefix such as "vendor-ips".',
    );
  }

  if (opts.cidrs.length === 0) {
    return refuse(
      'EMPTY_INPUT',
      'No CIDR entries were supplied.',
      'Supply at least one address or CIDR. An empty allowlist would compile to a deny with no conditions, which matches every request and takes the entire site offline.',
    );
  }

  const aggregated = canonicalSort(aggregateCidrs([...opts.cidrs]));
  if (aggregated.length === 0) {
    return refuse(
      'EMPTY_INPUT',
      'Aggregation produced no CIDR entries.',
      'Supply at least one address or CIDR. Emitting a rule with no conditions would match every request.',
    );
  }

  const warnings: PlanWarning[] = [];
  if (aggregated.length !== opts.cidrs.length) {
    warnings.push({
      code: 'AGGREGATION_CHANGED_INPUT',
      message: `Aggregation reduced ${opts.cidrs.length} input ${plural(opts.cidrs.length)} to ${aggregated.length} ${plural(aggregated.length)} covering the same addresses (overlapping, duplicate, or contiguous blocks were merged).`,
    });
  }

  if (opts.intent.kind === 'allowlist') {
    const versions = new Set(aggregated.map((cidr) => cidr.version));
    const only = aggregated[0];
    if (versions.size === 1 && only !== undefined) {
      const other = only.version === 4 ? 6 : 4;
      warnings.push({
        code: 'ALLOWLIST_COVERS_SINGLE_IP_VERSION',
        message: `Every entry is IPv${only.version}, so all IPv${other} traffic will be denied. That is usually intended, but dual-stack clients can pick IPv${other} without telling anyone — add the IPv${other} equivalents if the listed hosts have them.`,
      });
    }
  }

  const tier = opts.tier ?? 'pro';
  const ctx: PlanContext = {
    prefix,
    aggregated,
    inputCount: opts.cidrs.length,
    warnings,
    tier,
    ruleLimit: customRuleLimit(tier, opts.tierRuleOverride),
    ...hostPart(opts.hostname),
  };

  switch (opts.intent.kind) {
    case 'allowlist':
      return planAllowlist(ctx, opts.allowBypassEscalation === true);
    case 'blocklist':
      return planPositive(ctx, 'deny');
    case 'bypass':
      return planPositive(ctx, 'bypass');
  }
}
