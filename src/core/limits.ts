/**
 * Vercel WAF platform limits and the packing ceilings they imply.
 *
 * Every constant here is **server-enforced**: exceeding one produces a 400 from
 * the firewall config endpoint, not a degraded-but-working rule. They are
 * centralized (rather than inlined at each use site) because the decomposition
 * math is entirely derived from them — a single wrong number silently changes
 * how many rules a customer's list is split into.
 *
 * There are deliberately no runtime dependencies and no I/O: the planner must
 * be able to reason about limits offline, before any credential is loaded.
 */

/**
 * Maximum number of entries in a single array-valued condition `value`.
 * Server-enforced.
 */
export const MAX_VALUES_PER_CONDITION = 75;

/**
 * Maximum number of conditions inside one condition group.
 * Server-enforced.
 *
 * Conditions within a group are ANDed (the runtime does `every` over the
 * compiled route's match entries), so this bounds how deep an AND chain can be.
 */
export const MAX_CONDITIONS_PER_GROUP = 65;

/**
 * Maximum number of condition groups inside one custom rule.
 * Server-enforced.
 *
 * Groups within a rule are ORed (each group compiles to its own route), so this
 * bounds how wide an OR fan-out can be.
 */
export const MAX_GROUPS_PER_RULE = 25;

/** Maximum length of a custom rule `name`. Server-enforced. */
export const MAX_RULE_NAME_LEN = 160;

/** Maximum length of a custom rule `description`. Server-enforced. */
export const MAX_RULE_DESCRIPTION_LEN = 256;

/**
 * Billing plan tier, which determines how many custom rules a project may hold.
 *
 * Modelled as a literal union so that every switch over tiers is exhaustive and
 * a new tier cannot be added without the compiler pointing at each call site.
 */
export type PlanTier = 'hobby' | 'pro' | 'enterprise';

/**
 * Default custom-rule budget per project, by plan tier.
 *
 * Enterprise is a *default*, not a hard cap: it is overridable per team, which
 * is why {@link customRuleLimit} accepts an explicit override.
 */
const CUSTOM_RULE_LIMITS: Readonly<Record<PlanTier, number>> = {
  hobby: 3,
  pro: 40,
  enterprise: 1000,
};

/**
 * How many custom firewall rules the project may hold.
 *
 * `override` wins for every tier when supplied, because the authoritative value
 * lives on the team record and a caller that has already read it should not have
 * its answer second-guessed by a hardcoded default. Pass it through verbatim;
 * do not try to `Math.min` it with the tier default, because Enterprise teams
 * are routinely raised *above* 1000.
 */
export function customRuleLimit(tier: PlanTier, override?: number): number {
  return override ?? CUSTOM_RULE_LIMITS[tier];
}

/**
 * Maximum CIDR entries an **allowlist** rule can hold: 65 × 75 = 4875.
 *
 * Arithmetic: an allowlist is negative matching ("deny everything except these
 * addresses"), which means the per-chunk conditions must AND together. AND only
 * happens *within* one condition group, so an allowlist gets exactly ONE group
 * and must therefore fit inside
 * `MAX_CONDITIONS_PER_GROUP × MAX_VALUES_PER_CONDITION`.
 *
 * The 25-group budget is unusable here: adding a second group ORs, and
 * `NOT in A` OR `NOT in B` is true for every address that is not in *both*
 * chunks — i.e. it denies everything. See the extended note in `decompose.ts`.
 */
export const ALLOWLIST_MAX_PER_RULE = MAX_CONDITIONS_PER_GROUP * MAX_VALUES_PER_CONDITION;

/**
 * Maximum CIDR entries a **positive-matching** rule can hold: 25 × 75 = 1875.
 *
 * Arithmetic: blocklist and bypass are positive matching ("act on these
 * addresses"), so OR is exactly the semantics we want and the full group budget
 * is available — `MAX_GROUPS_PER_RULE × MAX_VALUES_PER_CONDITION`, one
 * `ip_address` condition per group.
 *
 * Packing more values into extra conditions *within* a group would AND, and an
 * address cannot be in two disjoint chunks at once, so that group would never
 * match. One condition per group is the only correct packing here.
 */
export const POSITIVE_MATCH_MAX_PER_RULE = MAX_GROUPS_PER_RULE * MAX_VALUES_PER_CONDITION;

/**
 * Allowlist ceiling adjusted for the non-IP conditions that share the group.
 *
 * ## Why any scoping condition costs an entry slot
 *
 * An allowlist lives in exactly ONE condition group (see
 * {@link ALLOWLIST_MAX_PER_RULE}), and every scoping condition has to sit
 * *inside* that same group so it ANDs with the negated IP conditions. Putting it
 * in a sibling group would OR instead, which does not scope anything. So each
 * scoping condition permanently occupies one of the 65 slots that would
 * otherwise hold 75 CIDR entries, and the ceiling drops by exactly 75 per
 * condition:
 *
 * | extra conditions       | ceiling |
 * | ---------------------- | ------- |
 * | 0 (unscoped)           | 4875    |
 * | 1 (`host` OR `environment`) | 4800 |
 * | 2 (`host` AND `environment`) | 4725 |
 *
 * `environment` costs a slot for exactly the same structural reason `host` does:
 * it is emitted as `{ type: 'environment', op: 'eq', value: 'preview' }` — an
 * ordinary condition, with no privileged position in the group. The staged
 * rollout ladder in `phase.ts` adds one during its `preview-deny` stage, which
 * is why an allowlist that fits at 4875 can stop fitting purely by being
 * promoted to the next phase.
 *
 * This is not a cosmetic detail: at exactly 4875 entries plus one scoping
 * condition the rule would carry 66 conditions and be rejected by the server, so
 * the planner has to escalate one chunk earlier than the unscoped ceiling
 * suggests.
 *
 * @param extraConditionsPerGroup Non-IP conditions sharing the allowlist group.
 * @throws {RangeError} if the count is not an integer in `[0, 65)`. A negative
 * count would inflate the ceiling above what the server accepts, and a count at
 * or above the per-group limit would produce a zero-or-negative ceiling that
 * silently refuses every possible list — both are caller bugs worth failing on
 * rather than quietly encoding into the arithmetic.
 */
export function allowlistMaxPerRule(extraConditionsPerGroup: number): number;
/**
 * Legacy boolean form, kept so existing call sites and tests that ask only about
 * a `host` condition continue to compile and mean the same thing.
 *
 * @deprecated Pass the number of extra conditions instead; `host` is no longer
 * the only condition that shares the allowlist group.
 */
export function allowlistMaxPerRule(hasHostCondition: boolean): number;
export function allowlistMaxPerRule(extra: number | boolean): number {
  const extraConditions = typeof extra === 'boolean' ? (extra ? 1 : 0) : extra;

  if (!Number.isInteger(extraConditions)) {
    throw new RangeError(
      `allowlistMaxPerRule: extraConditionsPerGroup must be an integer, received ${String(extraConditions)}.`,
    );
  }
  if (extraConditions < 0 || extraConditions >= MAX_CONDITIONS_PER_GROUP) {
    throw new RangeError(
      `allowlistMaxPerRule: extraConditionsPerGroup must be in [0, ${MAX_CONDITIONS_PER_GROUP}), received ${extraConditions}. ` +
        'Outside that range the ceiling is either larger than the server accepts or zero-or-negative, which would refuse every list.',
    );
  }

  return (MAX_CONDITIONS_PER_GROUP - extraConditions) * MAX_VALUES_PER_CONDITION;
}
