/**
 * Reconciliation: diff a desired {@link RulePlan} against the rules that already
 * exist in a project, and emit the smallest set of operations that closes the
 * gap.
 *
 * ## Why this diffs instead of deleting and recreating
 *
 * The tool this replaces deleted every rule whose name matched its prefix and
 * recreated the whole set on any change. That is wrong for a reason that has
 * nothing to do with efficiency: a recreated rule gets a **new server-assigned
 * `rule_id`**. Customer dashboards, alerts, and `vc metrics --group-by
 * waf_rule_id` are all keyed on that id, so every churn silently broke
 * continuity of the customer's own observability. It also opened a window in
 * which the allowlist had been deleted but not yet recreated.
 *
 * So the contract here is: if a rule's content is unchanged, do nothing; if it
 * changed, `update` it in place so the id survives; only `delete` a rule we own
 * that the plan no longer has a slot for.
 *
 * ## Ownership precedence
 *
 * Resolved in strict order, most authoritative first. The order matters because a
 * later signal must never override an earlier one — that is how a rule ends up
 * matched twice, or how a foreign rule gets adopted.
 *
 * 1. **Manifest `id`.** The server-assigned id recorded on a previous apply.
 *    Authoritative: it is immune to renames and to description edits.
 * 2. **Marker `setId`.** Recovery path. Covers "the manifest was lost" (never
 *    committed, wrong branch, fresh CI checkout) and "a human renamed the rule in
 *    the dashboard". See `marker.ts` for why the marker lives in `description`.
 * 3. **Legacy name prefix.** Compatibility only, for rules created by the old
 *    bash tool, which had no marker to leave behind. Matches are reported with
 *    `adopted: true` so the caller can say "adopting N pre-existing unmanaged
 *    rules" out loud — silently taking over rules by name is exactly the
 *    behaviour that produced orphans in the first place, and an operator should
 *    see it happen once.
 *
 * Anything not matched by one of those three is **foreign** and is never
 * modified, reordered, or deleted. There is no fourth heuristic; adding one is
 * how this tool starts deleting a customer's hand-written rules.
 *
 * ## The bypass-before-deny invariant
 *
 * For the `bypass-then-deny` topology the emitted ordering is not cosmetic. Every
 * bypass rule must sit before the terminal catch-all deny. The catch-all matches
 * *every* request, so if it is evaluated first the request is denied and the
 * bypass that would have rescued it never gets a chance. Getting this backwards
 * does not degrade the allowlist — it takes the entire site (or hostname) offline.
 *
 * The invariant is checked on the way out and throws
 * {@link ReconcileInvariantError} if it cannot be satisfied, because emitting an
 * unsafe plan is worse than refusing to emit one.
 *
 * ## No locking, deliberately
 *
 * The platform exposes no client-facing ETag/If-Match on the firewall config, so
 * concurrent writers cannot be detected from here. Do not add a lock, lease, or
 * retry loop. The agreed mitigations are exactly two: this differ (so a
 * concurrent change is narrowed rather than blown away) and aborting when a
 * foreign draft exists, which already lives in `exec/draft-guard.ts`.
 */

import type { PlannedRule, RulePlan } from '../core/decompose.js';
import type { FirewallCondition as RemoteCondition, FirewallRule } from '../exec/firewall.js';
import type {
  FirewallCondition,
  FirewallConditionGroup,
  FirewallRuleInput,
  MitigateAction,
} from '../core/rule-builder.js';
import { buildRuleJson, normalizeLegacyIpOp } from '../core/rule-builder.js';
import { hashRuleContent, placeholderShortHash, shortHash } from './hash.js';
import type { Manifest } from './manifest.js';
import type { Marker, MarkerRole } from './marker.js';
import { decodeMarker, fitHumanText, withMarker } from './marker.js';

/**
 * The minimal shape of a rule that already exists in the project.
 *
 * Aliased to the CLI wrapper's own `FirewallRule` rather than redeclared, so a
 * CLI schema change surfaces as a compile error here instead of as a silent
 * mismatch in the differ.
 */
export type RemoteRule = FirewallRule;

/** Why a rule is being updated rather than left alone. */
export type UpdateReason = 'content-changed' | 'adopting';

/** Why a rule we own is being removed. */
export type DeleteReason = 'surplus' | 'role-removed';

export interface RuleUpdate {
  readonly remoteId: string;
  readonly rule: PlannedRule;
  readonly reason: UpdateReason;
  /** True when ownership came from the legacy name-prefix fallback. */
  readonly adopted: boolean;
  /** Description to persist, including the marker. */
  readonly description: string;
  readonly contentHash: string;
}

export interface RuleDeletion {
  readonly remoteId: string;
  readonly name: string;
  readonly reason: DeleteReason;
}

export interface RuleCreation {
  readonly rule: PlannedRule;
  readonly description: string;
  readonly contentHash: string;
}

export interface RuleUnchanged {
  readonly remoteId: string;
  readonly contentHash: string;
}

export interface RuleReorder {
  readonly remoteId: string;
  /**
   * Target 0-based index in the intended final rule array, matching
   * {@link PlannedRule.order} semantics.
   *
   * The CLI's `rules reorder --position` is **1-based**, so an executor must add
   * one. Entries are emitted in ascending `targetPosition` and must be applied in
   * that order.
   */
  readonly targetPosition: number;
}

export interface ForeignRule {
  readonly id: string;
  readonly name: string;
}

export interface Reconciliation {
  readonly create: readonly RuleCreation[];
  readonly update: readonly RuleUpdate[];
  readonly delete: readonly RuleDeletion[];
  readonly unchanged: readonly RuleUnchanged[];
  readonly reorder: readonly RuleReorder[];
  readonly foreign: readonly ForeignRule[];
  readonly warnings: readonly string[];
}

/** Extra context the plan itself cannot carry. */
export interface ReconcileOptions {
  /**
   * Import-set id to claim.
   *
   * Only consulted when `manifest` is `null`. When neither is available the
   * reconciler tries to recover a single unambiguous `setId` from the markers
   * present on the remote rules, which is what makes "manifest lost entirely"
   * survivable with no extra caller wiring.
   */
  readonly setId?: string;
  /**
   * Rule-name prefixes written by the old bash tool, for the legacy adoption
   * path. Empty by default: adopting by name is opt-in, because a prefix is a
   * guess and the cost of guessing wrong is editing a customer's rule.
   */
  readonly legacyNamePrefixes?: readonly string[];
  /** Provenance tag embedded in the marker, e.g. `cloudflare`. */
  readonly source?: string;
}

/**
 * Thrown when the reconciler cannot emit a safe result.
 *
 * Separate from a warning because the only correct response is to stop. In
 * particular an ordering violation on a `bypass-then-deny` plan means the
 * operations, if applied, would deny all traffic.
 */
export class ReconcileInvariantError extends Error {
  readonly invariant: string;

  constructor(invariant: string, detail: string) {
    super(`WAF reconciliation invariant violated (${invariant}): ${detail}`);
    this.name = 'ReconcileInvariantError';
    this.invariant = invariant;
  }
}

/**
 * Map a planned rule to its marker role.
 *
 * `catch-all-deny` maps to `deny` and a positive deny maps to `block` so the two
 * stay distinguishable: they carry the same mitigation but occupy structurally
 * different slots, and matching one against the other would rewrite a blocklist
 * rule into a catch-all in place.
 */
function roleOf(rule: PlannedRule): MarkerRole {
  switch (rule.kind) {
    case 'negated-allowlist':
      return 'allow';
    case 'catch-all-deny':
      return 'deny';
    case 'positive-match':
      return rule.action === 'bypass' ? 'bypass' : 'block';
  }
}

/** A desired rule with its identity, final description, and content hash resolved. */
interface DesiredRule {
  readonly rule: PlannedRule;
  readonly role: MarkerRole;
  readonly index: number;
  readonly total: number;
  readonly contentHash: string;
  readonly description: string;
  readonly slotKey: string;
}

function slotKey(role: MarkerRole, index: number): string {
  return `${role}#${index}`;
}

/**
 * Resolve a planned rule's hash and final description in the one order that is
 * self-consistent.
 *
 * The circular dependency is: description contains the marker, the marker
 * contains the content hash, the content hash is computed over the description.
 * It is broken in three steps.
 *
 * 1. Fit the prose against a marker built with a **placeholder** hash. A marker's
 *    wire length depends on the hash's width, not its value, so the placeholder
 *    yields exactly the prose that will be persisted.
 * 2. Hash the rule carrying that already-fitted prose. `hashRuleContent` strips
 *    markers, so this is the same digest the rule will produce when read back
 *    from the API with its marker attached.
 * 3. Attach the real marker. It is the same width as the placeholder, so no
 *    further truncation happens and step 2 stays valid.
 *
 * Skipping step 1 is the subtle bug: hashing untruncated prose and then
 * persisting truncated prose makes every subsequent run see a changed hash and
 * rewrite the rule forever.
 */
function resolveDesired(
  rule: PlannedRule,
  setId: string,
  index: number,
  total: number,
  source: string | undefined,
): DesiredRule {
  const built = buildRuleJson(rule);
  const role = roleOf(rule);
  const markerShape = (contentHash: string): Marker => ({
    version: 1,
    setId,
    role,
    index,
    total,
    contentHash,
    ...(source === undefined ? {} : { source }),
  });

  const fitted = fitHumanText(built.description, markerShape(placeholderShortHash()));
  const contentHash = hashRuleContent({ ...built, description: fitted.text });
  const description = withMarker(fitted.text, markerShape(shortHash(contentHash)));

  return { rule, role, index, total, contentHash, description, slotKey: slotKey(role, index) };
}

function resolveDesiredPlan(
  plan: RulePlan,
  setId: string,
  source: string | undefined,
): DesiredRule[] {
  const totals = new Map<MarkerRole, number>();
  for (const rule of plan.rules) {
    const role = roleOf(rule);
    totals.set(role, (totals.get(role) ?? 0) + 1);
  }

  const seen = new Map<MarkerRole, number>();
  return plan.rules.map((rule) => {
    const role = roleOf(rule);
    const index = (seen.get(role) ?? 0) + 1;
    seen.set(role, index);
    return resolveDesired(rule, setId, index, totals.get(role) ?? 1, source);
  });
}

function isStringArray(value: unknown): value is readonly string[] {
  if (!Array.isArray(value)) return false;
  const items: readonly unknown[] = value;
  return items.every((entry) => typeof entry === 'string');
}

const MITIGATE_ACTIONS: readonly MitigateAction[] = [
  'deny',
  'challenge',
  'log',
  'bypass',
  'rate_limit',
  'redirect',
];

/**
 * Project a remote condition onto the closed emit-side union, or `null` if it is
 * a shape this tool never produces.
 *
 * A legacy `ninc` operator is folded into `neg: true` + `inc` via
 * {@link normalizeLegacyIpOp}, and `neg` is omitted when false, so a rule created
 * before that migration hashes identically to the modern form. Without that,
 * every pre-migration rule would look changed and be rewritten.
 */
function normalizeRemoteCondition(condition: RemoteCondition): FirewallCondition | null {
  if (condition.type === 'ip_address') {
    if (condition.op !== 'inc' && condition.op !== 'ninc') return null;
    if (!isStringArray(condition.value)) return null;
    const { neg } = normalizeLegacyIpOp(condition.op, condition.neg);
    return {
      type: 'ip_address',
      op: 'inc',
      value: condition.value,
      ...(neg ? { neg: true } : {}),
    };
  }

  if (condition.type === 'host') {
    if (condition.op !== 'eq' || typeof condition.value !== 'string') return null;
    return { type: 'host', op: 'eq', value: condition.value };
  }

  return null;
}

/**
 * Project a remote rule onto {@link FirewallRuleInput} so it can be hashed with
 * the same function as a desired rule.
 *
 * Returns `null` when the rule carries something this tool cannot express — a
 * rate-limit envelope, a condition type it never emits. That is treated as "not
 * comparable", which the caller turns into an `update`: we own the rule, we
 * cannot prove it matches, so we rewrite it to the desired content. Guessing
 * "unchanged" instead would leave a hand-edited rule enforcing something the
 * plan never asked for.
 */
function toComparableRule(remote: RemoteRule): FirewallRuleInput | null {
  const mitigate = remote.action.mitigate;
  if (mitigate === undefined) return null;

  const action = MITIGATE_ACTIONS.find((candidate) => candidate === mitigate.action);
  if (action === undefined) return null;
  if (mitigate.rateLimit !== undefined && mitigate.rateLimit !== null) return null;
  if (mitigate.redirect !== undefined && mitigate.redirect !== null) return null;
  if (mitigate.actionDuration !== undefined && mitigate.actionDuration !== null) return null;

  const groups: FirewallConditionGroup[] = [];
  for (const group of remote.conditionGroup) {
    const conditions: FirewallCondition[] = [];
    for (const condition of group.conditions) {
      const normalized = normalizeRemoteCondition(condition);
      if (normalized === null) return null;
      conditions.push(normalized);
    }
    groups.push({ conditions });
  }

  return {
    name: remote.name,
    description: remote.description ?? '',
    active: remote.active,
    conditionGroup: groups,
    action: { mitigate: { action } },
  };
}

function hashRemote(remote: RemoteRule): string | null {
  const comparable = toComparableRule(remote);
  return comparable === null ? null : hashRuleContent(comparable);
}

/** How a remote rule came to be recognized as ours. */
type OwnershipVia = 'manifest-id' | 'marker' | 'legacy-name';

interface OwnedRemote {
  readonly remote: RemoteRule;
  readonly position: number;
  readonly via: OwnershipVia;
  readonly marker: Marker | null;
  readonly manifestRole: MarkerRole | null;
  readonly manifestIndex: number | null;
}

/**
 * Recover the import-set id from remote markers when no manifest and no explicit
 * id are available.
 *
 * Only succeeds when exactly one distinct `setId` is present. Two sets means we
 * cannot tell which one this run is continuing, and picking either would adopt
 * the other's rules.
 */
function discoverSetId(remote: readonly RemoteRule[]): string | null {
  const ids = new Set<string>();
  for (const rule of remote) {
    const marker = decodeMarker(rule.description ?? '');
    if (marker !== null) ids.add(marker.setId);
  }
  if (ids.size !== 1) return null;
  const [only] = [...ids];
  return only ?? null;
}

function matchesLegacyPrefix(name: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => prefix !== '' && name.startsWith(prefix));
}

/** One rule's intended absolute slot in the project's final rule array. */
interface Placement {
  readonly role: MarkerRole;
  readonly name: string;
  readonly position: number;
}

/**
 * Assert that every bypass rule precedes the terminal catch-all deny.
 *
 * The runtime backstop for the invariant described in the module docstring. The
 * type system cannot express "this array element comes before that one", so it
 * has to be checked, and it is checked twice on purpose: once over the incoming
 * plan (to catch a misordered plan before we build anything from it) and once
 * over the absolute positions this function is about to emit (to catch an
 * ordering bug introduced by the anchoring arithmetic itself).
 */
function assertBypassBeforeDeny(where: string, placements: readonly Placement[]): void {
  const deny = placements.find((entry) => entry.role === 'deny');
  if (deny === undefined) return;

  for (const entry of placements) {
    if (entry.role === 'bypass' && entry.position > deny.position) {
      throw new ReconcileInvariantError(
        'bypass-precedes-catch-all-deny',
        `in ${where}, bypass rule ${JSON.stringify(entry.name)} lands at position ${entry.position}, ` +
          `after the catch-all deny at position ${deny.position}. The catch-all matches every ` +
          'request, so it would deny traffic the bypass was meant to admit — applying this would ' +
          'take the site offline.',
      );
    }
  }
}

function placementsOf(rules: readonly DesiredRule[], anchor: number): Placement[] {
  return rules.map((entry, index) => ({
    role: entry.role,
    name: entry.rule.name,
    position: anchor + index,
  }));
}

/**
 * Diff a plan against the project's current rules.
 *
 * Pure: performs no I/O and mutates nothing. `manifest` may be `null` for a first
 * apply or a lost-manifest recovery.
 *
 * @throws {ReconcileInvariantError} if the result could not be made safe to
 * apply.
 */
export function reconcile(
  desired: RulePlan,
  remote: readonly RemoteRule[],
  manifest: Manifest | null,
  options?: ReconcileOptions,
): Reconciliation {
  const warnings: string[] = [];
  const legacyPrefixes = options?.legacyNamePrefixes ?? [];

  let setId = manifest?.setId ?? options?.setId;
  if (setId === undefined) {
    const discovered = discoverSetId(remote);
    if (discovered !== null) {
      setId = discovered;
      warnings.push(
        `No manifest was supplied; recovered set id ${JSON.stringify(discovered)} from the ` +
          'markers on existing rules. Commit the regenerated manifest so the next run does not ' +
          'have to guess.',
      );
    }
  }

  if (setId === undefined) {
    throw new ReconcileInvariantError(
      'set-id-required',
      'no manifest, no explicit setId, and no recoverable marker on any existing rule. Every rule ' +
        'this tool writes must carry a set id so the next run can find it; generating one here ' +
        'would make reconciliation non-deterministic. Call newSetId() and pass it as options.setId.',
    );
  }

  const desiredRules = resolveDesiredPlan(desired, setId, options?.source);
  assertBypassBeforeDeny('the supplied plan', placementsOf(desiredRules, 0));

  const byId = new Map<string, { remote: RemoteRule; position: number }>();
  remote.forEach((rule, position) => byId.set(rule.id, { remote: rule, position }));

  const owned = new Map<string, OwnedRemote>();

  const claim = (
    entry: { remote: RemoteRule; position: number },
    via: OwnershipVia,
    marker: Marker | null,
    manifestRole: MarkerRole | null,
    manifestIndex: number | null,
  ): void => {
    if (owned.has(entry.remote.id)) return;
    owned.set(entry.remote.id, {
      remote: entry.remote,
      position: entry.position,
      via,
      marker,
      manifestRole,
      manifestIndex,
    });
  };

  for (const tracked of manifest?.rules ?? []) {
    if (tracked.id === undefined) continue;
    const entry = byId.get(tracked.id);
    if (entry === undefined) {
      warnings.push(
        `Manifest tracks rule id ${JSON.stringify(tracked.id)} (${JSON.stringify(tracked.name)}) ` +
          'but no rule with that id exists in the project — it was probably deleted in the ' +
          'dashboard. It will be recreated, which assigns a new rule_id and breaks continuity for ' +
          'anything keyed on the old one.',
      );
      continue;
    }
    claim(entry, 'manifest-id', decodeMarker(entry.remote.description ?? ''), tracked.role, tracked.index);
  }

  for (const [, entry] of byId) {
    const marker = decodeMarker(entry.remote.description ?? '');
    if (marker !== null && marker.setId === setId) {
      claim(entry, 'marker', marker, null, null);
    }
  }

  for (const [, entry] of byId) {
    if (owned.has(entry.remote.id)) continue;
    if (matchesLegacyPrefix(entry.remote.name, legacyPrefixes)) {
      claim(entry, 'legacy-name', null, null, null);
    }
  }

  const adoptedCount = [...owned.values()].filter((entry) => entry.via === 'legacy-name').length;
  if (adoptedCount > 0) {
    warnings.push(
      `Adopting ${adoptedCount} pre-existing rule${adoptedCount === 1 ? '' : 's'} matched only by ` +
        'legacy name prefix. These were created by the previous bash tool and carry no ownership ' +
        'marker; they will be rewritten in place (preserving their rule_id) and marked so future ' +
        'runs no longer depend on the name.',
    );
  }

  const slotOf = (entry: OwnedRemote): string | null => {
    if (entry.manifestRole !== null && entry.manifestIndex !== null) {
      return slotKey(entry.manifestRole, entry.manifestIndex);
    }
    if (entry.marker !== null) return slotKey(entry.marker.role, entry.marker.index);
    return null;
  };

  const bySlot = new Map<string, OwnedRemote>();
  const unslotted: OwnedRemote[] = [];
  for (const entry of [...owned.values()].sort((a, b) => a.position - b.position)) {
    const key = slotOf(entry);
    if (key === null || bySlot.has(key)) {
      unslotted.push(entry);
      continue;
    }
    bySlot.set(key, entry);
  }

  const create: RuleCreation[] = [];
  const update: RuleUpdate[] = [];
  const unchanged: RuleUnchanged[] = [];
  const consumed = new Set<string>();
  const layout: Array<{ readonly desired: DesiredRule; readonly remoteId: string | null }> = [];

  for (const target of desiredRules) {
    const matched = bySlot.get(target.slotKey) ?? unslotted.shift();

    if (matched === undefined) {
      create.push({
        rule: target.rule,
        description: target.description,
        contentHash: target.contentHash,
      });
      layout.push({ desired: target, remoteId: null });
      continue;
    }

    consumed.add(matched.remote.id);
    layout.push({ desired: target, remoteId: matched.remote.id });

    if (matched.via === 'legacy-name') {
      update.push({
        remoteId: matched.remote.id,
        rule: target.rule,
        reason: 'adopting',
        adopted: true,
        description: target.description,
        contentHash: target.contentHash,
      });
      continue;
    }

    const currentHash = hashRemote(matched.remote);
    if (currentHash === null) {
      warnings.push(
        `Rule ${JSON.stringify(matched.remote.name)} (${matched.remote.id}) contains conditions or ` +
          'an action this tool does not emit, so its content cannot be compared. It will be ' +
          'rewritten to the planned content.',
      );
    }

    if (currentHash === target.contentHash) {
      unchanged.push({ remoteId: matched.remote.id, contentHash: currentHash });
      continue;
    }

    update.push({
      remoteId: matched.remote.id,
      rule: target.rule,
      reason: 'content-changed',
      adopted: false,
      description: target.description,
      contentHash: target.contentHash,
    });
  }

  const desiredRoles = new Set(desiredRules.map((entry) => entry.role));
  const deletions: RuleDeletion[] = [];
  for (const entry of [...owned.values()].sort((a, b) => a.position - b.position)) {
    if (consumed.has(entry.remote.id)) continue;
    const role = entry.marker?.role ?? entry.manifestRole;
    deletions.push({
      remoteId: entry.remote.id,
      name: entry.remote.name,
      reason: role !== null && !desiredRoles.has(role) ? 'role-removed' : 'surplus',
    });
  }

  const foreign: ForeignRule[] = remote
    .filter((rule) => !owned.has(rule.id))
    .map((rule) => ({ id: rule.id, name: rule.name }));

  const anchor = managedBlockAnchor(owned, remote.length);
  assertBypassBeforeDeny(
    'the emitted layout',
    placementsOf(
      layout.map((slot) => slot.desired),
      anchor,
    ),
  );

  const reorder = layout
    .flatMap((slot, planIndex) => {
      if (slot.remoteId === null) return [];
      const current = owned.get(slot.remoteId);
      if (current === undefined || current.position === anchor + planIndex) return [];
      return [{ remoteId: slot.remoteId, targetPosition: anchor + planIndex }];
    })
    .sort((a, b) => a.targetPosition - b.targetPosition);

  return { create, update, delete: deletions, unchanged, reorder, foreign, warnings };
}

/**
 * Where our contiguous block of rules should start.
 *
 * Anchored at the position of the earliest rule we already own, so an existing
 * set stays where the customer put it relative to their own rules; a fresh apply
 * appends after everything foreign. Anchoring rather than forcing index 0 matters
 * because a customer's foreign rule may legitimately need to be evaluated first,
 * and this layer has no way to know that.
 */
function managedBlockAnchor(owned: ReadonlyMap<string, OwnedRemote>, remoteCount: number): number {
  let anchor = remoteCount;
  for (const entry of owned.values()) {
    if (entry.position < anchor) anchor = entry.position;
  }
  return anchor;
}
