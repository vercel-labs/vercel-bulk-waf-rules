/**
 * The ownership marker: a machine-readable token embedded in a rule's
 * `description` that says "this rule belongs to import set X, in role R, at
 * position i of n, and its content hashed to h".
 *
 * ## Why `description` and not `name`
 *
 * The tool this replaces identified the rules it owned by matching a name
 * prefix (`"IP Allowlist - Auto-managed"`, plus a `" (Part N/M)"` suffix). That
 * fails for a reason that has nothing to do with string matching: `name` is the
 * field a human sees in the dashboard rule list, so it is the field a human
 * edits. Renaming a rule to "Vendor IPs (do not delete)" is a completely
 * reasonable thing for a customer to do, and it silently severed the old tool's
 * only link to the rule. The next run then created a duplicate set alongside the
 * orphan, and the orphan kept enforcing.
 *
 * `description` is the right carrier because of three verified platform
 * properties:
 *
 * 1. It round-trips **verbatim** through PATCH and through the CLI. Nothing
 *    trims, normalizes, or truncates it; the API rejects a description over
 *    {@link MAX_RULE_DESCRIPTION_LEN} rather than silently cutting it, so a
 *    marker either survives intact or the write fails loudly.
 * 2. It is **never compiled into routes**. The description is management-plane
 *    metadata only, so embedding a token here has exactly zero effect on traffic
 *    matching. Encoding ownership into a condition, by contrast, would change
 *    what the rule does.
 * 3. It is far less likely to be hand-edited than `name`, and when it *is*
 *    edited we degrade gracefully: {@link decodeMarker} returns `null` and the
 *    reconciler falls back to its next ownership signal rather than crashing.
 *
 * The marker is nonetheless a *recovery* path, not the primary handle. The
 * server-assigned rule id recorded in the manifest is authoritative; the marker
 * is what lets us re-find a rule after the manifest is lost or the rule is
 * renamed. See the ownership precedence note in `reconcile.ts`.
 *
 * ## Format
 *
 *     [vbwr:1 set=<setId> role=bypass i=3/12 h=<hex> src=<source>]
 *
 * The delimiter set is `[`, `]`, `=`, and space. Every value-bearing field is
 * constrained to {@link SAFE_VALUE_PATTERN}, which excludes all four, so the
 * grammar is unambiguous by construction rather than by careful quoting.
 * {@link encodeMarker} enforces that on the way out — it throws rather than
 * emitting a marker that its own decoder could not read back, because a
 * self-corrupting marker would produce an unrecoverable orphan.
 */

import { MAX_RULE_DESCRIPTION_LEN } from '../core/limits.js';
import { stableStringify } from '../core/rule-builder.js';

/** Marker grammar version. Bumping this is a breaking change for decode. */
export const MARKER_VERSION = 1;

/** Sentinel that opens every marker. Namespaced to this tool. */
export const MARKER_SENTINEL = 'vbwr';

/**
 * What a rule does within its set.
 *
 * - `allow` — the negated single-rule allowlist (deny everything except).
 * - `bypass` — a positive-matching bypass rule.
 * - `block` — a positive-matching deny rule (blocklist).
 * - `deny` — the terminal catch-all deny of the `bypass-then-deny` topology.
 *
 * `block` and `deny` are deliberately distinct: they carry the same mitigation
 * but occupy structurally different slots, and conflating them would let the
 * reconciler match a blocklist rule against a catch-all and rewrite one into the
 * other in place.
 */
export type MarkerRole = 'allow' | 'bypass' | 'deny' | 'block';

const MARKER_ROLES: readonly MarkerRole[] = ['allow', 'bypass', 'deny', 'block'];

/** The parsed contents of a marker. */
export interface Marker {
  readonly version: 1;
  /** Import-set identifier. Stable across runs; see `newSetId` in `manifest.ts`. */
  readonly setId: string;
  readonly role: MarkerRole;
  /** 1-based position within the rules sharing this role. */
  readonly index: number;
  /** How many rules share this role in the same set. */
  readonly total: number;
  /**
   * Short content hash (see `shortHash` in `hash.ts`), not the full digest.
   *
   * Truncated because the marker competes with human prose for a 256-character
   * budget, and its job here is only to let a human eyeball "did this rule's
   * content change". The manifest carries the full digest and the reconciler
   * compares that; nothing load-bearing depends on the short form.
   */
  readonly contentHash: string;
  /** Where the input list came from, e.g. `cloudflare`. Free-form but constrained. */
  readonly source?: string;
}

/**
 * Characters permitted in `setId` and `source`.
 *
 * URL-safe unreserved characters only. Excludes every delimiter the grammar uses
 * (`[`, `]`, `=`, whitespace), which is what makes the format unambiguous.
 */
export const SAFE_VALUE_PATTERN = /^[A-Za-z0-9._~-]+$/;

/** A short hex digest as embedded in the marker. */
const HASH_PATTERN = /^[0-9a-f]{4,64}$/;

/**
 * Strict marker grammar, used for decoding.
 *
 * Every value class excludes the delimiters, so a match cannot run past the
 * closing bracket or swallow a neighbouring field.
 */
const MARKER_STRICT = new RegExp(
  String.raw`\[${MARKER_SENTINEL}:(\d+) ` +
    String.raw`set=([^\s\[\]=]+) ` +
    String.raw`role=([^\s\[\]=]+) ` +
    String.raw`i=(\d+)/(\d+) ` +
    String.raw`h=([^\s\[\]=]+)` +
    String.raw`(?: src=([^\s\[\]=]+))?\]`,
  'g',
);

/**
 * Permissive marker shape, used for stripping.
 *
 * Deliberately looser than {@link MARKER_STRICT}: it matches anything that opens
 * with our sentinel and closes before the next bracket, so a hand-mangled marker
 * is still removed from the human text. If stripping only recognized *valid*
 * markers, a corrupted one would stay embedded in the prose forever — it would
 * be hashed as content, and every subsequent run would rewrite the rule to add a
 * second, valid marker beside the broken one.
 */
const MARKER_LOOSE = new RegExp(String.raw`\[${MARKER_SENTINEL}:[^\[\]]*\]`, 'g');

/** Separator between human prose and the marker. */
const MARKER_SEPARATOR = ' ';

/** Appended when prose has to be cut to fit the description budget. */
const TRUNCATION_INDICATOR = '\u2026';

/**
 * Thrown when a marker cannot be encoded without corrupting its own grammar.
 *
 * An encode failure is a programmer error, not a user error: every field either
 * comes from a literal union or is generated by this package. Emitting a marker
 * that {@link decodeMarker} would reject means creating a rule we can never
 * re-identify, so this throws rather than returning a fallback.
 */
export class MarkerFormatError extends Error {
  readonly field: string;

  constructor(field: string, detail: string) {
    super(`Cannot encode WAF rule marker: field ${JSON.stringify(field)} ${detail}`);
    this.name = 'MarkerFormatError';
    this.field = field;
  }
}

function assertSafeValue(field: string, value: string): void {
  if (value === '') {
    throw new MarkerFormatError(field, 'is empty');
  }
  if (!SAFE_VALUE_PATTERN.test(value)) {
    throw new MarkerFormatError(
      field,
      `contains characters outside [A-Za-z0-9._~-] (${JSON.stringify(value)}); ` +
        'that could introduce a delimiter and make the marker undecodable',
    );
  }
}

function assertPositiveInt(field: string, value: number): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new MarkerFormatError(field, `must be an integer >= 1, got ${String(value)}`);
  }
}

/**
 * Render a marker as its wire form.
 *
 * @throws {MarkerFormatError} if any value would corrupt the grammar, if the
 * index/total pair is incoherent, or if the version is not
 * {@link MARKER_VERSION}.
 */
export function encodeMarker(m: Marker): string {
  if (m.version !== MARKER_VERSION) {
    throw new MarkerFormatError('version', `must be ${MARKER_VERSION}, got ${String(m.version)}`);
  }
  assertSafeValue('setId', m.setId);
  if (!MARKER_ROLES.includes(m.role)) {
    throw new MarkerFormatError('role', `is not a known role (${JSON.stringify(m.role)})`);
  }
  assertPositiveInt('index', m.index);
  assertPositiveInt('total', m.total);
  if (m.index > m.total) {
    throw new MarkerFormatError('index', `is ${m.index} of ${m.total}`);
  }
  if (!HASH_PATTERN.test(m.contentHash)) {
    throw new MarkerFormatError(
      'contentHash',
      `must be 4-64 lowercase hex characters, got ${JSON.stringify(m.contentHash)}`,
    );
  }
  if (m.source !== undefined) {
    assertSafeValue('source', m.source);
  }

  const src = m.source === undefined ? '' : ` src=${m.source}`;
  return (
    `[${MARKER_SENTINEL}:${m.version} set=${m.setId} role=${m.role} ` +
    `i=${m.index}/${m.total} h=${m.contentHash}${src}]`
  );
}

function toMarker(match: RegExpExecArray): Marker | null {
  const [, rawVersion, setId, rawRole, rawIndex, rawTotal, contentHash, source] = match;
  if (
    rawVersion === undefined ||
    setId === undefined ||
    rawRole === undefined ||
    rawIndex === undefined ||
    rawTotal === undefined ||
    contentHash === undefined
  ) {
    return null;
  }

  if (Number(rawVersion) !== MARKER_VERSION) return null;

  const role = MARKER_ROLES.find((candidate) => candidate === rawRole);
  if (role === undefined) return null;

  const index = Number(rawIndex);
  const total = Number(rawTotal);
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(total)) return null;
  if (index < 1 || total < 1 || index > total) return null;

  if (!SAFE_VALUE_PATTERN.test(setId)) return null;
  if (!HASH_PATTERN.test(contentHash)) return null;
  if (source !== undefined && !SAFE_VALUE_PATTERN.test(source)) return null;

  return {
    version: MARKER_VERSION,
    setId,
    role,
    index,
    total,
    contentHash,
    ...(source === undefined ? {} : { source }),
  };
}

/**
 * Extract the marker from a description, or `null` if there is not exactly one
 * unambiguous marker.
 *
 * Tolerant on purpose: this runs over **every** rule in a customer's firewall,
 * including rules we have never touched, so "no marker", "someone else's
 * bracket soup", and "our marker with a mangled field" all have to be ordinary
 * `null` returns rather than exceptions.
 *
 * Multiple markers are resolved conservatively. Byte-identical duplicates (the
 * shape a copy-paste in the dashboard produces) decode to that marker, because
 * the ownership claim is unambiguous. Two *different* markers decode to `null`:
 * we cannot tell which set owns the rule, and guessing risks rewriting a rule
 * that belongs to another import set. Losing a rule to the `foreign` list is
 * visible and recoverable; adopting someone else's rule is not.
 */
export function decodeMarker(description: string): Marker | null {
  MARKER_STRICT.lastIndex = 0;
  const found: Marker[] = [];

  let match = MARKER_STRICT.exec(description);
  while (match !== null) {
    const parsed = toMarker(match);
    if (parsed !== null) found.push(parsed);
    match = MARKER_STRICT.exec(description);
  }

  const first = found[0];
  if (first === undefined) return null;

  const canonical = stableStringify(first);
  for (const other of found.slice(1)) {
    if (stableStringify(other) !== canonical) return null;
  }
  return first;
}

/**
 * Return the human-readable part of a description, with any marker removed.
 *
 * This is the inverse of {@link withMarker} and the function that breaks the
 * hash/marker circularity — see `hashRuleContent` in `hash.ts`. It strips
 * loosely (see {@link MARKER_LOOSE}) so that a corrupted marker does not leak
 * into the hashed content.
 */
export function stripMarker(description: string): string {
  MARKER_LOOSE.lastIndex = 0;
  return description.replace(MARKER_LOOSE, '').trim();
}

/**
 * Cut `text` to at most `max` UTF-16 code units without splitting a surrogate
 * pair.
 *
 * Code units rather than code points because the server's length limit is
 * enforced the same way, and a lone surrogate would be an ill-formed string that
 * some JSON encoders replace with U+FFFD — which would change the description on
 * round-trip and make the content hash unstable.
 */
function truncateToLength(text: string, max: number): string {
  if (text.length <= max) return text;
  if (max <= 0) return '';
  if (max <= TRUNCATION_INDICATOR.length) return TRUNCATION_INDICATOR.slice(0, max);

  let end = max - TRUNCATION_INDICATOR.length;
  const lastKept = text.charCodeAt(end - 1);
  // A high surrogate at the cut boundary would be orphaned; drop it.
  if (lastKept >= 0xd800 && lastKept <= 0xdbff) end -= 1;
  return `${text.slice(0, end)}${TRUNCATION_INDICATOR}`;
}

/** Outcome of fitting prose alongside a marker. */
export interface FittedHumanText {
  readonly text: string;
  readonly truncated: boolean;
}

/**
 * Reduce `humanText` so that it plus `m`'s wire form fits the description
 * budget.
 *
 * Exposed separately from {@link withMarker} because the caller has to know the
 * *final* prose before it can compute the content hash that goes into the
 * marker. Encoding a placeholder hash of the same width gives an exact length,
 * so this can be called before the real hash exists. See the pipeline note in
 * `reconcile.ts`.
 *
 * @throws {MarkerFormatError} if the marker alone exceeds the budget, which
 * means no prose could rescue it.
 */
export function fitHumanText(humanText: string, m: Marker): FittedHumanText {
  const encoded = encodeMarker(m);
  if (encoded.length > MAX_RULE_DESCRIPTION_LEN) {
    throw new MarkerFormatError(
      'setId',
      `produces a ${encoded.length}-character marker, over the ` +
        `${MAX_RULE_DESCRIPTION_LEN}-character description budget; shorten setId or source`,
    );
  }

  const prose = stripMarker(humanText);
  const available = MAX_RULE_DESCRIPTION_LEN - encoded.length - MARKER_SEPARATOR.length;
  if (available <= 0) return { text: '', truncated: prose !== '' };
  if (prose.length <= available) return { text: prose, truncated: false };
  return { text: truncateToLength(prose, available), truncated: true };
}

/**
 * Compose a description from human prose and a marker.
 *
 * The prose yields, never the marker. If the two together exceed
 * {@link MAX_RULE_DESCRIPTION_LEN} the prose is truncated (with a trailing
 * ellipsis to make the cut visible) and the marker is emitted in full. That
 * priority is not a style choice: the marker is how the next run finds this
 * rule, so a truncated marker orphans it, whereas truncated prose costs a reader
 * a few words.
 *
 * Any marker already present in `humanText` is stripped first, so the result
 * always contains exactly one marker and `decodeMarker(withMarker(t, m))`
 * round-trips.
 */
export function withMarker(humanText: string, m: Marker): string {
  const fitted = fitHumanText(humanText, m);
  const encoded = encodeMarker(m);
  return fitted.text === '' ? encoded : `${fitted.text}${MARKER_SEPARATOR}${encoded}`;
}
