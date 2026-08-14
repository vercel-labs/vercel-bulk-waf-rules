/**
 * Content hashing: the mechanism that turns "re-apply the plan" from a rewrite
 * into a no-op.
 *
 * ## Resolving the hash/marker circularity
 *
 * A rule's `description` carries the ownership marker, and that marker embeds the
 * rule's own content hash. Hashing the description as-is would therefore be
 * self-referential: computing the hash needs the marker, producing the marker
 * needs the hash.
 *
 * The cut is to define the hashed content as the rule with its `description`
 * replaced by `stripMarker(description)` — the human-readable remainder. The
 * marker is *derived* metadata, not content, so excluding it loses nothing:
 *
 * - hashing a rule we are about to write (description = prose, no marker yet)
 *   and hashing the same rule read back from the API (description = prose +
 *   marker) produce the same digest, which is precisely the property an
 *   idempotent apply needs;
 * - a human editing the prose *does* change the hash, so a hand-edited
 *   description is correctly detected as drift and reverted;
 * - a corrupted marker is stripped too (`stripMarker` matches loosely), so
 *   bracket damage does not masquerade as a content change forever.
 *
 * The one obligation this places on callers: the prose that goes into the hash
 * must be the prose that ends up persisted. `withMarker` truncates prose to fit
 * the 256-character description budget, so a caller that hashes the *untruncated*
 * prose and then persists the truncated form would see a permanent mismatch and
 * rewrite the rule on every run. Use `fitHumanText` first. `reconcile.ts` does
 * this and documents the ordering.
 */

import { createHash } from 'node:crypto';

import { aggregateCidrs } from '../core/aggregate.js';
import type { Cidr } from '../core/ip.js';
import { cidrToRange, compareRanges, formatCidr } from '../core/ip.js';
import type { FirewallRuleInput } from '../core/rule-builder.js';
import { stableStringify } from '../core/rule-builder.js';
import { stripMarker } from './marker.js';

/** Default width of the abbreviated digest embedded in a marker. */
export const SHORT_HASH_LEN = 12;

/** Narrowest abbreviation accepted, matching the marker grammar's hash field. */
const MIN_SHORT_HASH_LEN = 4;

/** Width of a full sha256 digest in lowercase hex. */
const FULL_HASH_LEN = 64;

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Digest of a rule's semantic content: name, marker-free description, active
 * flag, action, and condition groups.
 *
 * Stable across key ordering (`stableStringify` sorts object keys) and across a
 * write/read round-trip through the API. Sensitive to every field a reviewer
 * would consider part of the rule's behaviour, so any real change shows up as a
 * different digest.
 *
 * See the module docstring for why `description` is stripped before hashing.
 */
export function hashRuleContent(rule: FirewallRuleInput): string {
  return sha256Hex(stableStringify({ ...rule, description: stripMarker(rule.description) }));
}

/**
 * Canonical total order over CIDRs: version, then start address, then prefix
 * length.
 *
 * Duplicated from the private `canonicalSort` in `decompose.ts` rather than
 * imported, because this layer is not allowed to widen that module's exports.
 * The two must stay byte-compatible: if they diverge, `hashInput` would report a
 * changed source list for an unchanged CSV.
 */
function canonicalSort(cidrs: readonly Cidr[]): Cidr[] {
  return [...cidrs].sort((a, b) => {
    const byRange = compareRanges(cidrToRange(a), cidrToRange(b));
    if (byRange !== 0) return byRange;
    return a.prefixLen - b.prefixLen;
  });
}

/**
 * Digest of an input CIDR set, answering "is the source list the same as last
 * run?".
 *
 * Aggregates and canonically sorts first, so the digest is invariant under row
 * order, duplicate rows, and any regrouping that covers the same addresses. That
 * is the right equivalence: two CSVs that describe identical address coverage
 * should not trigger a firewall rewrite just because someone re-sorted the file.
 */
export function hashInput(cidrs: readonly Cidr[]): string {
  return sha256Hex(stableStringify(canonicalSort(aggregateCidrs([...cidrs])).map(formatCidr)));
}

/**
 * Abbreviate a full digest for embedding in a marker.
 *
 * @throws {RangeError} if `len` is outside 4..64 or exceeds the digest's length.
 * A silently-clamped length would produce markers of varying width, and
 * `fitHumanText` relies on marker width being a function of the hash *length*
 * alone to compute truncation before the real hash exists.
 */
export function shortHash(full: string, len: number = SHORT_HASH_LEN): string {
  if (!Number.isInteger(len) || len < MIN_SHORT_HASH_LEN || len > FULL_HASH_LEN) {
    throw new RangeError(
      `shortHash length must be an integer in ${MIN_SHORT_HASH_LEN}..${FULL_HASH_LEN}, got ${String(len)}`,
    );
  }
  if (full.length < len) {
    throw new RangeError(`cannot take ${len} characters from a ${full.length}-character digest`);
  }
  return full.slice(0, len);
}

/**
 * A hash-shaped stand-in of the same width as a real {@link shortHash}.
 *
 * Used to build a marker whose *length* is correct before its content hash is
 * known, which is what makes the "fit prose, then hash, then attach marker"
 * ordering possible. Deliberately all-zero so it is obvious in a debug dump that
 * no real digest reached the wire.
 */
export function placeholderShortHash(len: number = SHORT_HASH_LEN): string {
  if (!Number.isInteger(len) || len < MIN_SHORT_HASH_LEN || len > FULL_HASH_LEN) {
    throw new RangeError(
      `placeholder length must be an integer in ${MIN_SHORT_HASH_LEN}..${FULL_HASH_LEN}, got ${String(len)}`,
    );
  }
  return '0'.repeat(len);
}
