/**
 * CIDR set algebra: merge, dedupe, membership, and cardinality.
 *
 * The overriding constraint for everything in this file is **losslessness**:
 * the output must cover exactly the same set of addresses as the input, never
 * more and never less. Over-aggregating an allowlist silently grants access to
 * addresses the customer never listed; under-aggregating silently locks out
 * addresses they did. Both are incidents, so the property is asserted directly
 * in the test suite rather than left implicit.
 */

import type { Cidr, IpRange, IpVersion } from './ip.js';
import { cidrToRange, compareRanges, rangeToCidrs } from './ip.js';

const VERSIONS: readonly IpVersion[] = [4, 6];

/**
 * Convert CIDRs to a sorted, pairwise-disjoint set of ranges for one version.
 *
 * Two ranges are coalesced when they overlap *or* merely touch
 * (`next.start <= current.end + 1`). Including the adjacency case is what lets
 * 1.0.0.0/25 + 1.0.0.128/25 collapse into 1.0.0.0/24; it is still lossless
 * because contiguous ranges cover exactly the union of their members.
 */
function disjointRangesForVersion(cidrs: readonly Cidr[], version: IpVersion): IpRange[] {
  const ranges = cidrs.filter((c) => c.version === version).map(cidrToRange);
  ranges.sort(compareRanges);

  const merged: IpRange[] = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last !== undefined && range.start <= last.end + 1n) {
      if (range.end > last.end) {
        merged[merged.length - 1] = { version, start: last.start, end: range.end };
      }
      continue;
    }
    merged.push(range);
  }
  return merged;
}

function disjointRanges(cidrs: readonly Cidr[]): IpRange[] {
  return VERSIONS.flatMap((version) => disjointRangesForVersion(cidrs, version));
}

/**
 * Merge overlapping and contiguous CIDRs into the minimal equivalent set.
 *
 * Works by lowering to ranges, coalescing, then re-emitting aligned blocks via
 * `rangeToCidrs`. Going through ranges rather than trying to pair up CIDR
 * siblings directly is what makes the result *minimal* and keeps it lossless:
 * the coalesced range set is exactly the union of the inputs, and
 * `rangeToCidrs` tiles each range exactly.
 *
 * IPv4 and IPv6 are processed independently; output is all v4 blocks (ascending)
 * followed by all v6 blocks (ascending) for stable, diffable rule payloads.
 */
export function aggregateCidrs(inputs: Cidr[]): Cidr[] {
  return VERSIONS.flatMap((version) =>
    disjointRangesForVersion(inputs, version).flatMap(rangeToCidrs),
  );
}

/**
 * Drop exact duplicates and fully-contained subnets, without merging siblings.
 *
 * Deliberately more conservative than {@link aggregateCidrs}: it only ever
 * removes redundant entries, so every block in the output is a block the
 * operator actually wrote. Useful when a reviewer needs to recognize their own
 * list — aggregation can invent prefixes (two /25s becoming a /24) that never
 * appeared in the source CSV.
 */
export function dedupeCidrs(inputs: Cidr[]): Cidr[] {
  const kept: Cidr[] = [];

  for (const version of VERSIONS) {
    const candidates = inputs
      .filter((c) => c.version === version)
      .map((cidr) => ({ cidr, range: cidrToRange(cidr) }))
      .sort((a, b) => {
        if (a.range.start !== b.range.start) return a.range.start < b.range.start ? -1 : 1;
        // Equal start: wider block (shorter prefix) first so it can absorb the rest.
        return a.cidr.prefixLen - b.cidr.prefixLen;
      });

    // CIDR blocks are always nested or disjoint, so a stack of currently-open
    // enclosing blocks is enough to test containment in a single pass.
    const openBlocks: IpRange[] = [];
    for (const candidate of candidates) {
      while (openBlocks.length > 0) {
        const top = openBlocks[openBlocks.length - 1];
        if (top !== undefined && top.end >= candidate.range.start) break;
        openBlocks.pop();
      }
      const enclosing = openBlocks[openBlocks.length - 1];
      if (enclosing !== undefined && candidate.range.end <= enclosing.end) {
        continue;
      }
      openBlocks.push(candidate.range);
      kept.push(candidate.cidr);
    }
  }

  return kept;
}

/**
 * Test whether an address falls inside any of the given CIDRs.
 *
 * Backs the self-lockout safety check ("is the operator's own IP still in the
 * allowlist?"), so correctness matters more than anything. The list is
 * coalesced into disjoint ranges first — binary search over raw input would be
 * wrong whenever a nested subnet sorts after the address inside its parent.
 * An address of the other IP version is simply not a member.
 */
export function containsAddress(
  cidrs: Cidr[],
  addr: { version: IpVersion; value: bigint },
): boolean {
  const ranges = disjointRangesForVersion(cidrs, addr.version);

  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    const range = ranges[mid];
    if (range === undefined) break;
    if (addr.value < range.start) {
      high = mid - 1;
    } else if (addr.value > range.end) {
      low = mid + 1;
    } else {
      return true;
    }
  }
  return false;
}

/**
 * Count the distinct addresses covered by a CIDR set.
 *
 * Counts the *union*, not the sum of block sizes, so overlapping or duplicated
 * input does not inflate the total. That is precisely what makes it usable as
 * the losslessness oracle: `countAddresses(before) === countAddresses(after)`
 * only holds for an aggregation that neither widened nor narrowed coverage.
 */
export function countAddresses(cidrs: Cidr[]): bigint {
  let total = 0n;
  for (const range of disjointRanges(cidrs)) {
    total += range.end - range.start + 1n;
  }
  return total;
}
