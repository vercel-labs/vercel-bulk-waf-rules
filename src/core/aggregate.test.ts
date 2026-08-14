import { describe, expect, it } from 'vitest';

import type { Cidr, IpVersion } from './ip.js';
import { bitWidth, cidrToRange, formatCidr, parseCidr, parseIp } from './ip.js';
import { aggregateCidrs, containsAddress, countAddresses, dedupeCidrs } from './aggregate.js';

function cidrs(...inputs: readonly string[]): Cidr[] {
  return inputs.map((input) => parseCidr(input));
}

function texts(input: readonly Cidr[]): string[] {
  return input.map(formatCidr);
}

function addr(input: string): { version: IpVersion; value: bigint } {
  return parseIp(input);
}

function maxAddress(version: IpVersion): bigint {
  return (1n << BigInt(bitWidth(version))) - 1n;
}

/**
 * Deterministic probe set for the losslessness property: every block's first
 * and last address plus its immediate outside neighbours, which is where an
 * off-by-one in coalescing would show up.
 */
function probeAddresses(input: readonly Cidr[]): Array<{ version: IpVersion; value: bigint }> {
  const probes: Array<{ version: IpVersion; value: bigint }> = [];
  for (const cidr of input) {
    const range = cidrToRange(cidr);
    const limit = maxAddress(cidr.version);
    const candidates = [
      range.start,
      range.end,
      range.start - 1n,
      range.end + 1n,
      range.start + (range.end - range.start) / 2n,
    ];
    for (const value of candidates) {
      if (value >= 0n && value <= limit) {
        probes.push({ version: cidr.version, value });
      }
    }
  }
  return probes;
}

const LOSSLESSNESS_CASES: ReadonlyArray<readonly [string, Cidr[]]> = [
  ['empty set', cidrs()],
  ['single host', cidrs('192.0.2.1')],
  ['mergeable sibling /25s', cidrs('1.0.0.0/25', '1.0.0.128/25')],
  ['non-adjacent /24s', cidrs('1.0.0.0/24', '1.0.2.0/24')],
  ['nested subnets', cidrs('10.0.0.0/8', '10.1.0.0/16', '10.1.2.3/32')],
  ['exact duplicates', cidrs('1.2.3.4', '1.2.3.4', '1.2.3.4/32')],
  ['partial overlap', cidrs('1.0.0.0/24', '1.0.0.128/25', '1.0.1.0/25')],
  ['three adjacent /24s', cidrs('1.0.0.0/24', '1.0.1.0/24', '1.0.2.0/24')],
  ['unsorted scattered hosts', cidrs('9.9.9.9', '1.1.1.1', '5.5.5.5', '1.1.1.2')],
  ['whole v4 space plus a host', cidrs('0.0.0.0/0', '8.8.8.8')],
  ['mixed versions', cidrs('1.0.0.0/25', '1.0.0.128/25', '2001:db8::/33', '2001:db8:8000::/33')],
  ['v6 nested and adjacent', cidrs('2001:db8::/32', '2001:db8:1::/48', '2001:db9::/32')],
  ['edge addresses', cidrs('0.0.0.0', '255.255.255.255', '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')],
];

describe('aggregateCidrs', () => {
  it('returns an empty array for empty input', () => {
    expect(aggregateCidrs([])).toEqual([]);
  });

  it('merges adjacent sibling blocks into their parent', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.0/25', '1.0.0.128/25')))).toEqual(['1.0.0.0/24']);
  });

  it('merges adjacent blocks regardless of input order', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.128/25', '1.0.0.0/25')))).toEqual(['1.0.0.0/24']);
  });

  it('does not merge non-adjacent blocks', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.0/24', '1.0.2.0/24')))).toEqual([
      '1.0.0.0/24',
      '1.0.2.0/24',
    ]);
  });

  it('does not merge two blocks that are not siblings even when adjacent to a gap', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.0/25', '1.0.1.0/25')))).toEqual([
      '1.0.0.0/25',
      '1.0.1.0/25',
    ]);
  });

  it('absorbs a nested subnet into its parent', () => {
    expect(texts(aggregateCidrs(cidrs('10.0.0.0/8', '10.1.0.0/16')))).toEqual(['10.0.0.0/8']);
    expect(texts(aggregateCidrs(cidrs('10.1.0.0/16', '10.0.0.0/8')))).toEqual(['10.0.0.0/8']);
  });

  it('collapses exact duplicates', () => {
    expect(texts(aggregateCidrs(cidrs('1.2.3.4', '1.2.3.4', '1.2.3.4/32')))).toEqual([
      '1.2.3.4/32',
    ]);
  });

  it('merges contiguous runs of single hosts', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.1', '1.0.0.2', '1.0.0.3', '1.0.0.4')))).toEqual([
      '1.0.0.1/32',
      '1.0.0.2/31',
      '1.0.0.4/32',
    ]);
  });

  it('re-emits a coalesced range as minimal aligned blocks', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.0/24', '1.0.1.0/24', '1.0.2.0/24')))).toEqual([
      '1.0.0.0/23',
      '1.0.2.0/24',
    ]);
  });

  it('merges overlapping blocks', () => {
    expect(texts(aggregateCidrs(cidrs('1.0.0.0/24', '1.0.0.128/25')))).toEqual(['1.0.0.0/24']);
  });

  it('collapses everything into /0 when the whole space is covered', () => {
    expect(texts(aggregateCidrs(cidrs('0.0.0.0/1', '128.0.0.0/1')))).toEqual(['0.0.0.0/0']);
    expect(texts(aggregateCidrs(cidrs('::/1', '8000::/1')))).toEqual(['::/0']);
  });

  it('keeps versions separate and emits IPv4 before IPv6', () => {
    const result = aggregateCidrs(
      cidrs('2001:db8:8000::/33', '1.0.0.128/25', '2001:db8::/33', '1.0.0.0/25'),
    );
    expect(texts(result)).toEqual(['1.0.0.0/24', '2001:db8::/32']);
    expect(result.map((c) => c.version)).toEqual([4, 6]);
  });

  it('sorts output ascending within each version', () => {
    const result = aggregateCidrs(cidrs('9.0.0.0/8', '1.0.0.0/8', '2001:dba::/32', '2001:db8::/32'));
    expect(texts(result)).toEqual(['1.0.0.0/8', '9.0.0.0/8', '2001:db8::/32', '2001:dba::/32']);
  });

  it('merges v6 siblings that differ only in the final prefix bit', () => {
    expect(texts(aggregateCidrs(cidrs('2001:db8::/32', '2001:db9::/32')))).toEqual([
      '2001:db8::/31',
    ]);
  });

  it('merges IPv6 siblings', () => {
    expect(texts(aggregateCidrs(cidrs('2001:db8::/33', '2001:db8:8000::/33')))).toEqual([
      '2001:db8::/32',
    ]);
  });

  it('is idempotent', () => {
    for (const [, input] of LOSSLESSNESS_CASES) {
      const once = aggregateCidrs(input);
      expect(texts(aggregateCidrs(once))).toEqual(texts(once));
    }
  });
});

describe('aggregateCidrs — losslessness', () => {
  it.each(LOSSLESSNESS_CASES)('covers exactly the same addresses for %s', (_label, input) => {
    expect(countAddresses(aggregateCidrs(input))).toBe(countAddresses(input));
  });

  it.each(LOSSLESSNESS_CASES)('classifies every probe address identically for %s', (_label, input) => {
    const aggregated = aggregateCidrs(input);
    for (const probe of probeAddresses(input)) {
      expect(containsAddress(aggregated, probe)).toBe(containsAddress(input, probe));
    }
  });

  it.each(LOSSLESSNESS_CASES)('produces pairwise-disjoint, minimal output for %s', (_label, input) => {
    const result = aggregateCidrs(input);
    const ranges = result.map(cidrToRange);
    for (let i = 1; i < result.length; i++) {
      const previousCidr = result[i - 1];
      const currentCidr = result[i];
      const previous = ranges[i - 1];
      const current = ranges[i];
      if (previousCidr === undefined || currentCidr === undefined) continue;
      if (previous === undefined || current === undefined) continue;
      if (previous.version !== current.version) continue;

      expect(current.start > previous.end).toBe(true);

      if (previousCidr.prefixLen === currentCidr.prefixLen && previousCidr.prefixLen > 0) {
        const blockSize = 1n << BigInt(bitWidth(previousCidr.version) - previousCidr.prefixLen);
        const areSiblings =
          previousCidr.addr % (blockSize * 2n) === 0n &&
          currentCidr.addr === previousCidr.addr + blockSize;
        expect(areSiblings).toBe(false);
      }
    }
  });

  it('never widens coverage when merging near a boundary', () => {
    const input = cidrs('1.0.0.0/25', '1.0.1.0/25');
    expect(countAddresses(input)).toBe(256n);
    expect(countAddresses(aggregateCidrs(input))).toBe(256n);
    expect(containsAddress(aggregateCidrs(input), addr('1.0.0.128'))).toBe(false);
    expect(containsAddress(aggregateCidrs(input), addr('1.0.0.255'))).toBe(false);
  });
});

describe('dedupeCidrs', () => {
  it('returns an empty array for empty input', () => {
    expect(dedupeCidrs([])).toEqual([]);
  });

  it('removes exact duplicates', () => {
    expect(texts(dedupeCidrs(cidrs('1.2.3.4', '1.2.3.4/32', '1.2.3.4')))).toEqual(['1.2.3.4/32']);
  });

  it('removes fully-contained subnets', () => {
    expect(texts(dedupeCidrs(cidrs('10.0.0.0/8', '10.1.0.0/16')))).toEqual(['10.0.0.0/8']);
    expect(texts(dedupeCidrs(cidrs('10.1.0.0/16', '10.0.0.0/8')))).toEqual(['10.0.0.0/8']);
  });

  it('removes subnets that sort after a sibling inside the same parent', () => {
    expect(texts(dedupeCidrs(cidrs('10.0.0.0/8', '10.1.0.0/16', '10.2.0.0/16')))).toEqual([
      '10.0.0.0/8',
    ]);
  });

  it('does not merge adjacent siblings', () => {
    expect(texts(dedupeCidrs(cidrs('1.0.0.0/25', '1.0.0.128/25')))).toEqual([
      '1.0.0.0/25',
      '1.0.0.128/25',
    ]);
  });

  it('keeps disjoint blocks', () => {
    expect(texts(dedupeCidrs(cidrs('1.0.2.0/24', '1.0.0.0/24')))).toEqual([
      '1.0.0.0/24',
      '1.0.2.0/24',
    ]);
  });

  it('keeps versions separate and emits IPv4 before IPv6', () => {
    expect(texts(dedupeCidrs(cidrs('2001:db8::/32', '1.0.0.0/24', '2001:db8:1::/48')))).toEqual([
      '1.0.0.0/24',
      '2001:db8::/32',
    ]);
  });

  it('is lossless', () => {
    for (const [, input] of LOSSLESSNESS_CASES) {
      expect(countAddresses(dedupeCidrs(input))).toBe(countAddresses(input));
    }
  });

  it('is idempotent', () => {
    for (const [, input] of LOSSLESSNESS_CASES) {
      const once = dedupeCidrs(input);
      expect(texts(dedupeCidrs(once))).toEqual(texts(once));
    }
  });
});

describe('containsAddress', () => {
  it('returns false for an empty list', () => {
    expect(containsAddress([], addr('1.2.3.4'))).toBe(false);
    expect(containsAddress([], addr('::1'))).toBe(false);
  });

  it('matches the first and last address of a block', () => {
    const list = cidrs('1.0.0.0/24');
    expect(containsAddress(list, addr('1.0.0.0'))).toBe(true);
    expect(containsAddress(list, addr('1.0.0.255'))).toBe(true);
  });

  it('rejects the addresses just outside a block', () => {
    const list = cidrs('1.0.0.0/24');
    expect(containsAddress(list, addr('0.255.255.255'))).toBe(false);
    expect(containsAddress(list, addr('1.0.1.0'))).toBe(false);
  });

  it('matches a single-host block exactly', () => {
    const list = cidrs('192.0.2.1');
    expect(containsAddress(list, addr('192.0.2.1'))).toBe(true);
    expect(containsAddress(list, addr('192.0.2.0'))).toBe(false);
    expect(containsAddress(list, addr('192.0.2.2'))).toBe(false);
  });

  it('matches through a parent block when a nested subnet sorts first', () => {
    const list = cidrs('10.0.0.0/8', '10.1.0.0/16');
    expect(containsAddress(list, addr('10.2.0.0'))).toBe(true);
    expect(containsAddress(list, addr('10.1.0.1'))).toBe(true);
    expect(containsAddress(list, addr('11.0.0.0'))).toBe(false);
  });

  it('never matches an address of the other version', () => {
    expect(containsAddress(cidrs('0.0.0.0/0'), addr('::1'))).toBe(false);
    expect(containsAddress(cidrs('::/0'), addr('1.2.3.4'))).toBe(false);
  });

  it('handles the whole-space blocks', () => {
    expect(containsAddress(cidrs('0.0.0.0/0'), addr('0.0.0.0'))).toBe(true);
    expect(containsAddress(cidrs('0.0.0.0/0'), addr('255.255.255.255'))).toBe(true);
    expect(containsAddress(cidrs('::/0'), addr('::'))).toBe(true);
    expect(
      containsAddress(cidrs('::/0'), addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')),
    ).toBe(true);
  });

  it('searches a many-block list correctly', () => {
    const list = cidrs(
      '1.0.0.0/24',
      '3.0.0.0/24',
      '5.0.0.0/24',
      '7.0.0.0/24',
      '9.0.0.0/24',
      '11.0.0.0/24',
      '13.0.0.0/24',
    );
    for (const octet of [1, 3, 5, 7, 9, 11, 13]) {
      expect(containsAddress(list, addr(`${octet}.0.0.1`))).toBe(true);
    }
    for (const octet of [0, 2, 4, 6, 8, 10, 12, 14]) {
      expect(containsAddress(list, addr(`${octet}.0.0.1`))).toBe(false);
    }
  });

  it('matches IPv6 boundaries', () => {
    const list = cidrs('2001:db8::/32');
    expect(containsAddress(list, addr('2001:db8::'))).toBe(true);
    expect(containsAddress(list, addr('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'))).toBe(true);
    expect(containsAddress(list, addr('2001:db7:ffff:ffff:ffff:ffff:ffff:ffff'))).toBe(false);
    expect(containsAddress(list, addr('2001:db9::'))).toBe(false);
  });
});

describe('countAddresses', () => {
  it('returns zero for an empty list', () => {
    expect(countAddresses([])).toBe(0n);
  });

  it('counts block sizes', () => {
    expect(countAddresses(cidrs('1.2.3.4'))).toBe(1n);
    expect(countAddresses(cidrs('1.0.0.0/24'))).toBe(256n);
    expect(countAddresses(cidrs('10.0.0.0/8'))).toBe(1n << 24n);
    expect(countAddresses(cidrs('0.0.0.0/0'))).toBe(1n << 32n);
    expect(countAddresses(cidrs('::/0'))).toBe(1n << 128n);
    expect(countAddresses(cidrs('2001:db8::/32'))).toBe(1n << 96n);
  });

  it('counts the union, not the sum, of overlapping blocks', () => {
    expect(countAddresses(cidrs('1.0.0.0/24', '1.0.0.0/24'))).toBe(256n);
    expect(countAddresses(cidrs('10.0.0.0/8', '10.1.0.0/16'))).toBe(1n << 24n);
    expect(countAddresses(cidrs('1.0.0.0/25', '1.0.0.128/25'))).toBe(256n);
  });

  it('sums across versions', () => {
    expect(countAddresses(cidrs('1.0.0.0/24', '2001:db8::/128'))).toBe(257n);
  });

  it('adds disjoint blocks', () => {
    expect(countAddresses(cidrs('1.0.0.0/24', '1.0.2.0/24'))).toBe(512n);
  });
});
