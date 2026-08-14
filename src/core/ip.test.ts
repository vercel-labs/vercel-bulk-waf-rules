import { describe, expect, it } from 'vitest';

import type { Cidr, IpRange } from './ip.js';
import {
  InvalidIpError,
  bitWidth,
  cidrToRange,
  compareRanges,
  formatCidr,
  formatIp,
  parseCidr,
  parseCidrLoose,
  parseIp,
  rangeToCidrs,
} from './ip.js';

const V4_MAX = (1n << 32n) - 1n;
const V6_MAX = (1n << 128n) - 1n;

function assertTiles(range: IpRange, cidrs: readonly Cidr[]): void {
  expect(cidrs.length).toBeGreaterThan(0);
  const width = bitWidth(range.version);
  let cursor = range.start;
  for (const cidr of cidrs) {
    expect(cidr.version).toBe(range.version);
    const blockSize = 1n << BigInt(width - cidr.prefixLen);
    expect(cidr.addr % blockSize).toBe(0n);
    const block = cidrToRange(cidr);
    expect(block.start).toBe(cursor);
    cursor = block.end + 1n;
  }
  expect(cursor - 1n).toBe(range.end);
}

describe('bitWidth', () => {
  it('reports the address space width per version', () => {
    expect(bitWidth(4)).toBe(32);
    expect(bitWidth(6)).toBe(128);
  });
});

describe('parseIp — IPv4', () => {
  it('parses valid dotted quads', () => {
    expect(parseIp('0.0.0.0')).toEqual({ version: 4, value: 0n });
    expect(parseIp('192.0.2.1')).toEqual({ version: 4, value: 3221225985n });
    expect(parseIp('255.255.255.255')).toEqual({ version: 4, value: V4_MAX });
    expect(parseIp('10.0.0.1')).toEqual({ version: 4, value: 167772161n });
  });

  it.each([
    ['leading zero octet', '01.2.3.4'],
    ['zero-padded octet', '1.2.3.04'],
    ['all-zero-padded', '010.010.010.010'],
    ['two-part shorthand', '10.1'],
    ['three-part shorthand', '10.1.2'],
    ['five parts', '1.2.3.4.5'],
    ['bare integer notation', '2130706433'],
    ['hex octets', '0xc0.0x00.0x02.0x01'],
    ['hex single value', '0x7f000001'],
    ['octet above 255', '256.1.1.1'],
    ['octet far above 255', '1.1.1.999'],
    ['trailing dot', '1.2.3.'],
    ['leading dot', '.1.2.3'],
    ['empty middle part', '1..3.4'],
    ['negative octet', '1.2.3.-1'],
    ['leading whitespace', ' 1.2.3.4'],
    ['trailing whitespace', '1.2.3.4 '],
    ['inner whitespace', '1.2. 3.4'],
    ['empty string', ''],
    ['plus sign', '+1.2.3.4'],
    ['non-numeric', 'a.b.c.d'],
  ])('rejects %s', (_label, input) => {
    expect(() => parseIp(input)).toThrow(InvalidIpError);
  });

  it('exposes the offending input on the error', () => {
    try {
      parseIp('01.2.3.4');
      expect.unreachable('should have thrown');
    } catch (error) {
      if (!(error instanceof InvalidIpError)) throw error;
      expect(error.input).toBe('01.2.3.4');
      expect(error.name).toBe('InvalidIpError');
      expect(error.message).toContain('01.2.3.4');
    }
  });
});

describe('parseIp — IPv6', () => {
  it('parses the fully expanded form', () => {
    expect(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toEqual({
      version: 6,
      value: 0x20010db8000000000000000000000001n,
    });
  });

  it('parses "::" in every position', () => {
    expect(parseIp('::').value).toBe(0n);
    expect(parseIp('::1').value).toBe(1n);
    expect(parseIp('1::').value).toBe(1n << 112n);
    expect(parseIp('2001:db8::1').value).toBe(0x20010db8000000000000000000000001n);
    expect(parseIp('fe80::').value).toBe(0xfe800000000000000000000000000000n);
    expect(parseIp('ffff::ffff').value).toBe((0xffffn << 112n) | 0xffffn);
  });

  it('accepts uppercase hex and equates it with lowercase', () => {
    expect(parseIp('2001:DB8::AB').value).toBe(parseIp('2001:db8::ab').value);
  });

  it('parses an IPv4-mapped tail', () => {
    expect(parseIp('::ffff:192.0.2.1').value).toBe(0xffffc0000201n);
    expect(parseIp('::ffff:c000:201').value).toBe(parseIp('::ffff:192.0.2.1').value);
    expect(parseIp('::192.0.2.1').value).toBe(0xc0000201n);
    expect(parseIp('64:ff9b::192.0.2.33').value).toBe(0x0064ff9b0000000000000000c0000221n);
  });

  it('accepts a compressed form with 7 explicit groups', () => {
    expect(parseIp('1:2:3:4:5:6:7::').value).toBe(parseIp('1:2:3:4:5:6:7:0').value);
  });

  it.each([
    ['two "::" runs', '1::2::3'],
    ['trailing extra "::"', '::1::'],
    ['triple colon', '1:::2'],
    ['quadruple colon', '::::'],
    ['zone identifier', 'fe80::1%eth0'],
    ['bracketed form', '[::1]'],
    ['bracketed with port-ish tail', '[::1]:8080'],
    ['nine groups', '1:2:3:4:5:6:7:8:9'],
    ['seven groups uncompressed', '1:2:3:4:5:6:7'],
    ['leading single colon', ':1:2:3:4:5:6:7:8'],
    ['trailing single colon', '1:2:3:4:5:6:7:8:'],
    ['"::" compressing nothing', '1:2:3:4:5:6:7:8::'],
    ['group with 5 hex digits', '12345::1'],
    ['non-hex group', 'gggg::1'],
    ['IPv4 part not at the end', '1.2.3.4::1'],
    ['IPv4 part mid-address', '::1.2.3.4:5'],
    ['over-long IPv4 tail', '::1.2.3.4.5'],
    ['invalid IPv4 tail', '::ffff:1.2.3.999'],
    ['leading-zero IPv4 tail', '::ffff:01.2.3.4'],
    ['whitespace inside', '2001:db8:: 1'],
  ])('rejects %s', (_label, input) => {
    expect(() => parseIp(input)).toThrow(InvalidIpError);
  });
});

describe('formatIp', () => {
  it('renders IPv4 as a dotted quad', () => {
    expect(formatIp(4, 0n)).toBe('0.0.0.0');
    expect(formatIp(4, 3221225985n)).toBe('192.0.2.1');
    expect(formatIp(4, V4_MAX)).toBe('255.255.255.255');
  });

  it('collapses the all-zero address to "::"', () => {
    expect(formatIp(6, 0n)).toBe('::');
  });

  it('collapses a leading zero run', () => {
    expect(formatIp(6, 1n)).toBe('::1');
    expect(formatIp(6, 0xffffc0000201n)).toBe('::ffff:c000:201');
  });

  it('collapses a trailing zero run', () => {
    expect(formatIp(6, parseIp('2001:db8:0:0:0:0:0:0').value)).toBe('2001:db8::');
    expect(formatIp(6, parseIp('1:2:3:4:5:6:7:0').value)).toBe('1:2:3:4:5:6:7:0');
  });

  it('lowercases hex and strips leading zeros within a group', () => {
    expect(formatIp(6, parseIp('2001:0DB8::00AB').value)).toBe('2001:db8::ab');
  });

  it('does not collapse a single zero group (RFC 5952 §4.2.2)', () => {
    expect(formatIp(6, parseIp('2001:db8:0:1:1:1:1:1').value)).toBe('2001:db8:0:1:1:1:1:1');
    expect(formatIp(6, parseIp('1:0:1:0:1:0:1:0').value)).toBe('1:0:1:0:1:0:1:0');
  });

  it('collapses the leftmost run when two runs tie (RFC 5952 §4.2.3)', () => {
    expect(formatIp(6, parseIp('2001:db8:0:0:1:0:0:1').value)).toBe('2001:db8::1:0:0:1');
    expect(formatIp(6, parseIp('1:0:0:2:0:0:3:4').value)).toBe('1::2:0:0:3:4');
  });

  it('collapses the longest run even when a shorter run comes first', () => {
    expect(formatIp(6, parseIp('1:0:0:2:0:0:0:3').value)).toBe('1:0:0:2::3');
  });

  it('rejects values outside the address space', () => {
    expect(() => formatIp(4, V4_MAX + 1n)).toThrow(InvalidIpError);
    expect(() => formatIp(4, -1n)).toThrow(InvalidIpError);
    expect(() => formatIp(6, V6_MAX + 1n)).toThrow(InvalidIpError);
  });
});

describe('round-tripping', () => {
  const table: ReadonlyArray<readonly [string, string]> = [
    ['0.0.0.0', '0.0.0.0'],
    ['192.0.2.1', '192.0.2.1'],
    ['255.255.255.255', '255.255.255.255'],
    ['::', '::'],
    ['::1', '::1'],
    ['1::', '1::'],
    ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
    ['2001:DB8::AB', '2001:db8::ab'],
    ['::ffff:192.0.2.1', '::ffff:c000:201'],
    ['2001:db8:0:0:1:0:0:1', '2001:db8::1:0:0:1'],
    ['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
    ['fe80::', 'fe80::'],
    ['1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8'],
  ];

  it.each(table)('%s canonicalizes to %s', (input, expected) => {
    const parsed = parseIp(input);
    expect(formatIp(parsed.version, parsed.value)).toBe(expected);
  });

  it.each(table)('%s is stable under re-parse', (input) => {
    const first = parseIp(input);
    const text = formatIp(first.version, first.value);
    const second = parseIp(text);
    expect(second).toEqual(first);
    expect(formatIp(second.version, second.value)).toBe(text);
  });
});

describe('parseCidr', () => {
  it('treats a bare address as a single-host prefix', () => {
    expect(parseCidr('1.2.3.4')).toEqual({ version: 4, addr: 16909060n, prefixLen: 32 });
    expect(parseCidr('::1')).toEqual({ version: 6, addr: 1n, prefixLen: 128 });
  });

  it('parses explicit prefixes at both edges', () => {
    expect(parseCidr('0.0.0.0/0')).toEqual({ version: 4, addr: 0n, prefixLen: 0 });
    expect(parseCidr('1.2.3.4/32')).toEqual({ version: 4, addr: 16909060n, prefixLen: 32 });
    expect(parseCidr('::/0')).toEqual({ version: 6, addr: 0n, prefixLen: 0 });
    expect(parseCidr('::1/128')).toEqual({ version: 6, addr: 1n, prefixLen: 128 });
  });

  it('masks host bits by default', () => {
    expect(formatCidr(parseCidr('1.2.3.4/24'))).toBe('1.2.3.0/24');
    expect(formatCidr(parseCidr('255.255.255.255/0'))).toBe('0.0.0.0/0');
    expect(formatCidr(parseCidr('2001:db8::1/32'))).toBe('2001:db8::/32');
  });

  it('rejects set host bits when strict', () => {
    expect(() => parseCidr('1.2.3.4/24', { strict: true })).toThrow(InvalidIpError);
    expect(() => parseCidr('2001:db8::1/32', { strict: true })).toThrow(InvalidIpError);
    expect(() => parseCidr('1.2.3.0/24', { strict: true })).not.toThrow();
    expect(() => parseCidr('1.2.3.4/32', { strict: true })).not.toThrow();
  });

  it.each([
    ['prefix above 32 for v4', '1.2.3.4/33'],
    ['prefix far above 32 for v4', '1.2.3.4/128'],
    ['prefix above 128 for v6', '::1/129'],
    ['zero-padded prefix', '1.2.3.0/024'],
    ['empty prefix', '1.2.3.4/'],
    ['negative prefix', '1.2.3.4/-1'],
    ['non-numeric prefix', '1.2.3.4/abc'],
    ['two slashes', '1.2.3.4/24/24'],
    ['prefix only', '/24'],
    ['float prefix', '1.2.3.4/24.0'],
  ])('rejects %s', (_label, input) => {
    expect(() => parseCidr(input)).toThrow(InvalidIpError);
  });
});

describe('parseCidrLoose', () => {
  it('reports when host bits were masked away', () => {
    const changed = parseCidrLoose('1.2.3.4/24');
    expect(changed.normalized).toBe(true);
    expect(formatCidr(changed.cidr)).toBe('1.2.3.0/24');
  });

  it('reports no change for already-aligned input', () => {
    expect(parseCidrLoose('1.2.3.0/24').normalized).toBe(false);
    expect(parseCidrLoose('1.2.3.4').normalized).toBe(false);
    expect(parseCidrLoose('2001:db8::/32').normalized).toBe(false);
    expect(parseCidrLoose('::/0').normalized).toBe(false);
  });

  it('reports normalization for IPv6 host bits', () => {
    const changed = parseCidrLoose('2001:db8::dead:beef/64');
    expect(changed.normalized).toBe(true);
    expect(formatCidr(changed.cidr)).toBe('2001:db8::/64');
  });
});

describe('cidrToRange', () => {
  it('expands to inclusive first..last', () => {
    expect(cidrToRange(parseCidr('1.2.3.0/24'))).toEqual({
      version: 4,
      start: parseIp('1.2.3.0').value,
      end: parseIp('1.2.3.255').value,
    });
    expect(cidrToRange(parseCidr('1.2.3.4/32'))).toEqual({
      version: 4,
      start: 16909060n,
      end: 16909060n,
    });
    expect(cidrToRange(parseCidr('0.0.0.0/0'))).toEqual({ version: 4, start: 0n, end: V4_MAX });
    expect(cidrToRange(parseCidr('::/0'))).toEqual({ version: 6, start: 0n, end: V6_MAX });
  });

  it('rejects an out-of-range prefix length', () => {
    expect(() => cidrToRange({ version: 4, addr: 0n, prefixLen: 33 })).toThrow(InvalidIpError);
    expect(() => cidrToRange({ version: 4, addr: 0n, prefixLen: -1 })).toThrow(InvalidIpError);
    expect(() => cidrToRange({ version: 6, addr: 0n, prefixLen: 129 })).toThrow(InvalidIpError);
  });

  it('rejects an address that does not fit the declared version', () => {
    expect(() => cidrToRange({ version: 4, addr: V4_MAX + 1n, prefixLen: 32 })).toThrow(
      InvalidIpError,
    );
  });
});

describe('rangeToCidrs', () => {
  it('emits a single /0 for the whole IPv4 space', () => {
    const cidrs = rangeToCidrs({ version: 4, start: 0n, end: V4_MAX });
    expect(cidrs.map(formatCidr)).toEqual(['0.0.0.0/0']);
  });

  it('emits a single /0 for the whole IPv6 space', () => {
    const cidrs = rangeToCidrs({ version: 6, start: 0n, end: V6_MAX });
    expect(cidrs.map(formatCidr)).toEqual(['::/0']);
  });

  it('emits a single /32 for one IPv4 address', () => {
    const value = parseIp('192.0.2.1').value;
    expect(rangeToCidrs({ version: 4, start: value, end: value }).map(formatCidr)).toEqual([
      '192.0.2.1/32',
    ]);
  });

  it('emits a single /128 for one IPv6 address', () => {
    expect(rangeToCidrs({ version: 6, start: 1n, end: 1n }).map(formatCidr)).toEqual(['::1/128']);
  });

  it('decomposes an unaligned range greedily', () => {
    const range: IpRange = {
      version: 4,
      start: parseIp('1.0.0.1').value,
      end: parseIp('1.0.0.6').value,
    };
    expect(rangeToCidrs(range).map(formatCidr)).toEqual([
      '1.0.0.1/32',
      '1.0.0.2/31',
      '1.0.0.4/31',
      '1.0.0.6/32',
    ]);
  });

  it('recognizes an aligned range as one block', () => {
    const range: IpRange = {
      version: 4,
      start: parseIp('10.0.0.0').value,
      end: parseIp('10.255.255.255').value,
    };
    expect(rangeToCidrs(range).map(formatCidr)).toEqual(['10.0.0.0/8']);
  });

  it('rejects an inverted range', () => {
    expect(() => rangeToCidrs({ version: 4, start: 10n, end: 9n })).toThrow(InvalidIpError);
  });

  const tiling: ReadonlyArray<readonly [string, IpRange]> = [
    ['whole v4 space', { version: 4, start: 0n, end: V4_MAX }],
    ['whole v6 space', { version: 6, start: 0n, end: V6_MAX }],
    ['single v4 address', { version: 4, start: 16909060n, end: 16909060n }],
    ['unaligned v4 span', { version: 4, start: 16909061n, end: 16909333n }],
    ['v4 span crossing an octet', { version: 4, start: 167772415n, end: 167772417n }],
    ['off-by-one from aligned v4', { version: 4, start: 1n, end: V4_MAX - 1n }],
    ['unaligned v6 span', { version: 6, start: 12345678901234567890n, end: 12345678901239999999n }],
    ['v6 span from zero', { version: 6, start: 0n, end: 1000n }],
  ];

  it.each(tiling)('exactly tiles %s with no gaps or overlaps', (_label, range) => {
    assertTiles(range, rangeToCidrs(range));
  });
});

describe('compareRanges', () => {
  const v4Low: IpRange = { version: 4, start: 10n, end: 20n };
  const v4LowWide: IpRange = { version: 4, start: 10n, end: 30n };
  const v4High: IpRange = { version: 4, start: 30n, end: 40n };
  const v6Low: IpRange = { version: 6, start: 1n, end: 2n };

  it('orders IPv4 before IPv6', () => {
    expect(compareRanges(v4High, v6Low)).toBeLessThan(0);
    expect(compareRanges(v6Low, v4High)).toBeGreaterThan(0);
  });

  it('orders by start, then end', () => {
    expect(compareRanges(v4Low, v4High)).toBeLessThan(0);
    expect(compareRanges(v4High, v4Low)).toBeGreaterThan(0);
    expect(compareRanges(v4Low, v4LowWide)).toBeLessThan(0);
    expect(compareRanges(v4LowWide, v4Low)).toBeGreaterThan(0);
  });

  it('reports equality for identical ranges', () => {
    expect(compareRanges(v4Low, { ...v4Low })).toBe(0);
  });

  it('sorts a mixed array deterministically', () => {
    const sorted = [v6Low, v4High, v4LowWide, v4Low].sort(compareRanges);
    expect(sorted).toEqual([v4Low, v4LowWide, v4High, v6Low]);
  });
});

describe('formatCidr', () => {
  it('always includes an explicit prefix length', () => {
    expect(formatCidr(parseCidr('1.2.3.4'))).toBe('1.2.3.4/32');
    expect(formatCidr(parseCidr('::1'))).toBe('::1/128');
    expect(formatCidr(parseCidr('10.0.0.0/8'))).toBe('10.0.0.0/8');
  });
});
