/**
 * IP address primitives for the WAF rule planner.
 *
 * Everything here is version-agnostic by representing an address as a `bigint`
 * plus an explicit `IpVersion`. IPv4 fits comfortably in a `number`, but IPv6
 * needs 128 bits, so using `bigint` uniformly means every piece of range/CIDR
 * math is written exactly once and IPv6 support falls out for free.
 *
 * There are deliberately zero runtime dependencies: this is ~200 lines of
 * bit math and we do not want third-party supply-chain surface on
 * customer-adjacent machines that hold WAF credentials.
 */

/** IP protocol version. Only 4 and 6 exist; modelled as a literal union so switches are exhaustive. */
export type IpVersion = 4 | 6;

/**
 * An inclusive address range, `start`..`end`.
 *
 * Ranges (not CIDRs) are the canonical internal representation for
 * aggregation, because arbitrary ranges are closed under union whereas CIDR
 * blocks are not (1.0.0.0/25 ∪ 1.0.0.128/25 happens to be a /24, but
 * 1.0.0.0/25 ∪ 1.0.1.0/25 is not any single CIDR).
 */
export interface IpRange {
  version: IpVersion;
  start: bigint;
  end: bigint;
}

/** A CIDR block. `addr` is always already masked to `prefixLen` (host bits zero). */
export interface Cidr {
  version: IpVersion;
  addr: bigint;
  prefixLen: number;
}

/** Options for {@link parseCidr}. */
export interface ParseCidrOptions {
  /**
   * When true, reject input whose host bits are set (e.g. `1.2.3.4/24`)
   * instead of silently masking them.
   */
  strict?: boolean;
}

/**
 * Thrown for every malformed IP / CIDR input.
 *
 * Carries the offending input verbatim so the CLI layer can point the user at
 * the exact CSV cell that failed without re-plumbing the string through the
 * error message.
 */
export class InvalidIpError extends Error {
  /** The raw input that failed to parse. */
  readonly input: string;

  constructor(input: string, reason: string) {
    super(`Invalid IP input ${JSON.stringify(input)}: ${reason}`);
    this.name = 'InvalidIpError';
    this.input = input;
  }
}

const IPV6_GROUP_COUNT = 8;
const IPV4_OCTET_COUNT = 4;

/**
 * Strict IPv4 octet: `0`, or 1-3 digits with no leading zero.
 *
 * The no-leading-zero rule is deliberate and security-relevant: many resolvers
 * treat `010.1.1.1` as octal (8.1.1.1), so accepting it in an allowlist would
 * mean the rule we ship does not match the addresses the operator believed
 * they typed.
 */
const IPV4_OCTET = /^(?:0|[1-9][0-9]{0,2})$/;

/** A single IPv6 hextet: 1-4 hex digits. Case-insensitive on input; output is lowercased. */
const IPV6_GROUP = /^[0-9a-fA-F]{1,4}$/;

/** Prefix length: a non-negative decimal integer with no leading zeros (rejects `/024`). */
const PREFIX_LEN = /^(?:0|[1-9][0-9]*)$/;

/** Address space width in bits: 32 for IPv4, 128 for IPv6. */
export function bitWidth(version: IpVersion): number {
  return version === 4 ? 32 : 128;
}

function maxAddress(version: IpVersion): bigint {
  return (1n << BigInt(bitWidth(version))) - 1n;
}

/** Guard against a v6-sized value being smuggled into a v4 structure (and negatives). */
function assertInAddressSpace(version: IpVersion, value: bigint, label: string): void {
  if (value < 0n || value > maxAddress(version)) {
    throw new InvalidIpError(
      value.toString(),
      `${label} is outside the IPv${version} address space`,
    );
  }
}

function parseIpv4Value(text: string, original: string): bigint {
  const parts = text.split('.');
  if (parts.length !== IPV4_OCTET_COUNT) {
    throw new InvalidIpError(
      original,
      `IPv4 address must have exactly 4 dot-separated octets, got ${parts.length}`,
    );
  }
  let value = 0n;
  for (const part of parts) {
    if (!IPV4_OCTET.test(part)) {
      throw new InvalidIpError(
        original,
        `invalid IPv4 octet ${JSON.stringify(part)} (decimal 0-255, no leading zeros)`,
      );
    }
    const octet = Number(part);
    if (octet > 255) {
      throw new InvalidIpError(original, `IPv4 octet out of range: ${JSON.stringify(part)}`);
    }
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

/**
 * Expand a run of colon-separated IPv6 tokens into 16-bit groups.
 *
 * `allowEmbeddedIpv4` is only true for the trailing run, because a dotted-quad
 * tail is legal only at the very end of the address (`::ffff:192.0.2.1`).
 */
function expandIpv6Tokens(
  tokens: readonly string[],
  original: string,
  allowEmbeddedIpv4: boolean,
): bigint[] {
  const groups: bigint[] = [];
  for (const [index, token] of tokens.entries()) {
    if (token === '') {
      throw new InvalidIpError(original, 'empty IPv6 group (stray or repeated ":")');
    }
    if (token.includes('.')) {
      if (!allowEmbeddedIpv4 || index !== tokens.length - 1) {
        throw new InvalidIpError(
          original,
          'an embedded IPv4 address is only allowed as the final part of an IPv6 address',
        );
      }
      const v4 = parseIpv4Value(token, original);
      groups.push((v4 >> 16n) & 0xffffn, v4 & 0xffffn);
      continue;
    }
    if (!IPV6_GROUP.test(token)) {
      throw new InvalidIpError(original, `invalid IPv6 group ${JSON.stringify(token)}`);
    }
    groups.push(BigInt(Number.parseInt(token, 16)));
  }
  return groups;
}

function parseIpv6Value(text: string): bigint {
  if (text.includes('%')) {
    throw new InvalidIpError(text, 'IPv6 zone identifiers are not supported');
  }
  if (text.includes('[') || text.includes(']')) {
    throw new InvalidIpError(text, 'bracketed IPv6 notation is not supported');
  }

  const halves = text.split('::');
  if (halves.length > 2) {
    throw new InvalidIpError(text, 'IPv6 address may contain at most one "::"');
  }

  let groups: bigint[];
  if (halves.length === 2) {
    const head = halves[0] ?? '';
    const tail = halves[1] ?? '';
    const headGroups = head === '' ? [] : expandIpv6Tokens(head.split(':'), text, false);
    const tailGroups = tail === '' ? [] : expandIpv6Tokens(tail.split(':'), text, true);
    const zeroGroups = IPV6_GROUP_COUNT - (headGroups.length + tailGroups.length);
    if (zeroGroups < 1) {
      throw new InvalidIpError(text, '"::" must compress at least one 16-bit group');
    }
    groups = [...headGroups, ...Array.from({ length: zeroGroups }, () => 0n), ...tailGroups];
  } else {
    groups = expandIpv6Tokens(text.split(':'), text, true);
    if (groups.length !== IPV6_GROUP_COUNT) {
      throw new InvalidIpError(
        text,
        `IPv6 address must have exactly 8 groups when uncompressed, got ${groups.length}`,
      );
    }
  }

  let value = 0n;
  for (const group of groups) {
    value = (value << 16n) | group;
  }
  return value;
}

/**
 * Parse a bare IP address (no prefix) into a version-tagged `bigint`.
 *
 * Parsing is intentionally strict — see {@link IPV4_OCTET}. We would rather
 * fail a customer's CSV loudly than quietly install a firewall rule that
 * matches a different address than the one they wrote down.
 *
 * @throws {InvalidIpError} on any malformed input.
 */
export function parseIp(input: string): { version: IpVersion; value: bigint } {
  if (input === '') {
    throw new InvalidIpError(input, 'empty string');
  }
  if (input.includes(':')) {
    return { version: 6, value: parseIpv6Value(input) };
  }
  return { version: 4, value: parseIpv4Value(input, input) };
}

function maskFor(version: IpVersion, prefixLen: number): bigint {
  const width = bitWidth(version);
  const hostBits = BigInt(width - prefixLen);
  return (maxAddress(version) >> hostBits) << hostBits;
}

function parseCidrParts(input: string): { cidr: Cidr; normalized: boolean } {
  const parts = input.split('/');
  if (parts.length > 2) {
    throw new InvalidIpError(input, 'CIDR may contain at most one "/"');
  }
  const addrPart = parts[0] ?? '';
  const { version, value } = parseIp(addrPart);
  const width = bitWidth(version);

  let prefixLen = width;
  if (parts.length === 2) {
    const lenPart = parts[1] ?? '';
    if (!PREFIX_LEN.test(lenPart)) {
      throw new InvalidIpError(
        input,
        `invalid prefix length ${JSON.stringify(lenPart)} (decimal integer, no leading zeros)`,
      );
    }
    prefixLen = Number(lenPart);
    if (prefixLen > width) {
      throw new InvalidIpError(input, `prefix length must be 0-${width} for IPv${version}`);
    }
  }

  const masked = value & maskFor(version, prefixLen);
  return { cidr: { version, addr: masked, prefixLen }, normalized: masked !== value };
}

/**
 * Parse `addr` or `addr/len` into a normalized {@link Cidr}.
 *
 * A bare address implies the single-host prefix (/32 or /128). By default host
 * bits outside the prefix are masked away; pass `{ strict: true }` to reject
 * such input instead. Use {@link parseCidrLoose} when you need to tell the
 * user that normalization happened.
 *
 * @throws {InvalidIpError} on malformed input, or on set host bits when strict.
 */
export function parseCidr(input: string, options?: ParseCidrOptions): Cidr {
  const { cidr, normalized } = parseCidrParts(input);
  if (normalized && options?.strict === true) {
    throw new InvalidIpError(
      input,
      `host bits are set outside the /${cidr.prefixLen} prefix (did you mean ${formatCidr(cidr)}?)`,
    );
  }
  return cidr;
}

/**
 * Like {@link parseCidr}, but reports whether host bits had to be masked.
 *
 * Exists so the import path can warn "1.2.3.4/24 was normalized to 1.2.3.0/24"
 * — silently widening an operator's entry from one host to 256 is exactly the
 * kind of surprise that turns into an incident.
 */
export function parseCidrLoose(input: string): { cidr: Cidr; normalized: boolean } {
  return parseCidrParts(input);
}

function formatIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 0xffn)).join('.');
}

/**
 * RFC 5952 §4 canonical IPv6 text form: lowercase hex, no leading zeros in a
 * group, the longest run of all-zero groups collapsed to `::` (leftmost run
 * wins a tie), and never collapsing a single zero group.
 *
 * Canonicalizing matters because we dedupe and diff rule contents as strings;
 * `2001:db8::1` and `2001:0db8:0:0:0:0:0:1` must not look like two entries.
 */
function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let i = IPV6_GROUP_COUNT - 1; i >= 0; i--) {
    groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  }

  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  let runLen = 0;
  for (const [index, group] of groups.entries()) {
    if (group === 0) {
      if (runStart === -1) {
        runStart = index;
        runLen = 1;
      } else {
        runLen += 1;
      }
      // Strict `>` keeps the leftmost run when two runs are the same length.
      if (runLen > bestLen) {
        bestLen = runLen;
        bestStart = runStart;
      }
    } else {
      runStart = -1;
      runLen = 0;
    }
  }

  const hex = groups.map((group) => group.toString(16));
  if (bestLen < 2) {
    return hex.join(':');
  }
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

/** Render an address in canonical text form (dotted quad for v4, RFC 5952 for v6). */
export function formatIp(version: IpVersion, value: bigint): string {
  assertInAddressSpace(version, value, 'address');
  return version === 4 ? formatIpv4(value) : formatIpv6(value);
}

/** Render a CIDR as `addr/len`, always with an explicit prefix length. */
export function formatCidr(c: Cidr): string {
  return `${formatIp(c.version, c.addr)}/${c.prefixLen}`;
}

/** Expand a CIDR block to its inclusive first..last address range. */
export function cidrToRange(c: Cidr): IpRange {
  const width = bitWidth(c.version);
  if (!Number.isInteger(c.prefixLen) || c.prefixLen < 0 || c.prefixLen > width) {
    throw new InvalidIpError(
      String(c.prefixLen),
      `prefix length must be an integer 0-${width} for IPv${c.version}`,
    );
  }
  assertInAddressSpace(c.version, c.addr, 'network address');
  const hostMask = (1n << BigInt(width - c.prefixLen)) - 1n;
  const start = c.addr & ~hostMask & maxAddress(c.version);
  return { version: c.version, start, end: start | hostMask };
}

/**
 * Decompose an arbitrary inclusive range into the minimal set of aligned CIDR
 * blocks that tile it exactly.
 *
 * Greedy is optimal here: at each step take the largest power-of-two block
 * that is both aligned at `start` and fits within `end`. The output covers the
 * input range exactly — no gaps, no overflow — which is what makes
 * aggregation safe to apply to an allowlist.
 */
export function rangeToCidrs(r: IpRange): Cidr[] {
  assertInAddressSpace(r.version, r.start, 'range start');
  assertInAddressSpace(r.version, r.end, 'range end');
  if (r.start > r.end) {
    throw new InvalidIpError(
      `${r.start}-${r.end}`,
      'range start must be less than or equal to range end',
    );
  }

  const width = bitWidth(r.version);
  const out: Cidr[] = [];
  let start = r.start;

  while (start <= r.end) {
    let prefixLen = width;
    while (prefixLen > 0) {
      const size = 1n << BigInt(width - (prefixLen - 1));
      if (start % size !== 0n) break; // widening would break alignment
      if (start + size - 1n > r.end) break; // widening would overshoot the range
      prefixLen -= 1;
    }
    out.push({ version: r.version, addr: start, prefixLen });
    start += 1n << BigInt(width - prefixLen);
  }

  return out;
}

/**
 * Total ordering over ranges: version, then start, then end.
 *
 * Shaped for `Array.prototype.sort`. Sorting v4 before v6 keeps rule output
 * stable across runs, which keeps diffs of generated WAF payloads readable.
 */
export function compareRanges(a: IpRange, b: IpRange): number {
  if (a.version !== b.version) return a.version - b.version;
  if (a.start !== b.start) return a.start < b.start ? -1 : 1;
  if (a.end !== b.end) return a.end < b.end ? -1 : 1;
  return 0;
}
