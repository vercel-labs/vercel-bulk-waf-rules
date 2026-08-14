import { describe, expect, it, vi } from 'vitest';

import { parseCidr } from '../core/ip.js';
import {
  LockoutError,
  assertNotLockedOut,
  resolveEgressIp,
  type EgressFetch,
} from './lockout-guard.js';

const cidrs = (...inputs: string[]) => inputs.map((i) => parseCidr(i));

describe('resolveEgressIp', () => {
  it('returns the trimmed IP from the injected transport', async () => {
    const fetchImpl: EgressFetch = vi.fn(async () => '203.0.113.7\n');
    await expect(resolveEgressIp(fetchImpl)).resolves.toEqual({ ok: true, ip: '203.0.113.7' });
  });

  it('accepts an IPv6 answer', async () => {
    const fetchImpl: EgressFetch = async () => '2001:db8::1';
    await expect(resolveEgressIp(fetchImpl)).resolves.toEqual({ ok: true, ip: '2001:db8::1' });
  });

  it('falls through to the second endpoint when the first fails', async () => {
    const fetchImpl = vi
      .fn<EgressFetch>()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockResolvedValueOnce('198.51.100.9');

    await expect(resolveEgressIp(fetchImpl)).resolves.toEqual({ ok: true, ip: '198.51.100.9' });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('returns a failure result instead of throwing when every endpoint fails', async () => {
    const fetchImpl: EgressFetch = async () => {
      throw new Error('offline');
    };
    const result = await resolveEgressIp(fetchImpl);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('offline');
  });

  it('rejects a non-IP body rather than trusting it', async () => {
    const fetchImpl: EgressFetch = async () => '<html>captive portal</html>';
    const result = await resolveEgressIp(fetchImpl);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('unparseable');
  });

  it('never performs a real network call when a transport is injected', async () => {
    const fetchImpl = vi.fn<EgressFetch>().mockResolvedValue('203.0.113.7');
    await resolveEgressIp(fetchImpl);
    expect(fetchImpl).toHaveBeenCalled();
  });
});

describe('assertNotLockedOut', () => {
  it('passes when the egress IP is inside the allowlist', () => {
    const result = assertNotLockedOut({
      allowlist: cidrs('203.0.113.0/24'),
      egress: '203.0.113.7',
      extraProtected: [],
      force: false,
    });
    expect(result.warnings).toEqual([]);
  });

  it('throws when the egress IP is outside the allowlist', () => {
    try {
      assertNotLockedOut({
        allowlist: cidrs('203.0.113.0/24'),
        egress: '198.51.100.1',
        extraProtected: [],
        force: false,
      });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(LockoutError);
      expect((err as LockoutError).unprotected).toEqual(['198.51.100.1']);
      expect((err as LockoutError).message).toContain('198.51.100.1');
      expect((err as LockoutError).message).toContain('203.0.113.0/24');
      expect((err as LockoutError).egressResolved).toBe(true);
    }
  });

  it('fails closed when egress resolution failed and force is not set', () => {
    try {
      assertNotLockedOut({
        allowlist: cidrs('203.0.113.0/24'),
        extraProtected: [],
        force: false,
      });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(LockoutError);
      expect((err as LockoutError).egressResolved).toBe(false);
      expect((err as LockoutError).message).toContain('Could not determine your public egress IP');
      expect((err as LockoutError).message).toContain('--force');
    }
  });

  it('passes with a warning when egress resolution failed and force is set', () => {
    const result = assertNotLockedOut({
      allowlist: cidrs('203.0.113.0/24'),
      extraProtected: [],
      force: true,
    });
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('NOT verified');
  });

  it('downgrades an uncovered address to a warning under force', () => {
    const result = assertNotLockedOut({
      allowlist: cidrs('203.0.113.0/24'),
      egress: '198.51.100.1',
      extraProtected: [],
      force: true,
    });
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('198.51.100.1');
  });

  it('honors extraProtected addresses', () => {
    expect(() =>
      assertNotLockedOut({
        allowlist: cidrs('203.0.113.0/24'),
        egress: '203.0.113.7',
        extraProtected: ['10.0.0.5'],
        force: false,
      }),
    ).toThrow(LockoutError);
  });

  it('passes when every extraProtected address is covered', () => {
    const result = assertNotLockedOut({
      allowlist: cidrs('203.0.113.0/24', '10.0.0.0/8'),
      egress: '203.0.113.7',
      extraProtected: ['10.0.0.5', '10.255.255.255'],
      force: false,
    });
    expect(result.warnings).toEqual([]);
  });

  it('reports every uncovered address at once, not just the first', () => {
    try {
      assertNotLockedOut({
        allowlist: cidrs('203.0.113.0/24'),
        egress: '198.51.100.1',
        extraProtected: ['10.0.0.5', '172.16.0.1'],
        force: false,
      });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect((err as LockoutError).unprotected).toEqual([
        '198.51.100.1',
        '10.0.0.5',
        '172.16.0.1',
      ]);
    }
  });

  it('treats an unparseable protected address as uncovered', () => {
    try {
      assertNotLockedOut({
        allowlist: cidrs('0.0.0.0/0'),
        egress: '203.0.113.7',
        extraProtected: ['not-an-ip'],
        force: false,
      });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect((err as LockoutError).unprotected[0]).toContain('unparseable');
    }
  });

  it('rejects everything against an empty allowlist', () => {
    expect(() =>
      assertNotLockedOut({
        allowlist: [],
        egress: '203.0.113.7',
        extraProtected: [],
        force: false,
      }),
    ).toThrow(LockoutError);
  });

  it('does not treat an IPv4 egress as covered by an IPv6 allowlist', () => {
    expect(() =>
      assertNotLockedOut({
        allowlist: cidrs('2001:db8::/32'),
        egress: '203.0.113.7',
        extraProtected: [],
        force: false,
      }),
    ).toThrow(LockoutError);
  });

  it('covers an IPv6 egress inside an IPv6 allowlist', () => {
    expect(
      assertNotLockedOut({
        allowlist: cidrs('2001:db8::/32'),
        egress: '2001:db8:dead:beef::1',
        extraProtected: [],
        force: false,
      }).warnings,
    ).toEqual([]);
  });
});

describe('CIDR boundary classification', () => {
  it('covers the first and last address of an IPv4 block', () => {
    const allowlist = cidrs('203.0.113.0/24');
    for (const egress of ['203.0.113.0', '203.0.113.255']) {
      expect(
        assertNotLockedOut({ allowlist, egress, extraProtected: [], force: false }).warnings,
      ).toEqual([]);
    }
  });

  it('excludes the addresses immediately outside an IPv4 block', () => {
    const allowlist = cidrs('203.0.113.0/24');
    for (const egress of ['203.0.112.255', '203.0.114.0']) {
      expect(() =>
        assertNotLockedOut({ allowlist, egress, extraProtected: [], force: false }),
      ).toThrow(LockoutError);
    }
  });

  it('handles a single-host /32 exactly', () => {
    const allowlist = cidrs('203.0.113.7/32');
    expect(
      assertNotLockedOut({
        allowlist,
        egress: '203.0.113.7',
        extraProtected: [],
        force: false,
      }).warnings,
    ).toEqual([]);
    expect(() =>
      assertNotLockedOut({
        allowlist,
        egress: '203.0.113.8',
        extraProtected: [],
        force: false,
      }),
    ).toThrow(LockoutError);
  });

  it('covers the first and last address of an IPv6 block', () => {
    const allowlist = cidrs('2001:db8::/126');
    for (const egress of ['2001:db8::', '2001:db8::3']) {
      expect(
        assertNotLockedOut({ allowlist, egress, extraProtected: [], force: false }).warnings,
      ).toEqual([]);
    }
    expect(() =>
      assertNotLockedOut({
        allowlist,
        egress: '2001:db8::4',
        extraProtected: [],
        force: false,
      }),
    ).toThrow(LockoutError);
  });

  it('classifies correctly across two adjacent blocks that merge', () => {
    const allowlist = cidrs('10.0.0.0/25', '10.0.0.128/25');
    for (const egress of ['10.0.0.0', '10.0.0.127', '10.0.0.128', '10.0.0.255']) {
      expect(
        assertNotLockedOut({ allowlist, egress, extraProtected: [], force: false }).warnings,
      ).toEqual([]);
    }
    expect(() =>
      assertNotLockedOut({
        allowlist,
        egress: '10.0.1.0',
        extraProtected: [],
        force: false,
      }),
    ).toThrow(LockoutError);
  });
});
