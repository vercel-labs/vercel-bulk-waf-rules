import { describe, expect, it } from 'vitest';

import { formatCidr } from '../core/ip.js';
import { parseCsv } from './csv.js';
import type { ImportProblem, ImportResult, NormalizeOptions, ProblemKind } from './normalize.js';
import {
  ALLOWLIST_WILDCARD_MARKER,
  hasFatalProblems,
  isAllowlistWildcardProblem,
  normalizeEntries,
} from './normalize.js';

function run(text: string, options: NormalizeOptions = {}): ImportResult {
  const { header, rows } = parseCsv(text);
  return normalizeEntries(rows, header, options);
}

function kinds(result: ImportResult): ProblemKind[] {
  return result.problems.map((problem) => problem.kind);
}

function of(result: ImportResult, kind: ProblemKind): ImportProblem[] {
  return result.problems.filter((problem) => problem.kind === kind);
}

function cidrTexts(result: ImportResult): string[] {
  return result.entries.map((entry) => formatCidr(entry.cidr));
}

describe('normalizeEntries — valid input', () => {
  it('accepts IPv4, IPv6 and mixed lists, reversing the legacy IPv6 rejection', () => {
    const result = run(
      ['ip,vendor_name,notes', '1.2.3.4,Acme,v4 host', '2001:db8:1::/48,Acme,v6 range', '5.6.7.0/24,Partner,api'].join(
        '\n',
      ),
    );
    expect(result.problems.filter((p) => p.kind === 'invalid-address')).toEqual([]);
    expect(cidrTexts(result)).toEqual(['1.2.3.4/32', '5.6.7.0/24', '2001:db8:1::/48']);
  });

  it('gives a bare address the single-host prefix', () => {
    expect(cidrTexts(run('ip\n1.2.3.4\n'))).toEqual(['1.2.3.4/32']);
    expect(cidrTexts(run('ip\n2001:db8::1\n'))).toEqual(['2001:db8::1/128']);
  });

  it('preserves vendor and note provenance per entry', () => {
    const result = run('ip,vendor_name,notes\n1.2.3.4,Acme Corp,Payment gateway\n');
    expect(result.entries[0]?.vendor).toBe('Acme Corp');
    expect(result.entries[0]?.note).toBe('Payment gateway');
    expect(result.entries[0]?.raw).toBe('1.2.3.4');
    expect(result.entries[0]?.lineNumber).toBe(2);
  });

  it('reads notes from the exporter header layout', () => {
    const result = run('ip,notes,mode,created_on\n1.2.3.4,vendor list,bypass,2024-01-01\n');
    expect(result.entries[0]?.note).toBe('vendor list');
    expect(result.entries[0]?.vendor).toBeUndefined();
  });

  it('omits vendor and note when the cells are blank', () => {
    const result = run('ip,vendor_name,notes\n1.2.3.4,,\n');
    expect(result.entries[0]?.vendor).toBeUndefined();
    expect(result.entries[0]?.note).toBeUndefined();
  });

  it('aggregates contiguous blocks losslessly', () => {
    const result = run('ip\n1.0.0.0/25\n1.0.0.128/25\n');
    expect(cidrTexts(result)).toEqual(['1.0.0.0/25', '1.0.0.128/25']);
    expect(result.aggregated.map(formatCidr)).toEqual(['1.0.0.0/24']);
    expect(result.stats.afterAggregation).toBe(1);
    expect(result.stats.addressesCovered).toBe(256n);
  });
});

describe('normalizeEntries — invalid addresses are collected, not thrown', () => {
  it('records every bad row in one pass with the right line numbers', () => {
    const result = run(
      ['ip', '999.1.1.1', '1.2.3.4', 'not-an-ip', '10.0.0.1/33', '2001:db8::1'].join('\n'),
    );
    const invalid = of(result, 'invalid-address');
    expect(invalid.map((problem) => problem.lineNumber)).toEqual([2, 4, 5]);
    expect(invalid.map((problem) => problem.raw)).toEqual(['999.1.1.1', 'not-an-ip', '10.0.0.1/33']);
    expect(result.stats.invalid).toBe(3);
    expect(result.stats.valid).toBe(2);
  });

  it('flags an empty address cell rather than skipping the row', () => {
    const result = run('ip,vendor_name\n,Acme\n');
    expect(of(result, 'invalid-address')).toHaveLength(1);
    expect(of(result, 'invalid-address')[0]?.message).toContain('empty');
  });

  it('flags a row with more values than headers as row-shape', () => {
    const result = run('ip,vendor_name,notes\n1.2.3.4,Acme, Inc,Payment,extra\n5.6.7.8,Ok,fine\n');
    const shape = of(result, 'row-shape');
    expect(shape).toHaveLength(1);
    expect(shape[0]?.lineNumber).toBe(2);
    expect(shape[0]?.message).toContain('unquoted comma');
    expect(result.stats.valid).toBe(1);
  });
});

describe('normalizeEntries — host-bit normalization', () => {
  it('warns and reports both the written and the masked form', () => {
    const result = run('ip\n1.2.3.4/24\n');
    const problems = of(result, 'normalized-host-bits');
    expect(problems).toHaveLength(1);
    expect(problems[0]?.raw).toBe('1.2.3.4/24');
    expect(problems[0]?.message).toContain('1.2.3.4/24');
    expect(problems[0]?.message).toContain('1.2.3.0/24');
    expect(problems[0]?.message).toContain('256 addresses');
    expect(cidrTexts(result)).toEqual(['1.2.3.0/24']);
    expect(result.stats.normalized).toBe(1);
  });

  it('does not warn when the block is already canonical', () => {
    expect(of(run('ip\n1.2.3.0/24\n'), 'normalized-host-bits')).toEqual([]);
  });
});

describe('normalizeEntries — duplicates and coverage', () => {
  it('cites both line numbers for an exact duplicate and keeps only the first', () => {
    const result = run('ip,vendor_name\n1.2.3.4,First\n1.2.3.4,Second\n');
    const duplicates = of(result, 'duplicate');
    expect(duplicates).toHaveLength(1);
    expect(duplicates[0]?.lineNumber).toBe(3);
    expect(duplicates[0]?.message).toContain('line 2');
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]?.vendor).toBe('First');
    expect(result.stats.duplicates).toBe(1);
  });

  it('treats differently-written but equal CIDRs as duplicates', () => {
    const result = run('ip\n2001:db8::1\n2001:0db8:0000:0000:0000:0000:0000:0001\n');
    expect(of(result, 'duplicate')).toHaveLength(1);
    expect(result.entries).toHaveLength(1);
  });

  it('flags an entry covered by a broader listed block but keeps it', () => {
    const result = run('ip\n10.0.0.0/8\n10.0.0.5\n', { intent: { kind: 'bypass' } });
    const covered = of(result, 'covered-by-cidr');
    expect(covered).toHaveLength(1);
    expect(covered[0]?.lineNumber).toBe(3);
    expect(covered[0]?.message).toContain('10.0.0.0/8');
    expect(covered[0]?.message).toContain('line 2');
    expect(result.entries).toHaveLength(2);
    expect(result.aggregated.map(formatCidr)).toEqual(['10.0.0.0/8']);
  });

  it('does not flag coverage across IP versions', () => {
    const result = run('ip\n::/0\n1.2.3.4\n', { intent: { kind: 'bypass' } });
    expect(of(result, 'covered-by-cidr')).toEqual([]);
  });
});

describe('normalizeEntries — suspicious ranges', () => {
  it('makes a /0 on an allowlist a loud, distinct problem', () => {
    const result = run('ip\n0.0.0.0/0\n', { intent: { kind: 'allowlist' } });
    const suspicious = of(result, 'suspicious-range');
    expect(suspicious).toHaveLength(1);
    const problem = suspicious[0];
    expect(problem?.message).toContain(ALLOWLIST_WILDCARD_MARKER);
    expect(problem?.message).toContain('defeats the rule');
    expect(problem === undefined ? false : isAllowlistWildcardProblem(problem)).toBe(true);
  });

  it('treats an IPv6 /0 on an allowlist the same way', () => {
    const result = run('ip\n::/0\n', { intent: { kind: 'allowlist' } });
    expect(of(result, 'suspicious-range')[0]?.message).toContain(ALLOWLIST_WILDCARD_MARKER);
  });

  it('still flags a /0 on a bypass list, but without the allowlist marker', () => {
    const result = run('ip\n0.0.0.0/0\n', { intent: { kind: 'bypass' } });
    const suspicious = of(result, 'suspicious-range');
    expect(suspicious).toHaveLength(1);
    expect(suspicious[0]?.message).not.toContain(ALLOWLIST_WILDCARD_MARKER);
  });

  it('warns on anything wider than /8 for an IPv4 allowlist', () => {
    const result = run('ip\n16.0.0.0/4\n11.0.0.0/8\n', { intent: { kind: 'allowlist' } });
    const suspicious = of(result, 'suspicious-range');
    expect(suspicious.map((problem) => problem.raw)).toEqual(['16.0.0.0/4']);
  });

  it('warns on anything wider than /32 for an IPv6 allowlist', () => {
    const result = run('ip\n2001::/16\n2400::/32\n', { intent: { kind: 'allowlist' } });
    expect(of(result, 'suspicious-range').map((problem) => problem.raw)).toEqual(['2001::/16']);
  });

  it('does not apply the allowlist breadth threshold to a bypass list', () => {
    const result = run('ip\n16.0.0.0/4\n', { intent: { kind: 'bypass' } });
    expect(of(result, 'suspicious-range')).toEqual([]);
  });

  it('honours an explicit threshold override', () => {
    const result = run('ip\n11.0.0.0/8\n', {
      intent: { kind: 'bypass' },
      suspiciousPrefixV4: 16,
    });
    expect(of(result, 'suspicious-range')).toHaveLength(1);
  });
});

describe('normalizeEntries — private addresses', () => {
  it('flags RFC1918, loopback, link-local, ULA and documentation ranges', () => {
    const result = run(
      ['ip', '10.1.2.3', '172.16.5.5', '192.168.1.1', '127.0.0.1', '169.254.1.1', 'fd00::1', 'fe80::1', '2001:db8::1', '8.8.8.8'].join(
        '\n',
      ),
      { intent: { kind: 'bypass' } },
    );
    expect(of(result, 'private-address').map((problem) => problem.raw).sort()).toEqual(
      ['10.1.2.3', '127.0.0.1', '169.254.1.1', '172.16.5.5', '192.168.1.1', '2001:db8::1', 'fd00::1', 'fe80::1'].sort(),
    );
  });

  it('warns rather than rejecting', () => {
    const result = run('ip\n10.1.2.3\n', { intent: { kind: 'bypass' } });
    expect(result.entries).toHaveLength(1);
    expect(result.stats.invalid).toBe(0);
  });

  it('can be suppressed', () => {
    const result = run('ip\n10.1.2.3\n', { intent: { kind: 'bypass' }, flagPrivate: false });
    expect(of(result, 'private-address')).toEqual([]);
  });
});

describe('normalizeEntries — determinism', () => {
  const addresses = [
    '2001:db8::1',
    '1.2.3.4',
    '10.0.0.0/8',
    '5.6.7.0/24',
    '2001:db8:1::/48',
    '203.0.113.9',
  ];

  function resultFor(order: readonly string[]): ImportResult {
    return run(['ip', ...order].join('\n'), { intent: { kind: 'bypass' } });
  }

  it('produces identical entries, aggregation and stats under row shuffling', () => {
    const baseline = resultFor(addresses);
    const shuffles = [
      [...addresses].reverse(),
      [addresses[3], addresses[0], addresses[5], addresses[1], addresses[4], addresses[2]].filter(
        (value): value is string => value !== undefined,
      ),
    ];

    for (const order of shuffles) {
      const shuffled = resultFor(order);
      expect(cidrTexts(shuffled)).toEqual(cidrTexts(baseline));
      expect(shuffled.aggregated.map(formatCidr)).toEqual(baseline.aggregated.map(formatCidr));
      expect(shuffled.stats).toEqual(baseline.stats);
      expect(kinds(shuffled).sort()).toEqual(kinds(baseline).sort());
    }
  });

  it('sorts IPv4 before IPv6 and ascending within a family', () => {
    expect(cidrTexts(resultFor(addresses))).toEqual([
      '1.2.3.4/32',
      '5.6.7.0/24',
      '10.0.0.0/8',
      '203.0.113.9/32',
      '2001:db8::1/128',
      '2001:db8:1::/48',
    ]);
  });

  it('orders problems by line number', () => {
    const result = run('ip\nbad-one\n1.2.3.4/24\nbad-two\n');
    expect(result.problems.map((problem) => problem.lineNumber)).toEqual([2, 3, 4]);
  });
});

describe('normalizeEntries — stats', () => {
  it('counts distinct non-blank vendors across duplicates and blanks', () => {
    const result = run(
      [
        'ip,vendor_name',
        '1.2.3.4,Acme',
        '5.6.7.8,Acme',
        '9.9.9.9,  Acme  ',
        '8.8.8.8,Partner',
        '4.4.4.4,',
        '2.2.2.2,   ',
      ].join('\n'),
      { intent: { kind: 'bypass' } },
    );
    expect(result.stats.vendorCount).toBe(2);
    expect(result.stats.valid).toBe(6);
  });

  it('reports rowsRead excluding the header, comments and blank lines', () => {
    const result = run('# note\nip\n\n1.2.3.4\n# another\n5.6.7.8\n');
    expect(result.stats.rowsRead).toBe(2);
  });

  it('counts the union of addresses, not the sum of block sizes', () => {
    const result = run('ip\n10.0.0.0/8\n10.0.0.5\n', { intent: { kind: 'bypass' } });
    expect(result.stats.addressesCovered).toBe(1n << 24n);
  });
});

describe('hasFatalProblems', () => {
  it('is fatal in strict mode for invalid addresses', () => {
    const result = run('ip\nnot-an-ip\n');
    expect(hasFatalProblems(result, true)).toBe(true);
    expect(hasFatalProblems(result, false)).toBe(false);
  });

  it('is fatal in strict mode for malformed rows', () => {
    const result = run('ip,vendor_name,notes\n1.2.3.4,Acme, Inc,Payment,extra\n');
    expect(hasFatalProblems(result, true)).toBe(true);
  });

  it('is never fatal for advisory problems, even in strict mode', () => {
    const result = run('ip\n0.0.0.0/0\n10.0.0.5\n1.2.3.4/24\n1.2.3.4/24\n');
    expect(of(result, 'invalid-address')).toEqual([]);
    expect(hasFatalProblems(result, true)).toBe(false);
  });

  it('does not throw from the parser itself', () => {
    expect(() => run('ip\nnot-an-ip\n', { strict: true })).not.toThrow();
  });
});
