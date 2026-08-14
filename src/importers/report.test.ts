import { describe, expect, it } from 'vitest';

import { parseCsv } from './csv.js';
import type { ImportResult, NormalizeOptions } from './normalize.js';
import { ALLOWLIST_WILDCARD_MARKER, normalizeEntries } from './normalize.js';
import { COLLAPSE_LIMIT, formatProblemReport, formatStatsSummary } from './report.js';

function run(text: string, options: NormalizeOptions = {}): ImportResult {
  const { header, rows } = parseCsv(text);
  return normalizeEntries(rows, header, options);
}

function csv(rows: readonly string[]): string {
  return ['ip,vendor_name,notes', ...rows].join('\n');
}

describe('formatProblemReport', () => {
  it('says so plainly when there is nothing wrong', () => {
    const report = formatProblemReport(run(csv(['1.2.3.4,Acme,ok']), { intent: { kind: 'bypass' } }));
    expect(report).toBe('No import problems found (1 rows read, 1 valid).');
  });

  it('summarises the counts in the header line', () => {
    const report = formatProblemReport(run(csv(['bad,Acme,x', '1.2.3.4/24,Acme,y'])));
    expect(report.split('\n')[0]).toContain('2 rows read');
    expect(report.split('\n')[0]).toContain('1 invalid');
  });

  it('groups by kind in the documented order, most actionable first', () => {
    const report = formatProblemReport(
      run(
        csv([
          'not-an-ip,Acme,bad',
          '0.0.0.0/0,Acme,everything',
          '10.1.2.3,Acme,internal',
          '1.2.3.4/24,Acme,hostbits',
          '1.2.3.0/24,Acme,again',
        ]),
        { intent: { kind: 'allowlist' } },
      ),
    );
    const titles = report
      .split('\n')
      .filter((line) => line !== '' && !line.startsWith('  ') && !line.startsWith('Import problems'));
    expect(titles).toEqual([
      'Invalid addresses (must be fixed) (1)',
      'Suspiciously broad ranges (1)',
      'Non-routable / private addresses (1)',
      'CIDRs normalized (host bits were set) (1)',
      'Duplicate entries (ignored) (1)',
      'Redundant entries (already covered) (2)',
    ]);
  });

  it('cites the line number and raw value on every problem line', () => {
    const report = formatProblemReport(run(csv(['not-an-ip,Acme,bad'])));
    expect(report).toContain('line 2: "not-an-ip" —');
  });

  it('renders an empty address cell readably', () => {
    expect(formatProblemReport(run(csv([',Acme,bad'])))).toContain('line 2: (empty) —');
  });

  it('never collapses invalid addresses, however many there are', () => {
    const bad = Array.from({ length: COLLAPSE_LIMIT + 7 }, (_, i) => `bad-${i},Acme,x`);
    const report = formatProblemReport(run(csv(bad)));
    for (let i = 0; i < bad.length; i += 1) {
      expect(report).toContain(`"bad-${i}"`);
    }
    expect(report).not.toContain('and 7 more');
  });

  it('never collapses a /0 in an allowlist, even behind many other broad ranges', () => {
    const broad = Array.from({ length: COLLAPSE_LIMIT + 1 }, (_, i) => `${(i + 1) * 16}.0.0.0/4,Acme,x`);
    const report = formatProblemReport(run(csv([...broad, '0.0.0.0/0,Acme,everything']), {
      intent: { kind: 'allowlist' },
    }));
    expect(report).toContain(ALLOWLIST_WILDCARD_MARKER);
    expect(report).toContain('"0.0.0.0/0"');
    expect(report).toContain('... and 1 more');
  });

  it('collapses a benign kind with an accurate remainder count', () => {
    const privates = Array.from({ length: COLLAPSE_LIMIT + 5 }, (_, i) => `10.0.0.${i + 1},Acme,x`);
    const report = formatProblemReport(run(csv(privates), { intent: { kind: 'bypass' } }));
    const group = report.slice(report.indexOf('Non-routable'));
    const listed = group.split('\n').filter((line) => line.startsWith('  line ')).length;
    expect(listed).toBe(COLLAPSE_LIMIT);
    expect(group).toContain('... and 5 more');
    expect(report).toContain('Non-routable / private addresses (15)');
  });

  it('is stable for the same input', () => {
    const text = csv(['not-an-ip,Acme,bad', '10.1.2.3,Acme,internal', '1.2.3.4/24,Acme,hostbits']);
    expect(formatProblemReport(run(text))).toBe(formatProblemReport(run(text)));
  });
});

describe('formatStatsSummary', () => {
  it('renders one aligned line per statistic', () => {
    const summary = formatStatsSummary(
      run(
        csv([
          '1.2.3.4,Acme,a',
          '1.2.3.4,Acme,duplicate',
          '5.6.7.4/24,Partner,hostbits',
          'nope,Partner,bad',
        ]),
        { intent: { kind: 'bypass' } },
      ),
    );
    expect(summary.split('\n')).toEqual([
      'Rows read:          4',
      'Valid entries:      2',
      'Invalid:            1',
      'Duplicates:         1',
      'Normalized:         1',
      'Addresses covered:  257',
      'After aggregation:  2',
      'Distinct vendors:   2',
    ]);
  });

  it('renders the address count as an exact integer for IPv6-sized totals', () => {
    const summary = formatStatsSummary(run('ip\n2001:db8::/32\n', { intent: { kind: 'bypass' } }));
    expect(summary).toContain(`Addresses covered:  ${(1n << 96n).toString()}`);
  });
});
