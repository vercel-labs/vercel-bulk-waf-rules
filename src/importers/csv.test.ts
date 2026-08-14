import { describe, expect, it } from 'vitest';

import {
  CsvParseError,
  cellAt,
  normalizeHeaderCell,
  parseCsv,
  resolveColumns,
} from './csv.js';

function rowValues(text: string): string[][] {
  return parseCsv(text).rows.map((row) => row.values);
}

function lineNumbers(text: string): number[] {
  return parseCsv(text).rows.map((row) => row.lineNumber);
}

describe('parseCsv', () => {
  it('parses the legacy three-column format', () => {
    const doc = parseCsv('ip,vendor_name,notes\n1.2.3.4,Acme Corp,Payment gateway\n');
    expect(doc.header).toEqual(['ip', 'vendor_name', 'notes']);
    expect(doc.rows).toEqual([
      { lineNumber: 2, values: ['1.2.3.4', 'Acme Corp', 'Payment gateway'] },
    ]);
  });

  it('parses the exporter format emitted by scripts/exports/*.sh', () => {
    const doc = parseCsv('ip,notes,mode,created_on\n1.2.3.4,vendor list,bypass,2024-01-01\n');
    expect(doc.header).toEqual(['ip', 'notes', 'mode', 'created_on']);
    expect(doc.rows[0]?.values).toEqual(['1.2.3.4', 'vendor list', 'bypass', '2024-01-01']);
  });

  it('parses the cloudflare --convert format', () => {
    const doc = parseCsv('ip,note\n"1.2.3.4","vendor"\n');
    expect(doc.header).toEqual(['ip', 'note']);
    expect(doc.rows[0]?.values).toEqual(['1.2.3.4', 'vendor']);
  });

  it('keeps commas inside quoted fields', () => {
    expect(rowValues('ip,notes\n1.2.3.4,"Acme, Inc, and friends"\n')).toEqual([
      ['1.2.3.4', 'Acme, Inc, and friends'],
    ]);
  });

  it('unescapes doubled quotes', () => {
    expect(rowValues('ip,notes\n1.2.3.4,"he said ""hi"""\n')).toEqual([
      ['1.2.3.4', 'he said "hi"'],
    ]);
  });

  it('keeps a bare doubled-quote field as an empty string', () => {
    expect(rowValues('ip,notes\n1.2.3.4,""\n')).toEqual([['1.2.3.4', '']]);
  });

  it('keeps newlines inside quoted fields and advances the line counter past them', () => {
    const text = 'ip,notes\n1.2.3.4,"line one\nline two"\n9.9.9.9,after\n';
    expect(rowValues(text)).toEqual([
      ['1.2.3.4', 'line one\nline two'],
      ['9.9.9.9', 'after'],
    ]);
    expect(lineNumbers(text)).toEqual([2, 4]);
  });

  it('handles CRLF line endings', () => {
    const doc = parseCsv('ip,notes\r\n1.2.3.4,alpha\r\n5.6.7.8,beta\r\n');
    expect(doc.header).toEqual(['ip', 'notes']);
    expect(doc.rows.map((row) => row.values)).toEqual([
      ['1.2.3.4', 'alpha'],
      ['5.6.7.8', 'beta'],
    ]);
  });

  it('strips a UTF-8 BOM from the first header cell', () => {
    const doc = parseCsv('\ufeffip,vendor_name\n1.2.3.4,Acme\n');
    expect(doc.header[0]).toBe('ip');
    expect(resolveColumns(doc.header).address).toBe(0);
  });

  it('skips comment lines and blank lines, preserving real line numbers', () => {
    const text = ['# vendor list', '', 'ip,notes', '  # indented comment', '', '1.2.3.4,a', '9.9.9.9,b'].join(
      '\n',
    );
    const doc = parseCsv(text);
    expect(doc.header).toEqual(['ip', 'notes']);
    expect(doc.rows.map((row) => row.lineNumber)).toEqual([6, 7]);
  });

  it('parses a final row with no trailing newline', () => {
    expect(rowValues('ip,notes\n1.2.3.4,last')).toEqual([['1.2.3.4', 'last']]);
  });

  it('trims whitespace around unquoted and quoted values alike', () => {
    expect(rowValues('ip , notes\n  1.2.3.4  ,   "  spaced  "  \n')).toEqual([
      ['1.2.3.4', '  spaced  '],
    ]);
  });

  it('reports rows with more values than headers verbatim so normalize can flag them', () => {
    const doc = parseCsv('ip,vendor_name,notes\n1.2.3.4,Acme, Inc,Payment,extra\n');
    expect(doc.rows[0]?.values).toHaveLength(5);
  });

  it('tolerates rows shorter than the header', () => {
    expect(rowValues('ip,vendor_name,notes\n1.2.3.4\n')).toEqual([['1.2.3.4']]);
  });

  it('throws a fatal missing-header error for an empty file', () => {
    expect(() => parseCsv('')).toThrowError(CsvParseError);
    try {
      parseCsv('');
    } catch (error) {
      expect(error).toBeInstanceOf(CsvParseError);
      expect((error as CsvParseError).kind).toBe('missing-header');
    }
  });

  it('throws a fatal missing-header error for a comments-only file', () => {
    expect(() => parseCsv('# nothing here\n\n')).toThrowError(/no header row/);
  });
});

describe('normalizeHeaderCell', () => {
  it('folds case, whitespace and hyphens', () => {
    expect(normalizeHeaderCell('  IP Address ')).toBe('ip_address');
    expect(normalizeHeaderCell('ip-address')).toBe('ip_address');
    expect(normalizeHeaderCell('IP__ADDRESS')).toBe('ip_address');
  });
});

describe('resolveColumns', () => {
  it('accepts every address alias', () => {
    for (const alias of ['ip', 'ip_address', 'address', 'cidr']) {
      expect(resolveColumns([alias, 'notes']).address).toBe(0);
    }
  });

  it('accepts every vendor alias', () => {
    for (const alias of ['vendor_name', 'vendor', 'name']) {
      expect(resolveColumns(['ip', alias]).vendor).toBe(1);
    }
  });

  it('accepts every note alias', () => {
    for (const alias of ['notes', 'note', 'description']) {
      expect(resolveColumns(['ip', alias]).note).toBe(1);
    }
  });

  it('matches headers case- and whitespace-insensitively', () => {
    const columns = resolveColumns([' IP Address ', 'Vendor Name', 'NOTES']);
    expect(columns).toEqual({ address: 0, vendor: 1, note: 2 });
  });

  it('resolves the exporter header by name, not position', () => {
    const columns = resolveColumns(['ip', 'notes', 'mode', 'created_on']);
    expect(columns.address).toBe(0);
    expect(columns.note).toBe(1);
    expect(columns.vendor).toBeUndefined();
  });

  it('omits optional columns that are absent', () => {
    expect(resolveColumns(['ip'])).toEqual({ address: 0 });
  });

  it('throws naming the headers it actually found when the address column is missing', () => {
    try {
      resolveColumns(['hostname', 'owner']);
      expect.unreachable('expected a CsvParseError');
    } catch (error) {
      expect(error).toBeInstanceOf(CsvParseError);
      const parseError = error as CsvParseError;
      expect(parseError.kind).toBe('missing-address-column');
      expect(parseError.message).toContain('"hostname"');
      expect(parseError.message).toContain('"owner"');
      expect(parseError.message).toContain('ip, ip_address, address, cidr');
    }
  });
});

describe('cellAt', () => {
  it('returns an empty string for absent columns and short rows', () => {
    expect(cellAt(['a'], undefined)).toBe('');
    expect(cellAt(['a'], 3)).toBe('');
    expect(cellAt(['a', 'b'], 1)).toBe('b');
  });
});
