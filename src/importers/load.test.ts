import { describe, expect, it } from 'vitest';

import { formatCidr } from '../core/ip.js';
import { CsvParseError } from './csv.js';
import type { ImportIo } from './load.js';
import { CsvLoadError, loadCsvFile } from './load.js';

function ioReturning(text: string, seen: string[] = []): ImportIo {
  return {
    readFile(path: string): Promise<string> {
      seen.push(path);
      return Promise.resolve(text);
    },
  };
}

function ioThrowing(error: unknown): ImportIo {
  return {
    readFile(): Promise<string> {
      return Promise.reject(error);
    },
  };
}

function withCode(message: string, code: string): Error {
  return Object.assign(new Error(message), { code });
}

describe('loadCsvFile', () => {
  it('reads through the injected IO and runs the full pipeline', async () => {
    const seen: string[] = [];
    const io = ioReturning('ip,vendor_name,notes\n1.2.3.4,Acme,a\n5.6.7.0/24,Partner,b\n', seen);

    const result = await loadCsvFile('/vendors/list.csv', { intent: { kind: 'bypass' } }, io);

    expect(seen).toEqual(['/vendors/list.csv']);
    expect(result.entries.map((entry) => formatCidr(entry.cidr))).toEqual([
      '1.2.3.4/32',
      '5.6.7.0/24',
    ]);
    expect(result.stats.vendorCount).toBe(2);
  });

  it('passes normalize options through', async () => {
    const io = ioReturning('ip\n0.0.0.0/0\n');
    const allowlist = await loadCsvFile('a.csv', { intent: { kind: 'allowlist' } }, io);
    const bypass = await loadCsvFile('a.csv', { intent: { kind: 'bypass' } }, io);
    expect(allowlist.problems[0]?.message).not.toBe(bypass.problems[0]?.message);
  });

  it('reports a missing file as not-found', async () => {
    const io = ioThrowing(withCode("ENOENT: no such file or directory, open 'gone.csv'", 'ENOENT'));
    await expect(loadCsvFile('gone.csv', {}, io)).rejects.toBeInstanceOf(CsvLoadError);

    const error = await loadCsvFile('gone.csv', {}, io).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(CsvLoadError);
    const loadError = error as CsvLoadError;
    expect(loadError.kind).toBe('not-found');
    expect(loadError.path).toBe('gone.csv');
    expect(loadError.message).toContain('gone.csv');
  });

  it('treats a path component that is not a directory as not-found', async () => {
    const io = ioThrowing(withCode('ENOTDIR: not a directory', 'ENOTDIR'));
    const error = await loadCsvFile('file.txt/list.csv', {}, io).catch((caught: unknown) => caught);
    expect((error as CsvLoadError).kind).toBe('not-found');
  });

  it('reports a permission failure as unreadable and keeps the underlying detail', async () => {
    const io = ioThrowing(withCode('EACCES: permission denied', 'EACCES'));
    const error = await loadCsvFile('/root/list.csv', {}, io).catch((caught: unknown) => caught);
    const loadError = error as CsvLoadError;
    expect(loadError.kind).toBe('unreadable');
    expect(loadError.message).toContain('/root/list.csv');
    expect(loadError.message).toContain('permission denied');
  });

  it('treats a non-Error rejection as unreadable', async () => {
    const error = await loadCsvFile('x.csv', {}, ioThrowing('boom')).catch(
      (caught: unknown) => caught,
    );
    expect((error as CsvLoadError).kind).toBe('unreadable');
    expect((error as CsvLoadError).message).toContain('boom');
  });

  it('lets structural CSV errors propagate untouched', async () => {
    const io = ioReturning('hostname,owner\nexample.com,me\n');
    const error = await loadCsvFile('bad.csv', {}, io).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(CsvParseError);
    expect((error as CsvParseError).kind).toBe('missing-address-column');
  });

  it('collects row problems rather than rejecting', async () => {
    const io = ioReturning('ip\nnot-an-ip\n1.2.3.4\n');
    const result = await loadCsvFile('mixed.csv', { strict: true }, io);
    expect(result.stats.invalid).toBe(1);
    expect(result.stats.valid).toBe(1);
  });
});
