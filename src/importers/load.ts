/**
 * File-backed entry point for the import pipeline.
 *
 * The filesystem arrives as an injected {@link ImportIo} and this module never
 * imports `node:fs`. That keeps the whole importer layer pure and testable
 * without touching a real disk, and it lets a future caller feed the same
 * pipeline from stdin, an HTTP body, or an in-memory fixture without a
 * temp-file dance.
 */

import { parseCsv } from './csv.js';
import type { ImportResult, NormalizeOptions } from './normalize.js';
import { normalizeEntries } from './normalize.js';

/** The only filesystem capability the importer needs. */
export interface ImportIo {
  readFile(path: string): Promise<string>;
}

/** Whether the path was absent, or present but unreadable. */
export type CsvLoadErrorKind = 'not-found' | 'unreadable';

/**
 * A read failure, carrying the path and which of the two failure modes it was.
 *
 * The distinction is worth a discriminant because the fixes differ: `not-found`
 * is a typo or a wrong working directory, while `unreadable` is a permission or
 * encoding problem the operator may need to escalate.
 */
export class CsvLoadError extends Error {
  readonly kind: CsvLoadErrorKind;
  readonly path: string;

  constructor(kind: CsvLoadErrorKind, path: string, detail: string) {
    super(
      kind === 'not-found'
        ? `CSV file not found: ${path}`
        : `CSV file could not be read: ${path} (${detail})`,
    );
    this.name = 'CsvLoadError';
    this.kind = kind;
    this.path = path;
  }
}

const NOT_FOUND_CODES: ReadonlySet<string> = new Set(['ENOENT', 'ENOTDIR']);

function errorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const code: unknown = Reflect.get(error, 'code');
  return typeof code === 'string' ? code : undefined;
}

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Read a CSV through the injected IO and run it through the full import pipeline. */
export async function loadCsvFile(
  path: string,
  options: NormalizeOptions,
  io: ImportIo,
): Promise<ImportResult> {
  let text: string;
  try {
    text = await io.readFile(path);
  } catch (error) {
    const code = errorCode(error);
    const kind: CsvLoadErrorKind =
      code !== undefined && NOT_FOUND_CODES.has(code) ? 'not-found' : 'unreadable';
    throw new CsvLoadError(kind, path, errorDetail(error));
  }

  const { header, rows } = parseCsv(text);
  return normalizeEntries(rows, header, options);
}
