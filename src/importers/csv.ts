/**
 * A minimal, correct CSV reader for vendor IP lists.
 *
 * This is hand-written rather than pulled from npm for the same reason
 * `core/ip.ts` is: the tool runs on machines that hold WAF credentials, and a
 * CSV reader is ~150 lines of state machine. A transitive dependency here buys
 * nothing and costs supply-chain surface.
 *
 * Scope: RFC 4180 (quoted fields, embedded commas / quotes / newlines, `""`
 * escapes) plus the three conventions the legacy bash tool established and
 * customers already have on disk — `#` comments, blank lines, and whitespace
 * trimmed around every value.
 *
 * Every row carries its **source line number**. That is not a nicety: an
 * operator fixing a 500-row vendor list edits it by hand in an editor, so a
 * diagnostic that cannot cite a line is a diagnostic they cannot act on.
 */

/** One parsed data row, tagged with the 1-based physical line it started on. */
export interface CsvRow {
  /** 1-based line where this record *begins* (a quoted field may span more). */
  readonly lineNumber: number;
  readonly values: string[];
}

/** Result of {@link parseCsv}: the header cells plus every data row. */
export interface CsvDocument {
  readonly header: string[];
  readonly rows: CsvRow[];
}

/** Discriminator for the two fatal, whole-file CSV failures. */
export type CsvParseErrorKind = 'missing-header' | 'missing-address-column';

/**
 * A structural problem that makes the whole file unusable.
 *
 * Deliberately rare: only a missing header row and a missing address column
 * qualify. Everything else — a bad IP, a ragged row — is a per-row problem
 * collected by `normalizeEntries`, because an operator needs the full list of
 * what is wrong in one pass.
 */
export class CsvParseError extends Error {
  readonly kind: CsvParseErrorKind;

  constructor(kind: CsvParseErrorKind, message: string) {
    super(message);
    this.name = 'CsvParseError';
    this.kind = kind;
  }
}

/** Header cells accepted for the address column, in preference order. */
export const ADDRESS_COLUMN_ALIASES: readonly string[] = ['ip', 'ip_address', 'address', 'cidr'];

/** Header cells accepted for the vendor column, in preference order. */
export const VENDOR_COLUMN_ALIASES: readonly string[] = ['vendor_name', 'vendor', 'name'];

/**
 * Header cells accepted for the note column, in preference order.
 *
 * `notes` first because that is what all four `scripts/exports/*.sh`
 * converters emit (`ip,notes,mode,created_on`); `note` second because
 * `cloudflare-export.sh --convert` emits `ip,note`.
 */
export const NOTE_COLUMN_ALIASES: readonly string[] = ['notes', 'note', 'description'];

/** Zero-based indices of the columns we care about. Absent optional columns are omitted. */
export interface ColumnMap {
  readonly address: number;
  readonly vendor?: number;
  readonly note?: number;
}

const BOM = '\ufeff';

function stripBom(text: string): string {
  return text.startsWith(BOM) ? text.slice(BOM.length) : text;
}

function isHorizontalSpace(ch: string): boolean {
  return ch === ' ' || ch === '\t';
}

/**
 * Canonical form of a header cell for matching: lowercased, trimmed, and with
 * runs of spaces / hyphens folded to a single underscore.
 *
 * So `"  IP Address "`, `"ip-address"` and `"IP_ADDRESS"` all resolve to the
 * same column. Header spelling varies across the four exporters and across
 * whatever the customer hand-edited, and none of that variation is meaningful.
 */
export function normalizeHeaderCell(cell: string): string {
  return cell
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
    .replace(/_+/g, '_');
}

function findColumn(header: readonly string[], aliases: readonly string[]): number | undefined {
  const normalized = header.map(normalizeHeaderCell);
  for (const alias of aliases) {
    const index = normalized.indexOf(alias);
    if (index !== -1) return index;
  }
  return undefined;
}

/**
 * Resolve the address / vendor / note columns from the header row.
 *
 * Resolution is by *name*, never by position, because the legacy hand-written
 * format (`ip,vendor_name,notes`) and the exporter format
 * (`ip,notes,mode,created_on`) disagree on what column 2 means — reading
 * positionally would silently file every Akamai list name under "vendor".
 *
 * @throws {CsvParseError} when no address column can be found. That is fatal:
 * without addresses there is nothing to import, and guessing (e.g. "column 0
 * is probably the IP") risks building a firewall rule out of the wrong field.
 */
export function resolveColumns(header: readonly string[]): ColumnMap {
  const address = findColumn(header, ADDRESS_COLUMN_ALIASES);
  if (address === undefined) {
    const found = header.length === 0 ? '(none)' : header.map((h) => JSON.stringify(h)).join(', ');
    throw new CsvParseError(
      'missing-address-column',
      `CSV has no address column. Expected one of: ${ADDRESS_COLUMN_ALIASES.join(', ')}. ` +
        `Headers found: ${found}.`,
    );
  }
  const vendor = findColumn(header, VENDOR_COLUMN_ALIASES);
  const note = findColumn(header, NOTE_COLUMN_ALIASES);
  return {
    address,
    ...(vendor === undefined ? {} : { vendor }),
    ...(note === undefined ? {} : { note }),
  };
}

/** Read `values[index]`, tolerating a short row and an absent column. */
export function cellAt(values: readonly string[], index: number | undefined): string {
  if (index === undefined) return '';
  return values[index] ?? '';
}

interface ScanState {
  pos: number;
  line: number;
}

/**
 * Consume one record starting at `state.pos`, returning its fields.
 *
 * Field grammar, per field: optional horizontal whitespace, then either a
 * quoted run (in which `""` is a literal quote and raw newlines are content)
 * or an unquoted run terminated by `,` / newline / EOF. Either way the value is
 * trimmed of surrounding horizontal whitespace — quoted content is preserved
 * verbatim inside the quotes.
 */
function readRecord(text: string, state: ScanState): string[] {
  const values: string[] = [];

  for (;;) {
    while (state.pos < text.length && isHorizontalSpace(text[state.pos] ?? '')) {
      state.pos += 1;
    }

    let value = '';
    let quoted = false;

    if (text[state.pos] === '"') {
      quoted = true;
      state.pos += 1;
      for (;;) {
        if (state.pos >= text.length) break; // unterminated quote: take what we have
        const ch = text[state.pos] ?? '';
        if (ch === '"') {
          if (text[state.pos + 1] === '"') {
            value += '"';
            state.pos += 2;
            continue;
          }
          state.pos += 1;
          break;
        }
        if (ch === '\n') state.line += 1;
        value += ch;
        state.pos += 1;
      }
    }

    // Trailing run after a closing quote (or the whole field, when unquoted).
    let tail = '';
    for (;;) {
      if (state.pos >= text.length) break;
      const ch = text[state.pos] ?? '';
      if (ch === ',' || ch === '\n') break;
      tail += ch;
      state.pos += 1;
    }
    // A CRLF line ending leaves a lone \r at the end of the tail.
    if (tail.endsWith('\r')) tail = tail.slice(0, -1);

    value = quoted ? value + tail.trim() : (value + tail).trim();
    values.push(value);

    if (text[state.pos] === ',') {
      state.pos += 1;
      continue;
    }
    break;
  }

  // Consume the record terminator.
  if (text[state.pos] === '\n') {
    state.pos += 1;
    state.line += 1;
  }

  return values;
}

/** True when the physical line at `pos` is blank or a `#` comment. */
function skipIgnorableLine(text: string, state: ScanState): boolean {
  let probe = state.pos;
  while (probe < text.length && isHorizontalSpace(text[probe] ?? '')) probe += 1;
  const ch = text[probe];
  const isBlank = ch === undefined || ch === '\n' || (ch === '\r' && text[probe + 1] === '\n');
  if (!isBlank && ch !== '#') return false;

  while (state.pos < text.length && text[state.pos] !== '\n') state.pos += 1;
  if (text[state.pos] === '\n') {
    state.pos += 1;
    state.line += 1;
  }
  return true;
}

/**
 * Parse CSV text into a header plus line-numbered rows.
 *
 * Handles: a UTF-8 BOM, CRLF or LF, a trailing newline or its absence, blank
 * lines anywhere, `#` comment lines, and RFC 4180 quoting.
 *
 * @throws {CsvParseError} when the file contains no header row at all.
 */
export function parseCsv(text: string): CsvDocument {
  const source = stripBom(text);
  const state: ScanState = { pos: 0, line: 1 };

  let header: string[] | undefined;
  const rows: CsvRow[] = [];

  while (state.pos < source.length) {
    if (skipIgnorableLine(source, state)) continue;
    const lineNumber = state.line;
    const values = readRecord(source, state);
    if (header === undefined) {
      header = values;
      continue;
    }
    rows.push({ lineNumber, values });
  }

  if (header === undefined) {
    throw new CsvParseError(
      'missing-header',
      'CSV has no header row (the file is empty, or contains only blank/comment lines). ' +
        `A header naming the address column is required, e.g. "${ADDRESS_COLUMN_ALIASES[0] ?? 'ip'},vendor_name,notes".`,
    );
  }

  return { header, rows };
}
