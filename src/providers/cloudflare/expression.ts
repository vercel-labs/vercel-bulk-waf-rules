import type {
  FirewallExpression,
  FirewallField,
  FirewallOperand,
  FirewallOperator,
  FirewallPredicate,
  FirewallScalar,
  FirewallTransformation,
} from '../../domains/firewall/model.js';

type TokenKind = 'word' | 'string' | 'left-paren' | 'right-paren' | 'left-brace' | 'right-brace' | 'comma';

interface Token {
  readonly kind: TokenKind;
  readonly value: string;
  readonly offset: number;
}

export class CloudflareExpressionError extends SyntaxError {
  readonly offset: number;

  constructor(message: string, offset: number) {
    super(`${message} at offset ${offset}.`);
    this.name = 'CloudflareExpressionError';
    this.offset = offset;
  }
}

function symbolKind(character: string): TokenKind | undefined {
  switch (character) {
    case '(':
      return 'left-paren';
    case ')':
      return 'right-paren';
    case '{':
      return 'left-brace';
    case '}':
      return 'right-brace';
    case ',':
      return 'comma';
    default:
      return undefined;
  }
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let offset = 0;

  while (offset < input.length) {
    const character = input[offset];
    if (character === undefined) break;
    if (/\s/.test(character)) {
      offset += 1;
      continue;
    }

    const symbol = symbolKind(character);
    if (symbol !== undefined) {
      tokens.push({ kind: symbol, value: character, offset });
      offset += 1;
      continue;
    }

    if (character === '"') {
      const start = offset;
      offset += 1;
      let value = '';
      let closed = false;
      while (offset < input.length) {
        const next = input[offset];
        if (next === undefined) break;
        if (next === '"') {
          offset += 1;
          closed = true;
          break;
        }
        if (next === '\\') {
          const escaped = input[offset + 1];
          if (escaped === undefined) break;
          const escapes: Readonly<Record<string, string>> = {
            '"': '"',
            '\\': '\\',
            n: '\n',
            r: '\r',
            t: '\t',
          };
          value += escapes[escaped] ?? escaped;
          offset += 2;
          continue;
        }
        value += next;
        offset += 1;
      }
      if (!closed) throw new CloudflareExpressionError('Unterminated string', start);
      tokens.push({ kind: 'string', value, offset: start });
      continue;
    }

    const start = offset;
    while (offset < input.length) {
      const next = input[offset];
      if (next === undefined || /\s/.test(next) || next === '"' || symbolKind(next) !== undefined) {
        break;
      }
      offset += 1;
    }
    if (start === offset) throw new CloudflareExpressionError(`Unexpected character ${character}`, offset);
    tokens.push({ kind: 'word', value: input.slice(start, offset), offset: start });
  }

  return tokens;
}

interface ParsedField {
  readonly field: FirewallField;
  readonly transformations: readonly FirewallTransformation[];
}

const FIELD_MAP: Readonly<Record<string, FirewallField>> = {
  'ip.src': 'client.ip',
  'ip.geoip.asnum': 'client.asn',
  'ip.src.country': 'client.country',
  'http.host': 'request.host',
  'http.request.uri.path': 'request.path',
  'raw.http.request.uri.path': 'request.rawPath',
  'http.request.method': 'request.method',
  'http.request.scheme': 'request.scheme',
  'http.request.version': 'request.protocol',
  'http.request.uri.query': 'request.query',
  'http.user_agent': 'request.userAgent',
};

const OPERATOR_MAP: Readonly<Record<string, FirewallOperator>> = {
  eq: 'equals',
  contains: 'contains',
  matches: 'matches-regex',
  in: 'in',
  gt: 'greater-than',
  ge: 'greater-than-or-equal',
  lt: 'less-than',
  le: 'less-than-or-equal',
};

class Parser {
  private index = 0;

  constructor(private readonly tokens: readonly Token[]) {}

  parse(): FirewallExpression {
    if (this.tokens.length === 0) throw new CloudflareExpressionError('Expression is empty', 0);
    const expression = this.parseOr();
    const trailing = this.peek();
    if (trailing !== undefined) {
      throw new CloudflareExpressionError(`Unexpected token ${JSON.stringify(trailing.value)}`, trailing.offset);
    }
    return expression;
  }

  private peek(offset = 0): Token | undefined {
    return this.tokens[this.index + offset];
  }

  private take(): Token {
    const token = this.peek();
    if (token === undefined) {
      const last = this.tokens[this.tokens.length - 1];
      throw new CloudflareExpressionError('Unexpected end of expression', (last?.offset ?? 0) + 1);
    }
    this.index += 1;
    return token;
  }

  private takeKind(kind: TokenKind): Token {
    const token = this.take();
    if (token.kind !== kind) {
      throw new CloudflareExpressionError(`Expected ${kind}, got ${JSON.stringify(token.value)}`, token.offset);
    }
    return token;
  }

  private peekWord(value: string): boolean {
    const token = this.peek();
    return token?.kind === 'word' && token.value.toLowerCase() === value;
  }

  private takeWord(): Token {
    return this.takeKind('word');
  }

  private parseOr(): FirewallExpression {
    const expressions = [this.parseAnd()];
    while (this.peekWord('or')) {
      this.take();
      expressions.push(this.parseAnd());
    }
    return expressions.length === 1 ? expressions[0] ?? this.impossible() : { kind: 'any', expressions };
  }

  private parseAnd(): FirewallExpression {
    const expressions = [this.parseUnary()];
    while (this.peekWord('and')) {
      this.take();
      expressions.push(this.parseUnary());
    }
    return expressions.length === 1 ? expressions[0] ?? this.impossible() : { kind: 'all', expressions };
  }

  private parseUnary(): FirewallExpression {
    if (this.peekWord('not')) {
      this.take();
      return { kind: 'not', expression: this.parseUnary() };
    }
    if (this.peek()?.kind === 'left-paren') {
      this.take();
      const expression = this.parseOr();
      this.takeKind('right-paren');
      return expression;
    }
    return this.parsePredicate();
  }

  private parsePredicate(): FirewallExpression {
    const first = this.peek();
    const second = this.peek(1);
    if (first?.kind === 'word' && second?.kind === 'left-paren') {
      const functionName = first.value.toLowerCase();
      if (functionName === 'starts_with' || functionName === 'ends_with') {
        this.take();
        this.take();
        const field = this.parseField();
        this.takeKind('comma');
        const operand = this.parseOperand();
        this.takeKind('right-paren');
        return this.predicate(
          field,
          functionName === 'starts_with' ? 'starts-with' : 'ends-with',
          operand,
        );
      }
    }

    const field = this.parseField();
    let negated = false;
    if (this.peekWord('not')) {
      this.take();
      negated = true;
    }
    const operatorToken = this.takeWord();
    const operatorName = operatorToken.value.toLowerCase();
    const operator = OPERATOR_MAP[operatorName];
    if (operator === undefined && operatorName !== 'ne') {
      throw new CloudflareExpressionError(
        `Unsupported Cloudflare operator ${JSON.stringify(operatorToken.value)}`,
        operatorToken.offset,
      );
    }
    const operand = this.parseOperand();
    const normalizedOperator: FirewallOperator =
      operatorName === 'ne' ? 'equals' : (operator ?? this.impossible());
    const predicate = this.predicate(field, normalizedOperator, operand);
    return negated || operatorName === 'ne' ? { kind: 'not', expression: predicate } : predicate;
  }

  private parseField(): ParsedField {
    if (this.peekWord('lower')) {
      this.take();
      this.takeKind('left-paren');
      const nested = this.parseField();
      this.takeKind('right-paren');
      return { field: nested.field, transformations: [...nested.transformations, 'lowercase'] };
    }
    const token = this.takeWord();
    const field = FIELD_MAP[token.value];
    if (field === undefined) {
      throw new CloudflareExpressionError(
        `Unsupported Cloudflare field ${JSON.stringify(token.value)}`,
        token.offset,
      );
    }
    return { field, transformations: [] };
  }

  private parseOperand(): FirewallOperand {
    if (this.peek()?.kind === 'left-brace') {
      this.take();
      const values: FirewallScalar[] = [];
      while (this.peek()?.kind !== 'right-brace') {
        if (this.peek() === undefined) throw new CloudflareExpressionError('Unterminated set', 0);
        values.push(this.parseScalar());
        if (this.peek()?.kind === 'comma') this.take();
      }
      this.take();
      if (values.length === 0) throw new CloudflareExpressionError('Set cannot be empty', 0);
      return { kind: 'set', values };
    }

    const token = this.peek();
    if (token?.kind === 'word' && token.value.startsWith('$')) {
      this.take();
      if (token.value.length === 1) {
        throw new CloudflareExpressionError('List reference has no name', token.offset);
      }
      return { kind: 'list-reference', resourceId: token.value.slice(1) };
    }
    return { kind: 'literal', value: this.parseScalar() };
  }

  private parseScalar(): FirewallScalar {
    const token = this.take();
    if (token.kind === 'string') return token.value;
    if (token.kind !== 'word') {
      throw new CloudflareExpressionError(`Expected a value, got ${JSON.stringify(token.value)}`, token.offset);
    }
    if (token.value === 'true') return true;
    if (token.value === 'false') return false;
    if (/^-?(?:\d+|\d+\.\d+)$/.test(token.value)) return Number(token.value);
    return token.value;
  }

  private predicate(
    field: ParsedField,
    operator: FirewallOperator,
    operand: FirewallOperand,
  ): FirewallPredicate {
    return {
      kind: 'predicate',
      field: field.field,
      operator,
      operand,
      transformations: field.transformations,
    };
  }

  private impossible(): never {
    throw new CloudflareExpressionError('Parser produced no expression', 0);
  }
}

/** Parse the deliberately supported subset of Cloudflare's Rules language. */
export function parseCloudflareExpression(input: string): FirewallExpression {
  return new Parser(tokenize(input)).parse();
}
