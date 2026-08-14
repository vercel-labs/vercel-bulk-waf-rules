import { describe, expect, it } from 'vitest';

import { CloudflareExpressionError, parseCloudflareExpression } from './expression.js';

describe('parseCloudflareExpression', () => {
  it('preserves AND/OR precedence and IP sets', () => {
    expect(
      parseCloudflareExpression(
        'ip.src in {192.0.2.0/24 2001:db8::/48} and http.host eq "example.com" or http.request.method eq "POST"',
      ),
    ).toEqual({
      kind: 'any',
      expressions: [
        {
          kind: 'all',
          expressions: [
            {
              kind: 'predicate',
              field: 'client.ip',
              operator: 'in',
              operand: { kind: 'set', values: ['192.0.2.0/24', '2001:db8::/48'] },
              transformations: [],
            },
            {
              kind: 'predicate',
              field: 'request.host',
              operator: 'equals',
              operand: { kind: 'literal', value: 'example.com' },
              transformations: [],
            },
          ],
        },
        {
          kind: 'predicate',
          field: 'request.method',
          operator: 'equals',
          operand: { kind: 'literal', value: 'POST' },
          transformations: [],
        },
      ],
    });
  });

  it('preserves negation, functions, transformations, and list references', () => {
    expect(
      parseCloudflareExpression(
        'not starts_with(lower(http.request.uri.path), "/private") and ip.src in $trusted_ips',
      ),
    ).toEqual({
      kind: 'all',
      expressions: [
        {
          kind: 'not',
          expression: {
            kind: 'predicate',
            field: 'request.path',
            operator: 'starts-with',
            operand: { kind: 'literal', value: '/private' },
            transformations: ['lowercase'],
          },
        },
        {
          kind: 'predicate',
          field: 'client.ip',
          operator: 'in',
          operand: { kind: 'list-reference', resourceId: 'trusted_ips' },
          transformations: [],
        },
      ],
    });
  });

  it('normalizes not-equal into an explicit NOT expression', () => {
    expect(parseCloudflareExpression('ip.src.country ne "US"')).toMatchObject({
      kind: 'not',
      expression: {
        kind: 'predicate',
        field: 'client.country',
        operator: 'equals',
      },
    });
  });

  it('fails closed on fields and operators outside the supported grammar', () => {
    expect(() => parseCloudflareExpression('cf.bot_management.score lt 30')).toThrow(
      CloudflareExpressionError,
    );
    expect(() => parseCloudflareExpression('http.host wildcard "*.example.com"')).toThrow(
      /Unsupported Cloudflare operator/,
    );
  });
});
