import type { ResourceIdentity, SourceReference } from '../../control-plane/model.js';

export type FirewallScalar = string | number | boolean;

export type FirewallField =
  | 'client.ip'
  | 'client.asn'
  | 'client.country'
  | 'client.region'
  | 'client.city'
  | 'client.continent'
  | 'request.host'
  | 'request.path'
  | 'request.rawPath'
  | 'request.method'
  | 'request.scheme'
  | 'request.protocol'
  | 'request.query'
  | 'request.header'
  | 'request.cookie'
  | 'request.userAgent'
  | 'request.route'
  | 'request.environment'
  | 'tls.ja3'
  | 'tls.ja4';

export type FirewallOperator =
  | 'equals'
  | 'contains'
  | 'starts-with'
  | 'ends-with'
  | 'matches-regex'
  | 'exists'
  | 'in'
  | 'greater-than'
  | 'greater-than-or-equal'
  | 'less-than'
  | 'less-than-or-equal';

export type FirewallTransformation =
  | 'lowercase'
  | 'uppercase'
  | 'url-decode'
  | 'html-decode'
  | 'normalize-path'
  | 'remove-nulls';

export type FirewallOperand =
  | { readonly kind: 'literal'; readonly value: FirewallScalar }
  | { readonly kind: 'set'; readonly values: readonly FirewallScalar[] }
  | { readonly kind: 'list-reference'; readonly resourceId: string };

export interface FirewallPredicate {
  readonly kind: 'predicate';
  readonly field: FirewallField;
  /** Header, cookie, or query-parameter name where the field requires one. */
  readonly key?: string;
  readonly operator: FirewallOperator;
  readonly operand?: FirewallOperand;
  readonly transformations: readonly FirewallTransformation[];
}

export type FirewallExpression =
  | FirewallPredicate
  | { readonly kind: 'all'; readonly expressions: readonly FirewallExpression[] }
  | { readonly kind: 'any'; readonly expressions: readonly FirewallExpression[] }
  | { readonly kind: 'not'; readonly expression: FirewallExpression };

export interface FirewallRateLimit {
  readonly requests: number;
  readonly windowSeconds: number;
  readonly characteristics: readonly FirewallField[];
  readonly algorithm?: 'fixed-window' | 'token-bucket';
  readonly exceedAction: Exclude<FirewallAction, { readonly kind: 'rate-limit' }>;
}

export type FirewallAction =
  | { readonly kind: 'allow' }
  | { readonly kind: 'deny'; readonly durationSeconds?: number }
  | { readonly kind: 'challenge'; readonly durationSeconds?: number }
  | { readonly kind: 'log' }
  | {
      readonly kind: 'bypass';
      readonly products: readonly ('custom-rules' | 'managed-rules' | 'rate-limits')[];
    }
  | { readonly kind: 'redirect'; readonly statusCode: 301 | 302 | 307 | 308; readonly location: string }
  | { readonly kind: 'rate-limit'; readonly limit: FirewallRateLimit };

export interface FirewallRule {
  readonly identity: ResourceIdentity;
  readonly sourceRefs: readonly SourceReference[];
  readonly name: string;
  readonly description?: string;
  readonly enabled: boolean;
  /** Lower numbers evaluate first. */
  readonly priority: number;
  readonly condition: FirewallExpression;
  readonly action: FirewallAction;
}

export interface FirewallListEntry {
  readonly value: string;
  readonly note?: string;
}

export interface FirewallList {
  readonly identity: ResourceIdentity;
  readonly sourceRefs: readonly SourceReference[];
  readonly kind: 'ip' | 'asn' | 'country' | 'string';
  readonly entries: readonly FirewallListEntry[];
}

export interface FirewallPolicy {
  readonly identity: ResourceIdentity;
  readonly sourceRefs: readonly SourceReference[];
  readonly defaultAction: 'allow' | 'deny';
  readonly rules: readonly FirewallRule[];
  readonly lists: readonly FirewallList[];
}
