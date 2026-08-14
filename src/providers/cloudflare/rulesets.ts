import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

import { z } from 'zod';

import { canonicalizeJson, sha256Canonical } from '../../control-plane/canonical.js';
import type {
  Assumption,
  Diagnostic,
  JsonValue,
  ResourceIdentity,
  SourceReference,
  SourceSnapshot,
  TranslationBatch,
  TranslationFidelity,
  TranslationResult,
} from '../../control-plane/model.js';
import type { FirewallAction, FirewallRule } from '../../domains/firewall/model.js';
import { CloudflareExpressionError, parseCloudflareExpression } from './expression.js';

const ruleSchema = z
  .object({
    id: z.string().min(1),
    ref: z.string().min(1).optional(),
    version: z.string().optional(),
    action: z.string().min(1),
    expression: z.string().min(1),
    description: z.string().optional(),
    enabled: z.boolean().optional(),
    action_parameters: z.unknown().optional(),
    logging: z.unknown().optional(),
    ratelimit: z.unknown().optional(),
    last_updated: z.string().optional(),
  })
  .passthrough();

const rulesetSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    description: z.string().optional(),
    kind: z.string().min(1),
    version: z.string().optional(),
    last_updated: z.string().optional(),
    phase: z.literal('http_request_firewall_custom'),
    rules: z.array(ruleSchema),
  })
  .passthrough();

const envelopeSchema = z.union([
  rulesetSchema,
  z
    .object({
      success: z.boolean().optional(),
      result: rulesetSchema,
      errors: z.array(z.unknown()).optional(),
      messages: z.array(z.unknown()).optional(),
    })
    .passthrough(),
]);

export type CloudflareCustomRule = z.infer<typeof ruleSchema>;
export type CloudflareCustomRuleset = z.infer<typeof rulesetSchema>;

export interface CloudflareRulesetInput {
  readonly ruleset: CloudflareCustomRuleset;
  readonly captured: JsonValue;
}

export interface CloudflareInputProblem {
  readonly path: string;
  readonly message: string;
}

export type ParseCloudflareRulesetResult =
  | { readonly ok: true; readonly input: CloudflareRulesetInput }
  | { readonly ok: false; readonly problems: readonly CloudflareInputProblem[] };

export interface SnapshotCloudflareRulesetOptions {
  readonly inputPath: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly capturedAt: string;
}

function zodPath(path: readonly PropertyKey[]): string {
  return path.reduce<string>(
    (current, segment) =>
      typeof segment === 'number' ? `${current}[${segment}]` : `${current}.${String(segment)}`,
    '$',
  );
}

export function parseCloudflareRulesetText(text: string): ParseCloudflareRulesetResult {
  let captured: unknown;
  try {
    captured = JSON.parse(text) as unknown;
  } catch (error) {
    return {
      ok: false,
      problems: [{ path: '$', message: error instanceof Error ? error.message : String(error) }],
    };
  }

  const parsed = envelopeSchema.safeParse(captured);
  if (!parsed.success) {
    return {
      ok: false,
      problems: parsed.error.issues.map((issue) => ({
        path: zodPath(issue.path),
        message: issue.message,
      })),
    };
  }

  const ruleset =
    'result' in parsed.data && parsed.data.result !== undefined
      ? rulesetSchema.parse(parsed.data.result)
      : rulesetSchema.parse(parsed.data);
  return { ok: true, input: { ruleset, captured: canonicalizeJson(captured) } };
}

function rawDigest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function rulesetScope(options: SnapshotCloudflareRulesetOptions): Readonly<Record<string, string>> {
  return { accountId: options.accountId, zoneId: options.zoneId };
}

function ruleIdentity(
  rule: CloudflareCustomRule,
  options: SnapshotCloudflareRulesetOptions,
): ResourceIdentity {
  return {
    provider: 'cloudflare',
    resourceType: 'firewall-custom-rule',
    externalId: rule.id,
    ...(rule.description === undefined || rule.description === '' ? {} : { name: rule.description }),
    scope: rulesetScope(options),
  };
}

export function snapshotCloudflareRuleset(
  text: string,
  input: CloudflareRulesetInput,
  options: SnapshotCloudflareRulesetOptions,
): SourceSnapshot {
  const digest = rawDigest(text);
  const id = `snapshot_${sha256Canonical({
    provider: 'cloudflare',
    adapter: 'cloudflare-rulesets/1',
    accountId: options.accountId,
    zoneId: options.zoneId,
    ruleset: input.ruleset,
  }).slice(0, 24)}`;

  return {
    schemaVersion: 1,
    id,
    provider: 'cloudflare',
    accountId: options.accountId,
    capturedAt: options.capturedAt,
    adapterVersion: 'cloudflare-rulesets/1',
    resources: [
      {
        identity: {
          provider: 'cloudflare',
          resourceType: 'firewall-custom-ruleset',
          externalId: input.ruleset.id,
          name: input.ruleset.name,
          scope: rulesetScope(options),
        },
        captured: input.captured,
      },
      ...input.ruleset.rules.map((rule) => ({
        identity: ruleIdentity(rule, options),
        captured: canonicalizeJson(rule),
      })),
    ],
    artifacts: [
      {
        mediaType: 'application/json',
        sha256: digest,
        location: resolve(options.inputPath),
      },
    ],
  };
}

interface MappedAction {
  readonly action?: FirewallAction;
  readonly fidelity: TranslationFidelity;
  readonly diagnostics: readonly Diagnostic[];
  readonly assumptions: readonly Assumption[];
}

function mapAction(rule: CloudflareCustomRule, sourceRef: SourceReference): MappedAction {
  switch (rule.action) {
    case 'block':
      return { action: { kind: 'deny' }, fidelity: 'exact', diagnostics: [], assumptions: [] };
    case 'log':
      return { action: { kind: 'log' }, fidelity: 'exact', diagnostics: [], assumptions: [] };
    case 'challenge':
    case 'managed_challenge':
      return {
        action: { kind: 'challenge' },
        fidelity: 'approximate',
        diagnostics: [],
        assumptions: [
          {
            code: 'CHALLENGE_IMPLEMENTATION_DIFFERS',
            message:
              `Cloudflare action ${JSON.stringify(rule.action)} is mapped to Vercel challenge; ` +
              'challenge behavior and solved-challenge lifetime are platform-specific.',
            sourceRefs: [sourceRef],
          },
        ],
      };
    case 'skip':
      return {
        fidelity: 'manual',
        diagnostics: [
          {
            code: 'CLOUDFLARE_SKIP_REQUIRES_MANUAL_MAPPING',
            severity: 'warning',
            message:
              'Cloudflare skip can target selected phases, rulesets, or products; it cannot be mapped to a broad bypass without reviewing action_parameters.',
            sourceRefs: [sourceRef],
            remediation: 'Review action_parameters and select the narrowest Vercel bypass behavior.',
          },
        ],
        assumptions: [],
      };
    default:
      return {
        fidelity: 'unsupported',
        diagnostics: [
          {
            code: 'CLOUDFLARE_ACTION_UNSUPPORTED',
            severity: 'error',
            message: `Cloudflare action ${JSON.stringify(rule.action)} is not supported by this adapter.`,
            sourceRefs: [sourceRef],
            remediation: 'Handle this rule manually or extend the action translator with target tests.',
          },
        ],
        assumptions: [],
      };
  }
}

function worseFidelity(
  left: TranslationFidelity,
  right: TranslationFidelity,
): TranslationFidelity {
  const order: readonly TranslationFidelity[] = ['exact', 'approximate', 'manual', 'unsupported'];
  return order.indexOf(left) >= order.indexOf(right) ? left : right;
}

export function translateCloudflareRuleset(
  input: CloudflareRulesetInput,
  snapshot: SourceSnapshot,
  options: SnapshotCloudflareRulesetOptions,
): TranslationBatch<FirewallRule> {
  const records: TranslationResult<FirewallRule>[] = input.ruleset.rules.map((rule, priority) => {
    const identity = ruleIdentity(rule, options);
    const sourceRef: SourceReference = { snapshotId: snapshot.id, resource: identity };
    const mappedAction = mapAction(rule, sourceRef);

    let condition: FirewallRule['condition'] | undefined;
    let expressionFidelity: TranslationFidelity = 'exact';
    const expressionDiagnostics: Diagnostic[] = [];
    try {
      condition = parseCloudflareExpression(rule.expression);
    } catch (error) {
      expressionFidelity = 'manual';
      expressionDiagnostics.push({
        code: 'CLOUDFLARE_EXPRESSION_REQUIRES_MANUAL_MAPPING',
        severity: 'warning',
        message:
          error instanceof CloudflareExpressionError
            ? error.message
            : `Could not parse Cloudflare expression: ${String(error)}`,
        sourceRefs: [sourceRef],
        remediation: 'Translate this expression manually or extend the fail-closed expression parser.',
      });
    }

    const fidelity = worseFidelity(mappedAction.fidelity, expressionFidelity);
    const diagnostics = [...mappedAction.diagnostics, ...expressionDiagnostics];
    if (mappedAction.action === undefined || condition === undefined) {
      return {
        fidelity,
        sourceRefs: [sourceRef],
        targetResources: [],
        diagnostics,
        assumptions: mappedAction.assumptions,
      };
    }

    const translated: FirewallRule = {
      identity,
      sourceRefs: [sourceRef],
      name: rule.description?.trim() || rule.ref || `Cloudflare rule ${rule.id}`,
      ...(rule.description === undefined || rule.description === ''
        ? {}
        : { description: rule.description }),
      enabled: rule.enabled ?? true,
      priority,
      condition,
      action: mappedAction.action,
    };
    return {
      fidelity,
      sourceRefs: [sourceRef],
      targetResources: [translated],
      diagnostics,
      assumptions: mappedAction.assumptions,
    };
  });

  return {
    product: 'firewall',
    records,
    diagnostics: records.flatMap(({ diagnostics }) => diagnostics),
  };
}
