import {
  MAX_CONDITIONS_PER_GROUP,
  MAX_GROUPS_PER_RULE,
  MAX_RULE_DESCRIPTION_LEN,
  MAX_RULE_NAME_LEN,
  MAX_VALUES_PER_CONDITION,
} from '../../../core/limits.js';
import type { CompilationResult } from '../../../control-plane/contracts.js';
import type {
  Diagnostic,
  JsonValue,
  PlanOperation,
  ResourceScope,
  SourceReference,
  TranslationBatch,
  TranslationFidelity,
  TranslationResult,
} from '../../../control-plane/model.js';
import type {
  FirewallAction,
  FirewallExpression,
  FirewallField,
  FirewallOperand,
  FirewallOperator,
  FirewallPredicate,
  FirewallRule,
} from '../../../domains/firewall/model.js';

interface VercelCondition {
  readonly type: string;
  readonly op: string;
  readonly key?: string;
  readonly value?: string | number | readonly (string | number)[];
  readonly neg?: true;
}

interface VercelRule {
  readonly name: string;
  readonly description: string;
  readonly active: boolean;
  readonly conditionGroup: readonly { readonly conditions: readonly VercelCondition[] }[];
  readonly action: { readonly mitigate: { readonly action: 'deny' | 'challenge' | 'log' | 'bypass' } };
}

export interface CompileFirewallTranslationOptions {
  readonly translation: TranslationBatch<FirewallRule>;
  readonly ownershipId: string;
  readonly targetScope: ResourceScope;
}

interface CompiledExpression {
  readonly groups: readonly (readonly VercelCondition[])[];
  readonly approximateReasons: readonly string[];
}

class FirewallCompilationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'FirewallCompilationError';
    this.code = code;
  }
}

const FIELD_MAP: Readonly<Record<FirewallField, string>> = {
  'client.ip': 'ip_address',
  'client.asn': 'geo_as_number',
  'client.country': 'geo_country',
  'client.region': 'geo_country_region',
  'client.city': 'geo_city',
  'client.continent': 'geo_continent',
  'request.host': 'host',
  'request.path': 'path',
  'request.rawPath': 'raw_path',
  'request.method': 'method',
  'request.scheme': 'scheme',
  'request.protocol': 'protocol',
  'request.query': 'query',
  'request.header': 'header',
  'request.cookie': 'cookie',
  'request.userAgent': 'user_agent',
  'request.route': 'route',
  'request.environment': 'environment',
  'tls.ja3': 'ja3_digest',
  'tls.ja4': 'ja4_digest',
};

const OPERATOR_MAP: Readonly<Record<FirewallOperator, string>> = {
  equals: 'eq',
  contains: 'sub',
  'starts-with': 'pre',
  'ends-with': 'suf',
  'matches-regex': 're',
  exists: 'ex',
  in: 'inc',
  'greater-than': 'gt',
  'greater-than-or-equal': 'gte',
  'less-than': 'lt',
  'less-than-or-equal': 'lte',
};

function operandValue(operand: FirewallOperand | undefined): VercelCondition['value'] {
  if (operand === undefined) return undefined;
  switch (operand.kind) {
    case 'list-reference':
      throw new FirewallCompilationError(
        'UNRESOLVED_LIST_REFERENCE',
        `List reference ${JSON.stringify(operand.resourceId)} must be resolved before Vercel compilation.`,
      );
    case 'literal':
      if (typeof operand.value === 'boolean') {
        throw new FirewallCompilationError(
          'BOOLEAN_OPERAND_UNSUPPORTED',
          'Vercel Firewall conditions do not accept a Boolean value for this canonical predicate.',
        );
      }
      return operand.value;
    case 'set': {
      if (operand.values.length > MAX_VALUES_PER_CONDITION) {
        throw new FirewallCompilationError(
          'CONDITION_VALUE_LIMIT',
          `Condition contains ${operand.values.length} values; Vercel accepts ${MAX_VALUES_PER_CONDITION}.`,
        );
      }
      if (operand.values.some((value) => typeof value === 'boolean')) {
        throw new FirewallCompilationError(
          'BOOLEAN_OPERAND_UNSUPPORTED',
          'Vercel Firewall set conditions do not accept Boolean values.',
        );
      }
      return operand.values as readonly (string | number)[];
    }
  }
}

function compilePredicate(predicate: FirewallPredicate, negated: boolean): VercelCondition {
  if (predicate.transformations.length > 0) {
    throw new FirewallCompilationError(
      'TRANSFORMATION_UNSUPPORTED',
      `Vercel compilation cannot preserve transformations: ${predicate.transformations.join(', ')}.`,
    );
  }
  if (
    (predicate.field === 'request.header' ||
      predicate.field === 'request.cookie' ||
      predicate.field === 'request.query') &&
    predicate.key === undefined
  ) {
    throw new FirewallCompilationError(
      'NAMED_FIELD_KEY_REQUIRED',
      `${predicate.field} requires a specific header, cookie, or query key on Vercel.`,
    );
  }
  if (predicate.operator === 'exists' && predicate.operand !== undefined) {
    throw new FirewallCompilationError(
      'EXISTS_HAS_OPERAND',
      'An exists predicate must not carry an operand.',
    );
  }
  if (predicate.operator !== 'exists' && predicate.operand === undefined) {
    throw new FirewallCompilationError(
      'OPERAND_REQUIRED',
      `${predicate.operator} requires an operand.`,
    );
  }

  const value = operandValue(predicate.operand);
  return {
    type: FIELD_MAP[predicate.field],
    op: OPERATOR_MAP[predicate.operator],
    ...(predicate.key === undefined ? {} : { key: predicate.key }),
    ...(value === undefined ? {} : { value }),
    ...(negated ? { neg: true } : {}),
  };
}

function cartesianAnd(
  left: readonly (readonly VercelCondition[])[],
  right: readonly (readonly VercelCondition[])[],
): readonly (readonly VercelCondition[])[] {
  const groups: VercelCondition[][] = [];
  for (const leftGroup of left) {
    for (const rightGroup of right) {
      groups.push([...leftGroup, ...rightGroup]);
      if (groups.length > MAX_GROUPS_PER_RULE) {
        throw new FirewallCompilationError(
          'DNF_GROUP_LIMIT',
          `Expression expands to more than ${MAX_GROUPS_PER_RULE} Vercel condition groups.`,
        );
      }
    }
  }
  return groups;
}

function toDnf(
  expression: FirewallExpression,
  negated = false,
): readonly (readonly VercelCondition[])[] {
  switch (expression.kind) {
    case 'predicate':
      return [[compilePredicate(expression, negated)]];
    case 'not':
      return toDnf(expression.expression, !negated);
    case 'all': {
      if (expression.expressions.length === 0) {
        throw new FirewallCompilationError('EMPTY_BOOLEAN_GROUP', 'AND expression cannot be empty.');
      }
      if (negated) return expression.expressions.flatMap((child) => toDnf(child, true));
      return expression.expressions.reduce<readonly (readonly VercelCondition[])[]>(
        (groups, child) => cartesianAnd(groups, toDnf(child)),
        [[]],
      );
    }
    case 'any': {
      if (expression.expressions.length === 0) {
        throw new FirewallCompilationError('EMPTY_BOOLEAN_GROUP', 'OR expression cannot be empty.');
      }
      if (negated) {
        return expression.expressions.reduce<readonly (readonly VercelCondition[])[]>(
          (groups, child) => cartesianAnd(groups, toDnf(child, true)),
          [[]],
        );
      }
      return expression.expressions.flatMap((child) => toDnf(child));
    }
  }
}

function compileExpression(expression: FirewallExpression): CompiledExpression {
  const groups = toDnf(expression);
  if (groups.length > MAX_GROUPS_PER_RULE) {
    throw new FirewallCompilationError(
      'GROUP_LIMIT',
      `Rule requires ${groups.length} groups; Vercel accepts ${MAX_GROUPS_PER_RULE}.`,
    );
  }
  for (const group of groups) {
    if (group.length > MAX_CONDITIONS_PER_GROUP) {
      throw new FirewallCompilationError(
        'CONDITION_LIMIT',
        `Rule group requires ${group.length} conditions; Vercel accepts ${MAX_CONDITIONS_PER_GROUP}.`,
      );
    }
  }
  const approximateReasons = groups
    .flat()
    .filter(({ op }) => op === 're')
    .map(() => 'Regular-expression engine compatibility requires review.');
  return { groups, approximateReasons: [...new Set(approximateReasons)] };
}

function compileAction(action: FirewallAction): VercelRule['action'] {
  switch (action.kind) {
    case 'deny':
      if (action.durationSeconds !== undefined) {
        throw new FirewallCompilationError(
          'ACTION_DURATION_REQUIRES_REVIEW',
          'Canonical deny duration must be mapped to an exact supported Vercel duration.',
        );
      }
      return { mitigate: { action: 'deny' } };
    case 'challenge':
      if (action.durationSeconds !== undefined) {
        throw new FirewallCompilationError(
          'ACTION_DURATION_REQUIRES_REVIEW',
          'Canonical challenge duration must be mapped to an exact supported Vercel duration.',
        );
      }
      return { mitigate: { action: 'challenge' } };
    case 'log':
      return { mitigate: { action: 'log' } };
    case 'bypass':
      return { mitigate: { action: 'bypass' } };
    case 'allow':
      throw new FirewallCompilationError(
        'ALLOW_ACTION_UNSUPPORTED',
        'Vercel custom Firewall rules do not expose an allow action; choose a reviewed bypass mapping.',
      );
    case 'redirect':
      throw new FirewallCompilationError(
        'REDIRECT_NOT_IMPLEMENTED',
        'Redirect payload compilation is not implemented in this target adapter.',
      );
    case 'rate-limit':
      throw new FirewallCompilationError(
        'RATE_LIMIT_NOT_IMPLEMENTED',
        'Rate-limit payload compilation is not implemented in this target adapter.',
      );
  }
}

function compileRule(rule: FirewallRule): {
  readonly rule: VercelRule;
  readonly approximateReasons: readonly string[];
} {
  if (rule.name.length > MAX_RULE_NAME_LEN) {
    throw new FirewallCompilationError(
      'RULE_NAME_LIMIT',
      `Rule name has ${rule.name.length} characters; Vercel accepts ${MAX_RULE_NAME_LEN}.`,
    );
  }
  const description = rule.description ?? `Migrated from ${rule.identity.provider}:${rule.identity.externalId}`;
  if (description.length > MAX_RULE_DESCRIPTION_LEN) {
    throw new FirewallCompilationError(
      'RULE_DESCRIPTION_LIMIT',
      `Rule description has ${description.length} characters; Vercel accepts ${MAX_RULE_DESCRIPTION_LEN}.`,
    );
  }
  const expression = compileExpression(rule.condition);
  return {
    rule: {
      name: rule.name,
      description,
      active: rule.enabled,
      conditionGroup: expression.groups.map((conditions) => ({ conditions })),
      action: compileAction(rule.action),
    },
    approximateReasons: expression.approximateReasons,
  };
}

function ruleJson(rule: VercelRule): JsonValue {
  return {
    name: rule.name,
    description: rule.description,
    active: rule.active,
    conditionGroup: rule.conditionGroup.map((group) => ({
      conditions: group.conditions.map((condition) => ({
        type: condition.type,
        op: condition.op,
        ...(condition.key === undefined ? {} : { key: condition.key }),
        ...(condition.value === undefined ? {} : { value: condition.value }),
        ...(condition.neg === undefined ? {} : { neg: condition.neg }),
      })),
    })),
    action: { mitigate: { action: rule.action.mitigate.action } },
  };
}

function worseFidelity(
  values: readonly TranslationFidelity[],
  fallback: TranslationFidelity,
): TranslationFidelity {
  const order: readonly TranslationFidelity[] = ['exact', 'approximate', 'manual', 'unsupported'];
  return values.reduce(
    (worst, value) => (order.indexOf(value) > order.indexOf(worst) ? value : worst),
    fallback,
  );
}

function uniqueRefs(records: readonly TranslationResult<FirewallRule>[]): SourceReference[] {
  const seen = new Set<string>();
  return records.flatMap(({ sourceRefs }) =>
    sourceRefs.filter((reference) => {
      const key = `${reference.snapshotId}:${reference.resource.provider}:${reference.resource.resourceType}:${reference.resource.externalId}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  );
}

function manualOperation(
  record: TranslationResult<FirewallRule>,
  targetScope: ResourceScope,
  sequence: number,
  compilerDiagnostic?: Diagnostic,
): PlanOperation {
  const source = record.sourceRefs[0];
  const externalId = source?.resource.externalId ?? `unknown-${sequence + 1}`;
  const diagnostics = [...record.diagnostics, ...(compilerDiagnostic === undefined ? [] : [compilerDiagnostic])];
  return {
    id: `vercel:firewall:manual:${externalId}:${sequence + 1}`,
    product: 'firewall',
    kind: 'manual',
    effect: 'external-manual',
    approval: 'before-execute',
    risk: 'high',
    fidelity: compilerDiagnostic === undefined ? record.fidelity : 'manual',
    resource: {
      provider: 'vercel',
      resourceType: 'firewall-manual-mapping',
      externalId,
      scope: targetScope,
    },
    sourceRefs: record.sourceRefs,
    dependsOn: [],
    payload: {
      sourceRuleId: externalId,
      diagnostics: diagnostics.map(({ code, severity, message, remediation }) => ({
        code,
        severity,
        message,
        ...(remediation === undefined ? {} : { remediation }),
      })),
      assumptions: record.assumptions.map(({ code, message }) => ({ code, message })),
    },
  };
}

/** Compile per-rule canonical mappings into one staged desired rule set plus explicit manual work. */
export function compileFirewallTranslation(
  options: CompileFirewallTranslationOptions,
): CompilationResult {
  const diagnostics: Diagnostic[] = [...options.translation.diagnostics];
  const manual: PlanOperation[] = [];
  const compiled: {
    readonly record: TranslationResult<FirewallRule>;
    readonly sourceRule: FirewallRule;
    readonly targetRule: VercelRule;
    readonly fidelity: TranslationFidelity;
  }[] = [];

  options.translation.records.forEach((record, sequence) => {
    const sourceRule = record.targetResources[0];
    if (sourceRule === undefined || record.fidelity === 'manual' || record.fidelity === 'unsupported') {
      manual.push(manualOperation(record, options.targetScope, sequence));
      return;
    }

    try {
      const target = compileRule(sourceRule);
      const fidelity =
        target.approximateReasons.length > 0
          ? worseFidelity([record.fidelity, 'approximate'], 'exact')
          : record.fidelity;
      for (const reason of target.approximateReasons) {
        diagnostics.push({
          code: 'REGEX_ENGINE_REVIEW_REQUIRED',
          severity: 'warning',
          message: reason,
          sourceRefs: record.sourceRefs,
        });
      }
      for (const assumption of record.assumptions) {
        diagnostics.push({
          code: assumption.code,
          severity: 'warning',
          message: assumption.message,
          sourceRefs: assumption.sourceRefs,
        });
      }
      compiled.push({ record, sourceRule, targetRule: target.rule, fidelity });
    } catch (error) {
      const code = error instanceof FirewallCompilationError ? error.code : 'FIREWALL_COMPILATION_FAILED';
      const diagnostic: Diagnostic = {
        code,
        severity: 'warning',
        message: error instanceof Error ? error.message : String(error),
        sourceRefs: record.sourceRefs,
        remediation: 'Review and map this source rule manually.',
      };
      diagnostics.push(diagnostic);
      manual.push(manualOperation(record, options.targetScope, sequence, diagnostic));
    }
  });

  const operations: PlanOperation[] = [];
  if (compiled.length > 0) {
    const ordered = [...compiled].sort((left, right) => left.sourceRule.priority - right.sourceRule.priority);
    const fidelity = worseFidelity(ordered.map((entry) => entry.fidelity), 'exact');
    const risk: PlanOperation['risk'] = ordered.some(({ sourceRule }) => sourceRule.action.kind === 'deny')
      ? 'high'
      : ordered.some(({ sourceRule }) => sourceRule.action.kind === 'challenge')
        ? 'medium'
        : 'low';
    operations.push({
      id: `vercel:firewall:policy:${options.ownershipId}:reconcile`,
      product: 'firewall',
      kind: 'reconcile',
      effect: 'staged',
      approval: 'before-publish',
      risk,
      fidelity,
      resource: {
        provider: 'vercel',
        resourceType: 'firewall-policy',
        externalId: options.ownershipId,
        scope: options.targetScope,
      },
      sourceRefs: uniqueRefs(ordered.map(({ record }) => record)),
      dependsOn: [],
      payload: {
        schemaVersion: 1,
        rules: ordered.map(({ sourceRule, targetRule, fidelity: ruleFidelity }) => ({
          sourceRuleId: sourceRule.identity.externalId,
          sourcePriority: sourceRule.priority,
          fidelity: ruleFidelity,
          rule: ruleJson(targetRule),
        })),
      },
    });
  }

  operations.push(...manual);
  return { operations, diagnostics };
}
