import type { RulePlan } from '../../../core/decompose.js';
import { buildRuleJson } from '../../../core/rule-builder.js';
import type { CompilationResult } from '../../../control-plane/contracts.js';
import type {
  Diagnostic,
  JsonValue,
  PlanOperation,
  ResourceScope,
  SourceReference,
  TranslationFidelity,
} from '../../../control-plane/model.js';

export interface CompileIpRulePlanOptions {
  readonly plan: RulePlan;
  readonly setId: string;
  readonly targetScope: ResourceScope;
  readonly sourceRefs: readonly SourceReference[];
  readonly fidelity?: TranslationFidelity;
}

function operationRisk(plan: RulePlan): PlanOperation['risk'] {
  if (plan.strategy === 'positive-packed') {
    return plan.rules.some((rule) => rule.action === 'bypass') ? 'high' : 'medium';
  }
  return 'critical';
}

function rulePayload(plan: RulePlan): JsonValue {
  return {
    schemaVersion: 1,
    strategy: plan.strategy,
    rules: plan.rules.map((plannedRule) => {
      const rule = buildRuleJson(plannedRule);
      return {
        order: plannedRule.order,
        name: rule.name,
        description: rule.description,
        active: rule.active,
        conditionGroup: rule.conditionGroup.map((group) => ({
          conditions: group.conditions.map((condition) => ({
            type: condition.type,
            op: condition.op,
            value: condition.value,
            ...(condition.type === 'ip_address' && condition.neg === true
              ? { neg: true }
              : {}),
          })),
        })),
        action: { mitigate: { action: rule.action.mitigate.action } },
      };
    }),
    stats: {
      inputCount: plan.stats.inputCount,
      afterAggregation: plan.stats.afterAggregation,
      ruleCount: plan.stats.ruleCount,
      conditionCount: plan.stats.conditionCount,
      addressesCovered: plan.stats.addressesCovered.toString(),
    },
  };
}

/** Bridge the existing safe IP planner into the generalized control plane. */
export function compileIpRulePlan(options: CompileIpRulePlanOptions): CompilationResult {
  const fidelity = options.fidelity ?? 'exact';
  const diagnostics: Diagnostic[] = options.plan.warnings.map((warning) => ({
    code: warning.code,
    severity: 'warning',
    message: warning.message,
    sourceRefs: options.sourceRefs,
  }));

  const operation: PlanOperation = {
    id: `vercel:firewall:rule-set:${options.setId}:reconcile`,
    product: 'firewall',
    kind: 'reconcile',
    effect: 'staged',
    approval: 'before-publish',
    risk: operationRisk(options.plan),
    fidelity,
    resource: {
      provider: 'vercel',
      resourceType: 'firewall-rule-set',
      externalId: options.setId,
      scope: options.targetScope,
    },
    sourceRefs: options.sourceRefs,
    dependsOn: [],
    payload: rulePayload(options.plan),
  };

  return { operations: [operation], diagnostics };
}
