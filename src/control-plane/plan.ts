import { sha256Canonical } from './canonical.js';
import {
  MIGRATION_PLAN_SCHEMA_VERSION,
  type Diagnostic,
  type MigrationPlan,
  type PlanOperation,
  type PlanTarget,
} from './model.js';

export type PlanIssueCode =
  | 'EMPTY_OPERATION_ID'
  | 'DUPLICATE_OPERATION_ID'
  | 'MISSING_DEPENDENCY'
  | 'SELF_DEPENDENCY'
  | 'DEPENDENCY_CYCLE'
  | 'DELETE_REQUIRES_APPROVAL'
  | 'RISKY_IMMEDIATE_OPERATION_REQUIRES_APPROVAL';

export interface PlanIssue {
  readonly code: PlanIssueCode;
  readonly message: string;
  readonly operationIds: readonly string[];
}

export interface BuildMigrationPlanInput {
  readonly createdAt: string;
  readonly sourceSnapshotIds: readonly string[];
  readonly target: PlanTarget;
  readonly operations: readonly PlanOperation[];
  readonly diagnostics?: readonly Diagnostic[];
}

export type BuildMigrationPlanResult =
  | { readonly ok: true; readonly plan: MigrationPlan }
  | { readonly ok: false; readonly issues: readonly PlanIssue[] };

function validateIdentities(operations: readonly PlanOperation[]): PlanIssue[] {
  const issues: PlanIssue[] = [];
  const counts = new Map<string, number>();

  for (const operation of operations) {
    if (operation.id.length === 0) {
      issues.push({
        code: 'EMPTY_OPERATION_ID',
        message: 'Every migration operation must have a non-empty stable id.',
        operationIds: [''],
      });
    }
    counts.set(operation.id, (counts.get(operation.id) ?? 0) + 1);

    if (operation.kind === 'delete' && operation.approval === 'none') {
      issues.push({
        code: 'DELETE_REQUIRES_APPROVAL',
        message: `Delete operation ${JSON.stringify(operation.id)} requires explicit approval.`,
        operationIds: [operation.id],
      });
    }

    if (
      operation.effect === 'immediate' &&
      (operation.risk === 'high' || operation.risk === 'critical') &&
      operation.approval === 'none'
    ) {
      issues.push({
        code: 'RISKY_IMMEDIATE_OPERATION_REQUIRES_APPROVAL',
        message:
          `Immediate ${operation.risk}-risk operation ${JSON.stringify(operation.id)} ` +
          'requires explicit approval.',
        operationIds: [operation.id],
      });
    }
  }

  for (const [id, count] of counts) {
    if (id !== '' && count > 1) {
      issues.push({
        code: 'DUPLICATE_OPERATION_ID',
        message: `Operation id ${JSON.stringify(id)} appears ${count} times.`,
        operationIds: [id],
      });
    }
  }

  return issues;
}

function orderOperations(
  operations: readonly PlanOperation[],
): { readonly ordered: readonly PlanOperation[]; readonly issues: readonly PlanIssue[] } {
  const issues: PlanIssue[] = [];
  const byId = new Map<string, PlanOperation>();
  const inputIndex = new Map<string, number>();

  operations.forEach((operation, index) => {
    if (!byId.has(operation.id)) {
      byId.set(operation.id, operation);
      inputIndex.set(operation.id, index);
    }
  });

  if (byId.size !== operations.length || byId.has('')) return { ordered: [], issues };

  const indegree = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  for (const operation of operations) {
    indegree.set(operation.id, 0);
    dependents.set(operation.id, []);
  }

  for (const operation of operations) {
    const uniqueDependencies = new Set(operation.dependsOn);
    for (const dependency of uniqueDependencies) {
      if (dependency === operation.id) {
        issues.push({
          code: 'SELF_DEPENDENCY',
          message: `Operation ${JSON.stringify(operation.id)} depends on itself.`,
          operationIds: [operation.id],
        });
        continue;
      }
      if (!byId.has(dependency)) {
        issues.push({
          code: 'MISSING_DEPENDENCY',
          message:
            `Operation ${JSON.stringify(operation.id)} depends on missing operation ` +
            `${JSON.stringify(dependency)}.`,
          operationIds: [operation.id, dependency],
        });
        continue;
      }
      indegree.set(operation.id, (indegree.get(operation.id) ?? 0) + 1);
      dependents.get(dependency)?.push(operation.id);
    }
  }

  if (issues.length > 0) return { ordered: [], issues };

  const sortByInput = (left: string, right: string): number =>
    (inputIndex.get(left) ?? 0) - (inputIndex.get(right) ?? 0);
  const ready = operations
    .filter((operation) => indegree.get(operation.id) === 0)
    .map((operation) => operation.id)
    .sort(sortByInput);

  const ordered: PlanOperation[] = [];
  while (ready.length > 0) {
    const id = ready.shift();
    if (id === undefined) break;
    const operation = byId.get(id);
    if (operation === undefined) continue;
    ordered.push(operation);

    for (const dependent of dependents.get(id) ?? []) {
      const remaining = (indegree.get(dependent) ?? 0) - 1;
      indegree.set(dependent, remaining);
      if (remaining === 0) {
        ready.push(dependent);
        ready.sort(sortByInput);
      }
    }
  }

  if (ordered.length !== operations.length) {
    const cycleIds = operations
      .filter((operation) => (indegree.get(operation.id) ?? 0) > 0)
      .map((operation) => operation.id);
    issues.push({
      code: 'DEPENDENCY_CYCLE',
      message: `Migration operation dependency cycle: ${cycleIds.join(' -> ')}.`,
      operationIds: cycleIds,
    });
  }

  return { ordered, issues };
}

/** Build a deterministic, dependency-ordered migration plan without I/O. */
export function buildMigrationPlan(input: BuildMigrationPlanInput): BuildMigrationPlanResult {
  const identityIssues = validateIdentities(input.operations);
  if (identityIssues.length > 0) return { ok: false, issues: identityIssues };

  const { ordered, issues } = orderOperations(input.operations);
  if (issues.length > 0) return { ok: false, issues };

  const sourceSnapshotIds = [...new Set(input.sourceSnapshotIds)].sort();
  const diagnostics = input.diagnostics ?? [];
  const content: Omit<MigrationPlan, 'id' | 'createdAt'> = {
    schemaVersion: MIGRATION_PLAN_SCHEMA_VERSION,
    sourceSnapshotIds,
    target: input.target,
    operations: ordered,
    diagnostics,
  };
  const id = `plan_${sha256Canonical(content).slice(0, 24)}`;

  return {
    ok: true,
    plan: {
      ...content,
      id,
      createdAt: input.createdAt,
    },
  };
}
