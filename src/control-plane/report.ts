import type {
  DiagnosticSeverity,
  MigrationBundle,
  OperationRisk,
  TranslationFidelity,
} from './model.js';

function countBy<T extends string>(values: readonly T[]): Readonly<Partial<Record<T, number>>> {
  const counts: Partial<Record<T, number>> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function formattedCounts<T extends string>(
  order: readonly T[],
  counts: Readonly<Partial<Record<T, number>>>,
): string {
  return order.map((key) => `${key}=${counts[key] ?? 0}`).join(', ');
}

export interface MigrationReportSummary {
  readonly planId: string;
  readonly sourceProviders: readonly string[];
  readonly snapshotCount: number;
  readonly operationCount: number;
  readonly fidelity: Readonly<Record<TranslationFidelity, number>>;
  readonly risk: Readonly<Record<OperationRisk, number>>;
  readonly diagnostics: Readonly<Record<DiagnosticSeverity, number>>;
  readonly approvalsRequired: number;
}

export function summarizeMigrationBundle(bundle: MigrationBundle): MigrationReportSummary {
  const operations = bundle.plan.operations;
  const diagnostics = bundle.plan.diagnostics;
  return {
    planId: bundle.plan.id,
    sourceProviders: [...new Set(bundle.snapshots.map(({ provider }) => provider))].sort(),
    snapshotCount: bundle.snapshots.length,
    operationCount: operations.length,
    fidelity: {
      exact: 0,
      approximate: 0,
      manual: 0,
      unsupported: 0,
      ...countBy(operations.map(({ fidelity }) => fidelity)),
    },
    risk: {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
      ...countBy(operations.map(({ risk }) => risk)),
    },
    diagnostics: {
      info: 0,
      warning: 0,
      error: 0,
      ...countBy(diagnostics.map(({ severity }) => severity)),
    },
    approvalsRequired: operations.filter(({ approval }) => approval !== 'none').length,
  };
}

export function formatMigrationReport(bundle: MigrationBundle): string {
  const summary = summarizeMigrationBundle(bundle);
  const lines = [
    `Migration plan: ${summary.planId}`,
    `Created: ${bundle.plan.createdAt}`,
    `Sources: ${summary.sourceProviders.join(', ') || '(none)'} (${summary.snapshotCount} snapshots)`,
    `Target: Vercel ${JSON.stringify(bundle.plan.target.scope)}`,
    `Operations: ${summary.operationCount}`,
    `Fidelity: ${formattedCounts(['exact', 'approximate', 'manual', 'unsupported'], summary.fidelity)}`,
    `Risk: ${formattedCounts(['low', 'medium', 'high', 'critical'], summary.risk)}`,
    `Diagnostics: ${formattedCounts(['info', 'warning', 'error'], summary.diagnostics)}`,
    `Approvals required: ${summary.approvalsRequired}`,
  ];

  if (bundle.plan.operations.length > 0) {
    lines.push('', 'Planned operations:');
    for (const operation of bundle.plan.operations) {
      lines.push(
        `  ${operation.id}: ${operation.product}/${operation.kind} ` +
          `[${operation.fidelity}, ${operation.risk}, ${operation.effect}, ${operation.approval}]`,
      );
    }
  }

  if (bundle.plan.diagnostics.length > 0) {
    lines.push('', 'Diagnostics:');
    for (const diagnostic of bundle.plan.diagnostics) {
      lines.push(`  ${diagnostic.severity.toUpperCase()} ${diagnostic.code}: ${diagnostic.message}`);
      if (diagnostic.remediation !== undefined) {
        lines.push(`    Remediation: ${diagnostic.remediation}`);
      }
    }
  }

  return `${lines.join('\n')}\n`;
}
