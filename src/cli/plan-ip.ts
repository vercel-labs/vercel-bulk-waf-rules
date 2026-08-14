import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

import { decompose, type Intent } from '../core/decompose.js';
import { formatCidr } from '../core/ip.js';
import type { PlanTier } from '../core/limits.js';
import { sha256Canonical } from '../control-plane/canonical.js';
import type {
  Diagnostic,
  JsonValue,
  MigrationBundle,
  SourceReference,
  SourceSnapshot,
  TranslationFidelity,
} from '../control-plane/model.js';
import { buildMigrationPlan, type PlanIssue } from '../control-plane/plan.js';
import { parseCsv } from '../importers/csv.js';
import { normalizeEntries, hasFatalProblems, type ImportProblem } from '../importers/normalize.js';
import { formatProblemReport } from '../importers/report.js';
import { compileIpRulePlan } from '../targets/vercel/firewall/compile-ip-plan.js';

export interface PlanIpOptions {
  readonly inputPath: string;
  readonly sourceProvider: string;
  readonly sourceAccountId?: string;
  readonly sourceResourceId?: string;
  readonly intent: Intent;
  readonly projectId: string;
  readonly teamId?: string;
  readonly hostname?: string;
  readonly ruleNamePrefix: string;
  readonly setId?: string;
  readonly tier?: PlanTier;
  readonly allowBypassEscalation?: boolean;
  readonly createdAt: string;
}

export type PlanIpResult =
  | { readonly ok: true; readonly bundle: MigrationBundle }
  | {
      readonly ok: false;
      readonly kind: 'import' | 'decomposition' | 'plan';
      readonly message: string;
      readonly issues?: readonly PlanIssue[];
    };

function rawDigest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function problemSeverity(problem: ImportProblem): Diagnostic['severity'] {
  switch (problem.kind) {
    case 'invalid-address':
    case 'row-shape':
      return 'error';
    case 'suspicious-range':
    case 'private-address':
      return 'warning';
    case 'normalized-host-bits':
    case 'duplicate':
    case 'covered-by-cidr':
      return 'info';
  }
}

function snapshotId(provider: string, digest: string): string {
  return `snapshot_${sha256Canonical({ provider, digest, adapter: 'csv-ip/1' }).slice(0, 24)}`;
}

function inferredSetId(options: PlanIpOptions, digest: string): string {
  return `set_${sha256Canonical({
    product: 'firewall',
    sourceProvider: options.sourceProvider,
    projectId: options.projectId,
    inputPath: resolve(options.inputPath),
    digest,
    intent: options.intent,
  }).slice(0, 12)}`;
}

function fidelityFor(options: PlanIpOptions): TranslationFidelity {
  return options.sourceProvider === 'csv' ? 'exact' : 'manual';
}

function entryPayload(
  entry: {
    readonly cidr: Parameters<typeof formatCidr>[0];
    readonly raw: string;
    readonly lineNumber: number;
    readonly vendor?: string;
    readonly note?: string;
  },
): JsonValue {
  return {
    address: formatCidr(entry.cidr),
    raw: entry.raw,
    lineNumber: entry.lineNumber,
    ...(entry.vendor === undefined ? {} : { vendor: entry.vendor }),
    ...(entry.note === undefined ? {} : { note: entry.note }),
  };
}

export function planIpCsv(text: string, options: PlanIpOptions): PlanIpResult {
  const digest = rawDigest(text);
  const document = parseCsv(text);
  const imported = normalizeEntries(document.rows, document.header, {
    intent: options.intent,
    strict: true,
  });

  if (hasFatalProblems(imported)) {
    return { ok: false, kind: 'import', message: formatProblemReport(imported) };
  }

  const id = snapshotId(options.sourceProvider, digest);
  const sourceIdentity = {
    provider: options.sourceProvider,
    resourceType: 'ip-list',
    externalId: options.sourceResourceId ?? `csv_${digest.slice(0, 16)}`,
    name: options.ruleNamePrefix,
    scope: { accountId: options.sourceAccountId ?? 'unattributed' },
  } as const;
  const sourceRef: SourceReference = { snapshotId: id, resource: sourceIdentity };

  const snapshot: SourceSnapshot = {
    schemaVersion: 1,
    id,
    provider: options.sourceProvider,
    accountId: options.sourceAccountId ?? 'unattributed',
    capturedAt: options.createdAt,
    adapterVersion: 'csv-ip/1',
    resources: [
      {
        identity: sourceIdentity,
        captured: {
          declaredIntent: options.intent.kind,
          entries: imported.entries.map(entryPayload),
          aggregated: imported.aggregated.map(formatCidr),
        },
      },
    ],
    artifacts: [
      {
        mediaType: 'text/csv',
        sha256: digest,
        location: resolve(options.inputPath),
      },
    ],
  };

  const decomposed = decompose({
    intent: options.intent,
    cidrs: imported.aggregated,
    ruleNamePrefix: options.ruleNamePrefix,
    ...(options.hostname === undefined ? {} : { hostname: options.hostname }),
    ...(options.tier === undefined ? {} : { tier: options.tier }),
    ...(options.allowBypassEscalation === undefined
      ? {}
      : { allowBypassEscalation: options.allowBypassEscalation }),
  });
  if (!decomposed.ok) {
    return {
      ok: false,
      kind: 'decomposition',
      message: `${decomposed.refusal.message}\n${decomposed.refusal.remediation}`,
    };
  }

  const fidelity = fidelityFor(options);
  const importDiagnostics: Diagnostic[] = imported.problems.map((problem) => ({
    code: `CSV_${problem.kind.toUpperCase().replaceAll('-', '_')}`,
    severity: problemSeverity(problem),
    message: `Line ${problem.lineNumber}: ${problem.message}`,
    sourceRefs: [sourceRef],
  }));
  if (options.sourceProvider !== 'csv') {
    importDiagnostics.push({
      code: 'SOURCE_INTENT_OPERATOR_DECLARED',
      severity: 'warning',
      message:
        `The CSV is attributed to ${options.sourceProvider}, but this adapter does not parse ` +
        'provider rule semantics. The operator-declared intent is a manual mapping.',
      sourceRefs: [sourceRef],
      remediation: 'Use a semantic provider adapter before classifying this translation as exact.',
    });
  }

  const targetScope = {
    projectId: options.projectId,
    ...(options.teamId === undefined ? {} : { teamId: options.teamId }),
  };
  const compiled = compileIpRulePlan({
    plan: decomposed.plan,
    setId: options.setId ?? inferredSetId(options, digest),
    targetScope,
    sourceRefs: [sourceRef],
    fidelity,
  });
  const built = buildMigrationPlan({
    createdAt: options.createdAt,
    sourceSnapshotIds: [snapshot.id],
    target: { provider: 'vercel', scope: targetScope },
    operations: compiled.operations,
    diagnostics: [...importDiagnostics, ...compiled.diagnostics],
  });
  if (!built.ok) {
    return {
      ok: false,
      kind: 'plan',
      message: built.issues.map((issue) => issue.message).join('\n'),
      issues: built.issues,
    };
  }

  return {
    ok: true,
    bundle: { schemaVersion: 1, snapshots: [snapshot], plan: built.plan },
  };
}
