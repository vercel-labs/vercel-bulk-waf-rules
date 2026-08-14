import { z } from 'zod';

import { canonicalStringify } from './canonical.js';
import type { MigrationBundle, ResourceIdentity, SourceReference } from './model.js';
import { buildMigrationPlan } from './plan.js';

const nonEmptyString = z.string().min(1);
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.string().refine(
  (value) => /^\d{4}-\d{2}-\d{2}T/.test(value) && !Number.isNaN(Date.parse(value)),
  'expected an ISO-8601 timestamp',
);

const jsonValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number().finite(),
    z.string(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

const scopeSchema = z.record(z.string(), z.string());

const resourceIdentitySchema = z
  .object({
    provider: nonEmptyString,
    resourceType: nonEmptyString,
    externalId: nonEmptyString,
    name: nonEmptyString.optional(),
    scope: scopeSchema,
  })
  .strict();

const sourceReferenceSchema = z
  .object({
    snapshotId: nonEmptyString,
    resource: resourceIdentitySchema,
    path: nonEmptyString.optional(),
  })
  .strict();

const diagnosticSchema = z
  .object({
    code: nonEmptyString,
    severity: z.enum(['info', 'warning', 'error']),
    message: nonEmptyString,
    sourceRefs: z.array(sourceReferenceSchema),
    remediation: nonEmptyString.optional(),
  })
  .strict();

const sourceSnapshotSchema = z
  .object({
    schemaVersion: z.literal(1),
    id: nonEmptyString,
    provider: nonEmptyString,
    accountId: nonEmptyString,
    capturedAt: timestamp,
    adapterVersion: nonEmptyString,
    resources: z.array(
      z
        .object({
          identity: resourceIdentitySchema,
          captured: jsonValueSchema,
        })
        .strict(),
    ),
    artifacts: z.array(
      z
        .object({
          mediaType: nonEmptyString,
          sha256,
          location: nonEmptyString,
        })
        .strict(),
    ),
  })
  .strict();

const planOperationSchema = z
  .object({
    id: nonEmptyString,
    product: z.enum(['firewall', 'cdn', 'domains', 'compute']),
    kind: z.enum(['create', 'update', 'delete', 'reconcile', 'reorder', 'verify', 'manual']),
    effect: z.enum(['read-only', 'staged', 'immediate', 'external-manual']),
    approval: z.enum(['none', 'before-execute', 'before-publish']),
    risk: z.enum(['low', 'medium', 'high', 'critical']),
    fidelity: z.enum(['exact', 'approximate', 'manual', 'unsupported']),
    resource: resourceIdentitySchema,
    sourceRefs: z.array(sourceReferenceSchema),
    dependsOn: z.array(nonEmptyString),
    payload: jsonValueSchema,
    rollback: jsonValueSchema.optional(),
  })
  .strict();

const migrationPlanSchema = z
  .object({
    schemaVersion: z.literal(1),
    id: z.string().regex(/^plan_[0-9a-f]{24}$/),
    createdAt: timestamp,
    sourceSnapshotIds: z.array(nonEmptyString),
    target: z
      .object({
        provider: z.literal('vercel'),
        scope: scopeSchema,
      })
      .strict(),
    operations: z.array(planOperationSchema),
    diagnostics: z.array(diagnosticSchema),
  })
  .strict();

const migrationBundleSchema = z
  .object({
    schemaVersion: z.literal(1),
    snapshots: z.array(sourceSnapshotSchema),
    plan: migrationPlanSchema,
  })
  .strict();

export type ArtifactProblemCode =
  | 'INVALID_JSON'
  | 'SCHEMA_INVALID'
  | 'DUPLICATE_SNAPSHOT_ID'
  | 'MISSING_SNAPSHOT'
  | 'SOURCE_REFERENCE_MISMATCH'
  | 'PLAN_INVALID'
  | 'PLAN_ID_MISMATCH';

export interface ArtifactProblem {
  readonly code: ArtifactProblemCode;
  readonly path: string;
  readonly message: string;
}

export type ParseMigrationBundleResult =
  | { readonly ok: true; readonly bundle: MigrationBundle }
  | { readonly ok: false; readonly problems: readonly ArtifactProblem[] };

function pathOf(segments: readonly PropertyKey[]): string {
  if (segments.length === 0) return '$';
  return segments.reduce<string>((path, segment) => {
    if (typeof segment === 'number') return `${path}[${segment}]`;
    return `${path}.${String(segment)}`;
  }, '$');
}

function sameIdentity(left: ResourceIdentity, right: ResourceIdentity): boolean {
  return canonicalStringify(left) === canonicalStringify(right);
}

function referencesFrom(bundle: MigrationBundle): readonly SourceReference[] {
  return [
    ...bundle.plan.operations.flatMap((operation) => operation.sourceRefs),
    ...bundle.plan.diagnostics.flatMap((diagnostic) => diagnostic.sourceRefs),
  ];
}

function validateSemantics(bundle: MigrationBundle): ArtifactProblem[] {
  const problems: ArtifactProblem[] = [];
  const snapshots = new Map<string, MigrationBundle['snapshots'][number]>();

  for (const [index, snapshot] of bundle.snapshots.entries()) {
    if (snapshots.has(snapshot.id)) {
      problems.push({
        code: 'DUPLICATE_SNAPSHOT_ID',
        path: `$.snapshots[${index}].id`,
        message: `Snapshot id ${JSON.stringify(snapshot.id)} appears more than once.`,
      });
    } else {
      snapshots.set(snapshot.id, snapshot);
    }
  }

  for (const [index, snapshotId] of bundle.plan.sourceSnapshotIds.entries()) {
    if (!snapshots.has(snapshotId)) {
      problems.push({
        code: 'MISSING_SNAPSHOT',
        path: `$.plan.sourceSnapshotIds[${index}]`,
        message: `Plan references missing snapshot ${JSON.stringify(snapshotId)}.`,
      });
    }
  }

  for (const reference of referencesFrom(bundle)) {
    const snapshot = snapshots.get(reference.snapshotId);
    if (snapshot === undefined) {
      problems.push({
        code: 'MISSING_SNAPSHOT',
        path: '$.plan',
        message: `Source reference points to missing snapshot ${JSON.stringify(reference.snapshotId)}.`,
      });
      continue;
    }
    if (!snapshot.resources.some(({ identity }) => sameIdentity(identity, reference.resource))) {
      problems.push({
        code: 'SOURCE_REFERENCE_MISMATCH',
        path: '$.plan',
        message:
          `Source reference ${JSON.stringify(reference.resource.externalId)} does not identify a ` +
          `resource captured by snapshot ${JSON.stringify(reference.snapshotId)}.`,
      });
    }
  }

  const rebuilt = buildMigrationPlan({
    createdAt: bundle.plan.createdAt,
    sourceSnapshotIds: bundle.plan.sourceSnapshotIds,
    target: bundle.plan.target,
    operations: bundle.plan.operations,
    diagnostics: bundle.plan.diagnostics,
  });
  if (!rebuilt.ok) {
    for (const issue of rebuilt.issues) {
      problems.push({ code: 'PLAN_INVALID', path: '$.plan', message: issue.message });
    }
  } else if (rebuilt.plan.id !== bundle.plan.id) {
    problems.push({
      code: 'PLAN_ID_MISMATCH',
      path: '$.plan.id',
      message:
        `Stored plan id ${JSON.stringify(bundle.plan.id)} does not match content id ` +
        `${JSON.stringify(rebuilt.plan.id)}. The artifact may have been edited after planning.`,
    });
  }

  return problems;
}

export function parseMigrationBundle(value: unknown): ParseMigrationBundleResult {
  const parsed = migrationBundleSchema.safeParse(value);
  if (!parsed.success) {
    return {
      ok: false,
      problems: parsed.error.issues.map((issue) => ({
        code: 'SCHEMA_INVALID',
        path: pathOf(issue.path),
        message: issue.message,
      })),
    };
  }

  const bundle: MigrationBundle = parsed.data as MigrationBundle;
  const problems = validateSemantics(bundle);
  return problems.length === 0 ? { ok: true, bundle } : { ok: false, problems };
}

export function parseMigrationBundleText(text: string): ParseMigrationBundleResult {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch (error) {
    return {
      ok: false,
      problems: [
        {
          code: 'INVALID_JSON',
          path: '$',
          message: error instanceof Error ? error.message : String(error),
        },
      ],
    };
  }
  return parseMigrationBundle(value);
}

export function formatArtifactProblems(problems: readonly ArtifactProblem[]): string {
  return problems.map((problem) => `${problem.code} ${problem.path}: ${problem.message}`).join('\n');
}
