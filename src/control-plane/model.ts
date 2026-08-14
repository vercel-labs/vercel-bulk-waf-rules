/** Shared workflow types for every migration product. */

export const SNAPSHOT_SCHEMA_VERSION = 1;
export const MIGRATION_PLAN_SCHEMA_VERSION = 1;

export type MigrationProduct = 'firewall' | 'cdn' | 'domains' | 'compute';

export type TranslationFidelity = 'exact' | 'approximate' | 'manual' | 'unsupported';

export type DiagnosticSeverity = 'info' | 'warning' | 'error';

export type OperationRisk = 'low' | 'medium' | 'high' | 'critical';

export type OperationKind =
  | 'create'
  | 'update'
  | 'delete'
  | 'reconcile'
  | 'reorder'
  | 'verify'
  | 'manual';

/**
 * How an operation can affect external state.
 *
 * `staged` means the operation may write a reviewable draft but cannot make it
 * live. `immediate` exists for APIs whose writes have no draft boundary.
 */
export type ExecutionEffect = 'read-only' | 'staged' | 'immediate' | 'external-manual';

export type ApprovalBoundary = 'none' | 'before-execute' | 'before-publish';

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue =
  | JsonPrimitive
  | { readonly [key: string]: JsonValue }
  | readonly JsonValue[];

/** Scope dimensions intentionally remain extensible across provider APIs. */
export type ResourceScope = Readonly<Record<string, string>>;

export interface ResourceIdentity {
  readonly provider: string;
  readonly resourceType: string;
  readonly externalId: string;
  readonly name?: string;
  readonly scope: ResourceScope;
}

export interface SourceReference {
  readonly snapshotId: string;
  readonly resource: ResourceIdentity;
  /** JSON Pointer or provider-specific path within the captured artifact. */
  readonly path?: string;
}

export interface Diagnostic {
  readonly code: string;
  readonly severity: DiagnosticSeverity;
  readonly message: string;
  readonly sourceRefs: readonly SourceReference[];
  readonly remediation?: string;
}

export interface Assumption {
  readonly code: string;
  readonly message: string;
  readonly sourceRefs: readonly SourceReference[];
}

export interface SnapshotArtifact {
  readonly mediaType: string;
  readonly sha256: string;
  readonly location: string;
}

export interface SourceResource {
  readonly identity: ResourceIdentity;
  readonly captured: JsonValue;
}

/** Immutable evidence captured by a provider connector. */
export interface SourceSnapshot {
  readonly schemaVersion: typeof SNAPSHOT_SCHEMA_VERSION;
  readonly id: string;
  readonly provider: string;
  readonly accountId: string;
  readonly capturedAt: string;
  readonly adapterVersion: string;
  readonly resources: readonly SourceResource[];
  readonly artifacts: readonly SnapshotArtifact[];
}

export interface TranslationResult<T> {
  readonly fidelity: TranslationFidelity;
  readonly sourceRefs: readonly SourceReference[];
  readonly targetResources: readonly T[];
  readonly diagnostics: readonly Diagnostic[];
  readonly assumptions: readonly Assumption[];
}

/** Per-source-resource mappings retain fidelity instead of averaging a batch. */
export interface TranslationBatch<T> {
  readonly product: MigrationProduct;
  readonly records: readonly TranslationResult<T>[];
  readonly diagnostics: readonly Diagnostic[];
}

export interface PlanTarget {
  readonly provider: 'vercel';
  readonly scope: ResourceScope;
}

/** A single dependency-aware unit in a reviewable migration plan. */
export interface PlanOperation {
  readonly id: string;
  readonly product: MigrationProduct;
  readonly kind: OperationKind;
  readonly effect: ExecutionEffect;
  readonly approval: ApprovalBoundary;
  readonly risk: OperationRisk;
  readonly fidelity: TranslationFidelity;
  readonly resource: ResourceIdentity;
  readonly sourceRefs: readonly SourceReference[];
  readonly dependsOn: readonly string[];
  readonly payload: JsonValue;
  readonly rollback?: JsonValue;
}

export interface MigrationPlan {
  readonly schemaVersion: typeof MIGRATION_PLAN_SCHEMA_VERSION;
  /** Stable content identifier; timestamps are deliberately excluded. */
  readonly id: string;
  readonly createdAt: string;
  readonly sourceSnapshotIds: readonly string[];
  readonly target: PlanTarget;
  readonly operations: readonly PlanOperation[];
  readonly diagnostics: readonly Diagnostic[];
}

/** Self-contained review artifact emitted by planning commands. */
export interface MigrationBundle {
  readonly schemaVersion: 1;
  readonly snapshots: readonly SourceSnapshot[];
  readonly plan: MigrationPlan;
}
