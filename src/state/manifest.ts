/**
 * The manifest: the authoritative record of which firewall rules this tool owns.
 *
 * It is designed to be **committed** to the customer-engagement repository, so it
 * doubles as the audit trail for "who changed the WAF, when, and to what". Two
 * consequences shape the format:
 *
 * - It must diff cleanly in a pull request. Keys are emitted in sorted order and
 *   the output is pretty-printed and newline-terminated, so an unrelated edit
 *   never produces a whole-file diff and a reviewer can see exactly which rule
 *   hash moved.
 * - It must be parsed defensively. A committed file gets rebased, merged, and
 *   occasionally hand-edited, so {@link parseManifest} validates with real type
 *   guards and returns a discriminated result rather than casting. A manifest we
 *   cannot trust is far more dangerous than no manifest at all: it names rule ids
 *   we would then update or delete.
 *
 * `ManifestRule.id` is the real ownership handle. Name and marker are recovery
 * paths for when this file is lost — see the precedence note in `reconcile.ts`.
 */

import { createHash, randomBytes } from 'node:crypto';

import type { Intent } from '../core/decompose.js';
import { stableStringify } from '../core/rule-builder.js';
import type { MarkerRole } from './marker.js';

/** Manifest schema version. */
export const MANIFEST_VERSION = 1;

const MANIFEST_ROLES: readonly MarkerRole[] = ['allow', 'bypass', 'deny', 'block'];

const INTENT_KINDS: readonly Intent['kind'][] = ['allowlist', 'blocklist', 'bypass'];

/** Rollout stages, in the order an operator is expected to walk them. */
export type PhaseName = 'log' | 'preview-deny' | 'prod-deny';

const PHASE_NAMES: readonly PhaseName[] = ['log', 'preview-deny', 'prod-deny'];

/** One rule we own. */
export interface ManifestRule {
  /**
   * Server-assigned rule id. Absent until the first successful apply.
   *
   * This is the authoritative handle: it survives dashboard renames and is what
   * `vc metrics --group-by waf_rule_id` is keyed on, which is why the reconciler
   * goes to some length to update rules in place rather than recreate them.
   */
  readonly id?: string;
  readonly name: string;
  readonly role: MarkerRole;
  /** 1-based position among rules sharing this role. */
  readonly index: number;
  readonly total: number;
  /** Full sha256 digest from `hashRuleContent`, not the marker's short form. */
  readonly contentHash: string;
}

/** A rollout stage that has been applied. */
export interface PhaseRecord {
  readonly name: PhaseName;
  readonly appliedAt: string;
  readonly configVersion?: string;
  /** Path or URL of the verification evidence captured for this phase. */
  readonly verifyArtifact?: string;
}

/** Everything we know about one import set. */
export interface Manifest {
  readonly version: 1;
  readonly setId: string;
  readonly teamId: string;
  readonly projectId: string;
  readonly teamLevel: boolean;
  readonly intent: Intent;
  readonly hostname?: string;
  /** `hashInput` digest of the source list, to detect an unchanged CSV. */
  readonly inputDigest: string;
  /**
   * Firewall config version observed immediately before the first write.
   *
   * Recorded for forensics only. The platform exposes no client-facing
   * ETag/If-Match on the firewall config, so this cannot be used for optimistic
   * concurrency — do not add a compare-and-swap on it. Concurrent-writer safety
   * comes from aborting when a foreign draft exists (`exec/draft-guard.ts`).
   */
  readonly preImportConfigVersion?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly phases: readonly PhaseRecord[];
  readonly rules: readonly ManifestRule[];
}

/** Result of validating untrusted manifest data. */
export type ParseManifestResult =
  | { readonly ok: true; readonly manifest: Manifest }
  | { readonly ok: false; readonly errors: readonly string[] };

/**
 * Alphabet for {@link newSetId}: Crockford base32 without `i`, `l`, `o`, `u`.
 *
 * Chosen so an id can be read aloud or transcribed from a PR without ambiguity,
 * and so it satisfies the marker grammar's `SAFE_VALUE_PATTERN` (alphanumeric
 * only, no delimiters).
 */
const SET_ID_ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

const DEFAULT_SET_ID_LEN = 12;

/** Options for {@link newSetId}. */
export interface SetIdOptions {
  /**
   * Deterministic seed, for tests and for reproducing an id in a bug report.
   *
   * When supplied the id is a pure function of the seed. Never pass a
   * caller-guessable value in production: two engagements seeded identically
   * would claim each other's rules.
   */
  readonly seed?: string;
  readonly length?: number;
}

/**
 * Generate a short, URL-safe import-set id.
 *
 * 12 characters over a 32-symbol alphabet is 60 bits, which is far beyond what
 * this scale needs — ids only have to be distinct across the handful of import
 * sets in one customer's firewall, not globally unique.
 *
 * `byte % 32` is unbiased here because 256 is an exact multiple of the alphabet
 * length; with a 31- or 33-symbol alphabet it would skew.
 */
export function newSetId(options?: SetIdOptions): string {
  const length = options?.length ?? DEFAULT_SET_ID_LEN;
  if (!Number.isInteger(length) || length < 4 || length > 32) {
    throw new RangeError(`setId length must be an integer in 4..32, got ${String(length)}`);
  }

  const bytes =
    options?.seed === undefined
      ? randomBytes(length)
      : createHash('sha256').update(options.seed, 'utf8').digest();

  let out = '';
  for (let index = 0; index < length; index += 1) {
    const byte = bytes[index % bytes.length] ?? 0;
    out += SET_ID_ALPHABET[byte % SET_ID_ALPHABET.length] ?? '0';
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Narrow to a read-only array without letting `Array.isArray`'s `any[]`
 * signature leak an implicit `any` into the validators.
 */
function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

function isPositiveInt(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
}

function isHexDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/**
 * Collects field-level failures instead of throwing on the first one.
 *
 * A hand-edited manifest usually has several problems at once, and making the
 * operator re-run to discover each in turn wastes a round trip against a live
 * firewall.
 */
class Problems {
  private readonly messages: string[] = [];

  add(path: string, detail: string): void {
    this.messages.push(`${path}: ${detail}`);
  }

  requireString(path: string, value: unknown): void {
    if (!isNonEmptyString(value)) {
      this.add(path, `expected a non-empty string, got ${describe(value)}`);
    }
  }

  get errors(): readonly string[] {
    return this.messages;
  }

  get ok(): boolean {
    return this.messages.length === 0;
  }
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (value === null) return 'null';
  if (isUnknownArray(value)) return `an array of ${value.length}`;
  if (typeof value === 'object') return 'an object';
  return `${typeof value} ${JSON.stringify(value)}`;
}

function parseIntent(value: unknown, path: string, problems: Problems): Intent | null {
  if (!isRecord(value)) {
    problems.add(path, `expected an object, got ${describe(value)}`);
    return null;
  }
  const kind = INTENT_KINDS.find((candidate) => candidate === value['kind']);
  if (kind === undefined) {
    problems.add(path, `kind must be one of ${INTENT_KINDS.join(', ')}, got ${describe(value['kind'])}`);
    return null;
  }
  return { kind };
}

function parseRule(value: unknown, path: string, problems: Problems): ManifestRule | null {
  if (!isRecord(value)) {
    problems.add(path, `expected an object, got ${describe(value)}`);
    return null;
  }

  const before = problems.errors.length;

  problems.requireString(`${path}.name`, value['name']);

  const role = MANIFEST_ROLES.find((candidate) => candidate === value['role']);
  if (role === undefined) {
    problems.add(`${path}.role`, `must be one of ${MANIFEST_ROLES.join(', ')}, got ${describe(value['role'])}`);
  }

  if (!isPositiveInt(value['index'])) {
    problems.add(`${path}.index`, `expected a 1-based integer, got ${describe(value['index'])}`);
  }
  if (!isPositiveInt(value['total'])) {
    problems.add(`${path}.total`, `expected a 1-based integer, got ${describe(value['total'])}`);
  }
  if (!isHexDigest(value['contentHash'])) {
    problems.add(
      `${path}.contentHash`,
      `expected a 64-character lowercase hex sha256 digest, got ${describe(value['contentHash'])}`,
    );
  }

  const id = value['id'];
  if (id !== undefined && !isNonEmptyString(id)) {
    problems.add(`${path}.id`, `expected a non-empty string when present, got ${describe(id)}`);
  }

  if (problems.errors.length !== before) return null;

  const name = value['name'];
  const index = value['index'];
  const total = value['total'];
  const contentHash = value['contentHash'];
  if (
    !isNonEmptyString(name) ||
    role === undefined ||
    !isPositiveInt(index) ||
    !isPositiveInt(total) ||
    !isHexDigest(contentHash)
  ) {
    return null;
  }

  return {
    name,
    role,
    index,
    total,
    contentHash,
    ...(isNonEmptyString(id) ? { id } : {}),
  };
}

function parsePhase(value: unknown, path: string, problems: Problems): PhaseRecord | null {
  if (!isRecord(value)) {
    problems.add(path, `expected an object, got ${describe(value)}`);
    return null;
  }

  const name = PHASE_NAMES.find((candidate) => candidate === value['name']);
  if (name === undefined) {
    problems.add(`${path}.name`, `must be one of ${PHASE_NAMES.join(', ')}, got ${describe(value['name'])}`);
  }
  const appliedAt = value['appliedAt'];
  if (!isNonEmptyString(appliedAt)) {
    problems.add(`${path}.appliedAt`, `expected an ISO timestamp string, got ${describe(appliedAt)}`);
  }

  const configVersion = value['configVersion'];
  const verifyArtifact = value['verifyArtifact'];
  if (configVersion !== undefined && !isNonEmptyString(configVersion)) {
    problems.add(`${path}.configVersion`, `expected a non-empty string when present`);
  }
  if (verifyArtifact !== undefined && !isNonEmptyString(verifyArtifact)) {
    problems.add(`${path}.verifyArtifact`, `expected a non-empty string when present`);
  }

  if (name === undefined || !isNonEmptyString(appliedAt)) return null;

  return {
    name,
    appliedAt,
    ...(isNonEmptyString(configVersion) ? { configVersion } : {}),
    ...(isNonEmptyString(verifyArtifact) ? { verifyArtifact } : {}),
  };
}

/**
 * Validate untrusted data as a {@link Manifest}.
 *
 * An unrecognized `version` is reported with an explicit upgrade instruction
 * rather than a generic shape error, because that is the one failure a caller can
 * act on without inspecting the file: the manifest is newer than this build.
 */
export function parseManifest(value: unknown): ParseManifestResult {
  const problems = new Problems();

  if (!isRecord(value)) {
    return { ok: false, errors: [`manifest: expected an object, got ${describe(value)}`] };
  }

  const version = value['version'];
  if (version !== MANIFEST_VERSION) {
    return {
      ok: false,
      errors: [
        `manifest.version: expected ${MANIFEST_VERSION}, got ${describe(version)}. ` +
          'This manifest was written by a different version of the tool. Upgrade this tool to ' +
          'the version that produced the manifest, or delete the manifest and re-import — ' +
          'deleting it orphans every rule it tracks, so prefer upgrading.',
      ],
    };
  }

  problems.requireString('manifest.setId', value['setId']);
  problems.requireString('manifest.teamId', value['teamId']);
  problems.requireString('manifest.projectId', value['projectId']);
  problems.requireString('manifest.inputDigest', value['inputDigest']);
  problems.requireString('manifest.createdAt', value['createdAt']);
  problems.requireString('manifest.updatedAt', value['updatedAt']);

  if (typeof value['teamLevel'] !== 'boolean') {
    problems.add('manifest.teamLevel', `expected a boolean, got ${describe(value['teamLevel'])}`);
  }

  const intent = parseIntent(value['intent'], 'manifest.intent', problems);

  const hostname = value['hostname'];
  if (hostname !== undefined && !isNonEmptyString(hostname)) {
    problems.add('manifest.hostname', `expected a non-empty string when present, got ${describe(hostname)}`);
  }
  const preImportConfigVersion = value['preImportConfigVersion'];
  if (preImportConfigVersion !== undefined && !isNonEmptyString(preImportConfigVersion)) {
    problems.add('manifest.preImportConfigVersion', 'expected a non-empty string when present');
  }

  const rawRules = value['rules'];
  const rules: ManifestRule[] = [];
  if (!isUnknownArray(rawRules)) {
    problems.add('manifest.rules', `expected an array, got ${describe(rawRules)}`);
  } else {
    rawRules.forEach((entry, index) => {
      const parsed = parseRule(entry, `manifest.rules[${index}]`, problems);
      if (parsed !== null) rules.push(parsed);
    });
  }

  const rawPhases = value['phases'];
  const phases: PhaseRecord[] = [];
  if (!isUnknownArray(rawPhases)) {
    problems.add('manifest.phases', `expected an array, got ${describe(rawPhases)}`);
  } else {
    rawPhases.forEach((entry, index) => {
      const parsed = parsePhase(entry, `manifest.phases[${index}]`, problems);
      if (parsed !== null) phases.push(parsed);
    });
  }

  if (!problems.ok) return { ok: false, errors: problems.errors };

  const setId = value['setId'];
  const teamId = value['teamId'];
  const projectId = value['projectId'];
  const inputDigest = value['inputDigest'];
  const createdAt = value['createdAt'];
  const updatedAt = value['updatedAt'];
  const teamLevel = value['teamLevel'];

  if (
    !isNonEmptyString(setId) ||
    !isNonEmptyString(teamId) ||
    !isNonEmptyString(projectId) ||
    !isNonEmptyString(inputDigest) ||
    !isNonEmptyString(createdAt) ||
    !isNonEmptyString(updatedAt) ||
    typeof teamLevel !== 'boolean' ||
    intent === null
  ) {
    return { ok: false, errors: ['manifest: failed final validation after field checks passed'] };
  }

  return {
    ok: true,
    manifest: {
      version: MANIFEST_VERSION,
      setId,
      teamId,
      projectId,
      teamLevel,
      intent,
      inputDigest,
      createdAt,
      updatedAt,
      phases,
      rules,
      ...(isNonEmptyString(hostname) ? { hostname } : {}),
      ...(isNonEmptyString(preImportConfigVersion) ? { preImportConfigVersion } : {}),
    },
  };
}

/**
 * Render a manifest for commit: sorted keys, two-space indent, trailing newline.
 *
 * `stableStringify` supplies the canonical key ordering; re-parsing and
 * re-stringifying with an indent then adds the human-readable layout without
 * disturbing that order, since both `JSON.parse` and `JSON.stringify` preserve
 * textual key order. Reusing the existing serializer this way avoids a second
 * canonicalization implementation that could drift from the one the content
 * hashes depend on.
 */
export function serializeManifest(manifest: Manifest): string {
  const canonical: unknown = JSON.parse(stableStringify(manifest));
  return `${JSON.stringify(canonical, null, 2)}\n`;
}

/**
 * Filesystem operations this module needs, supplied by the caller.
 *
 * Injected rather than importing `node:fs` so that tests are hermetic and this
 * layer stays portable. `rename` is part of the contract because an atomic write
 * cannot be expressed without it — see {@link writeManifest}.
 */
export interface ManifestIo {
  readFile(path: string): Promise<string>;
  writeFile(path: string, data: string): Promise<void>;
  mkdir(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
}

/** Outcome of reading a manifest from disk. */
export type ReadManifestResult =
  | { readonly kind: 'found'; readonly manifest: Manifest }
  | { readonly kind: 'absent' }
  | { readonly kind: 'invalid'; readonly errors: readonly string[] };

function isMissingFileError(error: unknown): boolean {
  return isRecord(error) && error['code'] === 'ENOENT';
}

/**
 * Directory portion of a path.
 *
 * Implemented locally rather than via `node:path` so that the same string
 * arithmetic runs under the in-memory fake as on a real filesystem, and so path
 * separators in test fixtures behave identically on every platform.
 */
function parentDir(path: string): string {
  const cut = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  return cut <= 0 ? '.' : path.slice(0, cut);
}

/**
 * Read and validate a manifest.
 *
 * "Absent" and "invalid" are separate outcomes on purpose. A missing manifest is
 * the normal first-run state and the caller should proceed with marker-based
 * recovery. An invalid manifest means the audit trail is untrustworthy, and the
 * caller must stop rather than guess which rules it owns.
 */
export async function readManifest(io: ManifestIo, path: string): Promise<ReadManifestResult> {
  let raw: string;
  try {
    raw = await io.readFile(path);
  } catch (error: unknown) {
    if (isMissingFileError(error)) return { kind: 'absent' };
    throw error;
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error);
    return { kind: 'invalid', errors: [`${path}: not valid JSON (${detail})`] };
  }

  const parsed = parseManifest(data);
  return parsed.ok ? { kind: 'found', manifest: parsed.manifest } : { kind: 'invalid', errors: parsed.errors };
}

/** Options for {@link writeManifest}. */
export interface WriteManifestOptions {
  /** Deterministic temp-file discriminator, for tests. */
  readonly tempSuffix?: string;
}

/**
 * Write a manifest durably: create the directory, write a sibling temp file,
 * then rename it over the target.
 *
 * The rename is what makes this safe. Writing in place means an interrupted run
 * (Ctrl-C, OOM, a CI step timing out) can leave a truncated file, and a truncated
 * manifest fails validation — which orphans **every rule it tracked**, because
 * the ids are gone and the next run has only markers to go on. Rename is atomic
 * within a filesystem, so an interrupted write leaves the previous manifest
 * entirely intact and the worst case is a stray temp file.
 */
export async function writeManifest(
  io: ManifestIo,
  path: string,
  manifest: Manifest,
  options?: WriteManifestOptions,
): Promise<void> {
  const suffix = options?.tempSuffix ?? randomBytes(6).toString('hex');
  const tempPath = `${path}.tmp-${suffix}`;

  await io.mkdir(parentDir(path));
  await io.writeFile(tempPath, serializeManifest(manifest));
  await io.rename(tempPath, path);
}
