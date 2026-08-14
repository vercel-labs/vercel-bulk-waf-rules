import { createHash } from 'node:crypto';

import type { JsonValue } from './model.js';

export class NonSerializableValueError extends TypeError {
  readonly path: string;

  constructor(path: string, detail: string) {
    super(`Value at ${path} is not migration-artifact JSON: ${detail}`);
    this.name = 'NonSerializableValueError';
    this.path = path;
  }
}

function normalize(value: unknown, path: string, ancestors: ReadonlySet<object>): JsonValue {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new NonSerializableValueError(path, `expected a finite number, got ${String(value)}`);
    }
    return value;
  }

  if (typeof value !== 'object') {
    throw new NonSerializableValueError(path, `got ${typeof value}`);
  }

  if (ancestors.has(value)) {
    throw new NonSerializableValueError(path, 'cyclic reference');
  }

  const nextAncestors = new Set(ancestors);
  nextAncestors.add(value);

  if (Array.isArray(value)) {
    return value.map((entry, index) => normalize(entry, `${path}[${index}]`, nextAncestors));
  }

  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new NonSerializableValueError(path, 'expected a plain object');
  }

  const normalized: Record<string, JsonValue> = {};
  for (const key of Object.keys(value).sort()) {
    const entry = (value as Record<string, unknown>)[key];
    if (entry === undefined) {
      throw new NonSerializableValueError(`${path}.${key}`, 'undefined is not allowed');
    }
    normalized[key] = normalize(entry, `${path}.${key}`, nextAncestors);
  }
  return normalized;
}

/** Canonical JSON with recursively sorted object keys and strict JSON values. */
export function canonicalizeJson(value: unknown): JsonValue {
  return normalize(value, '$', new Set());
}

export function canonicalStringify(value: unknown): string {
  return JSON.stringify(canonicalizeJson(value));
}

export function sha256Canonical(value: unknown): string {
  return createHash('sha256').update(canonicalStringify(value), 'utf8').digest('hex');
}
