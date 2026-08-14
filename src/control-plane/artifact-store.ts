import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import type { MigrationBundle } from './model.js';

export const DEFAULT_ARTIFACT_ROOT = '.vercel-migrate/artifacts';

/** Persist a bundle below a schema-versioned directory using private file permissions. */
export async function writeMigrationBundle(
  bundle: MigrationBundle,
  artifactRoot: string = DEFAULT_ARTIFACT_ROOT,
): Promise<string> {
  const directory = resolve(artifactRoot, `v${bundle.schemaVersion}`);
  const path = resolve(directory, `${bundle.plan.id}.json`);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(bundle, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  return path;
}
