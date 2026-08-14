import type { MigrationBundle } from '../control-plane/model.js';
import { buildMigrationPlan } from '../control-plane/plan.js';
import {
  parseCloudflareRulesetText,
  snapshotCloudflareRuleset,
  translateCloudflareRuleset,
} from '../providers/cloudflare/rulesets.js';
import { compileFirewallTranslation } from '../targets/vercel/firewall/compile-policy.js';

export interface PlanCloudflareOptions {
  readonly inputPath: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly projectId: string;
  readonly teamId?: string;
  readonly createdAt: string;
}

export type PlanCloudflareResult =
  | { readonly ok: true; readonly bundle: MigrationBundle }
  | { readonly ok: false; readonly kind: 'source' | 'plan'; readonly message: string };

/** Plan a Cloudflare custom Rulesets API response without contacting either provider. */
export function planCloudflareRuleset(
  text: string,
  options: PlanCloudflareOptions,
): PlanCloudflareResult {
  const parsed = parseCloudflareRulesetText(text);
  if (!parsed.ok) {
    return {
      ok: false,
      kind: 'source',
      message: parsed.problems.map(({ path, message }) => `${path}: ${message}`).join('\n'),
    };
  }

  const snapshotOptions = {
    inputPath: options.inputPath,
    accountId: options.accountId,
    zoneId: options.zoneId,
    capturedAt: options.createdAt,
  };
  const snapshot = snapshotCloudflareRuleset(text, parsed.input, snapshotOptions);
  const translation = translateCloudflareRuleset(parsed.input, snapshot, snapshotOptions);
  const targetScope = {
    projectId: options.projectId,
    ...(options.teamId === undefined ? {} : { teamId: options.teamId }),
  };
  const compilation = compileFirewallTranslation({
    translation,
    ownershipId: `cloudflare-${parsed.input.ruleset.id}`,
    targetScope,
  });
  const built = buildMigrationPlan({
    createdAt: options.createdAt,
    sourceSnapshotIds: [snapshot.id],
    target: { provider: 'vercel', scope: targetScope },
    operations: compilation.operations,
    diagnostics: compilation.diagnostics,
  });
  if (!built.ok) {
    return {
      ok: false,
      kind: 'plan',
      message: built.issues.map(({ message }) => message).join('\n'),
    };
  }

  return {
    ok: true,
    bundle: { schemaVersion: 1, snapshots: [snapshot], plan: built.plan },
  };
}
