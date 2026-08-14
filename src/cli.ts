#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';

import type { Intent } from './core/decompose.js';
import type { PlanTier } from './core/limits.js';
import { planCloudflareRuleset } from './cli/plan-cloudflare.js';
import { planIpCsv } from './cli/plan-ip.js';
import { writeMigrationBundle } from './control-plane/artifact-store.js';
import {
  formatArtifactProblems,
  parseMigrationBundleText,
} from './control-plane/artifacts.js';
import {
  CAPABILITY_REGISTRY,
  formatCapabilityRegistry,
} from './control-plane/capabilities.js';
import type { MigrationBundle } from './control-plane/model.js';
import { formatMigrationReport, summarizeMigrationBundle } from './control-plane/report.js';

const HELP = `Vercel Migration Control Plane (early preview)

Usage:
  vercel-migrate plan-ip --input <file.csv> --intent <intent> --project-id <id> [options]
  vercel-migrate plan-cloudflare --input <ruleset.json> --account-id <id> --zone-id <id> --project-id <id>
  vercel-migrate validate --input <migration-bundle.json>
  vercel-migrate report --input <migration-bundle.json>
  vercel-migrate support [--json]

Required:
  --input <path>             IP-list CSV to snapshot and plan
  --intent <kind>            allowlist, blocklist, or bypass
  --project-id <id>          Target Vercel project id

Options:
  --source-provider <name>   csv, cloudflare, aws, akamai, or fastly (default: csv)
  --source-account-id <id>   Source account identifier for provenance
  --source-resource-id <id>  Source list/rule identifier for provenance
  --account-id <id>          Source Cloudflare account id
  --zone-id <id>             Source Cloudflare zone id
  --team-id <id>             Target Vercel team id
  --hostname <host>          Restrict generated Firewall rules to one hostname
  --rule-name-prefix <text>  Stable rule name prefix (default: Migrated IP policy)
  --set-id <id>              Stable ownership id; derived when omitted
  --tier <tier>              hobby, pro, or enterprise (default: pro)
  --allow-bypass-escalation  Permit large allowlists to use bypass-then-deny
  --artifact-dir <path>      Write plan output below <path>/v1 instead of stdout
  --json                     Emit machine-readable support information
  --help                     Show this help

All commands are non-mutating with respect to Vercel. plan-ip writes a source
snapshot and migration plan bundle to stdout unless --artifact-dir is supplied.
`;

class UsageError extends Error {}

function required(value: string | undefined, flag: string): string {
  if (value === undefined || value.trim() === '') throw new UsageError(`${flag} is required.`);
  return value;
}

function parseIntent(value: string | undefined): Intent {
  switch (required(value, '--intent')) {
    case 'allowlist':
      return { kind: 'allowlist' };
    case 'blocklist':
      return { kind: 'blocklist' };
    case 'bypass':
      return { kind: 'bypass' };
    default:
      throw new UsageError('--intent must be allowlist, blocklist, or bypass.');
  }
}

function parseTier(value: string | undefined): PlanTier | undefined {
  if (value === undefined) return undefined;
  if (value === 'hobby' || value === 'pro' || value === 'enterprise') return value;
  throw new UsageError('--tier must be hobby, pro, or enterprise.');
}

async function loadBundle(path: string): Promise<MigrationBundle | null> {
  const result = parseMigrationBundleText(await readFile(path, 'utf8'));
  if (result.ok) return result.bundle;
  process.stderr.write(`${formatArtifactProblems(result.problems)}\n`);
  process.exitCode = 1;
  return null;
}

async function emitBundle(bundle: MigrationBundle, artifactDir: string | undefined): Promise<void> {
  if (artifactDir === undefined) {
    process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
    return;
  }
  const path = await writeMigrationBundle(bundle, artifactDir);
  process.stdout.write(`Wrote migration bundle ${bundle.plan.id} to ${path}\n`);
}

async function main(): Promise<void> {
  const parsed = parseArgs({
    allowPositionals: true,
    strict: true,
    options: {
      input: { type: 'string' },
      intent: { type: 'string' },
      'project-id': { type: 'string' },
      'team-id': { type: 'string' },
      hostname: { type: 'string' },
      'source-provider': { type: 'string', default: 'csv' },
      'source-account-id': { type: 'string' },
      'source-resource-id': { type: 'string' },
      'account-id': { type: 'string' },
      'zone-id': { type: 'string' },
      'rule-name-prefix': { type: 'string', default: 'Migrated IP policy' },
      'set-id': { type: 'string' },
      tier: { type: 'string' },
      'allow-bypass-escalation': { type: 'boolean', default: false },
      'artifact-dir': { type: 'string' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });

  if (parsed.values.help || parsed.positionals.length === 0) {
    process.stdout.write(HELP);
    return;
  }
  if (parsed.positionals.length !== 1) {
    throw new UsageError(`Unknown command: ${parsed.positionals.join(' ') || '(none)'}.`);
  }

  const command = parsed.positionals[0];
  if (command === 'support') {
    process.stdout.write(
      parsed.values.json
        ? `${JSON.stringify(CAPABILITY_REGISTRY, null, 2)}\n`
        : formatCapabilityRegistry(),
    );
    return;
  }

  if (command === 'validate') {
    const inputPath = required(parsed.values.input, '--input');
    const bundle = await loadBundle(inputPath);
    if (bundle === null) return;
    const summary = summarizeMigrationBundle(bundle);
    process.stdout.write(
      `Valid migration bundle ${summary.planId}: ${summary.snapshotCount} snapshot(s), ` +
        `${summary.operationCount} operation(s).\n`,
    );
    return;
  }

  if (command === 'report') {
    const inputPath = required(parsed.values.input, '--input');
    const bundle = await loadBundle(inputPath);
    if (bundle === null) return;
    process.stdout.write(formatMigrationReport(bundle));
    return;
  }

  if (command !== 'plan-ip') {
    if (command !== 'plan-cloudflare') {
      throw new UsageError(`Unknown command: ${command ?? '(none)'}.`);
    }

    const inputPath = required(parsed.values.input, '--input');
    const text = await readFile(inputPath, 'utf8');
    const result = planCloudflareRuleset(text, {
      inputPath,
      accountId: required(parsed.values['account-id'], '--account-id'),
      zoneId: required(parsed.values['zone-id'], '--zone-id'),
      projectId: required(parsed.values['project-id'], '--project-id'),
      createdAt: new Date().toISOString(),
      ...(parsed.values['team-id'] === undefined ? {} : { teamId: parsed.values['team-id'] }),
    });
    if (!result.ok) {
      process.stderr.write(`${result.message}\n`);
      process.exitCode = 1;
      return;
    }
    await emitBundle(result.bundle, parsed.values['artifact-dir']);
    return;
  }

  const inputPath = required(parsed.values.input, '--input');
  const tier = parseTier(parsed.values.tier);
  const text = await readFile(inputPath, 'utf8');
  const result = planIpCsv(text, {
    inputPath,
    sourceProvider: parsed.values['source-provider'] ?? 'csv',
    intent: parseIntent(parsed.values.intent),
    projectId: required(parsed.values['project-id'], '--project-id'),
    ruleNamePrefix: parsed.values['rule-name-prefix'] ?? 'Migrated IP policy',
    allowBypassEscalation: parsed.values['allow-bypass-escalation'] ?? false,
    createdAt: new Date().toISOString(),
    ...(parsed.values['source-account-id'] === undefined
      ? {}
      : { sourceAccountId: parsed.values['source-account-id'] }),
    ...(parsed.values['source-resource-id'] === undefined
      ? {}
      : { sourceResourceId: parsed.values['source-resource-id'] }),
    ...(parsed.values['team-id'] === undefined ? {} : { teamId: parsed.values['team-id'] }),
    ...(parsed.values.hostname === undefined ? {} : { hostname: parsed.values.hostname }),
    ...(parsed.values['set-id'] === undefined ? {} : { setId: parsed.values['set-id'] }),
    ...(tier === undefined ? {} : { tier }),
  });

  if (!result.ok) {
    process.stderr.write(`${result.message}\n`);
    process.exitCode = 1;
    return;
  }

  await emitBundle(result.bundle, parsed.values['artifact-dir']);
}

main().catch((error: unknown) => {
  const detail = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Error: ${detail}\n`);
  if (error instanceof UsageError) process.stderr.write(`\n${HELP}`);
  process.exitCode = 1;
});
