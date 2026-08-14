import type { MigrationProduct } from './model.js';

export const CAPABILITY_REGISTRY_VERSION = 1;

export type SourceSupportLevel =
  | 'planned'
  | 'manual-input'
  | 'offline-semantic'
  | 'native-inventory'
  | 'semantic-translation'
  | 'live-verified';

export type ApiVariantStatus = 'current' | 'compatibility';

export interface ApiVariant {
  readonly id: string;
  readonly status: ApiVariantStatus;
  readonly documentation: string;
}

export interface SourceCapability {
  readonly provider: 'cloudflare' | 'aws' | 'akamai' | 'fastly';
  readonly product: MigrationProduct;
  readonly supportLevel: SourceSupportLevel;
  readonly nativeDiscovery: boolean;
  readonly sourceSchemaValidation: boolean;
  readonly semanticCoverage: readonly string[];
  readonly knownUnsupported: readonly string[];
  readonly liveE2e: 'none' | 'harness-only' | 'passing';
  readonly apiVariants: readonly ApiVariant[];
  readonly lastVerified: string;
}

export interface TargetCapability {
  readonly provider: 'vercel';
  readonly product: MigrationProduct;
  readonly supportLevel: 'planned' | 'compiler-only' | 'staged-execution' | 'live-verified';
  readonly coverage: readonly string[];
  readonly knownUnsupported: readonly string[];
  readonly documentation: readonly string[];
  readonly lastVerified: string;
}

/**
 * Truthful advertised support, not the intended roadmap.
 *
 * Raising a support level requires updating AGENTS.md's definition-of-done
 * evidence and adding the corresponding contract/live tests.
 */
export const SOURCE_CAPABILITIES: readonly SourceCapability[] = [
  {
    provider: 'cloudflare',
    product: 'firewall',
    supportLevel: 'offline-semantic',
    nativeDiscovery: false,
    sourceSchemaValidation: true,
    semanticCoverage: [
      'Custom Rulesets API response snapshots',
      'Boolean expressions over IP, ASN, country, host, path, method, scheme, protocol, and user agent',
      'block and log actions',
      'challenge actions as an explicit approximation',
      'per-rule enabled state and priority',
    ],
    knownUnsupported: [
      'native authenticated discovery',
      'fields, functions, and transformations outside the fail-closed expression subset',
      'skip action parameters and execute actions',
      'rate limiting and managed rulesets',
      'IP Access Rule ASN and country targets',
    ],
    liveE2e: 'none',
    apiVariants: [
      {
        id: 'rulesets-http_request_firewall_custom',
        status: 'current',
        documentation: 'https://developers.cloudflare.com/waf/custom-rules/create-api/',
      },
      {
        id: 'ip-access-rules',
        status: 'compatibility',
        documentation: 'https://developers.cloudflare.com/waf/tools/ip-access-rules/',
      },
    ],
    lastVerified: '2026-08-14',
  },
  {
    provider: 'aws',
    product: 'firewall',
    supportLevel: 'manual-input',
    nativeDiscovery: false,
    sourceSchemaValidation: false,
    semanticCoverage: ['operator-declared IP-list intent from CSV'],
    knownUnsupported: [
      'Web ACL statement trees and default action',
      'rule actions and priority',
      'rate-based rules and forwarded-IP behavior',
      'managed rule groups and transformations',
    ],
    liveE2e: 'harness-only',
    apiVariants: [
      {
        id: 'wafv2',
        status: 'current',
        documentation: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-api.html',
      },
    ],
    lastVerified: '2026-08-14',
  },
  {
    provider: 'akamai',
    product: 'firewall',
    supportLevel: 'manual-input',
    nativeDiscovery: false,
    sourceSchemaValidation: false,
    semanticCoverage: ['operator-declared IP-list intent from CSV'],
    knownUnsupported: [
      'AppSec match targets and policy actions',
      'rule order and activation state',
      'rate policies, bot controls, and managed protections',
      'Network List usage context',
    ],
    liveE2e: 'none',
    apiVariants: [
      {
        id: 'application-security',
        status: 'current',
        documentation: 'https://techdocs.akamai.com/application-security/reference/api-summary',
      },
      {
        id: 'network-lists',
        status: 'current',
        documentation: 'https://techdocs.akamai.com/network-lists/reference/api',
      },
    ],
    lastVerified: '2026-08-14',
  },
  {
    provider: 'fastly',
    product: 'firewall',
    supportLevel: 'manual-input',
    nativeDiscovery: false,
    sourceSchemaValidation: false,
    semanticCoverage: ['operator-declared IP-list intent from CSV'],
    knownUnsupported: [
      'Next-Gen WAF rule conditions and action arrays',
      'rule scope, enabled state, expiry, and signals',
      'rate limits and request logging',
      'automatic distinction between allowlists and blacklists',
    ],
    liveE2e: 'none',
    apiVariants: [
      {
        id: 'ngwaf-v1',
        status: 'current',
        documentation: 'https://www.fastly.com/documentation/reference/api/ngwaf/rules/',
      },
      {
        id: 'signalsciences-v0',
        status: 'compatibility',
        documentation: 'https://www.fastly.com/documentation/signalsciences/api/',
      },
    ],
    lastVerified: '2026-08-14',
  },
];

export const TARGET_CAPABILITIES: readonly TargetCapability[] = [
  {
    provider: 'vercel',
    product: 'firewall',
    supportLevel: 'compiler-only',
    coverage: [
      'IPv4 and IPv6 IP-list decomposition',
      'allowlist, blocklist, and bypass intent',
      'condition packing and rule-limit validation',
      'staged reconciliation operation planning',
    ],
    knownUnsupported: [
      'control-plane execution orchestration',
      'publish, resume, and verified rollback',
      'general canonical Firewall AST compilation',
      'foreign-rule shadow and conflict analysis',
    ],
    documentation: [
      'https://vercel.com/docs/cli/firewall',
      'https://vercel.com/docs/vercel-firewall/vercel-waf/rule-configuration',
    ],
    lastVerified: '2026-08-14',
  },
  {
    provider: 'vercel',
    product: 'cdn',
    supportLevel: 'planned',
    coverage: [],
    knownUnsupported: ['CDN canonical model and compiler are not implemented'],
    documentation: ['https://vercel.com/docs/edge-network/caching'],
    lastVerified: '2026-08-14',
  },
  {
    provider: 'vercel',
    product: 'domains',
    supportLevel: 'planned',
    coverage: [],
    knownUnsupported: ['Domain/DNS canonical model and compiler are not implemented'],
    documentation: ['https://vercel.com/docs/domains'],
    lastVerified: '2026-08-14',
  },
];

export interface CapabilityRegistry {
  readonly schemaVersion: typeof CAPABILITY_REGISTRY_VERSION;
  readonly sources: readonly SourceCapability[];
  readonly targets: readonly TargetCapability[];
}

export const CAPABILITY_REGISTRY: CapabilityRegistry = {
  schemaVersion: CAPABILITY_REGISTRY_VERSION,
  sources: SOURCE_CAPABILITIES,
  targets: TARGET_CAPABILITIES,
};

export function formatCapabilityRegistry(registry: CapabilityRegistry = CAPABILITY_REGISTRY): string {
  const lines = [
    `Capability registry v${registry.schemaVersion}`,
    '',
    'Source adapters:',
  ];

  for (const source of registry.sources) {
    lines.push(
      `  ${source.provider}/${source.product}: ${source.supportLevel} ` +
        `(scan=${source.nativeDiscovery ? 'yes' : 'no'}, semantics=${source.sourceSchemaValidation ? 'validated' : 'operator-declared'}, ` +
        `live-e2e=${source.liveE2e}, verified=${source.lastVerified})`,
    );
  }

  lines.push('', 'Vercel targets:');
  for (const target of registry.targets) {
    lines.push(
      `  ${target.product}: ${target.supportLevel} ` +
        `(coverage=${target.coverage.length}, gaps=${target.knownUnsupported.length}, verified=${target.lastVerified})`,
    );
  }

  return `${lines.join('\n')}\n`;
}
