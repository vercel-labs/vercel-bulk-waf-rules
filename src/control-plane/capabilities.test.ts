import { describe, expect, it } from 'vitest';

import {
  CAPABILITY_REGISTRY,
  formatCapabilityRegistry,
  SOURCE_CAPABILITIES,
} from './capabilities.js';

describe('capability registry', () => {
  it('has one truthful Firewall entry for every advertised source provider', () => {
    expect(
      SOURCE_CAPABILITIES.filter(({ product }) => product === 'firewall')
        .map(({ provider }) => provider)
        .sort(),
    ).toEqual([
      'akamai',
      'aws',
      'cloudflare',
      'fastly',
    ]);
    expect(new Set(SOURCE_CAPABILITIES.map(({ provider, product }) => `${provider}/${product}`)).size).toBe(
      SOURCE_CAPABILITIES.length,
    );
    expect(
      SOURCE_CAPABILITIES.find(
        ({ provider, product }) => provider === 'cloudflare' && product === 'firewall',
      )?.supportLevel,
    ).toBe('offline-semantic');
    expect(
      SOURCE_CAPABILITIES.filter(
        ({ provider, product }) => provider !== 'cloudflare' && product === 'firewall',
      ).every(({ supportLevel }) => supportLevel === 'manual-input'),
    ).toBe(true);
  });

  it('advertises AWS compute assessment as planned rather than implemented', () => {
    const source = SOURCE_CAPABILITIES.find(
      ({ provider, product }) => provider === 'aws' && product === 'compute',
    );
    expect(source?.supportLevel).toBe('planned');
    expect(source?.nativeDiscovery).toBe(false);
    expect(source?.semanticCoverage).toEqual([]);
  });

  it('records current official documentation and a verification date', () => {
    for (const capability of SOURCE_CAPABILITIES) {
      expect(capability.lastVerified).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(capability.apiVariants.length).toBeGreaterThan(0);
      for (const variant of capability.apiVariants) {
        expect(variant.documentation).toMatch(/^https:\/\//);
      }
    }
  });

  it('renders support without overstating semantic coverage', () => {
    const report = formatCapabilityRegistry(CAPABILITY_REGISTRY);
    expect(report).toContain('cloudflare/firewall: offline-semantic');
    expect(report).toContain('aws/firewall: manual-input');
    expect(report).toContain('aws/compute: planned (scan=no, semantics=none');
    expect(report).toContain('semantics=operator-declared');
    expect(report).toContain('domains: planned (coverage=0');
    expect(report).toContain('compute: planned (coverage=0');
  });
});
