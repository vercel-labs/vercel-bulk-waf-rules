/**
 * Self-lockout prevention for allowlist publishes.
 *
 * The catastrophic failure mode this file exists to prevent: an operator
 * publishes a "block everything not on this list" rule whose list does not
 * contain the operator's own egress IP. The rule takes effect immediately, the
 * operator is now outside their own allowlist, and the only remaining recovery
 * path is the Vercel dashboard from a different network. On a customer call
 * that is an incident.
 *
 * Only meaningful for **allowlist** intent. Callers building blocklist or
 * bypass rules must skip this check entirely — an operator's IP being absent
 * from a blocklist is the correct and desired state, and running this guard
 * there would reject every legitimate blocklist.
 */

import type { Cidr, IpVersion } from '../core/ip.js';
import { formatCidr, InvalidIpError, parseIp } from '../core/ip.js';
import { containsAddress } from '../core/aggregate.js';
import { ExecError } from './errors.js';

/** Public IP echo endpoints, tried in order. Plain-text body, no auth, no JSON. */
const EGRESS_ENDPOINTS: readonly string[] = [
  'https://api.ipify.org',
  'https://checkip.amazonaws.com',
];

/** Deliberately short: this is a preflight, not a retry-until-the-network-heals loop. */
const EGRESS_TIMEOUT_MS = 5_000;

/**
 * Result of egress resolution. Discriminated rather than
 * `string | undefined` so a caller cannot accidentally treat "we could not
 * find out" as "there is nothing to protect".
 */
export type EgressResult = { ok: true; ip: string } | { ok: false; reason: string };

/**
 * Transport for egress lookup, injected so tests never touch the network.
 *
 * Note this is the ONE outbound HTTP call in the entire tool, and it goes to a
 * public IP-echo service — never to api.vercel.com. All Vercel interaction
 * still goes exclusively through spawning the CLI (see `spawn.ts`).
 */
export type EgressFetch = (url: string, timeoutMs: number) => Promise<string>;

async function defaultEgressFetch(url: string, timeoutMs: number): Promise<string> {
  const https = await import('node:https');
  return new Promise<string>((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`${url} responded ${String(res.statusCode)}`));
        return;
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        body += chunk;
      });
      res.on('end', () => resolve(body));
    });
    req.on('timeout', () => {
      req.destroy(new Error(`${url} timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
  });
}

/**
 * Determine the operator's public egress IP.
 *
 * Never throws: a network failure is a legitimate, expected outcome that the
 * caller must be able to reason about, and an exception here would tempt a
 * caller into a `try {} catch {}` that silently skips the lockout check.
 */
export async function resolveEgressIp(fetchImpl: EgressFetch = defaultEgressFetch): Promise<EgressResult> {
  const failures: string[] = [];

  for (const url of EGRESS_ENDPOINTS) {
    try {
      const body = await fetchImpl(url, EGRESS_TIMEOUT_MS);
      const candidate = body.trim();
      try {
        parseIp(candidate);
      } catch (err) {
        failures.push(
          `${url} returned unparseable body: ${err instanceof InvalidIpError ? err.message : String(err)}`,
        );
        continue;
      }
      return { ok: true, ip: candidate };
    } catch (err) {
      failures.push(`${url}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return { ok: false, reason: failures.join('; ') || 'no egress endpoints configured' };
}

/** Thrown when a publish would lock the operator (or another protected address) out. */
export class LockoutError extends ExecError {
  override readonly kind = 'lockout' as const;
  readonly unprotected: readonly string[];
  readonly egressResolved: boolean;

  constructor(args: { message: string; unprotected: readonly string[]; egressResolved: boolean }) {
    super(args.message);
    this.unprotected = [...args.unprotected];
    this.egressResolved = args.egressResolved;
  }
}

export interface LockoutCheckInput {
  /** The allowlist about to be published. */
  allowlist: Cidr[];
  /** The operator's egress IP, if resolution succeeded. */
  egress?: string;
  /** Additional addresses that must survive the publish (VPN, CI, monitors). */
  extraProtected: string[];
  /** Explicit operator override. Downgrades hard failures to warnings. */
  force: boolean;
}

export interface LockoutCheckResult {
  warnings: string[];
}

function parseProtected(
  raw: string,
): { ok: true; addr: { version: IpVersion; value: bigint } } | { ok: false; reason: string } {
  try {
    return { ok: true, addr: parseIp(raw) };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

function describeAllowlist(allowlist: Cidr[]): string {
  if (allowlist.length === 0) return '(empty allowlist)';
  const shown = allowlist.slice(0, 8).map(formatCidr);
  const suffix = allowlist.length > shown.length ? `, … ${allowlist.length - shown.length} more` : '';
  return `${shown.join(', ')}${suffix}`;
}

/**
 * Throw unless every protected address is covered by the allowlist.
 *
 * FAIL CLOSED ON UNRESOLVABLE EGRESS — this is the subtle one, and the reason
 * for the doc-comment. If we could not determine the operator's public IP, we
 * have *no evidence* that the publish is safe. Treating "unknown" as "probably
 * fine" converts a loud, recoverable preflight failure into the exact silent
 * lockout this module exists to prevent. So a failed egress lookup is itself a
 * hard failure unless the operator passes `force`, at which point they have
 * consciously accepted the risk and it is recorded as a warning.
 *
 * Do not add a "skip if offline" heuristic here.
 */
export function assertNotLockedOut(input: LockoutCheckInput): LockoutCheckResult {
  const warnings: string[] = [];
  const unprotected: string[] = [];

  if (input.egress === undefined) {
    const message = [
      'Could not determine your public egress IP, so it is impossible to verify that',
      'this allowlist still includes you.',
      '',
      'Refusing to continue: publishing an allowlist that omits your own address locks',
      'you out of the project, recoverable only from the Vercel dashboard on another',
      'network.',
      '',
      'Either restore network access so the egress IP can be resolved, pass the address',
      'explicitly, or re-run with --force to publish anyway at your own risk.',
    ].join('\n');

    if (!input.force) {
      throw new LockoutError({ message, unprotected: [], egressResolved: false });
    }
    warnings.push(
      'egress IP could not be resolved and --force was set; self-lockout was NOT verified',
    );
  }

  const candidates = [
    ...(input.egress === undefined ? [] : [input.egress]),
    ...input.extraProtected,
  ];

  for (const raw of candidates) {
    const parsed = parseProtected(raw);
    if (!parsed.ok) {
      unprotected.push(`${raw} (unparseable: ${parsed.reason})`);
      continue;
    }
    if (!containsAddress(input.allowlist, parsed.addr)) {
      unprotected.push(raw);
    }
  }

  if (unprotected.length > 0) {
    const message = [
      'Refusing to publish: this allowlist does not cover every protected address.',
      '',
      `  not covered: ${unprotected.join(', ')}`,
      `  allowlist:   ${describeAllowlist(input.allowlist)}`,
      '',
      'Publishing would block those addresses, including possibly your own, leaving the',
      'Vercel dashboard as the only way back in.',
      '',
      'Add the missing addresses to the list, or re-run with --force if you are certain.',
    ].join('\n');

    if (!input.force) {
      throw new LockoutError({
        message,
        unprotected,
        egressResolved: input.egress !== undefined,
      });
    }
    warnings.push(`--force set; publishing despite uncovered addresses: ${unprotected.join(', ')}`);
  }

  return { warnings };
}
