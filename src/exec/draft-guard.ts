/**
 * Foreign-draft detection: the most important safety check in this tool.
 *
 * THE HAZARD. Firewall `rules` and `ip-blocks` mutations do not go straight to
 * production; they accumulate in a single per-config **draft** which `publish`
 * then promotes wholesale. That draft is shared. If a colleague, or someone
 * clicking around the Vercel dashboard, has unpublished changes staged when we
 * start, our `publish` promotes THEIR changes to production alongside ours. The
 * operator believes they published an IP allowlist; they may also have shipped
 * a half-finished rate-limit rule someone was still experimenting with.
 *
 * WHY ABORTING IS THE ONLY HONEST MITIGATION. There is no client-facing ETag or
 * `If-Match` on the firewall config. Verified against the CLI source: the draft
 * PATCH sends only `Content-Type: application/json` with no conditional header
 * (`util/firewall/patch-firewall-draft.ts:11-18`), activation targets the
 * literal string `'draft'` rather than a negotiated version
 * (`util/firewall/activate-firewall-config.ts:11-17`), and the config listing is
 * a bare GET (`util/firewall/list-firewall-configs.ts:10`). The server keeps a
 * `version` counter in the response body (`util/firewall/types.ts:88`) but it is
 * never read back and never sent as a precondition. Concurrency is therefore
 * plain last-write-wins.
 *
 * Consequently: do NOT add a locking mechanism, a retry loop, or a
 * compare-and-swap here. Any such thing would be fake — there is no primitive
 * to build it on, and a fake conflict check is worse than none because it
 * manufactures confidence. Detect a foreign draft, refuse to continue, and make
 * the human choose. That is the whole design.
 */

import { ExecError } from './errors.js';
import type { DiffOutput, Scope } from './firewall.js';
import { getDiff, getDiffArgv } from './firewall.js';
import { runVercel } from './spawn.js';

/**
 * Outcome of a foreign-draft check.
 *
 * `via` records whether we read structured JSON or fell back to scraping the
 * human-readable diff, because the two have very different confidence levels
 * and the operator deserves to know which one gated their publish.
 */
export type DraftCheckResult =
  | { clean: true; via: 'json' | 'text' }
  | { clean: false; via: 'json' | 'text'; summary: string; raw: unknown };

function summarizeChanges(diff: DiffOutput): string {
  const byAction = new Map<string, number>();
  for (const change of diff.changes) {
    byAction.set(change.action, (byAction.get(change.action) ?? 0) + 1);
  }
  const parts = [...byAction.entries()].map(([action, count]) => `${action} x${String(count)}`);
  return `${String(diff.changes.length)} staged change(s): ${parts.join(', ')}`;
}

/**
 * Non-JSON fallback for `vercel firewall diff`.
 *
 * The CLI prints exactly `No pending changes.` when the draft is empty
 * (`diff.ts:33`), so its presence is a reliable clean signal. Anything else is
 * treated as dirty — erring toward "there might be a draft" is the safe
 * direction, since a false positive costs a confirmation and a false negative
 * costs an unintended production publish.
 */
async function checkForeignDraftViaText(scope: Scope): Promise<DraftCheckResult> {
  const argv = ['firewall', 'diff', ...(scope.teamLevel ? ['--team-level'] : [])];
  const result = await runVercel(argv, { cwd: scope.cwd });
  const text = `${result.stdout}\n${result.stderr}`.trim();

  if (/No pending changes\./i.test(text)) {
    return { clean: true, via: 'text' };
  }

  return {
    clean: false,
    via: 'text',
    summary: `non-JSON diff output did not report "No pending changes."`,
    raw: text,
  };
}

/**
 * Ask whether the config already has an unpublished draft.
 *
 * Prefers `diff --json`, whose output is always `{ changes: [...] }` with an
 * empty array meaning clean (`diff.ts:28-40`). Falls back to parsing the human
 * diff if the JSON is unusable — an old CLI, or a future output change — rather
 * than treating an unreadable answer as permission to proceed.
 */
export async function checkForeignDraft(scope: Scope): Promise<DraftCheckResult> {
  let diff: DiffOutput;
  try {
    diff = await getDiff(scope);
  } catch {
    return checkForeignDraftViaText(scope);
  }

  if (diff.changes.length === 0) return { clean: true, via: 'json' };

  return {
    clean: false,
    via: 'json',
    summary: summarizeChanges(diff),
    raw: diff,
  };
}

export class ForeignDraftError extends ExecError {
  override readonly kind = 'foreign-draft' as const;
  readonly summary: string;
  readonly via: 'json' | 'text';
  readonly raw: unknown;

  constructor(args: { summary: string; via: 'json' | 'text'; raw: unknown; argv: string[] }) {
    super(
      [
        'Refusing to continue: this firewall config already has an unpublished draft.',
        '',
        `  ${args.summary}`,
        `  detected via: ${args.via === 'json' ? '`diff --json`' : 'non-JSON `diff` text output'}`,
        `  reproduce:    ${args.argv.join(' ')}`,
        '',
        'Those changes are not ours. Publishing would promote them to production together',
        'with our changes, because the firewall draft is shared per config and `publish`',
        'promotes all of it at once. There is no per-change publish and no server-side',
        'precondition we could use to publish only our own edits.',
        '',
        'Two ways forward:',
        '  1. Drop the existing draft, if you know it is safe to lose:',
        '       vercel firewall discard --yes',
        '  2. Knowingly include those changes in your publish:',
        '       re-run with --adopt-draft',
      ].join('\n'),
    );
    this.summary = args.summary;
    this.via = args.via;
    this.raw = args.raw;
  }
}

export interface DraftGuardOptions {
  /** Operator has explicitly accepted publishing someone else's staged changes. */
  adoptDraft: boolean;
}

/**
 * Throw unless the config has no pre-existing draft.
 *
 * `adoptDraft` is the only bypass and must be set explicitly by a human — it is
 * never inferred, defaulted, or derived from "the diff looked small".
 */
export async function assertNoForeignDraft(
  scope: Scope,
  opts: DraftGuardOptions,
): Promise<DraftCheckResult> {
  const check = await checkForeignDraft(scope);
  if (check.clean || opts.adoptDraft) return check;

  throw new ForeignDraftError({
    summary: check.summary,
    via: check.via,
    raw: check.raw,
    argv: ['vercel', ...getDiffArgv(scope)],
  });
}
