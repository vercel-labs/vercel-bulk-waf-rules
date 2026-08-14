# Migration Control Plane Architecture

The TypeScript control plane separates a reusable migration workflow from product-specific semantics and provider-specific APIs.

## Processing model

```text
provider connector
  -> immutable source snapshot
  -> product translator
  -> per-resource fidelity records
  -> Vercel capability compiler
  -> dependency-ordered migration plan
  -> validation and report
  -> product-specific staging and verification (future)
```

Provider connectors own authentication, pagination, retries, API variants, and raw evidence. Product translators own the meaning of Firewall, CDN, Domain, or Compute configuration. Vercel compilers own target limits and payloads. The shared control plane owns provenance, diagnostics, dependencies, approvals, risk, artifact validation, and execution journals.

Product models remain separate. Shared resource identities and dependencies can connect a Compute route to a Domain attachment or Firewall policy without creating one universal provider configuration schema.

## Durable artifacts

A migration bundle contains:

- One or more immutable source snapshots with adapter version, capture time, resource identities, and raw-artifact hashes.
- A deterministic plan whose ID is derived from its semantic content rather than its creation time.
- Operations with explicit effect, risk, approval boundary, fidelity, dependencies, source references, and target payload.
- Diagnostics and remediation that survive terminal output.

`validate` rejects unknown schema fields, invalid versions/enums, missing snapshots, provenance references that do not match captured resources, unsafe dependency graphs, and edited plan content whose ID was not regenerated.

Local artifact storage uses `.vercel-migrate/artifacts/v<schemaVersion>/<planId>.json` with private permissions. The directory is ignored by Git because snapshots may contain customer IPs or security configuration.

## Fidelity

Every source-resource mapping is one of:

- `exact`: the represented source behavior is preserved by the emitted target behavior.
- `approximate`: an intentional, documented behavioral difference remains.
- `manual`: the tool has enough information to identify required work but will not choose the target behavior.
- `unsupported`: no safe mapping is implemented.

Manual and unsupported records become explicit plan operations. An adapter must never omit a rule because its expression or action is unknown.

## Execution boundaries

- `read-only`: observes state without mutation.
- `staged`: may create a reviewable draft but does not make it live.
- `immediate`: changes external state without a draft boundary.
- `external-manual`: records work an operator must perform outside the current executor.

Operations separately declare `none`, `before-execute`, or `before-publish` approval. Firewall reconciliation is staged and requires human approval before publication.

## Current implementation

The CLI provides:

- `plan-ip`: snapshot and plan an operator-declared IP-list policy.
- `plan-cloudflare`: snapshot and semantically translate an offline Cloudflare Custom Rulesets API response.
- `validate`: runtime-validate a saved migration bundle.
- `report`: render fidelity, risk, approvals, operations, and diagnostics.
- `support`: show the versioned provider/target capability registry.

Cloudflare's current adapter parses a deliberate subset of the Rules language and fails closed outside it. It compiles supported Boolean expressions into Vercel's OR-of-AND condition groups while respecting target group, condition, and value limits. Cloudflare skip actions, unresolved lists, transformations, unsupported fields/actions, and expression expansion beyond target limits remain explicit manual work.

The capability registry includes AWS Compute and Vercel Compute as `planned`. The current CLI does not discover, translate, or deploy AWS Lambda workloads.

See the root `AGENTS.md` for project invariants and milestone status. See [`docs/mvp-test-plan.md`](mvp-test-plan.md) for the MVP roadmap, test matrix, and release gates.
