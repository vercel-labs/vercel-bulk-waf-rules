# Vercel Migration Control Plane

This repository is evolving from a bulk IP/WAF script into a TypeScript migration control plane for moving Firewall, CDN, Domain, and application workload configuration from third-party providers to Vercel.

This file is both the project charter and the durable progress ledger. Update it whenever an architectural decision changes, a milestone is completed, or a newly discovered blocker changes the roadmap.

All migration direction references mean `{source platform} -> Vercel`. Reverse migrations from Vercel to another target require separate target compilers and are not part of the current goal.

## Product goal

Build a safe, inspectable migration workflow that can:

1. Discover and snapshot source-provider configuration.
2. Translate it into a typed, product-specific canonical model.
3. Compile that model against current Vercel capabilities.
4. Report every mapping as exact, approximate, manual, or unsupported.
5. Produce a deterministic, dependency-ordered migration plan.
6. Stage or execute operations using product-specific safety gates.
7. Verify the result and retain enough evidence to resume, audit, or roll back.

Initial source providers are Cloudflare, AWS, Akamai, and Fastly. Vercel is the initial and primary target.

## MVP scope

The MVP proves three vertical slices:

1. A complete, staged Firewall path for IP policies and Cloudflare custom rulesets.
2. An AWS Lambda and API Gateway assessment path that produces dependency-aware migration blueprints. Unsupported source runtimes such as .NET are explicit rewrite cases, not automatic lift-and-shift migrations.
3. A Domain/DNS planning path with dependency ordering, readiness checks, and human-approved cutover gates.

CDN policy translation follows the MVP. The first release may inventory CDN behavior and report gaps, but it must not advertise CDN migration until a compiler and verification path meet the definition of done.

The durable roadmap, case matrix, and release gates are in [`docs/mvp-test-plan.md`](docs/mvp-test-plan.md).

## Architecture invariants

- The control plane is generic; Firewall, CDN, Domains, and Compute keep separate typed domain models.
- Provider connectors own authentication, API compatibility, pagination, retries, and immutable raw snapshots. They do not decide target behavior.
- Domain translators preserve source semantics and provenance. They never silently discard an action, condition, scope, priority, default, or reference.
- Target compilers own Vercel capability checks, target limits, and target resource construction.
- Every translation result declares its fidelity: `exact`, `approximate`, `manual`, or `unsupported`.
- Plans are pure data, deterministic for the same inputs, dependency ordered, serializable, and reviewable before mutation.
- Unknown provider enum values or statement types fail closed instead of inheriting a default mapping.
- Deletes, global cutovers, immediate firewall controls, and other high-blast-radius operations are never implicit.
- Firewall changes are staged first. The tool may prepare a draft and verification evidence, but a human owns the production publish decision.
- Existing customer-managed resources are foreign unless a manifest ID or explicit ownership marker proves otherwise.
- Raw source snapshots, plans, manifests, and verification evidence are durable artifacts, not terminal-only output.
- Bash scripts are legacy compatibility surfaces. New control-plane behavior belongs in TypeScript.

## Intended package boundaries

```text
src/
  control-plane/       snapshots, contracts, plans, diagnostics, execution journal
  domains/
    firewall/          canonical firewall policy model
    cdn/               canonical CDN configuration model
    domains/           canonical domain and DNS model
    compute/           canonical workload, trigger, and dependency model
  providers/           Cloudflare, AWS, Akamai, Fastly connectors
  targets/
    vercel/            Vercel product compilers and executors
  core/                legacy IP/CIDR planning core during the transition
  exec/                legacy Vercel Firewall execution wrappers during transition
  state/               legacy WAF manifests/reconciliation during transition
```

Do not create a single universal configuration object with optional fields for every product. Shared types should cover workflow concerns such as identity, provenance, diagnostics, dependencies, risk, evidence, and execution boundaries.

## Delivery phases

### Phase 0 — Preserve the existing implementation

- [x] Checkpoint the existing TypeScript WAF planning work on `main`.
- [x] Push checkpoint commit `4c29f89` on 2026-08-14.
- [x] Create `codex/generalized-migration-control-plane` for the re-architecture.

### Phase 1 — Establish the control plane

- [x] Add shared snapshot, resource identity, diagnostic, fidelity, and plan primitives.
- [x] Add deterministic dependency validation and plan hashing.
- [x] Put the existing Firewall IP planner behind a Vercel target-compiler boundary.
- [x] Add a read-only `plan-ip` preview that emits a snapshot and plan bundle.
- [x] Add executable `plan-ip`, `validate`, and `report` CLI workflows.
- [ ] Add provider-native `scan` workflows.
- [x] Add a versioned artifact directory and runtime validation for files read from disk.

### Phase 2 — Complete Firewall semantics

- [x] Add a canonical Firewall condition/action AST.
- [x] Add an offline semantic adapter for Cloudflare Custom Rulesets API responses.
- [ ] Add authenticated Cloudflare discovery and semantic adapters for AWS WAF, Akamai, and Fastly.
- [x] Compile the supported canonical expression/action subset to staged Vercel rule-set operations.
- [ ] Add Vercel capability, capacity, rule-order, shadowing, and conflict analysis.
- [ ] Add staged log/preview/production rollout and traffic verification.
- [ ] Replace the unverified rollback path with a supported, tested recovery workflow.

### Phase 3 — Add Compute, Domains, and CDN

- [ ] Add AWS Lambda and API Gateway discovery with a typed workload and dependency model.
- [ ] Add compatibility assessment and migration blueprints for Vercel Functions, including explicit rewrite-required outcomes.
- [ ] Add Domain/DNS discovery, dependency planning, cutover, propagation, and verification.
- [ ] Add CDN origins, cache policies, redirects/rewrites, headers, and edge-behavior mapping.
- [ ] Represent provider-specific edge code and other non-portable behavior as manual or unsupported.

### Phase 4 — Operationalize compatibility

- [x] Define the MVP vertical slices, test matrix, and release gates.
- [ ] Add sanitized golden fixtures and contract tests for every advertised provider/product level.
- [ ] Add read-only live smoke tests and minimum/current Vercel CLI compatibility tests.
- [ ] Track `lastVerified`, API variants, and support levels in a capability registry.
- [ ] Add resume, drift detection, audit reporting, and verified rollback coverage.

## Current progress

Last updated: 2026-08-14

- The legacy Bash implementation and the initial TypeScript IP/WAF core are preserved on `main` at `4c29f89`.
- The architecture branch has 531 passing TypeScript tests and a clean strict typecheck/build; shell allowlist decomposition has 22 passing cases.
- The checkpoint's unused `CliResult` build failure has been corrected on the architecture branch.
- Only the AWS exporter has a built live E2E harness. Cloudflare, Akamai, and Fastly live coverage is still planned.
- The current implementation must be described as IP-list migration until provider actions, conditions, scopes, defaults, and ordering are preserved.
- Fastly blacklist import through the legacy workflow remains unsupported because `RULE_MODE=deny` reverses blacklist intent.
- The unsafe Fastly recommendation is now blocked in the exporter and documentation; the new CLI records provider-derived CSVs as manual-fidelity plans.
- Migration bundles are runtime validated before reporting: schema drift, missing snapshots, invalid provenance, unsafe dependency graphs, and content-ID mismatches are rejected.
- `plan-ip --artifact-dir` writes private bundle files under a schema-versioned `v1` directory; `validate` and `report` read the same durable format.
- `support` exposes a versioned capability registry. Cloudflare is `offline-semantic`; AWS, Akamai, and Fastly remain `manual-input`.
- `plan-cloudflare` validates Custom Rulesets API responses and preserves every rule as compiled or explicit manual/unsupported work. It has no authenticated source discovery yet.
- The MVP roadmap and test plan now cover IP policies, Cloudflare and AWS WAF, AWS .NET Lambda assessment and port validation, Domain/DNS planning, CDN inventory, shared safety cases, and pilot release gates.

## Near-term working sequence

1. Implement one provider end-to-end through semantic translation before expanding the matrix.
2. Add provider-native read-only scan workflows and capability/version reporting.
3. Add Vercel capacity, rule-order, shadowing, and conflict analysis.
4. Add execution journals and verified staged-apply/resume behavior.
5. Add the AWS Compute assessment path, beginning with the .NET Lambda reference fixture.
6. Introduce Domain/DNS primitives after the Firewall vertical proves the shared contracts.
7. Add CDN translation after the cross-product dependency model has been exercised.

## Definition of done for an advertised migration path

A provider/product path is supported only when it has:

- A documented source API/version and required permissions.
- Immutable snapshot capture with provenance.
- Runtime-validated fixtures from realistic source data.
- Explicit fidelity reporting with no silent semantic loss.
- Deterministic golden-plan tests.
- Target capacity and conflict validation.
- A non-mutating preview or staging path.
- Verification criteria and a tested recovery procedure.
- A recorded `lastVerified` date and an owner for compatibility drift.
