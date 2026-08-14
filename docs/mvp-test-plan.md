# Ship the first migration paths to Vercel

The migration control plane moves configuration and workloads from a source platform to Vercel. In this repository, `{platform}` means the source provider. Reverse migrations from Vercel to another target require different target compilers and are outside this MVP.

## MVP outcome

The MVP proves that one control plane can produce safe, inspectable migration work across more than one Vercel product. It does not promise automatic conversion for every provider resource.

The MVP includes three vertical slices:

1. **Firewall execution**: Import an IP policy or discover a Cloudflare custom ruleset, preserve its semantics, compile it for Vercel Firewall, stage the result, and verify behavior. A human publishes production Firewall changes.
2. **AWS compute assessment**: Discover AWS Lambda and API Gateway resources, classify compatibility, and produce a dependency-aware migration blueprint. A constrained HTTP Lambda can proceed to a Vercel implementation path. A .NET Lambda is reported as `manual` and `rewrite-required` because Vercel Functions do not provide a native .NET runtime.
3. **Domain and DNS planning**: Inventory a zone, plan supported record creation and domain attachment, and model certificate and cutover dependencies. Nameserver and production traffic cutovers remain human-approved.

CDN policy translation remains outside the first MVP, apart from inventory and explicit gap reporting. CDN becomes the next product compiler after the Firewall execution path and Domain/DNS planning path prove the shared contracts.

## Keep the shared primitives narrow

The control plane shares workflow contracts, while each product keeps a separate semantic model.

| Primitive | Responsibility |
|---|---|
| Resource identity | Stable provider, type, external ID, name, and scope |
| Source snapshot | Immutable raw resources, capture metadata, artifact hashes, and adapter version |
| Source reference | Provenance from a canonical or target resource back to its snapshot location |
| Translation result | Target resources, assumptions, diagnostics, and per-resource fidelity |
| Plan operation | Dependency, risk, execution effect, approval boundary, payload, and recovery data |
| Migration bundle | Portable snapshots and a deterministic plan with runtime validation |
| Execution journal | Attempt, result, evidence, resume position, and observed drift |

Firewall, CDN, Domains, and Compute must not share a universal configuration object. Their models can reference the shared primitives and each other through dependencies. For example, a Compute route can depend on a Domain attachment and a Firewall policy without merging their fields into one schema.

## Use the current preview

The current TypeScript Command Line Interface (CLI) is planning-only. It reads local exports, writes migration bundles, validates them, and renders reports. It does not authenticate to a source provider, stage Vercel changes, publish Firewall rules, or change DNS.

### Install and inspect support

Run these commands from the repository root:

```bash
npm ci
npm run --silent cli -- support
```

The support report is the authoritative implementation view. Check it before each migration because it distinguishes offline semantic support from operator-declared input and planned functionality.

### Plan an IP policy

Create a CSV with an `ip` column. `vendor_name` and `notes` are optional.

```csv
ip,vendor_name,notes
192.0.2.10,Acme,Webhook sender
2001:db8:1234::/48,Acme,IPv6 webhook range
```

The repository includes this format at [`scripts/tests/fixtures/mvp-ip-policy.csv`](../scripts/tests/fixtures/mvp-ip-policy.csv).

Generate a bundle:

```bash
npm run --silent cli -- plan-ip \
  --input vendor-ips.csv \
  --intent blocklist \
  --project-id prj_xxxxxxxxxxxx \
  > migration-bundle.json
```

Use `allowlist`, `blocklist`, or `bypass` for `--intent`. Add `--hostname api.example.com` to scope generated rules to one hostname. Add `--source-provider aws`, `cloudflare`, `akamai`, or `fastly` when the CSV came from a provider export. Provider-derived CSV plans have `manual` fidelity because the CSV cannot preserve the source rule's full behavior.

### Plan a Cloudflare custom ruleset

Save the zone-level `http_request_firewall_custom` Rulesets API response as JSON, then run:

```bash
npm run --silent cli -- plan-cloudflare \
  --input cloudflare-custom-ruleset.json \
  --account-id account_xxxxxxxxxxxx \
  --zone-id zone_xxxxxxxxxxxx \
  --project-id prj_xxxxxxxxxxxx \
  > migration-bundle.json
```

The adapter compiles supported expressions and records every unsupported or approximate rule as visible work. It never drops an unknown action or condition.

### Validate and review a bundle

```bash
npm run --silent cli -- validate --input migration-bundle.json
npm run --silent cli -- report --input migration-bundle.json
```

A valid result resembles:

```text
Valid migration bundle <plan_id>: 1 snapshot(s), <operation_count> operation(s).
```

Read the report's fidelity, risk, diagnostics, and approvals before treating a plan as migratable. `manual` and `unsupported` operations are unresolved work, not successful conversions.

For private artifact storage, replace stdout redirection with `--artifact-dir .vercel-migrate/artifacts`. The CLI prints the generated path below the schema-versioned `v1` directory.

## Build the MVP in four milestones

### Milestone 1: Complete the Firewall vertical

- Add authenticated, read-only Cloudflare discovery with pagination, retries, API-version metadata, and immutable snapshots.
- Add Vercel project inventory, capacity checks, rule-order analysis, shadow detection, and foreign-draft protection.
- Add a journaled `stage` command that writes drafts only.
- Add `verify` for structural diffing and traffic evidence.
- Require a human to publish production Firewall changes.

Exit signal: An IP blocklist and a supported Cloudflare custom ruleset pass `scan -> plan -> validate -> stage -> verify` in a test project with no silent semantic loss.

### Milestone 2: Add AWS workload assessment

- Discover Lambda functions, aliases, runtime, architecture, handler, layers, environment-variable names, timeout, memory, networking, tags, and event sources.
- Discover API Gateway routes, methods, authorizers, integrations, stages, domains, and mappings.
- Read CloudFormation, AWS SAM, CDK output, or Terraform when available to improve dependency discovery.
- Store secret names and references without storing secret values.
- Add a typed workload model for HTTP handlers, schedules, queues, storage, databases, identity, networking, and observability.
- Produce a target recommendation and a reasoned `exact`, `approximate`, `manual`, or `unsupported` result for every dependency.

Exit signal: The tool creates a complete migration blueprint for the .NET Lambda fixtures below, refuses a lift-and-shift claim, and provides contract tests for the rewritten Vercel implementation.

### Milestone 3: Add Domain and DNS planning

- Discover zones, records, aliases, redirects, domain ownership, certificate state, and relevant DNS Security Extensions (DNSSEC) state.
- Plan Vercel domain attachment, record changes, certificate readiness, and ordered cutover gates.
- Detect unsupported record types, provider-only traffic steering, conflicting records, and delegation risks.
- Verify DNS resolution and TLS before recommending traffic cutover.

Exit signal: A fixture zone produces a deterministic dependency graph, a reversible record plan, and a human-approved cutover checklist.

### Milestone 4: Harden the release

- Add resumable execution journals, drift detection, ownership manifests, and tested recovery paths.
- Add sanitized golden fixtures for each advertised provider and product.
- Run read-only provider contract tests on a schedule and staged Vercel integration tests on demand.
- Record `lastVerified`, API variants, plan constraints, and an owner in the capability registry.
- Package the CLI with pinned Node.js support, upgrade instructions, and machine-readable output contracts.

Exit signal: Every advertised path meets the repository definition of done, and a failed or interrupted run can resume without duplicating or deleting foreign resources.

## Test strategy

Each migration case runs through the same evidence layers.

| Layer | Purpose | Required evidence |
|---|---|---|
| Source contract | Prove discovery is complete and API drift is visible | Sanitized raw snapshot, pagination test, schema validation, source API variant |
| Canonical semantics | Prove source behavior is preserved | Golden canonical resources, provenance, fidelity record, explicit gaps |
| Target compilation | Prove the plan fits current Vercel capabilities | Golden target operations, capacity result, conflict result, stable operation order |
| Artifact integrity | Prove the bundle is portable and tamper-evident | Runtime validation, content-ID check, deterministic regeneration |
| Staged integration | Prove mutations remain bounded | Test-project draft diff, execution journal, ownership markers, no production publish |
| Behavioral verification | Prove user-visible behavior matches | Request truth table, DNS/TLS probes, or HTTP contract tests |
| Recovery | Prove the run can stop safely | Resume test, drift test, staged-discard or documented recovery evidence |

### Fidelity acceptance rules

| Fidelity | Acceptance rule |
|---|---|
| `exact` | Source and target truth tables match for every tested request or resource state. |
| `approximate` | The report names the semantic difference, affected resource, risk, and required approval. |
| `manual` | The plan contains a concrete operator task, required inputs, verification criteria, and dependency ordering. |
| `unsupported` | The plan performs no mutation for the resource and explains why the migration cannot proceed safely. |

## MVP case matrix

The following cases define the minimum fixture and integration coverage. Documentation examples use the reserved ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32` so tests cannot target real hosts.

### IP policy and Vercel Firewall cases

| ID | Case | Expected result |
|---|---|---|
| `IP-001` | IPv4 and IPv6 blocklist with individual addresses and CIDRs | Exact canonical intent, normalized addresses, deterministic Vercel rule operations, and no allowlist inversion |
| `IP-002` | Allowlist within target capacity | Exact deny-except behavior with a lockout analysis and hostname scope when provided |
| `IP-003` | Allowlist above direct target capacity | Fail safely without `--allow-bypass-escalation`; with the flag, report the bypass-then-deny design, elevated risk, and approval requirement |
| `IP-004` | Duplicate, overlapping, host-bit, private, malformed, and wildcard entries | Normalize safe inputs, report each anomaly, reject malformed entries, and block unsafe wildcard behavior |
| `IP-005` | Repeat the same plan with fixed inputs and metadata | Identical snapshot identities, plan ID, operation order, and target payloads |
| `IP-006` | Provider-derived CSV without complete rule semantics | `manual` fidelity with source-provider provenance and no claim of full WAF migration |
| `IP-007` | Fastly blacklist routed through legacy deny-mode behavior | Reject or mark unsupported; never invert a blacklist into deny-except behavior |

### Cloudflare Firewall cases

| ID | Case | Expected result |
|---|---|---|
| `CF-001` | Enabled block and log rules using supported Boolean fields | Exact translation with priority, enabled state, scope, and provenance preserved |
| `CF-002` | Managed Challenge or JavaScript Challenge | Approximate mapping with the behavior difference and approval visible |
| `CF-003` | `skip`, managed `execute`, rate limiting, unresolved lists, or transformations | Manual or unsupported operations; no source rule disappears from the report |
| `CF-004` | Unknown field, operator, action, or API enum | Fail closed for that resource and retain the raw snapshot for diagnosis |
| `CF-005` | Multi-page source response with a retryable API failure | Complete, deduplicated snapshot after bounded retry; incomplete scans cannot produce a stageable plan |
| `CF-006` | Existing Vercel rules and an unrelated pending draft | Detect ordering and shadow conflicts, identify foreign resources, and refuse to overwrite the draft |
| `CF-007` | Stage a log-only rule in a Vercel test project | Draft diff matches the plan, no production publish occurs, and traffic evidence can be attached |

### AWS WAF cases

| ID | Case | Expected result |
|---|---|---|
| `AWS-WAF-001` | Web ACL with an IP set statement and explicit default action | Preserve the referenced set, rule action, priority, scope, and default behavior |
| `AWS-WAF-002` | Nested `AND`, `OR`, and `NOT` statements over supported fields | Exact translation when the Vercel expression limits permit it; otherwise report capacity-driven manual work |
| `AWS-WAF-003` | Rate-based statement with forwarded-IP configuration | Manual or approximate result that identifies counter and client-IP differences |
| `AWS-WAF-004` | AWS managed rule group, scope-down statement, and exclusions | Manual operation with every exclusion and dependency retained |
| `AWS-WAF-005` | Regional and CloudFront Web ACLs with the same name | Stable provider identities include scope and region, preventing collisions |

### AWS Lambda application cases

Vercel's [official Functions runtimes](https://vercel.com/docs/functions/runtimes) do not include .NET. AWS Lambda currently supports [.NET managed and container runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-csharp.html). The MVP assesses .NET workloads and guides a port to a supported Vercel runtime; it does not report source-compatible deployment.

| ID | Case | Expected result |
|---|---|---|
| `AWS-APP-001` | .NET 8 Lambda behind API Gateway HTTP API with one JSON route and no external dependencies | Discover the HTTP contract and configuration, classify runtime compatibility as `manual` and `rewrite-required`, generate a TypeScript Vercel Functions blueprint, and create request/response parity tests |
| `AWS-APP-002` | ASP.NET Core Lambda with path parameters, query strings, binary response, cookies, and an authorizer | Inventory every route and auth dependency; parity tests cover status, body, headers, binary encoding, and unauthorized requests |
| `AWS-APP-003` | .NET Lambda using DynamoDB, S3, Secrets Manager, VPC access, IAM, and layers | Produce a dependency graph and target decision for each service; capture secret names only; no automatic deployment while a dependency is unresolved |
| `AWS-APP-004` | .NET Lambda triggered by SQS, EventBridge, or an asynchronous invocation | Do not reinterpret the event source as HTTP; produce a manual workflow or queue migration task with delivery, retry, ordering, and dead-letter semantics |
| `AWS-APP-005` | Lambda deployed as a container image or custom runtime | Report no lift-and-shift path to Vercel Functions and require application extraction or redesign |
| `AWS-APP-006` | Rewritten Vercel implementation under representative load | Match the golden HTTP contract, stay within configured duration and memory, emit usable logs, and meet the agreed latency and error budget |

The `.NET Lambda -> Vercel` fixture should contain the source application, its AWS SAM or CloudFormation template, captured API Gateway requests, expected responses, and a target TypeScript implementation. The source and target run the same contract suite. Provider-specific infrastructure assertions remain separate from behavior assertions.

### Domain, DNS, and CDN cases

| ID | Case | Expected result |
|---|---|---|
| `DNS-001` | Zone with apex, `A`, `AAAA`, `CNAME`, `TXT`, `MX`, and `CAA` records | Deterministic inventory and record plan with conflicts, ownership checks, and certificate dependencies |
| `DNS-002` | Delegated subdomain, wildcard record, DNSSEC, and provider proxy flag | Preserve delegation, report proxy-only behavior, and require an explicit DNSSEC and cutover decision |
| `DNS-003` | Interrupted record staging followed by source or target drift | Resume only unchanged operations and require replanning for drifted resources |
| `DNS-004` | Nameserver cutover before domain and TLS readiness | Block the cutover recommendation until domain verification, certificate readiness, and rollback data are present |
| `CDN-001` | Cache headers, redirects, rewrites, and origin settings | Inventory all behavior and mark each item exact, approximate, manual, or unsupported; no target mutation is required for the first MVP |
| `CDN-002` | Provider-specific edge code or request transformation | Preserve source code or configuration as an artifact and produce a manual redesign task |

## General control-plane cases

These cases apply to every provider and product:

- Unknown source enum values fail closed.
- A partial or paginated scan cannot be presented as complete.
- Reordering source resources changes a plan only when order changes behavior.
- Repeating a plan with the same effective inputs produces the same content identity.
- Editing a bundle without regenerating its content identity fails validation.
- Missing provenance or a missing referenced snapshot fails validation.
- Cycles, missing dependencies, and unstable operation ordering fail validation.
- Foreign target resources remain untouched without an ownership manifest or explicit adoption.
- Existing target drafts, capacity exhaustion, and plan-tier mismatches block staging.
- Expired credentials, missing permissions, rate limits, and retry exhaustion produce actionable diagnostics without leaking secrets.
- Interrupted execution resumes from the journal without duplicating successful operations.
- Source or target drift after planning requires revalidation or replanning.
- `manual` and `unsupported` work prevents an all-clear result.
- Production Firewall publish, DNS delegation, and traffic cutover always require a human decision.

## Test environments and cadence

| Environment | Cadence | Allowed actions |
|---|---|---|
| Pull request | Every change | Unit tests, schema contracts, sanitized fixtures, golden plans, and deterministic replay |
| Provider sandbox | Scheduled and on demand | Read-only scans plus resource setup and teardown in dedicated test accounts |
| Vercel test team | Scheduled and before release | Draft Firewall changes, preview deployments, temporary domains, verification, and draft discard |
| Production pilot | Manually approved release gate | One low-risk migration with canary traffic, observation window, and a documented recovery owner |

Live fixtures use dedicated accounts, synthetic data, unique run IDs, least-privilege credentials, and guaranteed teardown. Test artifacts must redact tokens, secret values, customer data, and account details that are not needed for provenance.

## MVP release gates

The MVP is ready for a pilot when all of the following are true:

- The basic IP policy and Cloudflare Firewall paths complete planning and staged verification in a Vercel test project.
- The .NET Lambda cases produce accurate rewrite classifications, complete dependency inventories, and passing cross-runtime HTTP contract tests for the reference port.
- The Domain/DNS cases produce a deterministic plan and block premature cutover.
- Every source resource appears in the report as `exact`, `approximate`, `manual`, or `unsupported`.
- No known case silently changes action, condition, priority, scope, default behavior, identity, or dependency.
- Plan generation is deterministic, bundle validation detects tampering, and interrupted staging resumes safely.
- Foreign target resources and unrelated drafts are protected.
- Recovery procedures have been exercised, and production-impacting actions remain human-approved.
- The capability registry matches the tested implementation and records current verification dates.

The existing Bash end-to-end plan in [`scripts/tests/E2E-TEST-PLAN.md`](../scripts/tests/E2E-TEST-PLAN.md) remains useful for legacy exporter coverage. It does not replace the semantic, control-plane, application, and cross-product cases in this MVP plan.
