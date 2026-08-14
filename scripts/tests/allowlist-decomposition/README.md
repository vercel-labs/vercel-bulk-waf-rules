# Allowlist Decomposition Tests

Offline regression tests for how `vercel-bulk-waf-rules.sh` decomposes a large IP
list into WAF rule conditions, and for the `audit` command that detects the
pre-2.1.0 split-allowlist outage bug.

No network, no credentials, no AWS or Vercel calls. Safe to run in CI.

## Run

```bash
./run-tests.sh                  # all tests
./run-tests.sh --filter 150     # only tests matching "150"
```

Exit code is 0 when every test passes.

## What is being guarded

A deny/allowlist rule matches IPs **not** in a list (`op: "ninc"`) and denies
them. Vercel's firewall evaluates:

- conditions within a condition group: **AND**
- condition groups within a rule: **OR**
- separate rules: **OR**, and a matching terminal action short-circuits

So a large allowlist must be split across **conditions in a single group**:

```text
deny if (ip ∉ s1) AND (ip ∉ s2) ... == deny if ip ∉ (s1 ∪ s2 ...)   correct
```

Splitting the same list across sibling rules or sibling condition groups ORs the
negations. Every address is absent from at least one disjoint slice, so every
request matches a deny — including the allowlisted ones. That is a total outage,
which is exactly what shipped before 2.1.0.

Bypass mode (`op: "inc"`, action `bypass`) matches positively, so ORing across
sibling rules is correct there and is intentionally left unchanged.

## Limits

| Limit | Value | Source |
|-------|-------|--------|
| Items per array condition value | 75 | API JSON schema |
| Conditions per condition group | 65 | API JSON schema |
| Condition groups per rule | 25 | API JSON schema |
| Allowlist ceiling (single deny rule) | 4875 | 65 × 75 |

Above 4,875 the script refuses. More condition *groups* would not help — groups
OR, which reintroduces the bug one level up.

## How it works

`run-tests.sh` sources the main script (whose `main` is guarded by a
`BASH_SOURCE` check) and stubs `api_request`, so the real PATCH request body is
captured and asserted against rather than sent. The stub also logs the request
sequence (`action` + `id`) so ordering can be asserted, and can inject insert or
removal failures via `FAIL_INSERT_AFTER` / `FAIL_REMOVALS`. Audit tests stub
`get_firewall_config` with canned firewall configs.

## Insert-then-remove ordering

`apply` creates the new rule(s) **first** and removes superseded ones only after
that succeeds. Removing first would be fail-OPEN in deny mode: a failed insert
would leave the project with no allowlist rule and the site open to everyone.
Overlapping keeps deny mode fail-CLOSED (the old rules keep blocking) and is
idempotent in bypass mode.

Removal targets the rule IDs captured from the config fetched *before* any
insert, so it can never delete the rule it just created.

## Coverage

| Area | Cases |
|------|-------|
| Deny decomposition | 1, 75, 76, 150, 4875 IPs; and 150 + `RULE_HOSTNAME` |
| No regression | 75 IPs keeps the single-condition shape; bypass still emits `inc`/`bypass` |
| Ceiling | 4876 IPs refused; `RULE_HOSTNAME` lowers it to 4800; 4801 without a hostname still fits |
| `audit` | sibling-rule variant, condition-group variant, OK, bypass-only, no rules |
| Ordering | insert precedes removal and targets only pre-existing IDs; insert failure removes nothing; partial chunked create removes nothing; `SKIP_REMOVAL`; removal failure keeps the new rule; `DRY_RUN` makes zero calls |

Each decomposition case asserts: exactly one `conditionGroup`, `ceil(n/75)`
ip_address conditions (+1 when a hostname is set), every ip condition `op:
"ninc"`, no slice over 75, the union of all slices equals the input with nothing
dropped or duplicated, and the rule name carries no `(Part N/M)` suffix.
