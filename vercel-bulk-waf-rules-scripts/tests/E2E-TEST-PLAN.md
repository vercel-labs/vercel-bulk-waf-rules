# E2E Test Plan — All Export Scripts

This document outlines the e2e testing strategy for each WAF export script, including cost analysis, resource requirements, and test coverage.

## Test Architecture

Each provider follows the same pattern:

```
tests/<provider>/
├── setup.sh          # Create test resources (idempotent)
├── teardown.sh       # Delete test resources (+ --force fallback)
├── run-tests.sh      # Test cases with assertions
├── .test-state.json  # Auto-generated (gitignored)
└── README.md         # Provider-specific docs
```

All suites share:
- Same bash conventions (`set -euo pipefail`, color logging, exit codes)
- Same test framework (`run_test`, `assert_*` helpers, pass/fail summary)
- State file for resource IDs (gitignored)
- Idempotent setup, aggressive teardown with `--force` fallback

---

## Cost Summary

| Provider | Cost Per Run | Account Required | Free Tier Usable? |
|----------|-------------|------------------|-------------------|
| **AWS WAF** | **$0** | Any AWS account | ✅ Yes |
| **Cloudflare** | **$0** | Free Cloudflare account | ⚠️ Partial — IP Lists need Enterprise |
| **Akamai** | **$0** | Active Akamai contract | ❌ No free tier |
| **Fastly** | **$0** | Active Fastly NGWAF subscription | ❌ No free tier |

**Bottom line:** AWS is the only platform where anyone can run the full suite from scratch with zero cost and no existing contract. The other platforms require existing paid accounts — but if you already have them, the API calls themselves are free.

---

## ✅ AWS WAF — BUILT

**Status:** Complete (`tests/aws-waf/`)

**Cost: $0** — IP Sets are free, Web ACLs only billed when attached to resources.

See [tests/aws-waf/README.md](aws-waf/README.md) for full details.

| Resources Created | Test Cases | Lines of Code |
|-------------------|------------|---------------|
| 4 IP Sets + 1 Web ACL | 17 | ~1,540 |

---

## 📋 Cloudflare — PLANNED

### Prerequisites
- Cloudflare account with API token (`CF_API_TOKEN`)
- At least one zone (free plan zone works for IP Access Rules)
- Enterprise plan for IP Lists (the `--list` command)

### Cost Breakdown

| Resource | Cloudflare Pricing | Test Usage | Cost |
|----------|-------------------|------------|------|
| IP Access Rules | Free on all plans | Create/delete test entries | **$0** |
| IP Lists | Enterprise only ($$$) | Create/delete test list | **$0 if you have Enterprise** |
| Zone Lockdown | Free on all plans | Not tested (deprecated feature) | N/A |
| API calls | Free — no per-call billing | ~40 calls per cycle | **$0** |

### Test Resources to Create

| Resource | Type | Contents | Purpose |
|----------|------|----------|---------|
| `e2e-test-block-1` | Account IP Access Rule | `192.0.2.1` (block) | Single rule export |
| `e2e-test-block-2` | Account IP Access Rule | `192.0.2.2` (block) | Multi-rule aggregation |
| `e2e-test-challenge-1` | Account IP Access Rule | `198.51.100.0/24` (challenge) | Mode filtering |
| `e2e-test-whitelist-1` | Account IP Access Rule | `203.0.113.1` (whitelist) | Whitelist mode |
| `e2e-test-zone-rule-1` | Zone IP Access Rule | `10.0.0.1` (block) | Zone-level export |
| `e2e-test-ip-list` | IP List | 5 entries | `--list` command (Enterprise only) |

### Proposed Test Cases (~14)

| # | Test | What It Validates |
|---|------|-------------------|
| 1 | `test_help` | `--help` exits 0 |
| 2 | `test_invalid_command` | Unknown flag exits 6 |
| 3 | `test_missing_token` | No `CF_API_TOKEN` exits 2 |
| 4 | `test_export_account_rules` | `--account` exports all account-level rules |
| 5 | `test_export_zone_rules` | `--zone` exports zone-level rules |
| 6 | `test_mode_filter` | `MODE_FILTER=block` only exports block rules |
| 7 | `test_csv_format` | Header is `ip,notes,mode,created_on`, 4 columns |
| 8 | `test_custom_output` | `OUTPUT_FILE=` writes to custom path |
| 9 | `test_dry_run` | `DRY_RUN=true` creates no output file |
| 10 | `test_idempotent` | Two runs produce identical output |
| 11 | `test_pagination` | Handles paginated responses (if enough rules) |
| 12 | `test_export_ip_list` | `--list` exports IP List entries (Enterprise) |
| 13 | `test_empty_account` | Account with no rules → header-only CSV |
| 14 | `test_invalid_token` | Bad token exits 3 |

### Notes
- Tests 12 can be skipped in non-Enterprise environments with a `SKIP_ENTERPRISE=true` flag
- Cloudflare API rate limit is 1200 requests/5 min — not a concern for tests
- IP Access Rules are created via `POST /client/v4/accounts/{id}/firewall/access_rules/rules`
- Teardown uses `DELETE` on the same endpoint with the rule ID

---

## 📋 Akamai — PLANNED

### Prerequisites
- Active Akamai contract with Network Lists API access
- EdgeGrid credentials in `~/.edgerc`
- API client with **Network Lists: READ-WRITE** permissions (READ for export, WRITE for setup/teardown)

### Cost Breakdown

| Resource | Akamai Pricing | Test Usage | Cost |
|----------|---------------|------------|------|
| Network Lists | Included with platform | Create/delete test lists | **$0** |
| Security Configs | Included with App Security | Read-only for tests | **$0** |
| API calls | No per-call billing | ~25 calls per cycle | **$0** |
| Activation | Free (staging/production) | **Not activated** — lists exist but aren't pushed | **$0** |

**Important:** Creating a Network List does NOT affect production traffic. Lists only take effect when activated on a security configuration. The test setup creates lists but never activates them.

### Test Resources to Create

| Resource | Type | Contents | Purpose |
|----------|------|----------|---------|
| `e2e-test-vendor-ips` | Network List (IP) | 5 IPs/CIDRs | Basic export |
| `e2e-test-geo-list` | Network List (GEO) | 2 country codes | Non-IP list (skip test) |
| `e2e-test-empty-list` | Network List (IP) | 0 entries | Empty list edge case |

### Proposed Test Cases (~12)

| # | Test | What It Validates |
|---|------|-------------------|
| 1 | `test_help` | `--help` exits 0 |
| 2 | `test_missing_edgerc` | No `.edgerc` exits 2 |
| 3 | `test_list_all` | `--list-all` shows all test lists |
| 4 | `test_export_network_list` | `--network-list` exports 5 IPs, correct CSV |
| 5 | `test_geo_list_skip` | GEO-type list warns and skips (or exports country codes) |
| 6 | `test_empty_list` | Empty list → header-only CSV, no crash |
| 7 | `test_csv_format` | Header is `ip,notes,mode,created_on`, 4 columns |
| 8 | `test_custom_output` | `OUTPUT_FILE=` writes to custom path |
| 9 | `test_dry_run` | `DRY_RUN=true` creates no output file |
| 10 | `test_idempotent` | Two runs produce identical output |
| 11 | `test_invalid_list_id` | Bad list ID exits 4 |
| 12 | `test_edgerc_section` | `AKAMAI_SECTION=test` uses correct section |

### Notes
- Network Lists are created via `POST /network-list/v2/network-lists`
- Teardown deletes via `DELETE /network-list/v2/network-lists/{listId}`
- Security config tests (`--security-config`) require an existing config — too complex to create in test setup, so this command is tested against an existing config or skipped with `SKIP_SECURITY_CONFIG=true`
- Akamai API rate limit varies by contract — typically generous for control plane operations
- EdgeGrid auth (HMAC signing) is handled by the export script itself

---

## 📋 Fastly — PLANNED

### Prerequisites
- Active Fastly account with NGWAF (Signal Sciences) subscription
- Signal Sciences credentials (`SIGSCI_EMAIL` + `SIGSCI_TOKEN`) and/or Fastly API token (`FASTLY_API_TOKEN`)
- At least one corp and site in Signal Sciences

### Cost Breakdown

| Resource | Fastly Pricing | Test Usage | Cost |
|----------|---------------|------------|------|
| Whitelist/blacklist entries | Included with NGWAF | Create/delete test entries | **$0** |
| Corp/site lists | Included with NGWAF | Create/delete test lists | **$0** |
| NGWAF account lists | Included with NGWAF | Create/delete test lists | **$0** |
| API calls | No per-call billing | ~50 calls per cycle | **$0** |

### Test Resources to Create

**Signal Sciences API:**

| Resource | Type | Contents | Purpose |
|----------|------|----------|---------|
| Whitelist entry × 3 | Site whitelist | 3 test IPs | `--whitelist` export |
| Blacklist entry × 2 | Site blacklist | 2 test IPs | `--blacklist` export |
| `e2e-test-corp-list` | Corp list (IP) | 4 IPs | `--corp-list` export |
| `e2e-test-site-list` | Site list (IP) | 3 IPs | `--site-list` export |

**Fastly NGWAF API:**

| Resource | Type | Contents | Purpose |
|----------|------|----------|---------|
| `e2e-test-account-list` | Account list (IP) | 5 IPs | `--account-list` export |

### Proposed Test Cases (~16)

| # | Test | What It Validates |
|---|------|-------------------|
| 1 | `test_help` | `--help` exits 0 |
| 2 | `test_version` | `--version` exits 0 |
| 3 | `test_missing_creds` | No credentials exits 2 |
| 4 | `test_list_corps` | `--list-corps` shows corps |
| 5 | `test_list_sites` | `--list-sites <corp>` shows sites |
| 6 | `test_export_whitelist` | `--whitelist` exports 3 IPs |
| 7 | `test_export_blacklist` | `--blacklist` exports 2 IPs |
| 8 | `test_list_corp_lists` | `--list-corp-lists` shows test list |
| 9 | `test_export_corp_list` | `--corp-list` exports 4 IPs |
| 10 | `test_list_site_lists` | `--list-site-lists` shows test list |
| 11 | `test_export_site_list` | `--site-list` exports 3 IPs |
| 12 | `test_account_lists` | `--account-lists` shows test list (NGWAF) |
| 13 | `test_export_account_list` | `--account-list` exports 5 IPs (NGWAF) |
| 14 | `test_csv_format` | Header is `ip,notes,mode,created_on`, 4 columns |
| 15 | `test_dry_run` | `DRY_RUN=true` creates no output file |
| 16 | `test_idempotent` | Two runs produce identical output |

### Notes
- Signal Sciences whitelist: `PUT /corps/{corp}/sites/{site}/whitelist` to add, `DELETE` to remove
- Signal Sciences lists: `POST /corps/{corp}/lists` to create, `DELETE` to remove
- NGWAF lists: `POST /ngwaf/v1/lists` to create, `DELETE` to remove
- Tests split into two groups: `SIGSCI_TESTS` (require Signal Sciences creds) and `NGWAF_TESTS` (require Fastly token). Either can be skipped with `SKIP_SIGSCI=true` or `SKIP_NGWAF=true`
- Corp and site must already exist — setup.sh validates they exist but doesn't create them (creating corps/sites requires Fastly account management, not just API)

---

## Implementation Priority

| # | Suite | Effort | Rationale |
|---|-------|--------|-----------|
| 1 | ✅ AWS WAF | Done | Free, no contract needed, anyone can run |
| 2 | Cloudflare | Medium | Free tier covers IP Access Rules (most common use case). IP Lists need Enterprise — skip with flag |
| 3 | Fastly | Medium | Requires existing NGWAF subscription, but two API surfaces means more test cases |
| 4 | Akamai | Medium | Requires contract + EdgeGrid setup. Network Lists API is straightforward |

### Recommended Build Order
1. **Cloudflare** — Most accessible after AWS (free account works for core features)
2. **Fastly** — Two API surfaces to test, slightly more complex
3. **Akamai** — EdgeGrid HMAC auth makes setup.sh more involved

---

## CI Strategy

Each suite runs independently in its own GitHub Actions job:

```yaml
jobs:
  e2e-aws-waf:
    if: contains(github.event.pull_request.changed_files, 'aws-waf-export')
    # ... (existing)
    
  e2e-cloudflare:
    if: contains(github.event.pull_request.changed_files, 'cloudflare-export')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./tests/cloudflare/setup.sh
        env:
          CF_API_TOKEN: ${{ secrets.CF_API_TOKEN_TEST }}
          CF_ACCOUNT_ID: ${{ secrets.CF_ACCOUNT_ID_TEST }}
      - run: ./tests/cloudflare/run-tests.sh
      - run: ./tests/cloudflare/teardown.sh
        if: always()

  e2e-akamai:
    if: contains(github.event.pull_request.changed_files, 'akamai-export')
    # ... similar pattern with EDGERC secret

  e2e-fastly:
    if: contains(github.event.pull_request.changed_files, 'fastly-export')
    # ... similar pattern with SIGSCI/FASTLY secrets
```

Path filters ensure each suite only runs when its export script changes. `workflow_dispatch` allows manual triggers for any suite.
