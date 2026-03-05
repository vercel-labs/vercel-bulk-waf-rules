# AWS WAF Export — E2E Tests

End-to-end tests for `exports/aws-waf-export.sh`. These tests create **real AWS WAF resources** in your AWS account, run the export script against them, and verify the output.

## Prerequisites

- **AWS CLI v2** — `aws --version` must show `aws-cli/2.x.x`
- **jq** — JSON processor
- **AWS credentials** — configured via `AWS_PROFILE`, env vars, or IAM role
- **IAM permissions** — your credentials need:
  ```
  wafv2:CreateIPSet, wafv2:DeleteIPSet, wafv2:GetIPSet, wafv2:ListIPSets
  wafv2:CreateWebACL, wafv2:DeleteWebACL, wafv2:GetWebACL, wafv2:ListWebACLs
  sts:GetCallerIdentity
  ```

## Quick Start

```bash
# 1. Set up credentials
export AWS_PROFILE=my-test-profile
export AWS_DEFAULT_REGION=us-east-1

# 2. Create test resources
./tests/aws-waf/setup.sh

# 3. Run tests
./tests/aws-waf/run-tests.sh

# 4. Clean up
./tests/aws-waf/teardown.sh
```

## What Gets Created

| Resource | Type | Contents | Purpose |
|----------|------|----------|---------|
| `e2e-test-allowlist-v4` | IPv4 IP Set | 5 CIDRs | Basic export, CSV format |
| `e2e-test-blocklist-v4` | IPv4 IP Set | 3 CIDRs | `--all-ip-sets` aggregation |
| `e2e-test-ipv6-only` | IPv6 IP Set | 2 CIDRs | IPv6 skip / `--include-ipv6` |
| `e2e-test-empty` | IPv4 IP Set | 0 entries | Empty set edge case |
| `e2e-test-web-acl` | Web ACL | References allowlist + blocklist | `--web-acl` deep scan |

All resources are created in REGIONAL scope. State is saved to `.test-state.json`.

## Test Cases (17)

| # | Test | What It Validates |
|---|------|-------------------|
| 1 | `test_help` | `--help` exits 0, shows usage |
| 2 | `test_version` | `--version` exits 0, shows version |
| 3 | `test_invalid_command` | Unknown flag exits 6 |
| 4 | `test_missing_args` | Missing required args exits 6 |
| 5 | `test_list_ip_sets` | Lists all 4 test IP Sets |
| 6 | `test_list_web_acls` | Lists test Web ACL |
| 7 | `test_export_single` | Single IP Set → 5 rows, correct CSV |
| 8 | `test_export_all` | All IP Sets → 8 rows (5+3), IPv6 skipped |
| 9 | `test_export_web_acl` | Web ACL resolves both references → 8 rows |
| 10 | `test_ipv6_skip` | IPv6 IP Set skipped with warning |
| 11 | `test_ipv6_include` | `--include-ipv6` exports 2 IPv6 rows |
| 12 | `test_empty_ip_set` | Empty IP Set doesn't crash |
| 13 | `test_dry_run` | `DRY_RUN=true` creates no output file |
| 14 | `test_custom_output` | `OUTPUT_FILE=` writes to custom path |
| 15 | `test_csv_format` | Header is `ip,notes,mode,created_on`, 4 columns |
| 16 | `test_idempotent` | Two runs produce identical output |
| 17 | `test_invalid_scope` | `--scope INVALID` exits 6 |

## Cost

**$0 per run.** Here's the breakdown:

| Resource | AWS Pricing | Test Usage | Cost |
|----------|-------------|------------|------|
| IP Sets (4) | Free — no charge for IP Sets themselves | Created/deleted per run | **$0** |
| Web ACL (1) | $5/month *when associated with a resource* | Not associated with any ALB/CloudFront/API GW | **$0** |
| API calls | Free — `wafv2:*` control plane calls are not billed | ~30 calls per full setup/test/teardown cycle | **$0** |
| Data transfer | N/A — no data plane traffic | No request inspection occurs | **$0** |

**Why it's free:** AWS WAF billing is triggered by Web ACL association with actual resources (ALB, CloudFront distribution, API Gateway, etc.) and per-request inspection. The test Web ACL is never attached to anything — it exists solely as a metadata object for the export script to read.

**Risk of accidental cost:** If you forget to run `teardown.sh` and later attach the test Web ACL to a real resource, it would cost $5/month. Mitigations:
- `teardown.sh` is run with `if: always()` in CI (runs even on test failure)
- `teardown.sh --force` finds orphaned `e2e-test-*` resources by name
- All test resources use a clear `e2e-test-` prefix — impossible to confuse with production

## Cleanup

Always run teardown after testing:

```bash
./tests/aws-waf/teardown.sh
```

If the state file is lost, use force mode to find and delete by name:

```bash
./tests/aws-waf/teardown.sh --force
```

## CI Integration (Future)

```yaml
name: E2E Tests - AWS WAF Export
on:
  pull_request:
    paths: ['exports/aws-waf-export.sh', 'tests/aws-waf/**']
  workflow_dispatch:

jobs:
  e2e-aws-waf:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/waf-e2e-test-role
          aws-region: us-east-1
      - run: sudo apt-get install -y jq bc
      - run: ./tests/aws-waf/setup.sh
      - run: ./tests/aws-waf/run-tests.sh
      - run: ./tests/aws-waf/teardown.sh
        if: always()
```

## Files

```
tests/aws-waf/
├── setup.sh          # Create test resources (idempotent)
├── teardown.sh       # Delete test resources (--force for orphans)
├── run-tests.sh      # 17 test cases with assertions
├── .test-state.json  # Auto-generated resource IDs (gitignored)
└── README.md         # This file
```

> **Note:** `.test-state.json` is auto-generated by `setup.sh` and should not be committed. Add it to `.gitignore`.
