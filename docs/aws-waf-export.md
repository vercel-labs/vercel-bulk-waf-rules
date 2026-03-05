# AWS WAF Export

The `exports/aws-waf-export.sh` script exports IP addresses and CIDR ranges from AWS WAF v2 (WAFV2) IP Sets to CSV format compatible with Vercel Firewall.

> **This script supports AWS WAF v2 (WAFV2) only.** AWS WAF Classic (v1) reached end of life on September 30, 2025. If you still have WAF Classic resources, migrate them to WAFV2 first using AWS's built-in migration tool. See [Migrating your AWS WAF Classic resources to AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-migrating-from-classic.html) for details.

## Overview

AWS WAF v2 stores IP addresses in **IP Sets** — dedicated collections of IP addresses or CIDR ranges. This script extracts those IP Sets and converts them to CSV for import into Vercel Firewall.

The script supports two WAF **scopes**:

| Scope | Protects | Region |
|-------|----------|--------|
| `REGIONAL` (default) | ALB, API Gateway, AppSync, Cognito, App Runner, Amplify, Verified Access | Your configured AWS region |
| `CLOUDFRONT` | CloudFront distributions | Always `us-east-1` |

## Prerequisites

### Dependencies

- `aws` CLI v2+ — for AWS API calls
- `jq` — for JSON parsing
- `bc` — for rate limiting calculations (optional, falls back to 1s delays)

**Install on macOS:**

```bash
brew install awscli jq
```

**Install on Ubuntu/Debian:**

```bash
sudo apt-get install awscli jq bc
```

**Verify AWS CLI version:**

```bash
aws --version
# Must be aws-cli/2.x.x or later
```

### IAM Permissions

Your AWS credentials need the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "wafv2:ListIPSets",
        "wafv2:GetIPSet",
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**Minimum permissions by command:**

| Command | Permissions Required |
|---------|---------------------|
| `--list-ip-sets` | `wafv2:ListIPSets`, `sts:GetCallerIdentity` |
| `--ip-set` | `wafv2:GetIPSet`, `sts:GetCallerIdentity` |
| `--all-ip-sets` | `wafv2:ListIPSets`, `wafv2:GetIPSet`, `sts:GetCallerIdentity` |
| `--list-web-acls` | `wafv2:ListWebACLs`, `sts:GetCallerIdentity` |
| `--web-acl` | `wafv2:GetWebACL`, `wafv2:ListIPSets`, `wafv2:GetIPSet`, `sts:GetCallerIdentity` |

## AWS Credential Setup

The script uses the standard AWS CLI credential chain. Configure credentials using any of these methods:

### Method 1: Named Profile (Recommended)

```bash
# Configure a named profile
aws configure --profile my-waf-profile

# Use it with the script
AWS_PROFILE=my-waf-profile ./exports/aws-waf-export.sh --list-ip-sets
```

### Method 2: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

./exports/aws-waf-export.sh --list-ip-sets
```

### Method 3: AWS SSO

```bash
aws sso login --profile my-sso-profile
AWS_PROFILE=my-sso-profile ./exports/aws-waf-export.sh --list-ip-sets
```

### Method 4: IAM Role (CI/CD)

In EC2, ECS, Lambda, or other AWS services, the IAM role attached to the compute resource is used automatically — no explicit credentials needed.

```bash
# Running on EC2 with an IAM role attached
./exports/aws-waf-export.sh --list-ip-sets
```

### Setting the Region

For `REGIONAL` scope, set your region:

```bash
export AWS_DEFAULT_REGION="us-west-2"
./exports/aws-waf-export.sh --list-ip-sets
```

For `CLOUDFRONT` scope, the script automatically uses `us-east-1` — no region configuration needed.

## Commands

### List IP Sets

```bash
./exports/aws-waf-export.sh --list-ip-sets
```

Output:
```
[INFO] Validating AWS credentials...
[INFO] Authenticated: arn:aws:iam::123456789012:user/admin (Account: 123456789012)

[INFO] Fetching IP Sets (scope: REGIONAL)...

==============================================
  IP Sets (REGIONAL)
==============================================

Name: vendor-allowlist
  ID:          a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
  Description: Trusted vendor IPs
  ARN:         arn:aws:wafv2:us-west-2:123456789012:regional/ipset/vendor-allowlist/a1b2c3d4-...

Name: blocked-ips
  ID:          b2c3d4e5-6789-01ab-cdef-EXAMPLE22222
  Description: Known bad actors
  ARN:         arn:aws:wafv2:us-west-2:123456789012:regional/ipset/blocked-ips/b2c3d4e5-...

[INFO] Found 2 IP Set(s) (scope: REGIONAL)

  To export an IP Set, run:
  ./aws-waf-export.sh --ip-set <name> <id> --scope REGIONAL
```

### List IP Sets (CloudFront)

```bash
./exports/aws-waf-export.sh --list-ip-sets --scope CLOUDFRONT
```

### List Web ACLs

```bash
./exports/aws-waf-export.sh --list-web-acls
```

### Export a Single IP Set

```bash
./exports/aws-waf-export.sh --ip-set vendor-allowlist a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
```

Output:
```
[INFO] ==============================================
[INFO]   AWS WAF IP Set Export
[INFO] ==============================================
[INFO]
[INFO] Name:  vendor-allowlist
[INFO] ID:    a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
[INFO] Scope: REGIONAL
[INFO] Output: aws_waf_ips.csv
[INFO]
[INFO] IP Set: vendor-allowlist
[INFO] IP version: IPV4
[INFO] Addresses: 15
[INFO]
[INFO] ==============================================
[INFO]   Export Summary
[INFO] ==============================================
[INFO]
[INFO]   IPs exported:   15
[INFO]   Time elapsed:   1s
[INFO]   Output file:    aws_waf_ips.csv
[INFO]   Output size:    16 lines
[INFO]
[INFO] First 5 entries:
"192.0.2.0/24","vendor-allowlist - Trusted vendor IPs","ip_set",""
"10.0.0.1/32","vendor-allowlist - Trusted vendor IPs","ip_set",""
"172.16.0.0/16","vendor-allowlist - Trusted vendor IPs","ip_set",""
```

### Export All IP Sets

```bash
./exports/aws-waf-export.sh --all-ip-sets
```

Exports every IP Set in the given scope into a single CSV file.

### Export IPs Referenced by a Web ACL

```bash
./exports/aws-waf-export.sh --web-acl my-web-acl a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
```

This command:
1. Fetches the Web ACL definition
2. Walks all rules looking for `IPSetReferenceStatement` references
3. Resolves each referenced IP Set
4. Exports all IPs to a single CSV

### Global Flags

All commands accept these flags:

```bash
# Set WAF scope (default: REGIONAL)
./exports/aws-waf-export.sh --list-ip-sets --scope CLOUDFRONT

# Include IPv6 addresses (skipped by default since Vercel WAF is IPv4-only)
./exports/aws-waf-export.sh --all-ip-sets --include-ipv6
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_PROFILE` | No | - | AWS CLI named profile |
| `AWS_ACCESS_KEY_ID` | No | - | AWS access key (alternative to profile) |
| `AWS_SECRET_ACCESS_KEY` | No | - | AWS secret key (used with access key) |
| `AWS_SESSION_TOKEN` | No | - | Session token for temporary credentials |
| `AWS_DEFAULT_REGION` | No | - | AWS region for REGIONAL scope |
| `AWS_REGION` | No | - | Alternative region variable |
| `OUTPUT_FILE` | No | `aws_waf_ips.csv` | Output CSV file path |
| `DRY_RUN` | No | `false` | Set to `true` for preview mode |
| `DEBUG` | No | `false` | Set to `true` for verbose output |
| `AUDIT_LOG` | No | - | Path to audit log file |

## Output Format

The script outputs CSV with these columns:

```csv
ip,notes,mode,created_on
"192.0.2.0/24","vendor-allowlist - Trusted vendor IPs","ip_set",""
"10.0.0.1/32","vendor-allowlist - Trusted vendor IPs","ip_set",""
```

| Column | Description |
|--------|-------------|
| `ip` | IP address or CIDR range |
| `notes` | IP Set name and description |
| `mode` | Always `ip_set` (source type identifier) |
| `created_on` | Empty — AWS does not provide per-IP timestamps |

This format is directly compatible with `vercel-bulk-waf-rules.sh`.

### IPv6 Handling

AWS WAF IP Sets can be either `IPV4` or `IPV6`. Since **Vercel WAF only supports IPv4**, the script skips IPv6 IP Sets by default with a warning:

```
[WARN] Skipping IPv6 IP Set: ipv6-blocklist (IPV6) — Vercel WAF only supports IPv4
[WARN] Use --include-ipv6 flag to include IPv6 addresses anyway.
```

To include IPv6 addresses (e.g., for record-keeping), pass `--include-ipv6`.

## AWS CLI Commands Used

| Operation | AWS CLI Command |
|-----------|----------------|
| Validate credentials | `aws sts get-caller-identity` |
| List IP Sets | `aws wafv2 list-ip-sets --scope <scope>` |
| Get IP Set | `aws wafv2 get-ip-set --name <name> --scope <scope> --id <id>` |
| List Web ACLs | `aws wafv2 list-web-acls --scope <scope>` |
| Get Web ACL | `aws wafv2 get-web-acl --name <name> --scope <scope> --id <id>` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Missing dependencies (aws CLI, jq) |
| 2 | Missing AWS credentials |
| 3 | Invalid AWS credentials |
| 4 | API error (non-retryable) |
| 5 | Rate limited (after max retries) |
| 6 | Invalid arguments |
| 7 | File I/O error |
| 8 | Network error |

## Migration Workflow

Complete workflow to migrate WAF IP rules from AWS WAF to Vercel:

```bash
# Step 1: Configure AWS credentials
export AWS_PROFILE=my-profile
export AWS_DEFAULT_REGION=us-west-2

# Step 2: Discover available IP Sets
./exports/aws-waf-export.sh --list-ip-sets

# Step 3: Export the desired IP Set
./exports/aws-waf-export.sh --ip-set vendor-allowlist a1b2c3d4-5678-90ab-cdef-EXAMPLE11111

# Or export ALL IP Sets at once
./exports/aws-waf-export.sh --all-ip-sets

# Step 4: Preview import to Vercel
DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply aws_waf_ips.csv

# Step 5: Apply to Vercel
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply aws_waf_ips.csv
```

**Choose your Vercel mode based on your use case:**
- `RULE_MODE=deny` - Block all traffic EXCEPT from these IPs (private apps)
- `RULE_MODE=bypass` - Skip WAF for these IPs (vendor integrations)

### Multi-Scope Migration

If you have IP Sets in both REGIONAL and CLOUDFRONT scopes:

```bash
# Export regional IP Sets
./exports/aws-waf-export.sh --all-ip-sets --scope REGIONAL
cp aws_waf_ips.csv regional_ips.csv

# Export CloudFront IP Sets
./exports/aws-waf-export.sh --all-ip-sets --scope CLOUDFRONT
cp aws_waf_ips.csv cloudfront_ips.csv

# Combine and deduplicate
{ head -1 regional_ips.csv; tail -n +2 regional_ips.csv; tail -n +2 cloudfront_ips.csv; } | sort -t, -k1,1 -u > combined_ips.csv

# Import to Vercel
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply combined_ips.csv
```

## Debugging

```bash
# Enable debug mode for verbose output
DEBUG=true ./exports/aws-waf-export.sh --list-ip-sets

# Enable audit logging
AUDIT_LOG="./aws-waf-export.log" ./exports/aws-waf-export.sh --all-ip-sets

# Dry run to preview without writing files
DRY_RUN=true ./exports/aws-waf-export.sh --ip-set my-list abc12345-...

# Combine debug + audit for full visibility
DEBUG=true AUDIT_LOG="./debug.log" ./exports/aws-waf-export.sh --all-ip-sets
```

## Error Handling

The script includes:

- **Automatic retry**: Up to 3 retries with exponential backoff for throttling and server errors
- **Throttle detection**: Automatic backoff on `ThrottlingException` / `TooManyRequestsException`
- **Credential redaction**: AWS keys and tokens are never logged, even in debug mode
- **Helpful error messages**: Access denied errors include the specific IAM permissions needed

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `AWS credentials not configured` | No credentials found | Configure via `aws configure`, `AWS_PROFILE`, or env vars |
| `AccessDeniedException` | Missing IAM permissions | Add required `wafv2:*` permissions to your IAM policy |
| `WAFNonexistentItemException` | Invalid Name or ID | Use `--list-ip-sets` to find valid Names and IDs |
| `ThrottlingException` | API rate limit hit | Script auto-retries; reduce concurrent calls if persistent |
| `Skipping IPv6 IP Set` | IPv6 not supported by Vercel | Use `--include-ipv6` if you want them exported anyway |
| `aws-cli version 1.x detected` | AWS CLI v1 installed | Upgrade to AWS CLI v2: `brew install awscli` or [install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| `CLOUDFRONT scope requires us-east-1` | Wrong region for CloudFront | Script handles this automatically; no action needed |

### Verify Credentials

```bash
# Test that your AWS credentials work
aws sts get-caller-identity

# Test with debug mode
DEBUG=true ./exports/aws-waf-export.sh --list-ip-sets
```

## Security Best Practices

1. **Use IAM roles over access keys** — IAM roles (for EC2, ECS, Lambda) are more secure than long-lived access keys
2. **Use AWS SSO for human access** — `aws sso login` is preferred over static credentials
3. **Least-privilege IAM policy** — Only grant `wafv2:List*`, `wafv2:Get*`, and `sts:GetCallerIdentity`
4. **Never commit credentials to version control** — Use `aws configure` or environment variables
5. **Rotate access keys regularly** — Especially after team member departures
6. **Enable audit logging** — Track all export operations with `AUDIT_LOG`

### CI/CD Setup

For CI/CD pipelines, use IAM roles or inject credentials as secrets:

```bash
# GitHub Actions example (using OIDC role)
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/waf-export-role
    aws-region: us-west-2

- run: ./exports/aws-waf-export.sh --all-ip-sets
```

```bash
# Or with access keys as secrets
export AWS_ACCESS_KEY_ID="${{ secrets.AWS_ACCESS_KEY_ID }}"
export AWS_SECRET_ACCESS_KEY="${{ secrets.AWS_SECRET_ACCESS_KEY }}"
export AWS_DEFAULT_REGION="us-west-2"
./exports/aws-waf-export.sh --all-ip-sets
```

## AWS WAF Classic (v1) — End of Life

> **AWS WAF Classic (v1) reached end of life on September 30, 2025.** This script does not support WAF Classic. If you have WAF Classic resources, you must migrate them to WAFV2 before using this export tool.

AWS provides a built-in migration tool:

```bash
# Migrate a WAF Classic Web ACL to WAFV2
aws wafv2 create-web-acl-migration-stack \
  --web-acl-arn arn:aws:waf::123456789012:webacl/example-web-acl-id \
  --web-acl-migration-stack \
  --scope REGIONAL
```

For full migration guidance, see:
- [Migrating your AWS WAF Classic resources to AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-migrating-from-classic.html)
- [Why migrate to AWS WAF?](https://docs.aws.amazon.com/waf/latest/developerguide/waf-migrating-why-migrate.html)
- [Migrating your rules from AWS WAF Classic to the new AWS WAF](https://aws.amazon.com/blogs/security/migrating-rules-from-aws-waf-classic-to-new-aws-waf/) (AWS Security Blog)

**Key timeline:**
- November 2019: AWS WAF v2 (WAFV2) released
- May 2025: Creation of new WAF Classic Web ACLs blocked
- September 30, 2025: AWS WAF Classic fully sunset

## Data Sources

IP addresses in AWS WAF v2 live in these locations:

| Source | How to Export | Notes |
|--------|--------------|-------|
| **IP Sets** | `--ip-set` or `--all-ip-sets` | Primary source — dedicated IP containers |
| **Web ACL rules** (via IPSetReferenceStatement) | `--web-acl` | References IP Sets; script resolves the references |
| **Rule Groups** (via IPSetReferenceStatement) | Not directly supported | Rule groups reference IP Sets; export the IP Sets directly |

The `--web-acl` command walks the Web ACL rule tree — including nested `AndStatement`, `OrStatement`, and `NotStatement` blocks — to find all `IPSetReferenceStatement` references and resolve them to their underlying IP Sets.
