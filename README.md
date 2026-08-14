# Vercel Migration Control Plane

This repository is being re-architected into a TypeScript control plane for planning and verifying Firewall, CDN, Domain, and application workload migrations to Vercel. See [AGENTS.md](AGENTS.md) for the product charter, architecture invariants, roadmap, and current progress.

The existing Bash workflow is a legacy **IP-list migration utility**. It does not yet preserve complete source-provider firewall semantics such as actions, nested conditions, priority, default behavior, rate limits, or scope. Do not treat its provider exporters as full WAF-policy migration support.

All migration direction references mean `{source platform} -> Vercel`. The [MVP roadmap and test plan](docs/mvp-test-plan.md) defines the first supported paths, including Firewall, AWS Lambda assessment, Domain/DNS planning, and the release gates for each path.

## Use the TypeScript preview

Install dependencies and inspect the truthful capability registry:

```bash
npm ci
npm run --silent cli -- support
```

The current TypeScript CLI is non-mutating. It creates, validates, and reports on migration bundles without authenticating to providers or changing Vercel resources.

The early TypeScript preview can create a non-mutating source snapshot and deterministic plan bundle:

```bash
npm run --silent cli -- plan-ip \
  --input vendor-ips.csv \
  --intent blocklist \
  --project-id prj_xxxxxxxxxxxx \
  > migration-bundle.json
```

Alternatively, write it with private permissions below a schema-versioned artifact directory:

```bash
npm run --silent cli -- plan-ip \
  --input vendor-ips.csv \
  --intent blocklist \
  --project-id prj_xxxxxxxxxxxx \
  --artifact-dir .vercel-migrate/artifacts
```

Validate or render a review report before any future staging step:

```bash
npm run --silent cli -- validate --input migration-bundle.json
npm run --silent cli -- report --input migration-bundle.json
npm run --silent cli -- support
```

Validation checks the artifact schema, snapshot provenance, dependency safety, and deterministic content ID. None of these TypeScript commands mutate Vercel.

Use `allowlist`, `blocklist`, or `bypass` for `--intent`. Add `--hostname api.example.com` to scope the planned rules. The TypeScript planner accepts IPv4 and IPv6; the legacy Bash workflow documented below remains IPv4-only.

`support` is the authoritative machine-readable compatibility view. It reports API variants, last-verification dates, semantic gaps, live-E2E status, and the actual implementation level instead of inferring support from the presence of a legacy export script.

### Cloudflare semantic preview

`plan-cloudflare` accepts the JSON response from Cloudflare's zone-level `http_request_firewall_custom` Rulesets entrypoint:

```bash
npm run --silent cli -- plan-cloudflare \
  --input cloudflare-custom-ruleset.json \
  --account-id account_xxxxxxxxxxxx \
  --zone-id zone_xxxxxxxxxxxx \
  --project-id prj_xxxxxxxxxxxx \
  > migration-bundle.json
```

The current fail-closed subset supports Boolean expressions over client IP/ASN/country and common request fields, plus block/log actions and explicitly approximate challenge mappings. Unsupported fields, transformations, unresolved lists, skip semantics, managed execution, and other actions become visible manual operations. They are never silently dropped. Authenticated Cloudflare discovery is not implemented yet.

Provider-derived CSVs must include `--source-provider`; these plans are intentionally classified as `manual` fidelity until native semantic adapters are implemented.

## Legacy Bash workflow

Bulk migrate IP allow/bypass lists to Vercel Firewall.

We currently support **two modes**:

| Mode | Description | Use Case |
|------|-------------|----------|
| **deny** | Block all traffic EXCEPT from listed IPs | Private apps, vendor-only access |
| **bypass** | Bypass WAF/security for listed IPs | Public apps with vendor integrations (webhooks, scanners, bots) |

## Repo Structure

```plaintext
docs/                        # Detailed guides (credentials, exports, CI/CD)
  scripts/
  vercel-bulk-waf-rules.sh   # Main script
  rollback.sh                # Backup & restore operations
  exports/                   # WAF migration scripts (Cloudflare, Akamai, Fastly, AWS)
  tests/                     # Test fixtures and test scripts
  examples/                  # CI/CD workflow examples (GitHub Actions)
```

## Quick Start

### 1. Set Up Environment

**Option A: Vercel CLI login (recommended for local use)**

```bash
cd /path/to/your/vercel/project
vercel link    # Creates .vercel/project.json (one-time)
vercel login   # Authenticate (one-time)
```

**Option B: Token-based (required for CI/CD)**

```bash
export VERCEL_TOKEN="your-vercel-api-token"
export PROJECT_ID="prj_xxxxxxxxxxxx"      # Or auto-detected from .vercel/project.json
export TEAM_ID="team_xxxxxxxxxxxx"        # Optional, for team projects
```

**Need help?** Run `./scripts/vercel-bulk-waf-rules.sh setup` for guided setup instructions.

### 2. Create IP List CSV

```csv
ip,vendor_name,notes
1.2.3.4,Acme Corp,Payment gateway
5.6.7.0/24,Partner Inc,API integration
10.20.30.40,Office,Main office egress
```

### 3. Preview Changes (Dry Run)

```bash
DRY_RUN=true RULE_MODE=deny ./scripts/vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### 4. Apply Rules

**Interactive Mode (recommended for first-time setup):**

```bash
./scripts/vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

The script will prompt you to choose your intended behavior:

```bash
Select rule mode:

  1) allowlist  - Block ALL traffic except listed IPs
                  Use for: Private apps, vendor-only access

  2) bypass     - Bypass WAF for listed IPs, allow all other traffic
                  Use for: Public apps with vendor integrations

Enter choice [1-2]:
```

**Explicit Mode (for CI/CD or scripting):**

```bash
# Deny mode - Block all except listed IPs
RULE_MODE=deny ./scripts/vercel-bulk-waf-rules.sh apply vendor-ips.csv

# Bypass mode - Bypass WAF for listed IPs
RULE_MODE=bypass ./scripts/vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

> **Note:** In non-interactive environments (CI/CD), you must set `RULE_MODE` explicitly or the script will exit with an error.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/vercel-bulk-waf-rules.sh` | Main script for bulk WAF rule management |
| `scripts/rollback.sh` | Backup, restore, enable/disable WAF rules |
| `scripts/exports/cloudflare-export.sh` | Export IPs from Cloudflare WAF rules |
| `scripts/exports/akamai-export.sh` | Export IPs from Akamai Network Lists |
| `scripts/exports/fastly-export.sh` | Export IPs from Fastly Next-Gen WAF |
| `scripts/exports/aws-waf-export.sh` | Export IPs from AWS WAF v2 (WAFV2) IP Sets |

## Commands

| Command | Description |
|---------|-------------|
| `./scripts/vercel-bulk-waf-rules.sh setup` | Show environment setup instructions |
| `./scripts/vercel-bulk-waf-rules.sh apply <csv>` | Create/update WAF rules from CSV |
| `./scripts/vercel-bulk-waf-rules.sh show` | Show current WAF rules |
| `./scripts/vercel-bulk-waf-rules.sh optimize <csv>` | Optimize IPs into CIDR ranges |
| `./scripts/vercel-bulk-waf-rules.sh disable` | Disable rule temporarily |
| `./scripts/vercel-bulk-waf-rules.sh remove` | Remove a single rule |
| `./scripts/vercel-bulk-waf-rules.sh purge` | Remove ALL auto-managed rules |
| `./scripts/vercel-bulk-waf-rules.sh backup` | Export current firewall config |

## Features

The script uses the [`vercel api` CLI command](https://vercel.com/changelog/introducing-the-vercel-api-cli-command) (vercel@50.5.1+) and provides:

- **Bulk IP management**: Apply hundreds of IPs from CSV in one command
- **CIDR optimization**: Automatically aggregate contiguous IPs into CIDR ranges
- **Two auth methods**: `vercel login` for local use, `VERCEL_TOKEN` for CI/CD
- **Chunking support**: Automatically splits large IP lists across multiple rules (75 IPs per rule limit)
- **Dry run mode**: Preview changes before applying

## Documentation

Detailed guides are available in the `docs/` folder:

| Guide | Description |
|-------|-------------|
| [MVP roadmap and test plan](docs/mvp-test-plan.md) | MVP product slices, implementation milestones, test cases, and release gates |
| [Control-plane architecture](docs/control-plane-architecture.md) | Shared workflow contracts and product-specific model boundaries |
| [Vercel Credentials](docs/vercel-credentials.md) | API token setup and project/team ID discovery |
| [Cloudflare Export](docs/cloudflare-export.md) | Export IPs from Cloudflare WAF rules |
| [Akamai Export](docs/akamai-export.md) | Export IPs from Akamai Network Lists |
| [Fastly Export](docs/fastly-export.md) | Export IPs from Fastly Next-Gen WAF |
| [AWS WAF Export](docs/aws-waf-export.md) | Export IPs from AWS WAF v2 IP Sets |
| [CI/CD Integration](docs/ci-cd-integration.md) | GitHub Actions, GitLab CI, CircleCI examples |

## How It Works

This tool creates a **custom firewall rule** with behavior based on the selected mode:

### Deny Mode (default)

1. Uses the `ninc` (NOT IN) operator to match IPs **not** in your list
2. Applies a `deny` action to block those IPs
3. Rule name: `IP Allowlist - Auto-managed`

### Bypass Mode

1. Uses the `inc` (IN) operator to match IPs **in** your list
2. Applies a `bypass` action to skip WAF/security checks
3. Rule name: `IP Bypass - Auto-managed`

Both modes support updating the rule in place as your IP list changes.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VERCEL_TOKEN` | Yes* | Vercel API token (*not needed if using `vercel login`) |
| `PROJECT_ID` | Auto | Auto-detected from `.vercel/project.json`, or set manually |
| `TEAM_ID` | Auto | Auto-detected from `.vercel/project.json`, or set manually |
| `RULE_MODE` | No* | `deny` or `bypass` (*required in CI/CD) |
| `RULE_HOSTNAME` | No | Scope rule to specific hostname |
| `DRY_RUN` | No | Set to "true" for preview mode |
| `AUDIT_LOG` | No | Path to audit log file |
| `DEBUG` | No | Set to "true" for verbose output |

## CSV Format

```csv
ip,vendor_name,notes
1.2.3.4,Acme Corp,Payment gateway
5.6.7.0/24,Partner Inc,API integration
10.20.30.40,Analytics Co,Tracking service
```

- `ip` (required): IPv4 address or CIDR range
- `vendor_name` (optional): Vendor name for tracking
- `notes` (optional): Additional notes

> **Note:** Only IPv4 is supported. IPv6 addresses will be rejected.

## Migrating from Other WAF Providers

Export scripts are available in the `scripts/exports/` directory to help migrate IP-based WAF rules from other providers.

### From Cloudflare

```bash
# Export from Cloudflare
export CF_API_TOKEN="your-cloudflare-token"
./scripts/exports/cloudflare-export.sh --account abc123def456

# Import to Vercel (choose your mode)
RULE_MODE=bypass ./scripts/vercel-bulk-waf-rules.sh apply cloudflare_ips.csv
```

See [docs/cloudflare-export.md](docs/cloudflare-export.md) for details.

### From Akamai

```bash
# Export from Akamai
./scripts/exports/akamai-export.sh --list-all
./scripts/exports/akamai-export.sh --network-list 38069_VENDORIPS

# Import to Vercel (choose your mode)
RULE_MODE=bypass ./scripts/vercel-bulk-waf-rules.sh apply akamai_ips.csv
```

See [docs/akamai-export.md](docs/akamai-export.md) for details.

### From Fastly

```bash
# Export from Fastly Next-Gen WAF (Signal Sciences API)
export SIGSCI_EMAIL="your-email@example.com"
export SIGSCI_TOKEN="your-api-token"
./scripts/exports/fastly-export.sh --whitelist mycorp mysite

# Or use Fastly NGWAF API
export FASTLY_API_TOKEN="your-fastly-token"
./scripts/exports/fastly-export.sh --account-list list_abc123

# Import to Vercel (choose your mode)
RULE_MODE=bypass ./scripts/vercel-bulk-waf-rules.sh apply fastly_ips.csv
```

See [docs/fastly-export.md](docs/fastly-export.md) for details.

### From AWS WAF

```bash
# Configure AWS credentials
export AWS_PROFILE=my-profile
export AWS_DEFAULT_REGION=us-west-2

# Discover and export IP Sets
./scripts/exports/aws-waf-export.sh --list-ip-sets
./scripts/exports/aws-waf-export.sh --ip-set vendor-allowlist a1b2c3d4-5678-90ab-cdef-EXAMPLE11111

# Or export all IP Sets at once
./scripts/exports/aws-waf-export.sh --all-ip-sets

# Import to Vercel (choose your mode)
RULE_MODE=bypass ./scripts/vercel-bulk-waf-rules.sh apply aws_waf_ips.csv
```

> **Note:** This script supports AWS WAF v2 (WAFV2) only. AWS WAF Classic (v1) was sunset on September 30, 2025. See the [migration guide](https://docs.aws.amazon.com/waf/latest/developerguide/waf-migrating-from-classic.html) if you need to migrate Classic resources first.

See [docs/aws-waf-export.md](docs/aws-waf-export.md) for details.

## Rollback Operations

```bash
# Create backup
./scripts/vercel-bulk-waf-rules.sh backup

# Disable temporarily
./scripts/vercel-bulk-waf-rules.sh disable

# Remove completely
./scripts/vercel-bulk-waf-rules.sh purge
```

## CI/CD Integration

See [docs/ci-cd-integration.md](docs/ci-cd-integration.md) for complete examples for:

- GitHub Actions
- GitLab CI
- CircleCI
- Azure DevOps
- AWS CodePipeline

## Best Practices

### Before Applying

1. **Backup First**: Run `./scripts/vercel-bulk-waf-rules.sh backup` before making changes
2. **Dry Run**: Always preview with `DRY_RUN=true`
3. **Test on Non-Production**: Test on a staging project first
4. **Include Your IP**: Make sure to include your office/VPN IPs!

### Security

- Store tokens in a secrets manager, not in env files
- Use project-scoped tokens when possible
- Enable `AUDIT_LOG` for compliance tracking
- Review IP lists regularly to remove stale entries

## Troubleshooting

### "I locked myself out!"

1. Use Vercel Dashboard to disable the rule:
   - Go to Project → Settings → Security → Firewall
   - Find the "IP Allowlist - Auto-managed" rule
   - Toggle it off or delete it

2. Or use the API from an allowed IP:

   ```bash
   ./scripts/vercel-bulk-waf-rules.sh disable
   ```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `IPv6 not supported` | IPv6 in CSV | Use IPv4 only |
| `HTTP 403` | Insufficient permissions | Check token scopes |
| `HTTP 404` | Project not found | Verify PROJECT_ID |
| `No managed rule found` | Rule doesn't exist | Run `apply` first |

## Resources

- [Vercel Firewall Documentation](https://vercel.com/docs/security/firewall)
- [Vercel REST API - Security](https://vercel.com/docs/rest-api/reference/endpoints/security)
- [Vercel Rate Limits](https://vercel.com/docs/rest-api/limits)

## Plan Availability

- WAF Custom Rules available on [all Vercel plans](https://vercel.com/docs/plans)
- Custom rules are part of the Firewall feature set
