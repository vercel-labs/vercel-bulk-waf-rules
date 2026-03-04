# Fastly WAF Export

The `exports/fastly-export.sh` script exports IP addresses from Fastly Next-Gen WAF (formerly Signal Sciences) to CSV format compatible with Vercel Firewall.

## Overview

This script supports **two APIs** depending on how you access Fastly's WAF:

| Access Method | API | Auth Headers |
|---------------|-----|--------------|
| dashboard.signalsciences.net | Signal Sciences API | `SIGSCI_EMAIL` + `SIGSCI_TOKEN` |
| manage.fastly.com | Fastly NGWAF API | `FASTLY_API_TOKEN` |

The script auto-detects which API to use based on which credentials you provide.

## Which API Should I Use?

| If you access WAF via... | Use these credentials |
|--------------------------|----------------------|
| dashboard.signalsciences.net | `SIGSCI_EMAIL` + `SIGSCI_TOKEN` |
| manage.fastly.com | `FASTLY_API_TOKEN` |
| Both (migrating) | Either works, Signal Sciences has more features |

**Signal Sciences API** is the legacy API but offers more granular access (whitelists, blacklists, corp/site lists).

**Fastly NGWAF API** is the newer API with account/workspace level lists.

## Prerequisites

### Dependencies

- `curl` - for API requests
- `jq` - for JSON parsing
- `bc` - for rate limiting calculations (optional, falls back to 1s delays)

**Install on macOS:**

```bash
brew install jq  # curl is pre-installed
```

**Install on Ubuntu/Debian:**

```bash
sudo apt-get install curl jq bc
```

## Signal Sciences API Setup

### Creating an API Token

1. Go to [Signal Sciences Dashboard](https://dashboard.signalsciences.net)
2. Click your profile icon → **My Profile**
3. Scroll to **API access tokens**
4. Click **Add API access token**
5. Give it a descriptive name (e.g., "Vercel Migration - Read Only")
6. Copy the token immediately (it won't be shown again)

**Token Limits:**
- Maximum 5 tokens per user
- Tokens don't expire automatically
- Tokens inherit user's permissions

### Setting Credentials

```bash
export SIGSCI_EMAIL="your-email@example.com"
export SIGSCI_TOKEN="your-api-token-here"
```

### Finding Corp and Site Names

Corps and sites are identified by their **short names** (not display names).

**Via UI:**
- Corp name: Look at the URL - `dashboard.signalsciences.net/corps/<corp_name>`
- Site name: Look at the URL - `dashboard.signalsciences.net/corps/<corp>/sites/<site_name>`

**Via API:**

```bash
# List all corps you have access to
./exports/fastly-export.sh --list-corps

# List sites in a corp
./exports/fastly-export.sh --list-sites mycorp
```

## Fastly NGWAF API Setup

### Creating an API Token

1. Go to [Fastly Manage](https://manage.fastly.com)
2. Click **Account** → **API tokens**
3. Click **Create Token**
4. Set scope to `global:read` or more permissive
5. Copy the token

### Setting Credentials

```bash
export FASTLY_API_TOKEN="your-fastly-token-here"
```

### Finding Workspace IDs

Workspace IDs are UUIDs shown in the Fastly console URL:

```
manage.fastly.com/ngwaf/workspaces/<workspace_id>/overview
```

Or list them via API (requires additional endpoints not currently in this script).

## Signal Sciences Commands

### List Corps

```bash
./exports/fastly-export.sh --list-corps
```

Output:
```
[INFO] Fetching available corps...

==============================================
  Available Corps (Accounts)
==============================================

Name: mycorp
  Display: My Corporation
  Created: 2023-01-15T10:30:00Z

[INFO] Found 1 corp(s)
```

### List Sites

```bash
./exports/fastly-export.sh --list-sites mycorp
```

Output:
```
[INFO] Fetching sites in corp: mycorp

==============================================
  Sites in Corp: mycorp
==============================================

Name: production
  Display: Production Site
  Agent Mode: block

Name: staging
  Display: Staging Site
  Agent Mode: log

[INFO] Found 2 site(s)
```

### Export Whitelist

Export all whitelisted IPs from a site:

```bash
./exports/fastly-export.sh --whitelist mycorp production
```

Output:
```
[INFO] ==============================================
[INFO]   Fastly Whitelist Export
[INFO] ==============================================
[INFO] 
[INFO] Corp: mycorp
[INFO] Site: production
[INFO] Output: fastly_ips.csv
[INFO] 
[INFO] Found 25 whitelist entries
[INFO] 
[INFO] ==============================================
[INFO]   Export Summary
[INFO] ==============================================
[INFO] 
[INFO]   IPs exported: 25
[INFO]   Time elapsed: 1s
[INFO]   Output file:  fastly_ips.csv
[INFO] 
[INFO] First 5 entries:
"192.0.2.1","Payment Gateway","whitelist","2024-01-15T10:30:00Z"
"10.0.0.0/8","Internal Network","whitelist","2024-01-10T14:20:00Z"
```

### Export Blacklist

Export all blacklisted IPs from a site:

```bash
./exports/fastly-export.sh --blacklist mycorp production
```

### List Corp-Level Lists

```bash
./exports/fastly-export.sh --list-corp-lists mycorp
```

Output:
```
[INFO] Fetching corp-level lists in: mycorp

==============================================
  Corp Lists in: mycorp
==============================================

ID: vendor-ips
  Name: Vendor IPs
  Type: ip
  Description: Trusted vendor IP addresses
  Entries: 50

ID: blocked-countries
  Name: Blocked Countries
  Type: country
  Description: Countries to block
  Entries: 5

[INFO] Found 2 list(s) total (1 IP lists)
```

### Export Corp List

```bash
./exports/fastly-export.sh --corp-list mycorp vendor-ips
```

### List Site-Level Lists

```bash
./exports/fastly-export.sh --list-site-lists mycorp production
```

### Export Site List

```bash
./exports/fastly-export.sh --site-list mycorp production site-specific-ips
```

## Fastly NGWAF Commands

### List Account Lists

```bash
./exports/fastly-export.sh --account-lists
```

### Export Account List

```bash
./exports/fastly-export.sh --account-list list_abc123def456
```

### List Workspace Lists

```bash
./exports/fastly-export.sh --workspace-lists ws_abc123def456
```

### Export Workspace List

```bash
./exports/fastly-export.sh --workspace-list ws_abc123def456 list_xyz789
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SIGSCI_EMAIL` | For Signal Sciences | - | User email for authentication |
| `SIGSCI_TOKEN` | For Signal Sciences | - | Personal API access token |
| `FASTLY_API_TOKEN` | For Fastly NGWAF | - | Fastly API token |
| `OUTPUT_FILE` | No | `fastly_ips.csv` | Output CSV file path |
| `DRY_RUN` | No | `false` | Set to `true` for preview mode |
| `DEBUG` | No | `false` | Set to `true` for verbose output |
| `AUDIT_LOG` | No | - | Path to audit log file |

## Output Format

The script outputs CSV with these columns:

```csv
ip,notes,mode,created_on
"192.0.2.1","Vendor IPs - Trusted vendors","whitelist","2024-01-15T10:30:00Z"
"10.0.0.0/8","Internal Network","whitelist","2024-01-10T14:20:00Z"
```

| Column | Description |
|--------|-------------|
| `ip` | IP address or CIDR range |
| `notes` | Source list name and description |
| `mode` | Original mode in source system (whitelist/blacklist/list) |
| `created_on` | Timestamp when entry was created |

This format is directly compatible with `vercel-bulk-waf-rules.sh`.

## API Endpoints Used

### Signal Sciences API

| Operation | Endpoint |
|-----------|----------|
| List corps | `GET /corps` |
| List sites | `GET /corps/{corp}/sites` |
| Get whitelist | `GET /corps/{corp}/sites/{site}/whitelist` |
| Get blacklist | `GET /corps/{corp}/sites/{site}/blacklist` |
| List corp lists | `GET /corps/{corp}/lists` |
| Get corp list | `GET /corps/{corp}/lists/{list_id}` |
| List site lists | `GET /corps/{corp}/sites/{site}/lists` |
| Get site list | `GET /corps/{corp}/sites/{site}/lists/{list_id}` |

### Fastly NGWAF API

| Operation | Endpoint |
|-----------|----------|
| List account lists | `GET /ngwaf/v1/lists` |
| Get account list | `GET /ngwaf/v1/lists/{list_id}` |
| List workspace lists | `GET /ngwaf/v1/workspaces/{workspace_id}/lists` |
| Get workspace list | `GET /ngwaf/v1/workspaces/{workspace_id}/lists/{list_id}` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Missing dependencies (curl, jq) |
| 2 | Missing credentials |
| 3 | Invalid credentials |
| 4 | API error (non-retryable) |
| 5 | Rate limited (after max retries) |
| 6 | Invalid arguments |
| 7 | File I/O error |
| 8 | Network error |

## Migration Workflow

Complete workflow to migrate WAF IP rules from Fastly to Vercel:

```bash
# Step 1: Set credentials (Signal Sciences example)
export SIGSCI_EMAIL="your-email@example.com"
export SIGSCI_TOKEN="your-api-token"

# Step 2: Explore available resources
./exports/fastly-export.sh --list-corps
./exports/fastly-export.sh --list-sites mycorp
./exports/fastly-export.sh --list-corp-lists mycorp

# Step 3: Export the whitelist
./exports/fastly-export.sh --whitelist mycorp production

# Step 4: Preview import to Vercel
DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply fastly_ips.csv

# Step 5: Apply to Vercel
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply fastly_ips.csv
```

**Choose your Vercel mode based on your use case:**
- `RULE_MODE=deny` - Block all traffic EXCEPT from these IPs (private apps)
- `RULE_MODE=bypass` - Skip WAF for these IPs (vendor integrations)

## Debugging

```bash
# Enable debug mode for verbose output
DEBUG=true ./exports/fastly-export.sh --list-corps

# Enable audit logging
AUDIT_LOG="./fastly-export.log" ./exports/fastly-export.sh --whitelist mycorp production

# Dry run to preview without writing files
DRY_RUN=true ./exports/fastly-export.sh --whitelist mycorp production
```

## Error Handling

The script includes:

- **Automatic retry**: Up to 3 retries with exponential backoff
- **Rate limit handling**: Automatic 60s backoff on HTTP 429
- **Credential redaction**: Credentials are never logged, even in debug mode
- **TLS verification**: All requests use verified TLS 1.2+

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `No credentials found` | Missing env vars | Set `SIGSCI_EMAIL`/`SIGSCI_TOKEN` or `FASTLY_API_TOKEN` |
| `HTTP 401` | Invalid credentials | Regenerate API token |
| `HTTP 403` | Insufficient permissions | Check token has read access |
| `HTTP 404` | Invalid corp/site/list | Use `--list-*` commands to find valid IDs |
| `HTTP 429` | Rate limited | Script auto-retries; wait if persistent |
| `List type is 'country', not 'ip'` | Non-IP list selected | Only IP lists can be exported |

### Verify Credentials

```bash
# Test Signal Sciences credentials
DEBUG=true ./exports/fastly-export.sh --list-corps

# Test Fastly NGWAF credentials
DEBUG=true ./exports/fastly-export.sh --account-lists
```

## Security Best Practices

1. **Never commit credentials to version control** - Use environment variables or secrets manager
2. **Use read-only tokens** - Create tokens with minimal permissions
3. **Rotate credentials regularly** - Especially after team member departures
4. **Enable audit logging** - Track all export operations with `AUDIT_LOG`
5. **Limit token distribution** - Don't share personal tokens

### CI/CD Setup

For CI/CD pipelines, set credentials as secrets:

```bash
# GitHub Actions example
export SIGSCI_EMAIL="${{ secrets.SIGSCI_EMAIL }}"
export SIGSCI_TOKEN="${{ secrets.SIGSCI_TOKEN }}"
./exports/fastly-export.sh --whitelist mycorp production
```

Store credentials as separate secrets in your CI/CD system:
- `SIGSCI_EMAIL`
- `SIGSCI_TOKEN`
- Or: `FASTLY_API_TOKEN`

## Data Sources Comparison

| Source | Signal Sciences API | Fastly NGWAF API |
|--------|---------------------|------------------|
| Site whitelist | `--whitelist` | N/A |
| Site blacklist | `--blacklist` | N/A |
| Corp lists | `--corp-list` | N/A |
| Site lists | `--site-list` | N/A |
| Account lists | N/A | `--account-list` |
| Workspace lists | N/A | `--workspace-list` |

Use Signal Sciences API for site-specific whitelists/blacklists. Use Fastly NGWAF API for account-wide or workspace-specific lists.
