# Akamai WAF Export

The `exports/akamai-export.sh` script exports IP addresses and CIDR ranges from Akamai Network Lists or Application Security configurations to CSV format compatible with Vercel Firewall.

## Overview

This script extracts IP-based rules from Akamai's security products so you can migrate or sync them to Vercel. The exported IPs can be used with Vercel's WAF in **any mode**:

- **Deny mode**: Block all traffic except from exported IPs
- **Bypass mode**: Skip WAF checks for exported IPs
- **Any custom rule**: Use exported IPs as input for your own firewall logic

## Why Use This Script?

- **Pure Bash Implementation**: No Python dependency - uses `openssl` for EdgeGrid authentication
- **Network Lists API**: Export shared IP/CIDR lists used across Akamai security products (Kona Site Defender, Web App Protector, App & API Protector, Bot Manager)
- **Application Security API**: Extract IP match conditions from WAF rules and exceptions
- **Vercel-Compatible Output**: Exports to CSV format that works directly with `vercel-bulk-waf-rules.sh`
- **Robust Error Handling**: Automatic retry with exponential backoff, rate limit handling

## Prerequisites

### Dependencies

- `curl` - for API requests
- `jq` - for JSON parsing  
- `openssl` - for HMAC-SHA-256 signing (EdgeGrid authentication)
- `bc` - for rate limiting calculations (optional, falls back to 1s delays)

**Install on macOS:**

```bash
brew install jq  # curl and openssl are pre-installed
```

**Install on Ubuntu/Debian:**

```bash
sudo apt-get install curl jq openssl bc
```

### Akamai API Credentials

Create API credentials in Akamai Control Center:

1. Go to [Akamai Control Center](https://control.akamai.com)
2. Navigate to **Identity & Access Management** → **API Clients**
3. Click **Create API Client**
4. Grant the following API permissions:
   - **Network Lists API**: READ (required)
   - **Application Security API**: READ (optional, for `--security-config`)
5. Click **Download .edgerc** and save to `~/.edgerc`
6. Set secure permissions: `chmod 600 ~/.edgerc`

### .edgerc File Format

The `.edgerc` file contains your API credentials:

```ini
[default]
client_secret = your-client-secret-here
host = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net
access_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
client_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
```

You can have multiple sections for different environments:

```ini
[default]
client_secret = ...
host = ...
access_token = ...
client_token = ...

[production]
client_secret = ...
host = ...
access_token = ...
client_token = ...
```

Use `AKAMAI_SECTION=production` to select a specific section.

## Usage

### List All Network Lists

```bash
./exports/akamai-export.sh --list-all
```

Output:
```
[INFO] Fetching all network lists...

==============================================
  Available Network Lists (IP type)
==============================================

ID: 38069_INTERNALIPS
  Name: Internal Network IPs
  Elements: 150
  Type: IP
  Updated: 2024-01-15T10:30:00Z

ID: 45123_VENDORIPS
  Name: Vendor IPs
  Elements: 75
  Type: IP
  Updated: 2024-01-10T14:20:00Z

[INFO] Found 2 IP network list(s)

[INFO] To export a list, run:
  ./exports/akamai-export.sh --network-list <uniqueId>
```

### Export a Network List

```bash
./exports/akamai-export.sh --network-list 38069_INTERNALIPS
```

Output:
```
[INFO] ==============================================
[INFO]   Akamai Network List Export
[INFO] ==============================================
[INFO] 
[INFO] List ID:     38069_INTERNALIPS
[INFO] Output file: akamai_ips.csv
[INFO] 
[INFO] List name:     Internal Network IPs
[INFO] List type:     IP
[INFO] Element count: 150
[INFO] Last updated:  2024-01-15T10:30:00Z
[INFO] 
[INFO] ==============================================
[INFO]   Export Summary
[INFO] ==============================================
[INFO] 
[INFO]   List name:        Internal Network IPs
[INFO]   IPs exported:     150
[INFO]   Time elapsed:     2s
[INFO]   Output file:      akamai_ips.csv
[INFO] 
[INFO] First 5 entries:
"192.0.2.1","Internal Network IPs","whitelist","2024-01-15T10:30:00Z"
"192.0.2.2","Internal Network IPs","whitelist","2024-01-15T10:30:00Z"
"10.0.0.0/8","Internal Network IPs","whitelist","2024-01-15T10:30:00Z"
```

### Export from Security Config

For advanced users with IP conditions embedded in WAF rules:

```bash
./exports/akamai-export.sh --security-config 12345 latest
```

This extracts IPs from:
- Custom rules with `ipMatch` conditions
- Security policy exceptions with IP conditions

> **Note:** The AppSec export endpoint is heavily rate-limited (3 requests/min). Use Network Lists for bulk IP management.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AKAMAI_EDGERC` | No | `~/.edgerc` | Path to .edgerc credentials file |
| `AKAMAI_SECTION` | No | `default` | Section name in .edgerc file |
| `OUTPUT_FILE` | No | `akamai_ips.csv` | Output CSV file path |
| `DRY_RUN` | No | `false` | Set to `true` for preview mode |
| `DEBUG` | No | `false` | Set to `true` for verbose output |
| `AUDIT_LOG` | No | - | Path to audit log file |

## Output Format

The script outputs CSV with these columns:

```csv
ip,notes,mode,created_on
"192.0.2.1","Internal Network IPs","whitelist","2024-01-15T10:30:00Z"
"10.0.0.0/8","Internal Network IPs","whitelist","2024-01-15T10:30:00Z"
```

| Column | Description |
|--------|-------------|
| `ip` | IP address or CIDR range |
| `notes` | Source list name (for reference) |
| `mode` | Original mode in source system (informational) |
| `created_on` | Last update timestamp |

This format is directly compatible with `vercel-bulk-waf-rules.sh`. The `mode` column reflects the source system's classification and doesn't affect how you use the IPs in Vercel.

## API Endpoints Used

| Operation | Endpoint |
|-----------|----------|
| List network lists | `GET /network-list/v2/network-lists?listType=IP` |
| Get network list | `GET /network-list/v2/network-lists/{listId}?includeElements=true` |
| Export security config | `GET /appsec/v1/export/configs/{configId}/versions/{version}` |
| List config versions | `GET /appsec/v1/configs/{configId}/versions` |

## Rate Limits

| API | Rate Limit | Notes |
|-----|------------|-------|
| Network Lists API | Standard | 100ms delay between requests |
| Application Security API | 100 requests/min | Shared across all clients |
| AppSec Export endpoint | 3 requests/min | Much more restrictive |

The script automatically handles rate limiting with retry and backoff.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Missing dependencies (curl, jq, openssl) |
| 2 | Missing .edgerc credentials |
| 3 | Invalid credentials |
| 4 | API error (non-retryable) |
| 5 | Rate limited (after max retries) |
| 6 | Invalid arguments |
| 7 | File I/O error |
| 8 | Network error |

## Migration Workflow

Complete workflow to migrate WAF IP rules from Akamai to Vercel:

```bash
# Step 1: Set up Akamai credentials (one-time)
# Download .edgerc from Akamai Control Center
chmod 600 ~/.edgerc

# Step 2: List available network lists
./exports/akamai-export.sh --list-all

# Step 3: Export the desired list
./exports/akamai-export.sh --network-list 38069_VENDORIPS

# Step 4: Preview import to Vercel (choose your mode)
DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply akamai_ips.csv

# Step 5: Apply to Vercel
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply akamai_ips.csv
```

**Choose your Vercel mode based on your use case:**
- `RULE_MODE=deny` - Block all traffic EXCEPT from these IPs (private apps)
- `RULE_MODE=bypass` - Skip WAF for these IPs (vendor integrations)

## Debugging

```bash
# Enable debug mode for verbose output
DEBUG=true ./exports/akamai-export.sh --list-all

# Enable audit logging
AUDIT_LOG="./akamai-export.log" ./exports/akamai-export.sh --network-list 38069_VENDORIPS

# Dry run to preview without writing files
DRY_RUN=true ./exports/akamai-export.sh --network-list 38069_VENDORIPS
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `.edgerc file not found` | Missing credentials file | Download from Akamai Control Center |
| `Incomplete credentials in .edgerc` | Missing required fields | Ensure all 4 fields are present in section |
| `HTTP 401` | Invalid or expired credentials | Regenerate API client in Akamai Control Center |
| `HTTP 403` | Insufficient permissions | Add Network Lists API READ access to API client |
| `HTTP 404` | Invalid list ID | Use `--list-all` to find valid list IDs |
| `HTTP 429` | Rate limited | Script auto-retries; wait if persistent |

### Verify Credentials

Test your credentials manually:

```bash
# Check if .edgerc exists and has correct permissions
ls -la ~/.edgerc

# Verify section exists
grep '\[default\]' ~/.edgerc

# Test API access (requires the script's auth mechanism)
DEBUG=true ./exports/akamai-export.sh --list-all
```

## Security Best Practices

1. **Never commit `.edgerc` to version control** - Add to `.gitignore`
2. **Use minimal permissions** - Create API client with only READ access
3. **Secure file permissions** - `chmod 600 ~/.edgerc`
4. **Rotate credentials regularly** - Especially after team member departures
5. **Use separate credentials for CI/CD** - Don't reuse personal credentials

### CI/CD Setup

For CI/CD pipelines, create `.edgerc` dynamically from secrets:

```bash
# GitHub Actions / GitLab CI / etc.
cat > ~/.edgerc << EOF
[default]
client_secret = $AKAMAI_CLIENT_SECRET
host = $AKAMAI_HOST
access_token = $AKAMAI_ACCESS_TOKEN
client_token = $AKAMAI_CLIENT_TOKEN
EOF
chmod 600 ~/.edgerc
```

Store the individual values as secrets in your CI/CD system:
- `AKAMAI_CLIENT_SECRET`
- `AKAMAI_HOST`
- `AKAMAI_ACCESS_TOKEN`
- `AKAMAI_CLIENT_TOKEN`

## Network Lists vs Security Config

Akamai has two main sources for IP-based WAF rules:

| Source | Best For | API |
|--------|----------|-----|
| **Network Lists** | Shared IP lists used across products | Network Lists API v2 |
| **Security Config** | IPs embedded in WAF rules/exceptions | Application Security API |

Most organizations use **Network Lists** for centralized IP management. Use `--security-config` only if your IPs are embedded directly in custom rules rather than referenced from Network Lists.
