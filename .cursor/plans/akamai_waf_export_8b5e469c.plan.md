---
name: Akamai WAF Export
overview: Create an Akamai WAF rules export script that extracts IP allowlists from Network Lists and Application Security configurations, outputting CSV compatible with the Vercel bulk WAF import. Also refactor documentation into separate markdown files per provider.
todos:
  - id: create-akamai-script
    content: Create akamai-export.sh script with Network Lists and Security Config export functionality using pure bash EdgeGrid authentication
    status: pending
  - id: create-docs-folder
    content: Create docs/ folder and split README into cloudflare-export.md, akamai-export.md, vercel-credentials.md, ci-cd-integration.md
    status: pending
  - id: update-main-readme
    content: Update main README.md with simplified structure linking to docs/
    status: pending
  - id: add-akamai-docs
    content: Write comprehensive Akamai export documentation including credentials setup, API permissions, and usage examples
    status: pending
isProject: false
---

# Akamai WAF Rules Export to Vercel

## Overview

Create `akamai-export.sh` to export IP allowlists from Akamai to CSV format compatible with Vercel Firewall import. Akamai has two main sources for IP allowlists:

1. **Network Lists API** - Shared IP/CIDR lists used across security products (Kona Site Defender, Web App Protector, App & API Protector, Bot Manager)
2. **Application Security API** - Custom WAF rules and security configurations with IP match conditions

## Research Findings Summary

### Authentication Options (Best Practice Analysis)


| Option | Tool              | Pros                                             | Cons                                | Recommendation             |
| ------ | ----------------- | ------------------------------------------------ | ----------------------------------- | -------------------------- |
| A      | `httpie-edgegrid` | Akamai's recommended modern tool, simpler syntax | Python dependency, httpie required  | Good for interactive use   |
| B      | `egcurl`          | Python wrapper around curl, well-documented      | Python dependency                   | Good but being phased out  |
| C      | Pure Bash         | No Python dependency, faster execution           | Complex HMAC-SHA-256 implementation | Best for portability       |
| D      | Akamai CLI        | Official CLI, installable packages               | Heavy dependency, Go-based          | Best for complex workflows |


**Decision: Use Option C (Pure Bash)** - Matches the existing `cloudflare-export.sh` pattern, avoids Python dependency, and provides maximum portability. Implementation is complex but achievable using `openssl` for HMAC-SHA-256 signing.

### Rate Limits (Critical for Performance)


| API                      | Rate Limit                           | Notes                                   |
| ------------------------ | ------------------------------------ | --------------------------------------- |
| Network Lists API        | Standard (not explicitly documented) | Use 100ms delay between requests        |
| Application Security API | 100 requests/min per account         | All clients in account counted together |
| AppSec Export endpoint   | 3 requests/min                       | Much more restrictive                   |


**Headers to monitor:**

- `X-RateLimit-Limit` - Maximum requests allowed
- `X-RateLimit-Remaining` - Requests remaining in window
- `X-Ids-Session-Id` - Session identifier

### API Response Formats (Verified via context7)

**Network Lists - List All:**

```json
{
  "networkLists": [
    {
      "uniqueId": "38069_INTERNALWHITELIST",
      "name": "My Network List",
      "type": "IP",
      "elementCount": 2
    }
  ]
}
```

**Network Lists - Get Single List (with elements):**

```json
{
  "uniqueId": "38069_INTERNALWHITELIST",
  "name": "My Network List",
  "type": "IP",
  "list": [
    "192.0.2.193/24",
    "192.0.2.75"
  ]
}
```

**Application Security - IP Match Conditions:**

```json
{
  "conditions": [
    {
      "ips": ["192.0.2.34", "10.0.0.0/8"],
      "positiveMatch": true,
      "type": "ipMatch",
      "useHeaders": false
    }
  ]
}
```

## Detailed Implementation Guide

### File Structure After Implementation

```
vercel-bulk-waf-rules-scripts/
├── akamai-export.sh              # NEW: Akamai export script
├── cloudflare-export.sh          # Existing
├── vercel-bulk-waf-rules.sh      # Existing
├── rollback.sh                   # Existing
├── docs/
│   ├── akamai-export.md          # NEW: Akamai documentation
│   ├── cloudflare-export.md      # NEW: Extracted from README
│   ├── vercel-credentials.md     # NEW: Extracted from README
│   └── ci-cd-integration.md      # NEW: Extracted from README
├── examples/
│   └── github-action.yml         # Existing
├── tests/                        # Existing
└── README.md                     # Updated with links to docs/
```

### akamai-export.sh - Complete Implementation Specification

#### Script Header & Constants

```bash
#!/bin/bash
# =============================================================================
# Akamai IP Allowlist Export Script
# =============================================================================
#
# Exports IP addresses from Akamai Network Lists or Application Security
# configurations to CSV format compatible with Vercel Firewall bypass import.
#
# IMPORTANT:
# - Requires Akamai EdgeGrid credentials in ~/.edgerc file
# - Create API client at: https://control.akamai.com/apps/identity-management
# - Required permissions: Network Lists API READ, Application Security API READ
#
# Usage:
#   ./akamai-export.sh --list-all                          List all network lists
#   ./akamai-export.sh --network-list <listId>             Export specific list
#   ./akamai-export.sh --security-config <configId>        Export IP rules from config
#   ./akamai-export.sh --help                              Show help
#
# Environment variables:
#   AKAMAI_EDGERC (optional): Path to .edgerc file (default: ~/.edgerc)
#   AKAMAI_SECTION (optional): Section in .edgerc (default: default)
#   OUTPUT_FILE (optional): Output CSV file path (default: akamai_ips.csv)
#   DRY_RUN (optional): Set to "true" for preview mode
#   DEBUG (optional): Set to "true" for verbose output
#   AUDIT_LOG (optional): Path to audit log file
#
# =============================================================================

set -euo pipefail

# Constants
readonly SCRIPT_VERSION="1.0.0"
readonly DEFAULT_EDGERC="$HOME/.edgerc"
readonly DEFAULT_SECTION="default"
readonly RATE_LIMIT_DELAY_MS=100
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly INITIAL_RETRY_DELAY=2

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_MISSING_DEPS=1
readonly EXIT_MISSING_CREDENTIALS=2
readonly EXIT_INVALID_CREDENTIALS=3
readonly EXIT_API_ERROR=4
readonly EXIT_RATE_LIMITED=5
readonly EXIT_INVALID_ARGS=6
readonly EXIT_FILE_ERROR=7
readonly EXIT_NETWORK_ERROR=8
```

#### EdgeGrid Authentication Implementation (Pure Bash)

```bash
# =============================================================================
# EdgeGrid Authentication (Pure Bash Implementation)
# =============================================================================
# 
# Implements Akamai EdgeGrid HMAC-SHA-256 authentication without Python.
# Reference: https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid
#
# The signing algorithm:
# 1. Create signing key: HMAC-SHA256(client_secret, timestamp)
# 2. Create content hash: SHA256(request_body) for POST/PUT, empty for GET
# 3. Create data to sign: method\tscheme\thost\tpath\tquery_params\tcontent_hash\tauth_header
# 4. Create signature: HMAC-SHA256(signing_key, data_to_sign)
# =============================================================================

# Parse .edgerc file and extract credentials
parse_edgerc() {
  local edgerc_path="${AKAMAI_EDGERC:-$DEFAULT_EDGERC}"
  local section="${AKAMAI_SECTION:-$DEFAULT_SECTION}"
  
  if [ ! -f "$edgerc_path" ]; then
    log_error ".edgerc file not found: $edgerc_path"
    log_error ""
    log_error "Create your Akamai API credentials:"
    log_error "  1. Go to: https://control.akamai.com/apps/identity-management"
    log_error "  2. Create API client with Network Lists API READ access"
    log_error "  3. Download .edgerc file to: ~/.edgerc"
    exit $EXIT_MISSING_CREDENTIALS
  fi
  
  # Parse the section from .edgerc
  local in_section=false
  while IFS= read -r line || [ -n "$line" ]; do
    # Check for section header
    if [[ "$line" =~ ^\[([a-zA-Z0-9_-]+)\]$ ]]; then
      if [ "${BASH_REMATCH[1]}" = "$section" ]; then
        in_section=true
      else
        in_section=false
      fi
      continue
    fi
    
    # Parse key-value pairs in our section
    if [ "$in_section" = true ] && [[ "$line" =~ ^([a-z_]+)[[:space:]]*=[[:space:]]*(.+)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local value="${BASH_REMATCH[2]}"
      # Trim whitespace
      value="${value#"${value%%[![:space:]]*}"}"
      value="${value%"${value##*[![:space:]]}"}"
      
      case "$key" in
        client_secret) AKAMAI_CLIENT_SECRET="$value" ;;
        host) AKAMAI_HOST="$value" ;;
        access_token) AKAMAI_ACCESS_TOKEN="$value" ;;
        client_token) AKAMAI_CLIENT_TOKEN="$value" ;;
        max_body) AKAMAI_MAX_BODY="$value" ;;
      esac
    fi
  done < "$edgerc_path"
  
  # Validate required fields
  if [ -z "${AKAMAI_CLIENT_SECRET:-}" ] || [ -z "${AKAMAI_HOST:-}" ] || \
     [ -z "${AKAMAI_ACCESS_TOKEN:-}" ] || [ -z "${AKAMAI_CLIENT_TOKEN:-}" ]; then
    log_error "Incomplete credentials in .edgerc section [$section]"
    log_error "Required fields: client_secret, host, access_token, client_token"
    exit $EXIT_INVALID_CREDENTIALS
  fi
  
  log_debug "Loaded credentials from .edgerc section [$section]"
  log_debug "Host: $AKAMAI_HOST"
}

# Generate UUID v4 for nonce (pure bash)
generate_uuid() {
  # Use /dev/urandom for randomness
  local hex
  hex=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "4${hex:13:3}" \
    "$(printf '%x' $((0x${hex:16:2} & 0x3f | 0x80)))${hex:18:2}" \
    "${hex:20:12}"
}

# Generate EdgeGrid timestamp (format: 20240115T10:30:00+0000)
generate_timestamp() {
  date -u +"%Y%m%dT%H:%M:%S+0000"
}

# HMAC-SHA256 using openssl
hmac_sha256() {
  local key="$1"
  local data="$2"
  printf '%s' "$data" | openssl dgst -sha256 -hmac "$key" -binary | openssl base64 -e -A
}

# SHA256 hash using openssl
sha256_hash() {
  local data="$1"
  printf '%s' "$data" | openssl dgst -sha256 -binary | openssl base64 -e -A
}

# Create EdgeGrid authorization header
create_auth_header() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  
  local timestamp
  timestamp=$(generate_timestamp)
  local nonce
  nonce=$(generate_uuid)
  
  # Create signing key: HMAC-SHA256(client_secret, timestamp)
  local signing_key
  signing_key=$(hmac_sha256 "$AKAMAI_CLIENT_SECRET" "$timestamp")
  
  # Content hash (SHA256 of body for POST/PUT, empty string for GET)
  local content_hash=""
  if [ -n "$body" ] && [ "$method" != "GET" ]; then
    content_hash=$(sha256_hash "$body")
  fi
  
  # Build auth header prefix
  local auth_header="EG1-HMAC-SHA256 client_token=${AKAMAI_CLIENT_TOKEN};access_token=${AKAMAI_ACCESS_TOKEN};timestamp=${timestamp};nonce=${nonce};"
  
  # Build data to sign (tab-separated)
  # Format: method\tscheme\thost\tpath\tquery\tcontent_hash\tauth_header
  local data_to_sign
  data_to_sign=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
    "$method" "https" "$AKAMAI_HOST" "$path" "" "$content_hash" "$auth_header")
  
  # Create signature
  local signature
  signature=$(hmac_sha256 "$signing_key" "$data_to_sign")
  
  # Return complete auth header
  echo "${auth_header}signature=${signature}"
}

# Make authenticated API request
akamai_api_request() {
  local method="$1"
  local endpoint="$2"
  local body="${3:-}"
  local attempt=1
  local delay=$INITIAL_RETRY_DELAY
  
  local url="https://${AKAMAI_HOST}${endpoint}"
  log_debug "API request: $method $url"
  
  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    # Generate fresh auth header for each attempt
    local auth_header
    auth_header=$(create_auth_header "$method" "$endpoint" "$body")
    
    # Build curl command
    local -a curl_args=(
      -s
      --proto '=https' --tlsv1.2
      -w "\n%{http_code}"
      -X "$method"
      -H "Authorization: $auth_header"
      -H "Accept: application/json"
      -H "Content-Type: application/json"
    )
    
    if [ -n "$body" ]; then
      curl_args+=(-d "$body")
    fi
    
    curl_args+=("$url")
    
    local response
    response=$(curl "${curl_args[@]}" 2>&1) || {
      log_error "Network error on attempt $attempt/$MAX_RETRIES"
      if [ "$attempt" -lt "$MAX_RETRIES" ]; then
        log_warn "Retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
        ((attempt++))
        continue
      fi
      return 1
    }
    
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body_response
    body_response=$(echo "$response" | sed '$d')
    
    log_debug "Response code: $http_code"
    
    # Handle rate limiting (429)
    if [ "$http_code" = "429" ]; then
      log_warn "Rate limited (HTTP 429). Waiting ${RATE_LIMIT_BACKOFF_SEC}s... (attempt $attempt/$MAX_RETRIES)"
      sleep "$RATE_LIMIT_BACKOFF_SEC"
      ((attempt++))
      continue
    fi
    
    # Handle server errors (5xx)
    if [ "$http_code" -ge 500 ] 2>/dev/null; then
      log_warn "Server error (HTTP $http_code) on attempt $attempt/$MAX_RETRIES"
      if [ "$attempt" -lt "$MAX_RETRIES" ]; then
        sleep "$delay"
        delay=$((delay * 2))
        ((attempt++))
        continue
      fi
      return 1
    fi
    
    # Handle client errors (4xx)
    if [ "$http_code" -ge 400 ] 2>/dev/null && [ "$http_code" != "429" ]; then
      log_error "API error (HTTP $http_code)"
      log_error "Endpoint: $endpoint"
      echo "$body_response" | jq '.' 2>/dev/null || echo "$body_response"
      return 1
    fi
    
    # Success - add rate limit delay
    sleep "$(echo "scale=3; $RATE_LIMIT_DELAY_MS / 1000" | bc)"
    
    echo "$body_response"
    echo "$http_code"
    return 0
  done
  
  return 1
}
```

#### Network Lists Export Functions

```bash
# =============================================================================
# Network Lists API Functions
# =============================================================================

# List all network lists (IP type only)
list_network_lists() {
  log_info "Fetching all network lists..."
  
  local response
  if ! response=$(akamai_api_request "GET" "/network-list/v2/network-lists?listType=IP&includeElements=false"); then
    log_error "Failed to fetch network lists"
    return 1
  fi
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" != "200" ]; then
    log_error "API returned HTTP $http_code"
    return 1
  fi
  
  # Display network lists
  echo ""
  echo "=============================================="
  echo "  Available Network Lists (IP type)"
  echo "=============================================="
  echo ""
  
  echo "$body" | jq -r '.networkLists[] | "ID: \(.uniqueId)\n  Name: \(.name)\n  Elements: \(.elementCount)\n  Updated: \(.updateDate // "N/A")\n"'
  
  local count
  count=$(echo "$body" | jq '.networkLists | length')
  
  echo ""
  log_info "Found $count IP network list(s)"
  echo ""
  log_info "To export a list, run:"
  echo "  ./akamai-export.sh --network-list <uniqueId>"
}

# Export a specific network list
export_network_list() {
  local list_id="$1"
  local output_file="${OUTPUT_FILE:-akamai_ips.csv}"
  
  log_info "=============================================="
  log_info "  Akamai Network List Export"
  log_info "=============================================="
  log_info ""
  log_info "List ID:     $list_id"
  log_info "Output file: $output_file"
  log_info ""
  
  audit_log "EXPORT_START" "list_id=$list_id output=$output_file"
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export Network List: $list_id"
    log_info "Would write to: $output_file"
    return 0
  fi
  
  # Fetch the network list with elements
  local response
  if ! response=$(akamai_api_request "GET" "/network-list/v2/network-lists/${list_id}?includeElements=true"); then
    log_error "Failed to fetch network list: $list_id"
    return 1
  fi
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" != "200" ]; then
    log_error "API returned HTTP $http_code"
    if [ "$http_code" = "404" ]; then
      log_error "Network list not found: $list_id"
      log_error "Use --list-all to see available lists"
    fi
    return 1
  fi
  
  # Extract list metadata
  local list_name
  list_name=$(echo "$body" | jq -r '.name // "Unknown"')
  local list_type
  list_type=$(echo "$body" | jq -r '.type // "IP"')
  local element_count
  element_count=$(echo "$body" | jq -r '.elementCount // 0')
  local update_date
  update_date=$(echo "$body" | jq -r '.updateDate // "N/A"')
  
  log_info "List name:    $list_name"
  log_info "List type:    $list_type"
  log_info "Element count: $element_count"
  log_info "Last updated: $update_date"
  log_info ""
  
  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    exit $EXIT_FILE_ERROR
  fi
  
  # Extract and format IPs
  local ips
  ips=$(echo "$body" | jq -r '.list[]' 2>/dev/null)
  
  local exported_count=0
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    # Escape any commas in the list name for CSV
    local safe_name
    safe_name=$(echo "$list_name" | sed 's/,/;/g')
    echo "\"$ip\",\"$safe_name\",\"whitelist\",\"$update_date\"" >> "$output_file"
    ((exported_count++))
  done <<< "$ips"
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  List name:        $list_name"
  log_info "  IPs exported:     $exported_count"
  log_info "  Output file:      $output_file"
  log_info ""
  
  # Show sample
  if [ "$exported_count" -gt 0 ]; then
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
  fi
  
  audit_log "EXPORT_COMPLETE" "list_id=$list_id list_name=$list_name ips=$exported_count"
}
```

#### Application Security Export (Optional/Advanced)

```bash
# =============================================================================
# Application Security API Functions (Advanced)
# =============================================================================
# Rate limit: 100 requests/min, export endpoint: 3 requests/min

export_security_config() {
  local config_id="$1"
  local version="${2:-latest}"
  local output_file="${OUTPUT_FILE:-akamai_ips.csv}"
  
  log_info "=============================================="
  log_info "  Akamai Security Config Export"
  log_info "=============================================="
  log_info ""
  log_info "Config ID:   $config_id"
  log_info "Version:     $version"
  log_info "Output file: $output_file"
  log_info ""
  
  log_warn "Note: AppSec export is rate-limited to 3 requests/min"
  
  # If version is "latest", we need to fetch the latest version first
  if [ "$version" = "latest" ]; then
    log_info "Fetching latest version number..."
    local versions_response
    if ! versions_response=$(akamai_api_request "GET" "/appsec/v1/configs/${config_id}/versions?page=1&pageSize=1"); then
      log_error "Failed to fetch config versions"
      return 1
    fi
    
    local versions_http
    versions_http=$(echo "$versions_response" | tail -n1)
    local versions_body
    versions_body=$(echo "$versions_response" | sed '$d')
    
    version=$(echo "$versions_body" | jq -r '.versions[0].version // empty')
    if [ -z "$version" ]; then
      log_error "Could not determine latest version"
      return 1
    fi
    log_info "Latest version: $version"
  fi
  
  # Export the configuration
  log_info "Exporting security configuration..."
  local response
  if ! response=$(akamai_api_request "GET" "/appsec/v1/export/configs/${config_id}/versions/${version}"); then
    log_error "Failed to export security config"
    return 1
  fi
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" != "200" ]; then
    log_error "API returned HTTP $http_code"
    return 1
  fi
  
  # Extract IP addresses from various locations in the config
  # 1. Custom rules with ipMatch conditions
  # 2. Security policy exceptions with IP conditions
  
  log_info "Parsing IP addresses from configuration..."
  
  # Write CSV header
  echo "ip,notes,mode,created_on" > "$output_file"
  
  local exported_count=0
  local config_name
  config_name=$(echo "$body" | jq -r '.configName // "Security Config"')
  
  # Extract from custom rules
  local custom_rule_ips
  custom_rule_ips=$(echo "$body" | jq -r '
    .customRules[]? | 
    .conditions[]? | 
    select(.type == "ipMatch") | 
    .value[]?' 2>/dev/null)
  
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    echo "\"$ip\",\"$config_name - Custom Rule\",\"whitelist\",\"\"" >> "$output_file"
    ((exported_count++))
  done <<< "$custom_rule_ips"
  
  # Extract from security policy exceptions
  local exception_ips
  exception_ips=$(echo "$body" | jq -r '
    .. | 
    .advancedExceptions?.conditions[]? | 
    select(.type == "ipMatch") | 
    .ips[]?' 2>/dev/null)
  
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    echo "\"$ip\",\"$config_name - Exception\",\"whitelist\",\"\"" >> "$output_file"
    ((exported_count++))
  done <<< "$exception_ips"
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  Config name:      $config_name"
  log_info "  Version:          $version"
  log_info "  IPs exported:     $exported_count"
  log_info "  Output file:      $output_file"
  log_info ""
  
  if [ "$exported_count" -eq 0 ]; then
    log_warn "No IP addresses found in this configuration"
    log_warn "IP addresses may be in Network Lists instead"
    log_warn "Run: ./akamai-export.sh --list-all"
  fi
}
```

#### Dependency Check & Main Function

```bash
# =============================================================================
# Dependency Check
# =============================================================================

check_dependencies() {
  local missing=()
  
  if ! command -v curl &> /dev/null; then
    missing+=("curl")
  fi
  
  if ! command -v jq &> /dev/null; then
    missing+=("jq")
  fi
  
  if ! command -v openssl &> /dev/null; then
    missing+=("openssl")
  fi
  
  if ! command -v bc &> /dev/null; then
    missing+=("bc")
  fi
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required dependencies: ${missing[*]}"
    log_error ""
    log_error "Installation:"
    log_error "  macOS:  brew install ${missing[*]}"
    log_error "  Ubuntu: sudo apt-get install ${missing[*]}"
    exit $EXIT_MISSING_DEPS
  fi
  
  log_debug "Dependencies check passed: curl, jq, openssl, bc"
}

# =============================================================================
# Main
# =============================================================================

main() {
  check_dependencies
  
  if [ $# -eq 0 ]; then
    show_usage
    exit $EXIT_INVALID_ARGS
  fi
  
  case "${1:-}" in
    --help|-h)
      show_usage
      exit $EXIT_SUCCESS
      ;;
    --list-all)
      parse_edgerc
      list_network_lists
      ;;
    --network-list)
      if [ -z "${2:-}" ]; then
        log_error "Network list ID required"
        log_error "Usage: $0 --network-list <listId>"
        exit $EXIT_INVALID_ARGS
      fi
      parse_edgerc
      export_network_list "$2"
      ;;
    --security-config)
      if [ -z "${2:-}" ]; then
        log_error "Security config ID required"
        log_error "Usage: $0 --security-config <configId> [version]"
        exit $EXIT_INVALID_ARGS
      fi
      parse_edgerc
      export_security_config "$2" "${3:-latest}"
      ;;
    *)
      log_error "Unknown option: $1"
      show_usage
      exit $EXIT_INVALID_ARGS
      ;;
  esac
}

main "$@"
```

## Security Best Practices

### Credential Storage

1. **Never commit `.edgerc` to version control** - Add to `.gitignore`
2. **Use minimal permissions** - Create API client with only READ access to Network Lists
3. **Rotate credentials regularly** - Especially after team member departures
4. **Use separate credentials for CI/CD** - Don't reuse personal credentials

### CI/CD Security

For CI/CD pipelines, use environment variables with a secrets manager:

```bash
# Store in GitHub Secrets, GitLab CI Variables, etc.
# Then create .edgerc dynamically:

cat > ~/.edgerc << EOF
[default]
client_secret = $AKAMAI_CLIENT_SECRET
host = $AKAMAI_HOST
access_token = $AKAMAI_ACCESS_TOKEN
client_token = $AKAMAI_CLIENT_TOKEN
EOF
chmod 600 ~/.edgerc
```

**Important:** Environment variables for credentials are acceptable in CI/CD when injected from a secrets manager. The concern is storing them directly in code or config files.

## Performance Optimization

1. **Rate limit awareness** - 100ms delay between requests for Network Lists
2. **Batch operations** - Export all lists in one session to minimize overhead
3. **Use `includeElements=false**` when listing to reduce response size
4. **Cache list IDs** - No need to re-fetch list of lists each time

## Documentation Structure

### docs/akamai-export.md

Complete documentation including:

- Prerequisites and installation
- Creating Akamai API credentials step-by-step
- .edgerc file format and security
- All commands with examples
- Troubleshooting guide
- Migration workflow from Akamai to Vercel

### docs/cloudflare-export.md

Extract existing Cloudflare documentation from README.md

### docs/vercel-credentials.md

Extract Vercel credentials setup section from README.md

### docs/ci-cd-integration.md

Extract and expand CI/CD section with examples for:

- GitHub Actions
- GitLab CI
- CircleCI
- Generic CI/CD

## Testing Strategy

Create test files in `tests/`:

- Mock `.edgerc` file for testing
- Expected output verification
- Error handling tests

## Dependencies


| Dependency | Required For            | Install           | Notes             |
| ---------- | ----------------------- | ----------------- | ----------------- |
| `curl`     | HTTP requests           | Pre-installed     | With TLS 1.2+     |
| `jq`       | JSON parsing            | `brew install jq` | v1.6+             |
| `openssl`  | HMAC-SHA-256 signing    | Pre-installed     | For EdgeGrid auth |
| `bc`       | Rate limit calculations | Pre-installed     | Basic math        |


## Required Akamai API Permissions


| API                      | Permission      | Created At                                           |
| ------------------------ | --------------- | ---------------------------------------------------- |
| Network Lists API        | READ            | Akamai Control Center > Identity & Access Management |
| Application Security API | READ (optional) | Same location, for security config export            |


## Migration Workflow

```bash
# Step 1: Set up Akamai credentials
# Download .edgerc from Akamai Control Center

# Step 2: List available network lists
./akamai-export.sh --list-all

# Step 3: Export the desired list
./akamai-export.sh --network-list 38069_WHITELIST

# Step 4: Preview import to Vercel
DRY_RUN=true ./vercel-bulk-waf-rules.sh apply akamai_ips.csv

# Step 5: Apply to Vercel
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply akamai_ips.csv
```

