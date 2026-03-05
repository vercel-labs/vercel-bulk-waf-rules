---
name: Fastly WAF Export Integration
overview: Create a Fastly Next-Gen WAF export script supporting BOTH APIs (Signal Sciences legacy and Fastly NGWAF), with secure credential handling, comprehensive error handling, and performance optimization.
todos:
  - id: create-fastly-export-script
    content: Create exports/fastly-export.sh (~900 lines) with dual API support, secure credential handling, all export commands, rate limiting, and comprehensive error handling
    status: pending
  - id: create-fastly-docs
    content: Create docs/fastly-export.md (~350 lines) with comprehensive documentation including dual API setup, security best practices, and troubleshooting
    status: pending
  - id: update-readme
    content: Update README.md to add Fastly export references in Scripts table, Documentation table, and Migration section
    status: pending
isProject: false
---

# Fastly WAF Export to Vercel - Comprehensive Implementation Plan

## Executive Summary

This plan creates a production-ready export script for Fastly Next-Gen WAF (formerly Signal Sciences) that:

- Supports **both** Fastly APIs (legacy Signal Sciences and new Fastly NGWAF)
- Follows security best practices for credential handling
- Implements robust error handling with exponential backoff
- Optimizes performance with rate limiting and parallel-safe design
- Produces CSV output compatible with `vercel-bulk-waf-rules.sh`

---

## CRITICAL: Dual API Support

Fastly has **two separate APIs** depending on the customer's access method:

### 1. Signal Sciences API (Legacy - dashboard.signalsciences.net)


| Attribute      | Value                                            |
| -------------- | ------------------------------------------------ |
| Base URL       | `https://dashboard.signalsciences.net/api/v0`    |
| Auth Headers   | `x-api-user` (email) + `x-api-token` (API token) |
| Hierarchy      | Corp > Site                                      |
| Token Creation | My Profile > API access tokens                   |
| Token Limit    | 5 per person                                     |
| Use When       | Access via dashboard.signalsciences.net          |


**Endpoints:**

- `GET /corps` - List all corps
- `GET /corps/{corp}/sites` - List sites in corp
- `GET /corps/{corp}/sites/{site}/whitelist` - Get site whitelist
- `GET /corps/{corp}/sites/{site}/blacklist` - Get site blacklist
- `GET /corps/{corp}/lists` - Get corp-level lists
- `GET /corps/{corp}/sites/{site}/lists` - Get site-level lists

### 2. Fastly NGWAF API (New - api.fastly.com)


| Attribute      | Value                                    |
| -------------- | ---------------------------------------- |
| Base URL       | `https://api.fastly.com`                 |
| Auth Header    | `Fastly-Key: <token>` (NOT Bearer)       |
| Hierarchy      | Account > Workspace                      |
| Token Creation | manage.fastly.com > Account > API tokens |
| Token Scopes   | `global`, `global:read`, etc.            |
| Use When       | Access via manage.fastly.com             |


**Endpoints:**

- `GET /ngwaf/v1/lists` - List account-level lists
- `GET /ngwaf/v1/lists/{listId}` - Get specific account list
- `GET /ngwaf/v1/workspaces/{workspaceId}/lists` - List workspace lists
- `GET /ngwaf/v1/workspaces/{workspaceId}/lists/{listId}` - Get specific workspace list

---

## Security Best Practices (OWASP Compliant)

### Credential Handling

1. **Never pass credentials as command arguments** - visible in `ps` output
2. **Use environment variables** - but document they can be visible to other processes
3. **Support credential files** - with restricted permissions (600)
4. **Validate file permissions** - warn if credentials file is world-readable
5. **Never log credentials** - even in debug mode
6. **Use TLS 1.2+** - enforce with `--proto '=https' --tlsv1.2`

### Implementation Pattern

```bash
# Credential loading priority:
# 1. Environment variables (SIGSCI_EMAIL, SIGSCI_TOKEN or FASTLY_API_TOKEN)
# 2. Credentials file (~/.fastly/credentials or custom path)
# 3. Interactive prompt (if terminal attached)

load_credentials() {
  # Check environment variables first
  if [ -n "${SIGSCI_EMAIL:-}" ] && [ -n "${SIGSCI_TOKEN:-}" ]; then
    API_MODE="sigsci"
    return 0
  fi
  
  if [ -n "${FASTLY_API_TOKEN:-}" ]; then
    API_MODE="fastly"
    return 0
  fi
  
  # Try credentials file
  local creds_file="${FASTLY_CREDENTIALS:-$HOME/.fastly/credentials}"
  if [ -f "$creds_file" ]; then
    # Check permissions
    local perms
    perms=$(stat -f "%Lp" "$creds_file" 2>/dev/null || stat -c "%a" "$creds_file" 2>/dev/null)
    if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
      log_warn "Credentials file has insecure permissions ($perms). Run: chmod 600 $creds_file"
    fi
    # Parse file...
  fi
}
```

---

## Data Sources for Export

### Signal Sciences API Data Model


| Source     | Endpoint                                   | Response Structure                                                     |
| ---------- | ------------------------------------------ | ---------------------------------------------------------------------- |
| Whitelist  | `GET /corps/{corp}/sites/{site}/whitelist` | `{data: [{id, source, note, expires, createdBy, created}]}`            |
| Blacklist  | `GET /corps/{corp}/sites/{site}/blacklist` | `{data: [{id, source, note, expires, createdBy, created}]}`            |
| Corp Lists | `GET /corps/{corp}/lists`                  | `{data: [{id, name, type, description, entries[], created, updated}]}` |
| Site Lists | `GET /corps/{corp}/sites/{site}/lists`     | `{data: [{id, name, type, description, entries[], created, updated}]}` |


### Fastly NGWAF API Data Model


| Source          | Endpoint                              | Response Structure                                                          |
| --------------- | ------------------------------------- | --------------------------------------------------------------------------- |
| Account Lists   | `GET /ngwaf/v1/lists`                 | `[{id, name, type, description, entries[], scope, created_at, updated_at}]` |
| Workspace Lists | `GET /ngwaf/v1/workspaces/{id}/lists` | `[{id, name, type, description, entries[], created_at, updated_at}]`        |


**List Types (both APIs):** `ip`, `string`, `country`, `wildcard`, `signal`

---

## Detailed Implementation Guide

### File 1: exports/fastly-export.sh (~900 lines)

```bash
#!/bin/bash
# =============================================================================
# Fastly Next-Gen WAF Export Script
# =============================================================================
#
# Exports IP addresses from Fastly Next-Gen WAF (Signal Sciences) to CSV format
# compatible with Vercel Firewall.
#
# SUPPORTS TWO APIs:
#   1. Signal Sciences API (dashboard.signalsciences.net) - uses SIGSCI_EMAIL/SIGSCI_TOKEN
#   2. Fastly NGWAF API (api.fastly.com) - uses FASTLY_API_TOKEN
#
# The script auto-detects which API to use based on provided credentials.
#
# Usage:
#   # Signal Sciences API
#   export SIGSCI_EMAIL="user@example.com"
#   export SIGSCI_TOKEN="your-api-token"
#   ./fastly-export.sh --whitelist <corp> <site>
#   ./fastly-export.sh --blacklist <corp> <site>
#   ./fastly-export.sh --corp-list <corp> <list_id>
#   ./fastly-export.sh --site-list <corp> <site> <list_id>
#   ./fastly-export.sh --list-corps
#   ./fastly-export.sh --list-sites <corp>
#   ./fastly-export.sh --list-corp-lists <corp>
#   ./fastly-export.sh --list-site-lists <corp> <site>
#
#   # Fastly NGWAF API
#   export FASTLY_API_TOKEN="your-fastly-token"
#   ./fastly-export.sh --account-lists
#   ./fastly-export.sh --account-list <list_id>
#   ./fastly-export.sh --workspace-lists <workspace_id>
#   ./fastly-export.sh --workspace-list <workspace_id> <list_id>
#
# Environment Variables:
#   SIGSCI_EMAIL       Signal Sciences user email
#   SIGSCI_TOKEN       Signal Sciences API token
#   FASTLY_API_TOKEN   Fastly API token (alternative to SIGSCI_*)
#   OUTPUT_FILE        Output CSV file (default: fastly_ips.csv)
#   DRY_RUN            Set to "true" for preview mode
#   DEBUG              Set to "true" for verbose output
#   AUDIT_LOG          Path to audit log file
#
# Security Notes:
#   - All API calls use verified TLS 1.2+ (--proto '=https' --tlsv1.2)
#   - Credentials are never logged, even in debug mode
#   - Store tokens securely, never commit to version control
#
# =============================================================================

set -euo pipefail
```

#### Constants Section (~lines 45-85)

```bash
# =============================================================================
# Constants & Configuration
# =============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="fastly-export.sh"

# API Configuration
readonly SIGSCI_API_BASE="https://dashboard.signalsciences.net/api/v0"
readonly FASTLY_API_BASE="https://api.fastly.com"

# Rate limiting (conservative to avoid 429)
readonly RATE_LIMIT_DELAY_MS=100
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly INITIAL_RETRY_DELAY=2

# Exit codes (matching akamai-export.sh for consistency)
readonly EXIT_SUCCESS=0
readonly EXIT_MISSING_DEPS=1
readonly EXIT_MISSING_CREDENTIALS=2
readonly EXIT_INVALID_CREDENTIALS=3
readonly EXIT_API_ERROR=4
readonly EXIT_RATE_LIMITED=5
readonly EXIT_INVALID_ARGS=6
readonly EXIT_FILE_ERROR=7
readonly EXIT_NETWORK_ERROR=8

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Script state
SCRIPT_START_TIME=$(date +%s)
API_MODE=""  # "sigsci" or "fastly"
```

#### Logging Functions (~lines 87-135)

```bash
# =============================================================================
# Logging Functions (matching akamai-export.sh pattern)
# =============================================================================

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
  if [ "${DEBUG:-false}" = "true" ]; then
    # SECURITY: Never log credentials
    local msg="$1"
    msg=$(echo "$msg" | sed -E 's/(token|password|secret|key)=[^&[:space:]]*/\1=[REDACTED]/gi')
    echo -e "${BLUE}[DEBUG]${NC} $msg" >&2
  fi
}

audit_log() {
  local action="$1"
  local details="$2"
  local log_file="${AUDIT_LOG:-}"
  
  if [ -n "$log_file" ]; then
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local user="${USER:-unknown}"
    echo "[${timestamp}] user=${user} action=${action} ${details}" >> "$log_file"
  fi
}

rate_limit_sleep() {
  local ms="${1:-$RATE_LIMIT_DELAY_MS}"
  if command -v bc &> /dev/null; then
    sleep "$(echo "scale=3; $ms / 1000" | bc)"
  else
    sleep 1
  fi
}

get_elapsed_time() {
  local end_time
  end_time=$(date +%s)
  echo $((end_time - SCRIPT_START_TIME))
}
```

#### Dependency Check (~lines 137-175)

```bash
# =============================================================================
# Dependency & Validation Functions
# =============================================================================

check_dependencies() {
  local missing=()
  
  command -v curl &> /dev/null || missing+=("curl")
  command -v jq &> /dev/null || missing+=("jq")
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required dependencies: ${missing[*]}"
    log_error ""
    log_error "Installation:"
    log_error "  macOS:  brew install ${missing[*]}"
    log_error "  Ubuntu: sudo apt-get install ${missing[*]}"
    log_error "  Alpine: apk add ${missing[*]}"
    exit $EXIT_MISSING_DEPS
  fi
  
  if ! command -v bc &> /dev/null; then
    log_warn "bc not found - rate limiting will use 1s minimum delay"
  fi
  
  log_debug "Dependencies check passed: curl, jq"
}
```

#### Credential Loading (~lines 177-275)

```bash
# =============================================================================
# Credential Management
# =============================================================================

validate_sigsci_token() {
  local email="$1"
  local token="$2"
  
  log_debug "Validating Signal Sciences credentials..."
  
  local response
  local http_code
  
  response=$(curl -s --proto '=https' --tlsv1.2 \
    -w "\n%{http_code}" \
    -H "x-api-user: $email" \
    -H "x-api-token: $token" \
    -H "Content-Type: application/json" \
    "${SIGSCI_API_BASE}/corps" 2>&1) || {
    log_error "Network error validating credentials"
    return 1
  }
  
  http_code=$(echo "$response" | tail -n1)
  
  if [ "$http_code" = "200" ]; then
    log_debug "Signal Sciences credentials validated"
    return 0
  elif [ "$http_code" = "401" ]; then
    log_error "Invalid Signal Sciences credentials (HTTP 401)"
    log_error "Check your SIGSCI_EMAIL and SIGSCI_TOKEN"
    return 1
  else
    log_error "Credential validation failed (HTTP $http_code)"
    return 1
  fi
}

validate_fastly_token() {
  local token="$1"
  
  log_debug "Validating Fastly API token..."
  
  local response
  local http_code
  
  response=$(curl -s --proto '=https' --tlsv1.2 \
    -w "\n%{http_code}" \
    -H "Fastly-Key: $token" \
    -H "Accept: application/json" \
    "${FASTLY_API_BASE}/current_user" 2>&1) || {
    log_error "Network error validating credentials"
    return 1
  }
  
  http_code=$(echo "$response" | tail -n1)
  
  if [ "$http_code" = "200" ]; then
    log_debug "Fastly API token validated"
    return 0
  elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    log_error "Invalid Fastly API token (HTTP $http_code)"
    return 1
  else
    log_error "Token validation failed (HTTP $http_code)"
    return 1
  fi
}

load_credentials() {
  # Priority 1: Signal Sciences environment variables
  if [ -n "${SIGSCI_EMAIL:-}" ] && [ -n "${SIGSCI_TOKEN:-}" ]; then
    API_MODE="sigsci"
    log_debug "Using Signal Sciences API (env vars)"
    if ! validate_sigsci_token "$SIGSCI_EMAIL" "$SIGSCI_TOKEN"; then
      exit $EXIT_INVALID_CREDENTIALS
    fi
    return 0
  fi
  
  # Priority 2: Fastly API token
  if [ -n "${FASTLY_API_TOKEN:-}" ]; then
    API_MODE="fastly"
    log_debug "Using Fastly NGWAF API (env var)"
    if ! validate_fastly_token "$FASTLY_API_TOKEN"; then
      exit $EXIT_INVALID_CREDENTIALS
    fi
    return 0
  fi
  
  # No credentials found
  log_error "No credentials found."
  log_error ""
  log_error "Set one of the following:"
  log_error ""
  log_error "  Option 1: Signal Sciences API (dashboard.signalsciences.net)"
  log_error "    export SIGSCI_EMAIL=\"your-email@example.com\""
  log_error "    export SIGSCI_TOKEN=\"your-api-token\""
  log_error ""
  log_error "  Option 2: Fastly NGWAF API (manage.fastly.com)"
  log_error "    export FASTLY_API_TOKEN=\"your-fastly-token\""
  log_error ""
  log_error "Create API tokens at:"
  log_error "  Signal Sciences: dashboard.signalsciences.net -> My Profile -> API access tokens"
  log_error "  Fastly: manage.fastly.com -> Account -> API tokens"
  exit $EXIT_MISSING_CREDENTIALS
}
```

#### API Request Functions (~lines 277-400)

```bash
# =============================================================================
# API Request Functions
# =============================================================================

# Generic API request with retry logic
api_request() {
  local method="$1"
  local endpoint="$2"
  local attempt=1
  local delay=$INITIAL_RETRY_DELAY
  
  local url
  local -a headers
  
  if [ "$API_MODE" = "sigsci" ]; then
    url="${SIGSCI_API_BASE}${endpoint}"
    headers=(
      -H "x-api-user: $SIGSCI_EMAIL"
      -H "x-api-token: $SIGSCI_TOKEN"
    )
  else
    url="${FASTLY_API_BASE}${endpoint}"
    headers=(
      -H "Fastly-Key: $FASTLY_API_TOKEN"
    )
  fi
  
  headers+=(-H "Accept: application/json" -H "Content-Type: application/json")
  
  log_debug "API request: $method $url"
  
  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    local response
    response=$(curl -s --proto '=https' --tlsv1.2 \
      -w "\n%{http_code}" \
      -X "$method" \
      "${headers[@]}" \
      "$url" 2>&1) || {
      log_error "Network error on attempt $attempt/$MAX_RETRIES"
      if [ "$attempt" -lt "$MAX_RETRIES" ]; then
        log_warn "Retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
        ((attempt++))
        continue
      fi
      audit_log "API_NETWORK_ERROR" "endpoint=$endpoint attempts=$attempt"
      return 1
    }
    
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')
    
    log_debug "Response code: $http_code"
    
    # Handle rate limiting (429)
    if [ "$http_code" = "429" ]; then
      log_warn "Rate limited (HTTP 429). Waiting ${RATE_LIMIT_BACKOFF_SEC}s... (attempt $attempt/$MAX_RETRIES)"
      audit_log "RATE_LIMITED" "endpoint=$endpoint attempt=$attempt"
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
      audit_log "API_SERVER_ERROR" "endpoint=$endpoint http_code=$http_code"
      return 1
    fi
    
    # Handle client errors (4xx)
    if [ "$http_code" -ge 400 ] 2>/dev/null; then
      log_error "API error (HTTP $http_code)"
      log_error "Endpoint: $endpoint"
      
      local error_msg
      error_msg=$(echo "$body" | jq -r '.message // .error // "Unknown error"' 2>/dev/null)
      log_error "Error: $error_msg"
      
      case "$http_code" in
        401) log_error "Authentication failed. Check your credentials." ;;
        403) log_error "Access denied. Check API token permissions." ;;
        404) log_error "Resource not found. Check corp/site/list IDs." ;;
      esac
      
      audit_log "API_CLIENT_ERROR" "endpoint=$endpoint http_code=$http_code"
      return 1
    fi
    
    # Success
    rate_limit_sleep
    echo "$body"
    echo "$http_code"
    return 0
  done
  
  return 1
}
```

#### Export Functions (~lines 402-650)

```bash
# =============================================================================
# Signal Sciences Export Functions
# =============================================================================

list_corps() {
  log_info "Fetching available corps..."
  
  local response
  if ! response=$(api_request "GET" "/corps"); then
    return 1
  fi
  
  local body
  body=$(echo "$response" | sed '$d')
  
  echo ""
  echo "=============================================="
  echo "  Available Corps (Accounts)"
  echo "=============================================="
  echo ""
  
  echo "$body" | jq -r '.data[] | "Name: \(.name)\n  Display: \(.displayName)\n  Created: \(.created)\n"'
  
  local count
  count=$(echo "$body" | jq '.data | length')
  log_info "Found $count corp(s)"
}

list_sites() {
  local corp="$1"
  
  log_info "Fetching sites in corp: $corp"
  
  local response
  if ! response=$(api_request "GET" "/corps/${corp}/sites"); then
    return 1
  fi
  
  local body
  body=$(echo "$response" | sed '$d')
  
  echo ""
  echo "=============================================="
  echo "  Sites in Corp: $corp"
  echo "=============================================="
  echo ""
  
  echo "$body" | jq -r '.data[] | "Name: \(.name)\n  Display: \(.displayName)\n  Agent Mode: \(.agentLevel)\n"'
  
  local count
  count=$(echo "$body" | jq '.data | length')
  log_info "Found $count site(s)"
}

export_whitelist() {
  local corp="$1"
  local site="$2"
  local output_file="${OUTPUT_FILE:-fastly_ips.csv}"
  
  log_info "=============================================="
  log_info "  Fastly Whitelist Export"
  log_info "=============================================="
  log_info ""
  log_info "Corp: $corp"
  log_info "Site: $site"
  log_info "Output: $output_file"
  log_info ""
  
  local response
  if ! response=$(api_request "GET" "/corps/${corp}/sites/${site}/whitelist"); then
    return 1
  fi
  
  local body
  body=$(echo "$response" | sed '$d')
  
  local count
  count=$(echo "$body" | jq '.data | length')
  
  if [ "$count" = "0" ]; then
    log_warn "No whitelist entries found"
    return 0
  fi
  
  log_info "Found $count whitelist entries"
  
  # Write CSV
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "[DRY RUN] Would write $count entries to $output_file"
    echo "$body" | jq -r '.data[:5][] | "\"\(.source)\",\"\(.note // "")\",\"whitelist\",\"\(.created)\""'
    return 0
  fi
  
  {
    echo "ip,notes,mode,created_on"
    echo "$body" | jq -r '.data[] | 
      "\"\(.source)\",\"\(.note // "" | gsub(","; ";") | gsub("\n"; " "))\",\"whitelist\",\"\(.created)\""'
  } > "$output_file" || {
    log_error "Failed to write output file: $output_file"
    exit $EXIT_FILE_ERROR
  }
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  IPs exported: $count"
  log_info "  Time elapsed: $(get_elapsed_time)s"
  log_info "  Output file:  $output_file"
  log_info ""
  
  audit_log "EXPORT_WHITELIST" "corp=$corp site=$site count=$count file=$output_file"
}

export_blacklist() {
  local corp="$1"
  local site="$2"
  local output_file="${OUTPUT_FILE:-fastly_ips.csv}"
  
  # Similar to export_whitelist but with mode="blacklist"
  # ... implementation follows same pattern
}

export_corp_list() {
  local corp="$1"
  local list_id="$2"
  local output_file="${OUTPUT_FILE:-fastly_ips.csv}"
  
  log_info "Exporting corp list: $list_id"
  
  local response
  if ! response=$(api_request "GET" "/corps/${corp}/lists/${list_id}"); then
    return 1
  fi
  
  local body
  body=$(echo "$response" | sed '$d')
  
  local list_type
  list_type=$(echo "$body" | jq -r '.type')
  
  if [ "$list_type" != "ip" ]; then
    log_error "List type is '$list_type', not 'ip'. Only IP lists can be exported."
    exit $EXIT_INVALID_ARGS
  fi
  
  local list_name
  list_name=$(echo "$body" | jq -r '.name')
  
  local entries
  entries=$(echo "$body" | jq -r '.entries[]' 2>/dev/null)
  local count
  count=$(echo "$body" | jq '.entries | length')
  
  log_info "List: $list_name"
  log_info "Type: $list_type"
  log_info "Entries: $count"
  
  # Write CSV
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "[DRY RUN] Would write $count entries to $output_file"
    return 0
  fi
  
  local created
  created=$(echo "$body" | jq -r '.created // empty')
  local description
  description=$(echo "$body" | jq -r '.description // "" | gsub(","; ";") | gsub("\n"; " ")')
  
  {
    echo "ip,notes,mode,created_on"
    echo "$entries" | while IFS= read -r ip; do
      [ -n "$ip" ] && echo "\"$ip\",\"$list_name - $description\",\"list\",\"$created\""
    done
  } > "$output_file"
  
  log_info "Exported $count IPs to $output_file"
  audit_log "EXPORT_CORP_LIST" "corp=$corp list=$list_id count=$count"
}

# Similar functions for:
# - export_site_list()
# - list_corp_lists()
# - list_site_lists()

# =============================================================================
# Fastly NGWAF Export Functions (for api.fastly.com)
# =============================================================================

export_account_list() {
  local list_id="$1"
  local output_file="${OUTPUT_FILE:-fastly_ips.csv}"
  
  log_info "Exporting account list: $list_id"
  
  local response
  if ! response=$(api_request "GET" "/ngwaf/v1/lists/${list_id}"); then
    return 1
  fi
  
  # Similar processing to export_corp_list
  # Uses different JSON field names (entries vs entries, created_at vs created)
}

export_workspace_list() {
  local workspace_id="$1"
  local list_id="$2"
  # Similar implementation
}
```

#### Main & Help (~lines 652-900)

```bash
# =============================================================================
# Help & Usage
# =============================================================================

show_help() {
  cat << 'EOF'
Fastly Next-Gen WAF Export Script

Exports IP addresses from Fastly Next-Gen WAF to CSV format for Vercel Firewall.

USAGE:
  ./fastly-export.sh <command> [arguments]

SIGNAL SCIENCES COMMANDS (dashboard.signalsciences.net):
  --list-corps                      List available corps
  --list-sites <corp>               List sites in a corp
  --list-corp-lists <corp>          List all corp-level lists
  --list-site-lists <corp> <site>   List site-level lists
  --whitelist <corp> <site>         Export site whitelist to CSV
  --blacklist <corp> <site>         Export site blacklist to CSV
  --corp-list <corp> <list_id>      Export specific corp list
  --site-list <corp> <site> <id>    Export specific site list

FASTLY NGWAF COMMANDS (api.fastly.com):
  --account-lists                   List account-level lists
  --account-list <list_id>          Export account-level list
  --workspace-lists <workspace_id>  List workspace-level lists
  --workspace-list <ws_id> <id>     Export workspace-level list

GENERAL:
  --help, -h                        Show this help message
  --version, -v                     Show version

ENVIRONMENT VARIABLES:
  Signal Sciences API:
    SIGSCI_EMAIL    User email for authentication
    SIGSCI_TOKEN    Personal API access token

  Fastly NGWAF API:
    FASTLY_API_TOKEN   Fastly API token with NGWAF read access

  Common:
    OUTPUT_FILE     Output CSV file (default: fastly_ips.csv)
    DRY_RUN         Set to "true" for preview mode
    DEBUG           Set to "true" for verbose output
    AUDIT_LOG       Path to audit log file

EXAMPLES:
  # List available corps and sites
  ./fastly-export.sh --list-corps
  ./fastly-export.sh --list-sites mycorp

  # Export site whitelist
  export SIGSCI_EMAIL="user@example.com"
  export SIGSCI_TOKEN="your-token"
  ./fastly-export.sh --whitelist mycorp mysite

  # Export to specific file
  OUTPUT_FILE="vendor_ips.csv" ./fastly-export.sh --whitelist mycorp mysite

  # Dry run to preview
  DRY_RUN=true ./fastly-export.sh --whitelist mycorp mysite

For detailed documentation, see: docs/fastly-export.md
EOF
}

# =============================================================================
# Main Entry Point
# =============================================================================

main() {
  check_dependencies
  
  if [ $# -eq 0 ]; then
    show_help
    exit $EXIT_INVALID_ARGS
  fi
  
  case "${1:-}" in
    --help|-h)
      show_help
      exit $EXIT_SUCCESS
      ;;
    --version|-v)
      echo "$SCRIPT_NAME version $SCRIPT_VERSION"
      exit $EXIT_SUCCESS
      ;;
    --list-corps|--list-sites|--list-corp-lists|--list-site-lists|\
    --whitelist|--blacklist|--corp-list|--site-list)
      load_credentials
      if [ "$API_MODE" != "sigsci" ]; then
        log_error "This command requires Signal Sciences credentials (SIGSCI_EMAIL/SIGSCI_TOKEN)"
        exit $EXIT_INVALID_ARGS
      fi
      ;;
    --account-lists|--account-list|--workspace-lists|--workspace-list)
      load_credentials
      if [ "$API_MODE" != "fastly" ]; then
        log_error "This command requires Fastly API token (FASTLY_API_TOKEN)"
        exit $EXIT_INVALID_ARGS
      fi
      ;;
    *)
      log_error "Unknown command: $1"
      log_error "Run with --help for usage information"
      exit $EXIT_INVALID_ARGS
      ;;
  esac
  
  case "$1" in
    --list-corps)
      list_corps
      ;;
    --list-sites)
      [ -z "${2:-}" ] && { log_error "Missing corp name"; exit $EXIT_INVALID_ARGS; }
      list_sites "$2"
      ;;
    --whitelist)
      [ -z "${2:-}" ] || [ -z "${3:-}" ] && { log_error "Usage: --whitelist <corp> <site>"; exit $EXIT_INVALID_ARGS; }
      export_whitelist "$2" "$3"
      ;;
    --blacklist)
      [ -z "${2:-}" ] || [ -z "${3:-}" ] && { log_error "Usage: --blacklist <corp> <site>"; exit $EXIT_INVALID_ARGS; }
      export_blacklist "$2" "$3"
      ;;
    --corp-list)
      [ -z "${2:-}" ] || [ -z "${3:-}" ] && { log_error "Usage: --corp-list <corp> <list_id>"; exit $EXIT_INVALID_ARGS; }
      export_corp_list "$2" "$3"
      ;;
    --site-list)
      [ -z "${2:-}" ] || [ -z "${3:-}" ] || [ -z "${4:-}" ] && { 
        log_error "Usage: --site-list <corp> <site> <list_id>"; exit $EXIT_INVALID_ARGS; 
      }
      export_site_list "$2" "$3" "$4"
      ;;
    --list-corp-lists)
      [ -z "${2:-}" ] && { log_error "Usage: --list-corp-lists <corp>"; exit $EXIT_INVALID_ARGS; }
      list_corp_lists "$2"
      ;;
    --list-site-lists)
      [ -z "${2:-}" ] || [ -z "${3:-}" ] && { log_error "Usage: --list-site-lists <corp> <site>"; exit $EXIT_INVALID_ARGS; }
      list_site_lists "$2" "$3"
      ;;
    --account-lists)
      list_account_lists
      ;;
    --account-list)
      [ -z "${2:-}" ] && { log_error "Usage: --account-list <list_id>"; exit $EXIT_INVALID_ARGS; }
      export_account_list "$2"
      ;;
    --workspace-lists)
      [ -z "${2:-}" ] && { log_error "Usage: --workspace-lists <workspace_id>"; exit $EXIT_INVALID_ARGS; }
      list_workspace_lists "$2"
      ;;
    --workspace-list)
      [ -z "${2:-}" ] || [ -z "${3:-}" ] && { log_error "Usage: --workspace-list <workspace_id> <list_id>"; exit $EXIT_INVALID_ARGS; }
      export_workspace_list "$2" "$3"
      ;;
  esac
}

main "$@"
```

---

### File 2: docs/fastly-export.md (~350 lines)

Documentation sections:

1. **Title & Overview** - Script purpose, dual API support
2. **Which API Should I Use?** - Decision matrix based on control panel access
3. **Prerequisites** - curl, jq, bc (optional)
4. **Signal Sciences API Setup**
  - Creating API token (step-by-step with screenshots references)
  - Token restrictions and expiration
  - Security best practices
5. **Fastly NGWAF API Setup**
  - Creating Fastly API token
  - Required scopes
6. **Finding Corp/Site/Workspace IDs**
  - Via UI
  - Via API commands
7. **Signal Sciences Commands** - All commands with examples and output
8. **Fastly NGWAF Commands** - All commands with examples
9. **Output Format** - CSV structure, column descriptions
10. **API Endpoints Used** - Table for each API
11. **Environment Variables** - Complete reference
12. **Exit Codes** - Table matching other scripts
13. **Migration Workflow** - End-to-end example
14. **Debugging** - DEBUG=true, AUDIT_LOG
15. **Error Handling** - Retry logic, rate limits
16. **Troubleshooting** - Common errors table
17. **Security Best Practices** - Token storage, rotation

---

### File 3: README.md Updates

Add to Scripts table (line ~88):

```markdown
| `exports/fastly-export.sh` | Export IPs from Fastly Next-Gen WAF |
```

Add to Documentation table (line ~122):

```markdown
| [Fastly Export](docs/fastly-export.md) | Export IPs from Fastly Next-Gen WAF |
```

Add migration section after Akamai (line ~199):

```markdown
### From Fastly

```bash
# Export from Fastly Next-Gen WAF (Signal Sciences API)
export SIGSCI_EMAIL="your-email@example.com"
export SIGSCI_TOKEN="your-api-token"
./exports/fastly-export.sh --whitelist mycorp mysite

# Import to Vercel (choose your mode)
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply fastly_ips.csv
```

See [docs/fastly-export.md](docs/fastly-export.md) for details.

```

---

## Performance Optimizations

1. **Rate limiting with bc** - Sub-second delays (100ms) when bc is available
2. **Connection reuse** - curl handles Keep-Alive automatically
3. **Minimal jq calls** - Process JSON in single passes where possible
4. **Early exit on errors** - Don't continue processing after failures
5. **Lazy credential validation** - Only validate when actually needed

---

## Testing Checklist

- [ ] Signal Sciences API: list corps
- [ ] Signal Sciences API: list sites
- [ ] Signal Sciences API: export whitelist
- [ ] Signal Sciences API: export blacklist
- [ ] Signal Sciences API: export corp list (IP type)
- [ ] Signal Sciences API: export site list (IP type)
- [ ] Fastly NGWAF API: list account lists
- [ ] Fastly NGWAF API: export account list
- [ ] Fastly NGWAF API: list workspace lists
- [ ] Fastly NGWAF API: export workspace list
- [ ] Error handling: invalid credentials
- [ ] Error handling: missing corp/site
- [ ] Error handling: rate limiting (429)
- [ ] Error handling: network errors
- [ ] Dry run mode
- [ ] Debug mode
- [ ] Audit logging
- [ ] CSV output compatibility with vercel-bulk-waf-rules.sh

```

