#!/bin/bash
# =============================================================================
# Akamai WAF Export Script
# =============================================================================
#
# Exports IP addresses and CIDR ranges from Akamai Network Lists or Application
# Security configurations to CSV format compatible with Vercel Firewall.
#
# The exported IPs can be used with Vercel WAF in any mode:
#   - deny mode:   Block all traffic except from exported IPs
#   - bypass mode: Skip WAF checks for exported IPs
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
# Security Notes:
#   - All API calls use verified TLS (--proto '=https' --tlsv1.2)
#   - Never use curl -k or --insecure
#   - Store credentials in ~/.edgerc with 600 permissions
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly DEFAULT_EDGERC="$HOME/.edgerc"
readonly DEFAULT_SECTION="default"

# Rate limiting configuration
readonly RATE_LIMIT_DELAY_MS=100
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly INITIAL_RETRY_DELAY=2

# Exit codes for different error conditions
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
readonly NC='\033[0m' # No Color

# Script start time for elapsed calculation
SCRIPT_START_TIME=$(date +%s)

# Credential variables (set by parse_edgerc)
AKAMAI_CLIENT_SECRET=""
AKAMAI_HOST=""
AKAMAI_ACCESS_TOKEN=""
AKAMAI_CLIENT_TOKEN=""
AKAMAI_MAX_BODY=""

# =============================================================================
# Utility Functions
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
    echo -e "${BLUE}[DEBUG]${NC} $1" >&2
  fi
}

# Write audit log entry
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

# Rate limit sleep with millisecond precision
rate_limit_sleep() {
  local ms="${1:-$RATE_LIMIT_DELAY_MS}"
  if command -v bc &> /dev/null; then
    sleep "$(echo "scale=3; $ms / 1000" | bc)"
  else
    # Fallback: sleep minimum 1 second if bc not available
    sleep 1
  fi
}

# Calculate elapsed time
get_elapsed_time() {
  local end_time
  end_time=$(date +%s)
  echo $((end_time - SCRIPT_START_TIME))
}

# =============================================================================
# Dependency & Validation Functions
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
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required dependencies: ${missing[*]}"
    log_error "Please install them and try again."
    log_error ""
    log_error "Installation:"
    log_error "  macOS:  brew install ${missing[*]}"
    log_error "  Ubuntu: sudo apt-get install ${missing[*]}"
    log_error "  Alpine: apk add ${missing[*]}"
    exit $EXIT_MISSING_DEPS
  fi
  
  # Check optional dependency
  if ! command -v bc &> /dev/null; then
    log_warn "bc not found - rate limiting will use 1s minimum delay"
  fi
  
  log_debug "Dependencies check passed: curl, jq, openssl"
}

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
    log_error "  4. Set permissions: chmod 600 ~/.edgerc"
    exit $EXIT_MISSING_CREDENTIALS
  fi
  
  # Check file permissions (should be 600)
  local perms
  perms=$(stat -f "%Lp" "$edgerc_path" 2>/dev/null || stat -c "%a" "$edgerc_path" 2>/dev/null)
  if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
    log_warn ".edgerc has insecure permissions ($perms). Consider: chmod 600 $edgerc_path"
  fi
  
  # Parse the section from .edgerc
  local in_section=false
  while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
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
    log_error ""
    log_error "Available sections in $edgerc_path:"
    grep -E '^\[' "$edgerc_path" | sed 's/\[//g; s/\]//g; s/^/  - /'
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
      log_error "Max retries exceeded due to network errors"
      audit_log "API_NETWORK_ERROR" "endpoint=$endpoint attempts=$attempt"
      return 1
    }
    
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body_response
    body_response=$(echo "$response" | sed '$d')
    
    log_debug "Response code: $http_code"
    log_debug "Response body: $(echo "$body_response" | head -c 500)..."
    
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
        log_warn "Retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
        ((attempt++))
        continue
      fi
      log_error "Max retries exceeded for server errors"
      audit_log "API_SERVER_ERROR" "endpoint=$endpoint http_code=$http_code attempts=$attempt"
      return 1
    fi
    
    # Handle client errors (4xx)
    if [ "$http_code" -ge 400 ] 2>/dev/null && [ "$http_code" != "429" ]; then
      log_error "API error (HTTP $http_code)"
      log_error "Endpoint: $endpoint"
      
      # Parse and display Akamai error details
      local error_title
      local error_detail
      error_title=$(echo "$body_response" | jq -r '.title // .type // "Unknown error"' 2>/dev/null)
      error_detail=$(echo "$body_response" | jq -r '.detail // .message // empty' 2>/dev/null)
      
      log_error "Error: $error_title"
      [ -n "$error_detail" ] && log_error "Detail: $error_detail"
      
      # Provide helpful guidance for common errors
      case "$http_code" in
        401)
          log_error ""
          log_error "Authentication failed. Check your .edgerc credentials."
          log_error "Ensure client_token, access_token, and client_secret are correct."
          ;;
        403)
          log_error ""
          log_error "Access denied. Your API client may lack required permissions."
          log_error "Required: Network Lists API READ access"
          ;;
        404)
          log_error ""
          log_error "Resource not found. Check your list/config ID."
          ;;
      esac
      
      audit_log "API_CLIENT_ERROR" "endpoint=$endpoint http_code=$http_code"
      return 1
    fi
    
    # Success - add rate limit delay
    rate_limit_sleep
    
    echo "$body_response"
    echo "$http_code"
    return 0
  done
  
  return 1
}

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
  
  local list_output
  list_output=$(echo "$body" | jq -r '.networkLists[] | "ID: \(.uniqueId)\n  Name: \(.name)\n  Elements: \(.elementCount)\n  Type: \(.type)\n  Updated: \(.updateDate // "N/A")\n"' 2>/dev/null)
  
  if [ -n "$list_output" ]; then
    echo "$list_output"
  else
    echo "No IP network lists found."
  fi
  
  local count
  count=$(echo "$body" | jq '.networkLists | length')
  
  echo ""
  log_info "Found $count IP network list(s)"
  echo ""
  log_info "To export a list, run:"
  echo "  ./akamai-export.sh --network-list <uniqueId>"
  
  audit_log "LIST_NETWORK_LISTS" "count=$count"
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
    log_info ""
    log_info "Remove DRY_RUN=true to perform actual export."
    audit_log "EXPORT_DRY_RUN" "list_id=$list_id"
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
  
  log_info "List name:     $list_name"
  log_info "List type:     $list_type"
  log_info "Element count: $element_count"
  log_info "Last updated:  $update_date"
  log_info ""
  
  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    log_error "Check file permissions and disk space."
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
  
  local elapsed
  elapsed=$(get_elapsed_time)
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  List name:        $list_name"
  log_info "  IPs exported:     $exported_count"
  log_info "  Time elapsed:     ${elapsed}s"
  log_info "  Output file:      $output_file"
  log_info "  Output size:      $(wc -l < "$output_file" | tr -d ' ') lines"
  log_info ""
  
  # Show sample
  if [ "$exported_count" -gt 0 ]; then
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
  fi
  
  echo ""
  log_info "Next step: Import to Vercel"
  echo "  DRY_RUN=true ./vercel-bulk-waf-rules.sh apply $output_file"
  
  audit_log "EXPORT_COMPLETE" "list_id=$list_id list_name=$list_name ips=$exported_count elapsed=${elapsed}s"
}

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
  
  audit_log "SECURITY_EXPORT_START" "config_id=$config_id version=$version"
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export Security Config: $config_id"
    log_info "Would fetch version: $version"
    log_info "Would write to: $output_file"
    return 0
  fi
  
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
    
    if [ "$versions_http" != "200" ]; then
      log_error "Failed to fetch versions (HTTP $versions_http)"
      return 1
    fi
    
    version=$(echo "$versions_body" | jq -r '.versionList[0].version // .versions[0].version // empty')
    if [ -z "$version" ]; then
      log_error "Could not determine latest version"
      log_error "Response: $versions_body"
      return 1
    fi
    log_info "Latest version: $version"
  fi
  
  # Export the configuration
  log_info "Exporting security configuration (this may take a moment)..."
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
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    exit $EXIT_FILE_ERROR
  fi
  
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
  
  # Try alternative structures for IP conditions
  local alt_ips
  alt_ips=$(echo "$body" | jq -r '
    .. | objects | 
    select(.type? == "ipMatch" or .conditionType? == "ipMatch") | 
    (.value // .ips // .ipAddresses // [])[]?' 2>/dev/null)
  
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    # Check if already exported
    if ! grep -q "\"$ip\"" "$output_file" 2>/dev/null; then
      echo "\"$ip\",\"$config_name - IP Condition\",\"whitelist\",\"\"" >> "$output_file"
      ((exported_count++))
    fi
  done <<< "$alt_ips"
  
  local elapsed
  elapsed=$(get_elapsed_time)
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  Config name:      $config_name"
  log_info "  Version:          $version"
  log_info "  IPs exported:     $exported_count"
  log_info "  Time elapsed:     ${elapsed}s"
  log_info "  Output file:      $output_file"
  log_info ""
  
  if [ "$exported_count" -eq 0 ]; then
    log_warn "No IP addresses found in this configuration"
    log_warn "IP addresses may be in Network Lists instead"
    log_warn "Run: ./akamai-export.sh --list-all"
  else
    # Show sample
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
    
    echo ""
    log_info "Next step: Import to Vercel"
    echo "  DRY_RUN=true ./vercel-bulk-waf-rules.sh apply $output_file"
  fi
  
  audit_log "SECURITY_EXPORT_COMPLETE" "config_id=$config_id version=$version ips=$exported_count"
}

# =============================================================================
# Help & Usage
# =============================================================================

show_usage() {
  cat << EOF
Akamai WAF Export Script
Version: $SCRIPT_VERSION

Exports IP addresses and CIDR ranges from Akamai Network Lists or Application
Security configurations to CSV format compatible with Vercel Firewall.

The exported IPs can be used with Vercel WAF in any mode:
  - deny mode:   Block all traffic except from exported IPs
  - bypass mode: Skip WAF checks for exported IPs

USAGE:
  $0 --list-all                           List all IP network lists
  $0 --network-list <listId>              Export IPs from a network list
  $0 --security-config <configId> [ver]   Export IPs from security config
  $0 --help                               Show this help message

ENVIRONMENT VARIABLES:
  AKAMAI_EDGERC   (optional) Path to .edgerc file (default: ~/.edgerc)
  AKAMAI_SECTION  (optional) Section in .edgerc (default: default)
  OUTPUT_FILE     (optional) Output CSV file path (default: akamai_ips.csv)
  DRY_RUN         (optional) Set to "true" for preview mode
  DEBUG           (optional) Set to "true" for verbose debug output
  AUDIT_LOG       (optional) Path to audit log file

PREREQUISITES:
  1. Create API credentials in Akamai Control Center:
     https://control.akamai.com/apps/identity-management

  2. Download and save .edgerc to ~/.edgerc

  3. Set secure permissions: chmod 600 ~/.edgerc

  4. Required API permissions:
     - Network Lists API: READ
     - Application Security API: READ (optional, for --security-config)

EXAMPLES:
  # List all available network lists
  ./akamai-export.sh --list-all

  # Export a specific network list
  ./akamai-export.sh --network-list 38069_VENDORIPS

  # Export to custom file
  OUTPUT_FILE="vendor_ips.csv" ./akamai-export.sh --network-list 38069_VENDORIPS

  # Use a different .edgerc section
  AKAMAI_SECTION=production ./akamai-export.sh --list-all

  # Dry run (preview without writing)
  DRY_RUN=true ./akamai-export.sh --network-list 38069_VENDORIPS

  # Debug mode
  DEBUG=true ./akamai-export.sh --list-all

  # Export from security config
  ./akamai-export.sh --security-config 12345 latest

.EDGERC FORMAT:
  [default]
  client_secret = your-client-secret
  host = akab-xxx.luna.akamaiapis.net
  access_token = akab-xxx
  client_token = akab-xxx

OUTPUT FORMAT:
  CSV with columns: ip,notes,mode,created_on
  Compatible with vercel-bulk-waf-rules.sh

EXIT CODES:
  0  - Success
  1  - Missing dependencies (curl, jq, openssl)
  2  - Missing .edgerc credentials
  3  - Invalid credentials
  4  - API error (non-retryable)
  5  - Rate limited (after max retries)
  6  - Invalid arguments
  7  - File I/O error
  8  - Network error

MIGRATION WORKFLOW:
  # Step 1: List available network lists
  ./akamai-export.sh --list-all

  # Step 2: Export the desired list
  ./akamai-export.sh --network-list 38069_VENDORIPS

  # Step 3: Preview import to Vercel (choose your mode)
  DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply akamai_ips.csv

  # Step 4: Apply to Vercel
  RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply akamai_ips.csv

EOF
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Check dependencies first
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
        log_error ""
        log_error "To find available list IDs, run:"
        log_error "  $0 --list-all"
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
      log_error ""
      show_usage
      exit $EXIT_INVALID_ARGS
      ;;
  esac
}

main "$@"
