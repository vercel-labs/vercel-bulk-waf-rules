#!/bin/bash
# =============================================================================
# Cloudflare WAF Export Script
# =============================================================================
#
# Exports IP addresses and CIDR ranges from Cloudflare IP Access Rules or IP
# Lists to CSV format compatible with Vercel Firewall.
#
# The exported IPs can be used with Vercel WAF in any mode:
#   - deny mode:   Block all traffic except from exported IPs
#   - bypass mode: Skip WAF checks for exported IPs
#
# IMPORTANT:
# - Requires Cloudflare API Token with "Account Firewall Access Rules Read" 
#   or "Zone Firewall Access Rules Read" permissions
# - No UI export is available in Cloudflare - API is the only option
# - Handles pagination for large lists (600+ IPs)
#
# Usage:
#   # Export account-level IP Access Rules
#   ./cloudflare-export.sh --account <account_id>
#
#   # Export zone-level IP Access Rules  
#   ./cloudflare-export.sh --zone <zone_id>
#
#   # Export from IP List
#   ./cloudflare-export.sh --list <account_id> <list_id>
#
#   # Export all lists from an account
#   ./cloudflare-export.sh --all-lists <account_id>
#
# Environment variables:
#   CF_API_TOKEN (required): Cloudflare API token
#   OUTPUT_FILE (optional): Output CSV file path (default: cloudflare_ips.csv)
#   MODE_FILTER (optional): Filter by mode - whitelist, block, challenge (default: whitelist)
#   DRY_RUN (optional): Set to "true" to preview without making changes
#   DEBUG (optional): Set to "true" for verbose output
#   AUDIT_LOG (optional): Path to audit log file
#
# Security Notes:
#   - All API calls use verified TLS (--proto '=https' --tlsv1.2)
#   - Never use curl -k or --insecure
#   - Store tokens in a secrets manager, not in env files committed to git
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly CF_API_BASE="https://api.cloudflare.com/client/v4"
readonly DEFAULT_PER_PAGE=100
readonly MAX_PER_PAGE=1000

# Rate limiting configuration (Cloudflare: 1200 req/5min, 200/sec per IP)
readonly RATE_LIMIT_DELAY_MS=100
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly INITIAL_RETRY_DELAY=2

# Exit codes for different error conditions
readonly EXIT_SUCCESS=0
readonly EXIT_MISSING_DEPS=1
readonly EXIT_MISSING_TOKEN=2
readonly EXIT_INVALID_TOKEN=3
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
  
  log_debug "Dependencies check passed: curl, jq"
}

# Validate token format and presence
validate_token_format() {
  if [ -z "${CF_API_TOKEN:-}" ]; then
    log_error "CF_API_TOKEN environment variable is not set"
    log_error ""
    log_error "Set your Cloudflare API token:"
    log_error "  export CF_API_TOKEN='your-cloudflare-api-token'"
    log_error ""
    log_error "Create a token at: https://dash.cloudflare.com/profile/api-tokens"
    log_error "Required permissions: Account Firewall Access Rules Read"
    exit $EXIT_MISSING_TOKEN
  fi
  
  # Basic format validation - Cloudflare tokens are alphanumeric with underscores/hyphens
  # Typical format: 40+ characters
  if [[ ! "$CF_API_TOKEN" =~ ^[a-zA-Z0-9_-]{20,}$ ]]; then
    log_error "CF_API_TOKEN appears malformed"
    log_error "Expected: 20+ alphanumeric characters with underscores/hyphens"
    log_error "Actual length: ${#CF_API_TOKEN} characters"
    exit $EXIT_INVALID_TOKEN
  fi
  
  log_debug "Token format validation passed (${#CF_API_TOKEN} chars)"
}

# Verify token with Cloudflare API
verify_token_api() {
  log_info "Verifying API token..."
  
  local response
  local http_code
  local body
  
  # Use token verify endpoint
  response=$(curl -s --proto '=https' --tlsv1.2 -w "\n%{http_code}" \
    "${CF_API_BASE}/user/tokens/verify" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" 2>&1) || {
    log_error "Network error: Failed to connect to Cloudflare API"
    log_error "Check your internet connection and try again"
    exit $EXIT_NETWORK_ERROR
  }
  
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  
  log_debug "Token verify response code: $http_code"
  log_debug "Token verify response: $body"
  
  if [ "$http_code" -ne 200 ]; then
    log_error "Token verification failed (HTTP $http_code)"
    
    # Parse error details
    local error_code
    local error_message
    error_code=$(echo "$body" | jq -r '.errors[0].code // "unknown"' 2>/dev/null)
    error_message=$(echo "$body" | jq -r '.errors[0].message // "Unknown error"' 2>/dev/null)
    
    log_error "Error code: $error_code"
    log_error "Error message: $error_message"
    
    if [ "$http_code" -eq 401 ]; then
      log_error ""
      log_error "Your token is invalid or expired."
      log_error "Create a new token at: https://dash.cloudflare.com/profile/api-tokens"
    fi
    
    audit_log "TOKEN_VERIFY_FAILED" "http_code=$http_code error_code=$error_code"
    exit $EXIT_INVALID_TOKEN
  fi
  
  # Check token status
  local status
  status=$(echo "$body" | jq -r '.result.status // "unknown"' 2>/dev/null)
  
  if [ "$status" != "active" ]; then
    log_error "Token status: $status (expected: active)"
    log_error "Your token may be expired or revoked"
    audit_log "TOKEN_INACTIVE" "status=$status"
    exit $EXIT_INVALID_TOKEN
  fi
  
  log_info "Token verified: active"
  audit_log "TOKEN_VERIFIED" "status=active"
}

show_usage() {
  cat << EOF
Cloudflare WAF Export Script

Exports IP addresses and CIDR ranges from Cloudflare IP Access Rules or IP
Lists to CSV format compatible with Vercel Firewall.

The exported IPs can be used with Vercel WAF in any mode:
  - deny mode:   Block all traffic except from exported IPs
  - bypass mode: Skip WAF checks for exported IPs

USAGE:
  $0 --account <account_id>              Export account-level IP Access Rules
  $0 --zone <zone_id>                    Export zone-level IP Access Rules
  $0 --list <account_id> <list_id>       Export items from a specific IP List
  $0 --all-lists <account_id>            List all IP Lists in an account
  $0 --convert <input_csv> [output_csv]  Convert Cloudflare CSV to Vercel format
  $0 --help                              Show this help message

ENVIRONMENT VARIABLES:
  CF_API_TOKEN    (required) Cloudflare API token
  OUTPUT_FILE     (optional) Output CSV file path (default: cloudflare_ips.csv)
  MODE_FILTER     (optional) Filter by Cloudflare mode: whitelist, block, challenge (default: whitelist)
  DRY_RUN         (optional) Set to "true" for preview mode (no file writes)
  DEBUG           (optional) Set to "true" for verbose debug output
  AUDIT_LOG       (optional) Path to audit log file for tracking operations

EXAMPLES:
  # Export IPs with "whitelist" mode from account
  CF_API_TOKEN="token" ./cloudflare-export.sh --account abc123def456

  # Export to specific file
  OUTPUT_FILE="vendor_ips.csv" ./cloudflare-export.sh --account abc123def456

  # Export all modes (whitelist, block, challenge)
  MODE_FILTER="" ./cloudflare-export.sh --zone xyz789

  # Dry run (preview without writing files)
  DRY_RUN=true ./cloudflare-export.sh --account abc123def456

  # Debug mode (verbose output)
  DEBUG=true ./cloudflare-export.sh --account abc123def456

  # With audit logging
  AUDIT_LOG="./cloudflare-export.log" ./cloudflare-export.sh --account abc123def456

OUTPUT FORMAT:
  CSV with columns: ip,notes,mode,created_on
  Compatible with vercel-bulk-waf-rules.sh

EXIT CODES:
  0  - Success
  1  - Missing dependencies (curl, jq)
  2  - Missing CF_API_TOKEN
  3  - Invalid or expired token
  4  - API error (non-retryable)
  5  - Rate limited (after max retries)
  6  - Invalid arguments
  7  - File I/O error
  8  - Network error

EOF
}

# =============================================================================
# API Functions
# =============================================================================

# Make authenticated API request with retry logic and rate limit handling
# Returns: JSON body on success, exits on failure
cf_api_request() {
  local endpoint="$1"
  local attempt=1
  local delay=$INITIAL_RETRY_DELAY
  local response
  local http_code
  local body
  local headers
  
  log_debug "API request: GET ${CF_API_BASE}${endpoint}"
  
  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    # Make request with explicit TLS verification
    # Capture both headers and body for rate limit handling
    response=$(curl -s --proto '=https' --tlsv1.2 \
      -w "\n%{http_code}" \
      -D - \
      "${CF_API_BASE}${endpoint}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" 2>&1) || {
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
    
    # Parse response - last line is HTTP code, rest is headers + body
    http_code=$(echo "$response" | tail -n1)
    # Extract body (everything after the blank line separating headers from body)
    body=$(echo "$response" | sed '$d' | sed -n '/^\r*$/,$p' | tail -n +2)
    # Extract headers (everything before the blank line)
    headers=$(echo "$response" | sed '$d' | sed '/^\r*$/q')
    
    log_debug "Response code: $http_code"
    log_debug "Response body: $(echo "$body" | head -c 500)..."
    
    # Handle rate limiting (HTTP 429)
    if [ "$http_code" -eq 429 ]; then
      local retry_after
      # Try to extract Retry-After header
      retry_after=$(echo "$headers" | grep -i "retry-after:" | sed 's/[^0-9]*//g' | head -1)
      retry_after="${retry_after:-$RATE_LIMIT_BACKOFF_SEC}"
      
      log_warn "Rate limited (HTTP 429). Waiting ${retry_after}s... (attempt $attempt/$MAX_RETRIES)"
      audit_log "RATE_LIMITED" "endpoint=$endpoint attempt=$attempt retry_after=${retry_after}s"
      
      sleep "$retry_after"
      ((attempt++))
      continue
    fi
    
    # Handle server errors (5xx) - retryable
    if [ "$http_code" -ge 500 ]; then
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
    
    # Handle client errors (4xx except 429) - not retryable
    if [ "$http_code" -ge 400 ] && [ "$http_code" -ne 429 ]; then
      log_error "API request failed (HTTP $http_code)"
      log_error "Endpoint: $endpoint"
      
      # Parse and display Cloudflare error details
      local error_code
      local error_message
      local error_chain
      error_code=$(echo "$body" | jq -r '.errors[0].code // "unknown"' 2>/dev/null)
      error_message=$(echo "$body" | jq -r '.errors[0].message // "Unknown error"' 2>/dev/null)
      error_chain=$(echo "$body" | jq -r '.errors[0].error_chain // empty' 2>/dev/null)
      
      log_error "Error code: $error_code"
      log_error "Error message: $error_message"
      
      if [ -n "$error_chain" ] && [ "$error_chain" != "null" ]; then
        log_error "Error chain: $error_chain"
      fi
      
      # Provide helpful guidance for common errors
      case "$http_code" in
        401)
          log_error ""
          log_error "Authentication failed. Check your CF_API_TOKEN."
          ;;
        403)
          log_error ""
          log_error "Access denied. Your token may lack required permissions."
          log_error "Required: Account Firewall Access Rules Read"
          ;;
        404)
          log_error ""
          log_error "Resource not found. Check your account/zone/list ID."
          ;;
      esac
      
      audit_log "API_CLIENT_ERROR" "endpoint=$endpoint http_code=$http_code error_code=$error_code"
      return 1
    fi
    
    # Success (2xx)
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
      # Check Cloudflare success field
      local success
      success=$(echo "$body" | jq -r '.success // "false"' 2>/dev/null)
      
      if [ "$success" != "true" ]; then
        log_error "Cloudflare API returned success=false"
        
        local error_code
        local error_message
        error_code=$(echo "$body" | jq -r '.errors[0].code // "unknown"' 2>/dev/null)
        error_message=$(echo "$body" | jq -r '.errors[0].message // "Unknown error"' 2>/dev/null)
        
        log_error "Error code: $error_code"
        log_error "Error message: $error_message"
        
        if [ "${DEBUG:-false}" = "true" ]; then
          log_debug "Full response:"
          echo "$body" | jq '.' 2>/dev/null || echo "$body"
        fi
        
        audit_log "API_LOGICAL_ERROR" "endpoint=$endpoint error_code=$error_code"
        return 1
      fi
      
      # Rate limit delay between successful requests
      rate_limit_sleep
      
      # Return the body (to stdout, not stderr)
      echo "$body"
      return 0
    fi
    
    # Unexpected status code
    log_error "Unexpected HTTP status: $http_code"
    return 1
  done
  
  # Should not reach here, but handle it
  log_error "API request failed after $MAX_RETRIES attempts"
  audit_log "API_MAX_RETRIES" "endpoint=$endpoint attempts=$MAX_RETRIES"
  return 1
}

# =============================================================================
# Export Functions
# =============================================================================

# Export IP Access Rules (account or zone level)
export_ip_access_rules() {
  local scope="$1"  # "accounts" or "zones"
  local id="$2"     # account_id or zone_id
  local output_file="${OUTPUT_FILE:-cloudflare_ips.csv}"
  local mode_filter="${MODE_FILTER:-whitelist}"
  
  log_info "=============================================="
  log_info "  Cloudflare IP Access Rules Export"
  log_info "=============================================="
  log_info ""
  log_info "Scope:       $scope/$id"
  log_info "Mode filter: ${mode_filter:-all modes}"
  log_info "Output file: $output_file"
  log_info ""
  
  audit_log "EXPORT_START" "scope=$scope id=$id mode_filter=${mode_filter:-all} output=$output_file"
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export IP Access Rules from: $scope/$id"
    log_info "Would write to: $output_file"
    log_info ""
    log_info "Remove DRY_RUN=true to perform actual export."
    audit_log "EXPORT_DRY_RUN" "scope=$scope id=$id"
    return 0
  fi
  
  # Build query params
  local query_params="per_page=${DEFAULT_PER_PAGE}"
  if [ -n "$mode_filter" ]; then
    query_params="${query_params}&mode=${mode_filter}"
  fi
  
  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    log_error "Check file permissions and disk space."
    exit $EXIT_FILE_ERROR
  fi
  
  local page=1
  local total_count=0
  local total_pages=1
  local exported_count=0
  
  while [ "$page" -le "$total_pages" ]; do
    log_info "Fetching page $page${total_pages:+/$total_pages}..."
    
    local response
    if ! response=$(cf_api_request "/${scope}/${id}/firewall/access_rules/rules?${query_params}&page=${page}"); then
      log_error "Failed to fetch page $page"
      audit_log "EXPORT_FAILED" "scope=$scope id=$id page=$page"
      return 1
    fi
    
    # Extract pagination info
    total_pages=$(echo "$response" | jq -r '.result_info.total_pages // 1')
    local page_count
    page_count=$(echo "$response" | jq -r '.result_info.count // 0')
    
    if [ "$page" -eq 1 ]; then
      total_count=$(echo "$response" | jq -r '.result_info.total_count // 0')
      log_info "Total rules to export: $total_count (across $total_pages pages)"
      log_info ""
    fi
    
    # Extract and format results
    local page_data
    page_data=$(echo "$response" | jq -r '.result[] | [
      .configuration.value,
      (.notes // "" | gsub(","; ";") | gsub("\n"; " ") | gsub("\r"; "")),
      .mode,
      .created_on
    ] | @csv' 2>/dev/null)
    
    if [ -n "$page_data" ]; then
      echo "$page_data" >> "$output_file"
      exported_count=$((exported_count + page_count))
    fi
    
    log_info "  Page $page/$total_pages: $page_count rules (total exported: $exported_count)"
    
    ((page++))
  done
  
  local elapsed
  elapsed=$(get_elapsed_time)
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  Total rules exported: $exported_count"
  log_info "  Pages fetched:        $((total_pages))"
  log_info "  Time elapsed:         ${elapsed}s"
  log_info "  Output file:          $output_file"
  log_info "  Output size:          $(wc -l < "$output_file" | tr -d ' ') lines"
  log_info ""
  
  # Show sample
  if [ "$exported_count" -gt 0 ]; then
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
  fi
  
  audit_log "EXPORT_COMPLETE" "scope=$scope id=$id rules=$exported_count pages=$total_pages elapsed=${elapsed}s"
}

# List all IP Lists in an account
list_ip_lists() {
  local account_id="$1"
  
  log_info "Fetching IP Lists from account $account_id"
  log_info ""
  
  audit_log "LIST_IP_LISTS_START" "account_id=$account_id"
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "[DRY-RUN] Would fetch IP Lists from account: $account_id"
    return 0
  fi
  
  local response
  if ! response=$(cf_api_request "/accounts/${account_id}/rules/lists"); then
    log_error "Failed to fetch IP Lists"
    audit_log "LIST_IP_LISTS_FAILED" "account_id=$account_id"
    return 1
  fi
  
  # Display IP lists
  echo "$response" | jq -r '.result[] | select(.kind == "ip") | "ID: \(.id)\n  Name: \(.name)\n  Description: \(.description // "N/A")\n  Item Count: \(.num_items)\n  Created: \(.created_on)\n"'
  
  local list_count
  list_count=$(echo "$response" | jq '[.result[] | select(.kind == "ip")] | length')
  
  log_info ""
  log_info "Found $list_count IP lists"
  log_info ""
  log_info "To export a specific list, run:"
  log_info "  $0 --list $account_id <list_id>"
  
  audit_log "LIST_IP_LISTS_COMPLETE" "account_id=$account_id count=$list_count"
}

# Export items from a specific IP List
export_ip_list() {
  local account_id="$1"
  local list_id="$2"
  local output_file="${OUTPUT_FILE:-cloudflare_ips.csv}"
  
  log_info "=============================================="
  log_info "  Cloudflare IP List Export"
  log_info "=============================================="
  log_info ""
  log_info "Account ID: $account_id"
  log_info "List ID:    $list_id"
  log_info "Output:     $output_file"
  log_info ""
  
  audit_log "EXPORT_LIST_START" "account_id=$account_id list_id=$list_id output=$output_file"
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export IP List: $list_id"
    log_info "Would write to: $output_file"
    return 0
  fi
  
  # Get list metadata first
  local list_info
  if ! list_info=$(cf_api_request "/accounts/${account_id}/rules/lists/${list_id}"); then
    log_error "Failed to fetch list metadata"
    audit_log "EXPORT_LIST_FAILED" "account_id=$account_id list_id=$list_id reason=metadata_fetch"
    return 1
  fi
  
  local list_name
  list_name=$(echo "$list_info" | jq -r '.result.name // "Unknown"')
  local item_count
  item_count=$(echo "$list_info" | jq -r '.result.num_items // 0')
  
  log_info "List name:      $list_name"
  log_info "Expected items: $item_count"
  log_info ""
  
  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    exit $EXIT_FILE_ERROR
  fi
  
  # Fetch all items (uses cursor-based pagination)
  local cursor=""
  local total_exported=0
  local page=1
  
  while true; do
    log_info "Fetching page $page..."
    
    local endpoint="/accounts/${account_id}/rules/lists/${list_id}/items"
    if [ -n "$cursor" ]; then
      endpoint="${endpoint}?cursor=${cursor}"
    fi
    
    local response
    if ! response=$(cf_api_request "$endpoint"); then
      log_error "Failed to fetch page $page"
      audit_log "EXPORT_LIST_FAILED" "account_id=$account_id list_id=$list_id page=$page"
      return 1
    fi
    
    # Extract items
    local page_count
    page_count=$(echo "$response" | jq '.result | length')
    
    local page_data
    page_data=$(echo "$response" | jq -r '.result[] | [
      .ip,
      (.comment // "" | gsub(","; ";") | gsub("\n"; " ") | gsub("\r"; "")),
      "whitelist",
      .created_on
    ] | @csv' 2>/dev/null)
    
    if [ -n "$page_data" ]; then
      echo "$page_data" >> "$output_file"
    fi
    
    total_exported=$((total_exported + page_count))
    log_info "  Page $page: $page_count items (total: $total_exported)"
    
    # Check for more pages (cursor-based pagination)
    cursor=$(echo "$response" | jq -r '.result_info.cursors.after // empty')
    if [ -z "$cursor" ]; then
      break
    fi
    
    ((page++))
  done
  
  local elapsed
  elapsed=$(get_elapsed_time)
  
  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  List name:        $list_name"
  log_info "  Items exported:   $total_exported"
  log_info "  Pages fetched:    $page"
  log_info "  Time elapsed:     ${elapsed}s"
  log_info "  Output file:      $output_file"
  log_info ""
  
  # Show sample
  if [ "$total_exported" -gt 0 ]; then
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
  fi
  
  audit_log "EXPORT_LIST_COMPLETE" "account_id=$account_id list_id=$list_id items=$total_exported pages=$page elapsed=${elapsed}s"
}

# =============================================================================
# Conversion to Vercel Format (Optimized with awk)
# =============================================================================

convert_to_vercel_format() {
  local input_file="$1"
  local output_file="${2:-vercel_ips.csv}"
  
  if [ ! -f "$input_file" ]; then
    log_error "Input file not found: $input_file"
    exit $EXIT_FILE_ERROR
  fi
  
  log_info "Converting $input_file to Vercel format..."
  
  audit_log "CONVERT_START" "input=$input_file output=$output_file"
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "[DRY-RUN] Would convert: $input_file -> $output_file"
    return 0
  fi
  
  # Use awk for fast processing (handles quoted CSV fields properly)
  # Vercel format: ip,note (note is optional, max 500 chars for bypass API)
  {
    echo "ip,note"
    
    # Skip header line, process rest with awk
    tail -n +2 "$input_file" | awk -F',' '
    BEGIN { OFS="," }
    {
      # Extract IP (first field)
      ip = $1
      gsub(/^[[:space:]]*"?|"?[[:space:]]*$/, "", ip)
      
      # Extract notes (second field)
      notes = $2
      gsub(/^[[:space:]]*"?|"?[[:space:]]*$/, "", notes)
      
      # Skip empty IPs
      if (ip == "" || tolower(ip) == "ip") next
      
      # Truncate notes to 500 chars (Vercel limit)
      if (length(notes) > 500) {
        notes = substr(notes, 1, 497) "..."
      }
      
      # Output in Vercel format with proper quoting
      printf "\"%s\",\"%s\"\n", ip, notes
    }'
  } > "$output_file"
  
  local line_count
  line_count=$(wc -l < "$output_file" | tr -d ' ')
  
  log_info "Converted to: $output_file"
  log_info "Total entries: $((line_count - 1))"
  
  audit_log "CONVERT_COMPLETE" "input=$input_file output=$output_file entries=$((line_count - 1))"
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Check dependencies first
  check_dependencies
  
  # Handle help early (before token validation)
  if [ $# -eq 0 ]; then
    show_usage
    exit $EXIT_INVALID_ARGS
  fi
  
  case "${1:-}" in
    --help|-h)
      show_usage
      exit $EXIT_SUCCESS
      ;;
  esac
  
  # Convert command doesn't need API token
  if [ "${1:-}" = "--convert" ]; then
    if [ -z "${2:-}" ]; then
      log_error "Input file required"
      log_error "Usage: $0 --convert <input_csv> [output_csv]"
      exit $EXIT_INVALID_ARGS
    fi
    convert_to_vercel_format "$2" "${3:-vercel_ips.csv}"
    exit $EXIT_SUCCESS
  fi
  
  # Validate token for all API commands
  validate_token_format
  verify_token_api
  log_info ""
  
  case "$1" in
    --account)
      if [ -z "${2:-}" ]; then
        log_error "Account ID required"
        log_error "Usage: $0 --account <account_id>"
        exit $EXIT_INVALID_ARGS
      fi
      export_ip_access_rules "accounts" "$2"
      ;;
    
    --zone)
      if [ -z "${2:-}" ]; then
        log_error "Zone ID required"
        log_error "Usage: $0 --zone <zone_id>"
        exit $EXIT_INVALID_ARGS
      fi
      export_ip_access_rules "zones" "$2"
      ;;
    
    --list)
      if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
        log_error "Account ID and List ID required"
        log_error "Usage: $0 --list <account_id> <list_id>"
        exit $EXIT_INVALID_ARGS
      fi
      export_ip_list "$2" "$3"
      ;;
    
    --all-lists)
      if [ -z "${2:-}" ]; then
        log_error "Account ID required"
        log_error "Usage: $0 --all-lists <account_id>"
        exit $EXIT_INVALID_ARGS
      fi
      list_ip_lists "$2"
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
