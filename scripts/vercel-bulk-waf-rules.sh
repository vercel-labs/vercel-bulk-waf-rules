#!/bin/bash
# =============================================================================
# Vercel Bulk WAF Rules
# =============================================================================
#
# Bulk manage Vercel WAF (Web Application Firewall) rules via CSV.
# Supports IP allowlisting, WAF bypass, and automatic CIDR optimization.
#
# Two modes available:
#
#   DENY MODE (default):   Block all traffic EXCEPT from whitelisted IPs
#                          Use case: Private apps, vendor-only access
#
#   BYPASS MODE:           Bypass WAF/security checks for whitelisted IPs
#                          Use case: Public apps with vendor integrations
#                          (webhooks, scanners, bots, etc.)
#
# IMPORTANT:
# - WAF Custom Rules available on all Vercel plans
# - Changes affect traffic immediately
# - Firewall rules are PROJECT-SCOPED (not team/org-wide)
# - ALWAYS run with DRY_RUN=true first
#
# Usage:
#   ./vercel-bulk-waf-rules.sh apply vendor-ips.csv           # Create/update rule (deny mode)
#   RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply ips.csv # Bypass mode
#   ./vercel-bulk-waf-rules.sh show                           # Show current rules
#   ./vercel-bulk-waf-rules.sh audit                          # Check for the split-allowlist outage bug
#   ./vercel-bulk-waf-rules.sh disable                        # Disable rule temporarily
#   ./vercel-bulk-waf-rules.sh remove                         # Remove a single rule
#   ./vercel-bulk-waf-rules.sh purge                          # Remove ALL auto-managed rules
#   DRY_RUN=true ./vercel-bulk-waf-rules.sh apply ips.csv     # Preview changes
#
# Environment variables:
#   VERCEL_TOKEN (optional): Vercel API token - if not set, uses `vercel login` auth
#   PROJECT_ID (auto): Auto-detected from .vercel/project.json, or set manually
#   TEAM_ID (auto): Auto-detected from .vercel/project.json, or set manually
#   TEAM_SLUG (optional): Team slug (alternative to TEAM_ID)
#   RULE_MODE (optional): "deny" (default) or "bypass"
#   DRY_RUN (optional): Set to "true" to preview without applying
#   RULE_HOSTNAME (optional): Hostname pattern for scoped rules
#   AUDIT_LOG (optional): Path to audit log file
#
# Requirements:
#   - vercel CLI v50.5.1+ (or uses npx vercel@latest)
#   - jq for JSON parsing
#   - bc for calculations
#
# Security Notes:
#   - Store tokens in a secrets manager, not in env files committed to git
#   - Use minimal token scopes: read:project, write:project
#
# Changelog:
#   2.1.0 - P0 FIX: deny/allowlist mode no longer splits a large IP list across
#           sibling "(Part N/M)" rules. Sibling rules OR together, so a disjoint
#           split of a "ninc" (NOT IN) allowlist denied EVERY request, including
#           the allowlisted ones. Large allowlists now build ONE rule with ONE
#           condition group holding multiple ANDed ip_address/ninc conditions.
#           Hard ceiling: 65 conditions x 75 IPs = 4875 entries; above that the
#           script refuses instead of emitting a broken rule.
#           Adds the read-only 'audit' command to detect already-deployed
#           instances of the bug (exit 2 = VULNERABLE).
#           Bypass mode chunking is unchanged (positive matching ORs correctly).
#   2.0.0 - Two-mode support (deny/bypass), CIDR optimization, chunking.
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly SCRIPT_VERSION="2.1.0"
readonly RATE_LIMIT_DELAY_MS=800
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly MAX_IPS_PER_CONDITION=75  # Vercel limit per condition array

# Server-side schema caps (hard limits, enforced by the firewall API):
# 75 items per array condition value, 65 conditions per group, 25 groups per rule
readonly MAX_CONDITIONS_PER_GROUP=65
# Ceiling for a single allowlist (deny) rule: conditions AND, so all slices fit
# in one group. 65 conditions x 75 IPs each. More GROUPS would not help - groups
# OR, which reintroduces the outage one level up.
readonly MAX_ALLOWLIST_IPS=$((MAX_CONDITIONS_PER_GROUP * MAX_IPS_PER_CONDITION))
# Custom rules per project: 3 (Hobby) / 40 (Pro) / 1000 (Enterprise)
readonly MAX_RULES_PRO_PLAN=40

# Managed rule name prefixes (used by find_allowlist_rules and cmd_audit)
readonly ALLOWLIST_RULE_NAME="IP Allowlist - Auto-managed"

# Vercel CLI command (set in check_dependencies)
VERCEL_CMD=""

# Rule mode configuration
# - "deny" (allowlist): Block all traffic except whitelisted IPs
# - "bypass": Bypass WAF for whitelisted IPs (public apps)
# Mode is determined by: RULE_MODE env var, interactive prompt, or error in CI/CD

# Prompt user to select mode interactively
select_rule_mode() {
  echo "" >&2
  echo "Select rule mode:" >&2
  echo "" >&2
  echo "  1) allowlist  - Block ALL traffic except listed IPs" >&2
  echo "                  Use for: Private apps, vendor-only access" >&2
  echo "" >&2
  echo "  2) bypass     - Bypass WAF for listed IPs, allow all other traffic" >&2
  echo "                  Use for: Public apps with vendor integrations" >&2
  echo "" >&2
  read -p "Enter choice [1-2]: " choice
  case "$choice" in
    1) echo "deny" ;;
    2) echo "bypass" ;;
    *) echo "invalid" ;;
  esac
}

# Determine rule mode based on environment and context
resolve_rule_mode() {
  if [ -n "${RULE_MODE:-}" ]; then
    # Explicitly set via environment variable - use it
    if [[ "$RULE_MODE" != "deny" && "$RULE_MODE" != "bypass" ]]; then
      echo "ERROR: RULE_MODE must be 'deny' or 'bypass', got: $RULE_MODE" >&2
      exit 1
    fi
    echo "$RULE_MODE"
  elif [ -t 0 ]; then
    # Interactive terminal (TTY) - prompt user
    local mode
    mode=$(select_rule_mode)
    if [ "$mode" = "invalid" ]; then
      echo "ERROR: Invalid selection. Please enter 1 or 2." >&2
      exit 1
    fi
    echo "$mode"
  else
    # Non-interactive (CI/CD) - require explicit setting
    echo "ERROR: RULE_MODE must be set in non-interactive mode." >&2
    echo "" >&2
    echo "Set RULE_MODE to 'deny' or 'bypass':" >&2
    echo "  RULE_MODE=deny   - Block all except listed IPs (allowlist)" >&2
    echo "  RULE_MODE=bypass - Bypass WAF for listed IPs" >&2
    echo "" >&2
    echo "Example: RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply vendor-ips.csv" >&2
    exit 1
  fi
}

# Initialize rule mode (deferred until needed by commands that require it)
# This allows setup, optimize, and help to work without prompts
CURRENT_RULE_MODE=""
RULE_NAME=""
RULE_DESCRIPTION=""
RULE_IP_OP=""
RULE_ACTION=""

# Configure rule settings based on mode
configure_rule_mode() {
  if [ -n "$RULE_NAME" ]; then
    # Already configured
    return 0
  fi
  
  CURRENT_RULE_MODE=$(resolve_rule_mode)
  
  if [ "$CURRENT_RULE_MODE" = "bypass" ]; then
    RULE_NAME="IP Bypass - Auto-managed"
    RULE_DESCRIPTION="Bypass WAF/security for whitelisted IPs. Managed by vercel-bulk-waf-rules.sh"
    RULE_IP_OP="inc"       # Match IPs IN the list
    RULE_ACTION="bypass"   # Bypass WAF checks
  else
    RULE_NAME="IP Allowlist - Auto-managed"
    RULE_DESCRIPTION="Block all traffic except whitelisted IPs. Managed by vercel-bulk-waf-rules.sh"
    RULE_IP_OP="ninc"      # Match IPs NOT IN the list
    RULE_ACTION="deny"     # Deny matching traffic
  fi
}

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

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

# Safe string trimming
trim() {
  local var="$1"
  var="${var#"${var%%[![:space:]]*}"}"
  var="${var%"${var##*[![:space:]]}"}"
  echo "$var"
}

# Validate IPv4 address or CIDR
validate_ipv4() {
  local ip="$1"
  local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
  
  if [[ ! "$ip" =~ $ipv4_regex ]]; then
    return 1
  fi
  
  # Validate each octet is <= 255
  local ip_part="${ip%%/*}"
  IFS='.' read -ra octets <<< "$ip_part"
  for octet in "${octets[@]}"; do
    if [ "$octet" -gt 255 ]; then
      return 1
    fi
  done
  
  return 0
}

# Check for IPv6
is_ipv6() {
  local ip="$1"
  if [[ "$ip" =~ : ]]; then
    return 0
  fi
  return 1
}

# =============================================================================
# CIDR Aggregation Functions
# =============================================================================

# Convert IP to 32-bit integer
ip_to_int() {
  local ip="$1"
  local ip_part="${ip%%/*}"
  IFS='.' read -ra octets <<< "$ip_part"
  echo $(( (${octets[0]} << 24) + (${octets[1]} << 16) + (${octets[2]} << 8) + ${octets[3]} ))
}

# Convert 32-bit integer to IP
int_to_ip() {
  local int="$1"
  echo "$(( (int >> 24) & 255 )).$(( (int >> 16) & 255 )).$(( (int >> 8) & 255 )).$(( int & 255 ))"
}

# Get CIDR prefix for a block size (block size must be power of 2)
block_size_to_prefix() {
  local size="$1"
  local prefix=32
  local s=1
  while [ "$s" -lt "$size" ]; do
    s=$((s * 2))
    prefix=$((prefix - 1))
  done
  echo "$prefix"
}

# Check if IP is aligned to a given block size
is_aligned() {
  local ip_int="$1"
  local block_size="$2"
  [ $((ip_int % block_size)) -eq 0 ]
}

# Find the largest CIDR block that fits starting at ip_int and covering up to max_count IPs
# Returns: "prefix count" where prefix is the CIDR prefix and count is how many IPs it covers
find_largest_cidr() {
  local ip_int="$1"
  local max_count="$2"
  
  local best_prefix=32
  local best_count=1
  
  # Try progressively larger block sizes (must be power of 2 and aligned)
  local block_size=1
  while [ "$block_size" -le "$max_count" ]; do
    # Check alignment
    if is_aligned "$ip_int" "$block_size"; then
      best_prefix=$(block_size_to_prefix "$block_size")
      best_count="$block_size"
    else
      # Not aligned for this size, stop
      break
    fi
    block_size=$((block_size * 2))
  done
  
  echo "$best_prefix $best_count"
}

# Aggregate a sorted list of IP integers into CIDR blocks
# Input: newline-separated list of IP integers (sorted)
# Output: newline-separated list of CIDR notations
aggregate_ips_to_cidrs() {
  local ip_ints="$1"
  local result=""
  
  # Convert to array (compatible with bash 3.x on macOS)
  local -a ips=()
  while IFS= read -r line; do
    [ -n "$line" ] && ips+=("$line")
  done <<< "$ip_ints"
  
  local count=${#ips[@]}
  if [ "$count" -eq 0 ]; then
    return
  fi
  
  local i=0
  while [ "$i" -lt "$count" ]; do
    local start_ip="${ips[$i]}"
    
    # Find contiguous range starting at this IP
    local range_end="$i"
    while [ "$((range_end + 1))" -lt "$count" ]; do
      local next_ip="${ips[$((range_end + 1))]}"
      if [ "$next_ip" -eq "$((ips[range_end] + 1))" ]; then
        range_end=$((range_end + 1))
      else
        break
      fi
    done
    
    local range_count=$((range_end - i + 1))
    
    # Greedily assign CIDR blocks to cover this contiguous range
    local pos="$i"
    while [ "$pos" -le "$range_end" ]; do
      local remaining=$((range_end - pos + 1))
      local current_ip="${ips[$pos]}"
      
      # Find largest valid CIDR starting at current_ip covering up to remaining IPs
      local cidr_info
      cidr_info=$(find_largest_cidr "$current_ip" "$remaining")
      local prefix
      prefix=$(echo "$cidr_info" | cut -d' ' -f1)
      local covered
      covered=$(echo "$cidr_info" | cut -d' ' -f2)
      
      # Output CIDR
      local ip_str
      ip_str=$(int_to_ip "$current_ip")
      if [ "$prefix" -eq 32 ]; then
        result="${result}${ip_str}"$'\n'
      else
        result="${result}${ip_str}/${prefix}"$'\n'
      fi
      
      pos=$((pos + covered))
    done
    
    i=$((range_end + 1))
  done
  
  echo -n "$result"
}

# Main CIDR optimization function
# Input: JSON array of IPs (may include existing CIDRs)
# Output: JSON array of optimized IPs/CIDRs
optimize_ip_list() {
  local ips_json="$1"
  
  # Separate individual IPs from existing CIDRs
  local individual_ips
  individual_ips=$(echo "$ips_json" | jq -r '.[] | select(contains("/") | not)')
  
  local existing_cidrs
  existing_cidrs=$(echo "$ips_json" | jq -r '.[] | select(contains("/"))')
  
  # Convert individual IPs to integers and sort
  local ip_ints=""
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    local ip_int
    ip_int=$(ip_to_int "$ip")
    ip_ints="${ip_ints}${ip_int}"$'\n'
  done <<< "$individual_ips"
  
  # Sort integers
  local sorted_ints
  sorted_ints=$(echo -n "$ip_ints" | sort -n | uniq)
  
  # Aggregate to CIDRs
  local aggregated
  aggregated=$(aggregate_ips_to_cidrs "$sorted_ints")
  
  # Combine with existing CIDRs and output as JSON
  local all_entries=""
  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    all_entries="${all_entries}${entry}"$'\n'
  done <<< "$aggregated"
  
  while IFS= read -r cidr; do
    [ -z "$cidr" ] && continue
    all_entries="${all_entries}${cidr}"$'\n'
  done <<< "$existing_cidrs"
  
  # Convert to JSON array (deduplicated)
  echo -n "$all_entries" | sort -u | jq -R -s 'split("\n") | map(select(length > 0))'
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
    echo "[${timestamp}] user=${user} project=${PROJECT_ID:-unknown} action=${action} ${details}" >> "$log_file"
  fi
}

# Rate limit sleep
rate_limit_sleep() {
  local ms="${1:-$RATE_LIMIT_DELAY_MS}"
  sleep "$(echo "scale=3; $ms / 1000" | bc)"
}

# =============================================================================
# Auto-detect from Vercel CLI
# =============================================================================

# Fetch team slug from Vercel API using team ID
# Some Vercel API endpoints prefer slug over teamId
fetch_team_slug() {
  local team_id="$1"
  
  if [ -z "$team_id" ]; then
    return 1
  fi
  
  log_debug "Fetching team slug for: $team_id"
  
  local response
  response=$(api_request "GET" "/v2/teams/${team_id}")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    local slug
    slug=$(echo "$body" | jq -r '.slug // empty' 2>/dev/null)
    if [ -n "$slug" ]; then
      echo "$slug"
      return 0
    fi
  fi
  
  return 1
}

# Try to load PROJECT_ID and TEAM_ID from .vercel/project.json
# This file is created by `vercel link`
auto_detect_vercel_config() {
  local search_dir="${1:-.}"
  local vercel_config=""
  
  # Search for .vercel/project.json in current dir and parent dirs
  local dir="$search_dir"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/.vercel/project.json" ]; then
      vercel_config="$dir/.vercel/project.json"
      break
    fi
    dir=$(dirname "$dir")
  done
  
  if [ -z "$vercel_config" ]; then
    return 1
  fi
  
  log_debug "Found Vercel config: $vercel_config"
  
  # Extract projectId and orgId (team ID)
  local project_id
  local org_id
  project_id=$(jq -r '.projectId // empty' "$vercel_config" 2>/dev/null)
  org_id=$(jq -r '.orgId // empty' "$vercel_config" 2>/dev/null)
  
  if [ -n "$project_id" ] && [ -z "${PROJECT_ID:-}" ]; then
    export PROJECT_ID="$project_id"
    log_info "Auto-detected PROJECT_ID: $project_id"
  fi
  
  if [ -n "$org_id" ] && [ -z "${TEAM_ID:-}" ]; then
    export TEAM_ID="$org_id"
    log_info "Auto-detected TEAM_ID: $org_id"
  fi
  
  return 0
}

# Fetch team slug after auth is validated (requires API access)
resolve_team_slug() {
  # Skip if we already have a slug or no team ID
  if [ -n "${TEAM_SLUG:-}" ] || [ -z "${TEAM_ID:-}" ]; then
    return 0
  fi
  
  local slug
  slug=$(fetch_team_slug "$TEAM_ID")
  
  if [ -n "$slug" ]; then
    export TEAM_SLUG="$slug"
    log_info "Resolved TEAM_SLUG: $slug"
  fi
}

# Generate shell exports for environment setup
generate_env_exports() {
  local vercel_config="${1:-.vercel/project.json}"
  
  if [ ! -f "$vercel_config" ]; then
    echo "# Run 'vercel link' first to create .vercel/project.json"
    return 1
  fi
  
  local project_id
  local org_id
  project_id=$(jq -r '.projectId // empty' "$vercel_config" 2>/dev/null)
  org_id=$(jq -r '.orgId // empty' "$vercel_config" 2>/dev/null)
  
  echo "# Auto-generated from $vercel_config"
  echo "# Add these to your shell or .env file:"
  echo ""
  if [ -n "$project_id" ]; then
    echo "export PROJECT_ID=\"$project_id\""
  fi
  if [ -n "$org_id" ]; then
    echo "export TEAM_ID=\"$org_id\""
  fi
  echo ""
  echo "# Authentication options:"
  echo "# Option 1: Run 'vercel login' (recommended for local use)"
  echo "# Option 2: Set VERCEL_TOKEN (required for CI/CD)"
  echo "# export VERCEL_TOKEN=\"your-token-here\""
}

# =============================================================================
# API Functions (using vercel api CLI)
# =============================================================================

# Make API request using vercel api CLI
# Returns: response body followed by HTTP status code on last line
# This maintains compatibility with the original curl-based api_request
api_request() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"
  local attempt=1
  
  while [ $attempt -le $MAX_RETRIES ]; do
    log_debug "API request: $method $endpoint (attempt $attempt)"
    
    # Build command arguments
    local -a args=("api" "$endpoint" -X "$method" --raw)
    
    # Pass token if set (CI/CD compatibility)
    if [ -n "${VERCEL_TOKEN:-}" ]; then
      args+=(-t "$VERCEL_TOKEN")
    fi
    
    # Add scope for team context (prefer slug over ID)
    if [ -n "${TEAM_SLUG:-}" ]; then
      args+=(--scope "$TEAM_SLUG")
    elif [ -n "${TEAM_ID:-}" ]; then
      args+=(--scope "$TEAM_ID")
    fi
    
    # Handle request body
    local tmp_file=""
    if [ -n "$data" ]; then
      log_debug "Request body: $data"
      tmp_file=$(mktemp)
      echo "$data" > "$tmp_file"
      args+=(--input "$tmp_file")
    fi
    
    # Execute the request
    # Note: We redirect stderr to /dev/null to suppress the CLI banner
    # (e.g., "Vercel CLI 50.7.1 | api is in beta") which would corrupt JSON parsing
    local response=""
    local exit_code=0
    
    response=$($VERCEL_CMD "${args[@]}" 2>/dev/null) || exit_code=$?
    
    # Clean up temp file
    [ -n "$tmp_file" ] && rm -f "$tmp_file"
    
    log_debug "Response (exit code $exit_code): $response"
    
    # Convert exit code to HTTP-like status code for compatibility
    local http_code
    if [ $exit_code -eq 0 ]; then
      http_code="200"
    else
      # Try to extract error info from response
      local error_code
      error_code=$(echo "$response" | jq -r '.error.code // empty' 2>/dev/null || echo "")
      
      if [[ "$response" == *"rate limit"* ]] || [[ "$error_code" == "RATE_LIMITED" ]]; then
        http_code="429"
      elif [[ "$response" == *"not found"* ]] || [[ "$error_code" == "NOT_FOUND" ]]; then
        http_code="404"
      elif [[ "$response" == *"forbidden"* ]] || [[ "$response" == *"unauthorized"* ]]; then
        http_code="403"
      else
        http_code="500"
      fi
    fi
    
    # Handle rate limiting with retry
    if [ "$http_code" = "429" ]; then
      log_warn "Rate limited (429). Backing off for ${RATE_LIMIT_BACKOFF_SEC}s... (attempt $attempt/$MAX_RETRIES)"
      audit_log "RATE_LIMITED" "attempt=$attempt backoff_sec=$RATE_LIMIT_BACKOFF_SEC"
      sleep "$RATE_LIMIT_BACKOFF_SEC"
      ((attempt++))
      continue
    fi
    
    # Return response body and HTTP code
    echo "$response"
    echo "$http_code"
    return 0
  done
  
  echo "Max retries exceeded"
  echo "429"
  return 1
}

# Validate authentication (either via vercel login or VERCEL_TOKEN)
validate_auth() {
  log_info "Validating authentication..."
  
  # Build command arguments
  local -a args=("api" "/v2/user" --raw)
  
  # Pass token if set
  if [ -n "${VERCEL_TOKEN:-}" ]; then
    args+=(-t "$VERCEL_TOKEN")
  fi
  
  local response=""
  local exit_code=0
  
  # Redirect stderr to /dev/null to suppress CLI banner that corrupts JSON parsing
  response=$($VERCEL_CMD "${args[@]}" 2>/dev/null) || exit_code=$?
  
  if [ $exit_code -ne 0 ]; then
    log_error "Authentication failed"
    if [ -n "${VERCEL_TOKEN:-}" ]; then
      log_error "VERCEL_TOKEN is set but may be invalid or expired"
      log_error "Ensure your token has the required scopes: read:project, write:project"
    else
      log_error "Not logged in. Run 'vercel login' or set VERCEL_TOKEN"
    fi
    if [ -n "${TEAM_ID:-}${TEAM_SLUG:-}" ]; then
      log_error "For team projects, also ensure: read:team, write:team"
    fi
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    return 1
  fi
  
  local username
  username=$(echo "$response" | jq -r '.user.username // .username // "unknown"')
  log_info "Authenticated as: $username"
  return 0
}

# Get current firewall configuration
get_firewall_config() {
  local project_id="$1"
  
  log_info "Fetching current firewall configuration..."
  
  # Build endpoint with query parameters
  local endpoint="/v1/security/firewall/config/active?projectId=${project_id}"
  
  # Add team parameters if available
  if [ -n "${TEAM_ID:-}" ]; then
    endpoint="${endpoint}&teamId=${TEAM_ID}"
  fi
  if [ -n "${TEAM_SLUG:-}" ]; then
    endpoint="${endpoint}&slug=${TEAM_SLUG}"
  fi
  
  local response
  local http_code
  local body
  
  log_debug "Trying: GET $endpoint"
  response=$(api_request "GET" "$endpoint")
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    echo "$body"
    return 0
  fi
  
  # Try alternative endpoint without /active
  endpoint="/v1/security/firewall/config?projectId=${project_id}"
  if [ -n "${TEAM_ID:-}" ]; then
    endpoint="${endpoint}&teamId=${TEAM_ID}"
  fi
  if [ -n "${TEAM_SLUG:-}" ]; then
    endpoint="${endpoint}&slug=${TEAM_SLUG}"
  fi
  
  log_debug "Trying: GET $endpoint"
  response=$(api_request "GET" "$endpoint")
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    echo "$body"
    return 0
  fi
  
  # All methods failed
  log_error "Failed to get firewall config (HTTP $http_code)"
  
  if [ "$http_code" = "404" ]; then
    log_error "Firewall config not found. Possible causes:"
    log_error "  - Project is not on Pro/Enterprise plan (Firewall requires Pro+)"
    log_error "  - Firewall is not enabled for this project"
    log_error "  - PROJECT_ID is incorrect: $project_id"
    log_error "  - TEAM_ID/TEAM_SLUG mismatch"
  elif [ "$http_code" = "403" ]; then
    log_error "Access denied. Check token permissions (need read:project, write:project)."
  fi
  
  echo "$body" | jq '.' 2>/dev/null || echo "$body"
  return 1
}

# Find our managed allowlist rule(s) in the config
# Returns all matching rules (including chunked "Part X/Y" rules and duplicates)
# If RULE_NAME is set, searches for that specific name pattern
# If RULE_NAME is not set, searches for ALL managed rules (both bypass and allowlist)
find_allowlist_rules() {
  local config="$1"
  local rules=""
  
  # Handle empty or invalid config
  if [ -z "$config" ] || [ "$config" = "{}" ] || [ "$config" = "null" ]; then
    log_debug "Config is empty, returning empty array"
    echo "[]"
    return 0
  fi
  
  # Determine search pattern(s)
  local bypass_name="IP Bypass - Auto-managed"
  local allowlist_name="IP Allowlist - Auto-managed"
  
  if [ -n "$RULE_NAME" ]; then
    # Mode is configured - search for specific rule type
    log_debug "Searching for rules starting with name: $RULE_NAME"
    
    # Structure 1: Nested under .active.rules (most common from API)
    rules=$(echo "$config" | jq -c --arg name "$RULE_NAME" '[.active.rules[]? | select(.name == $name or (.name | startswith($name + " (Part")))] // []' 2>/dev/null) || rules="[]"
    
    if [ -n "$rules" ] && [ "$rules" != "[]" ] && [ "$rules" != "null" ]; then
      log_debug "Found rules in .active.rules: $rules"
      echo "$rules"
      return 0
    fi
    
    # Structure 2: Direct .rules array
    rules=$(echo "$config" | jq -c --arg name "$RULE_NAME" '[.rules[]? | select(.name == $name or (.name | startswith($name + " (Part")))] // []' 2>/dev/null) || rules="[]"
    
    if [ -n "$rules" ] && [ "$rules" != "[]" ] && [ "$rules" != "null" ]; then
      log_debug "Found rules in .rules: $rules"
      echo "$rules"
      return 0
    fi
  else
    # No mode configured - search for ALL managed rules (both bypass and allowlist)
    log_debug "Searching for all managed rules (bypass and allowlist)"
    
    # Structure 1: Nested under .active.rules (most common from API)
    rules=$(echo "$config" | jq -c --arg bypass "$bypass_name" --arg allowlist "$allowlist_name" '
      [.active.rules[]? | select(
        .name == $bypass or (.name | startswith($bypass + " (Part")) or
        .name == $allowlist or (.name | startswith($allowlist + " (Part"))
      )] // []' 2>/dev/null) || rules="[]"
    
    if [ -n "$rules" ] && [ "$rules" != "[]" ] && [ "$rules" != "null" ]; then
      log_debug "Found rules in .active.rules: $rules"
      echo "$rules"
      return 0
    fi
    
    # Structure 2: Direct .rules array
    rules=$(echo "$config" | jq -c --arg bypass "$bypass_name" --arg allowlist "$allowlist_name" '
      [.rules[]? | select(
        .name == $bypass or (.name | startswith($bypass + " (Part")) or
        .name == $allowlist or (.name | startswith($allowlist + " (Part"))
      )] // []' 2>/dev/null) || rules="[]"
    
    if [ -n "$rules" ] && [ "$rules" != "[]" ] && [ "$rules" != "null" ]; then
      log_debug "Found rules in .rules: $rules"
      echo "$rules"
      return 0
    fi
  fi
  
  log_debug "No matching rules found"
  echo "[]"
  return 0
}

# Find single allowlist rule (for backward compatibility)
find_allowlist_rule() {
  local config="$1"
  local rules
  rules=$(find_allowlist_rules "$config") || rules="[]"
  
  # Return the first rule if any exist
  local first_rule
  first_rule=$(echo "$rules" | jq -c '.[0] // empty' 2>/dev/null) || first_rule=""
  
  if [ -n "$first_rule" ] && [ "$first_rule" != "null" ]; then
    echo "$first_rule"
    return 0
  fi
  
  # Return empty string, not error (to avoid triggering set -e)
  echo ""
  return 0
}

# Build endpoint with query parameters for firewall operations
build_firewall_endpoint() {
  local project_id="$1"
  local endpoint="/v1/security/firewall/config?projectId=${project_id}"
  
  if [ -n "${TEAM_ID:-}" ]; then
    endpoint="${endpoint}&teamId=${TEAM_ID}"
  fi
  if [ -n "${TEAM_SLUG:-}" ]; then
    endpoint="${endpoint}&slug=${TEAM_SLUG}"
  fi
  
  echo "$endpoint"
}

# Build the conditions array for ONE condition group.
#
# IPs are packed into ceil(n / MAX_IPS_PER_CONDITION) ip_address conditions that
# all live in the SAME group. This MUST stay conditions-in-one-group and must
# never become sibling rules or extra condition groups: conditions within a
# group AND together, while rules and condition groups OR together. For an
# allowlist (op "ninc" + action "deny") the correct decomposition is
# deny if (ip NOT IN s1) AND (ip NOT IN s2) ... == deny if ip NOT IN (s1 U s2),
# whereas ORing the negated slices matches every address (each address is absent
# from at least one disjoint slice) and denies ALL traffic - a total outage.
build_ip_conditions() {
  local ips_json="$1"
  local ip_op="$2"
  local hostname="${3:-}"
  
  local ip_conditions
  ip_conditions=$(jq -n \
    --arg ip_op "$ip_op" \
    --argjson max "$MAX_IPS_PER_CONDITION" \
    --argjson ips "$ips_json" \
    '[range(0; ($ips | length); $max) as $i
      | {"type": "ip_address", "op": $ip_op, "value": $ips[$i:$i + $max]}]')
  
  if [ -n "$hostname" ]; then
    # Scoped to specific hostname
    jq -n \
      --arg hostname "$hostname" \
      --argjson ip_conditions "$ip_conditions" \
      '[{"type": "host", "op": "eq", "value": $hostname}] + $ip_conditions'
  else
    # Project-wide
    echo "$ip_conditions"
  fi
}

# Create or update the allowlist rule
update_allowlist_rule() {
  local project_id="$1"
  local ips_json="$2"
  local action="$3"  # "insert" or "update"
  local existing_rule_id="${4:-}"
  local hostname="${RULE_HOSTNAME:-}"
  
  local endpoint
  endpoint=$(build_firewall_endpoint "$project_id")
  
  # Build conditions array using mode-specific operator
  local conditions
  conditions=$(build_ip_conditions "$ips_json" "$RULE_IP_OP" "$hostname")
  
  # Build the rule value with mode-specific action
  local rule_value
  rule_value=$(jq -n \
    --arg name "$RULE_NAME" \
    --arg description "$RULE_DESCRIPTION" \
    --arg rule_action "$RULE_ACTION" \
    --argjson conditions "$conditions" \
    '{
      name: $name,
      description: $description,
      active: true,
      conditionGroup: [{conditions: $conditions}],
      action: {
        mitigate: {
          action: $rule_action
        }
      }
    }')
  
  # Build the request body
  local request_body
  if [ "$action" = "update" ] && [ -n "$existing_rule_id" ]; then
    request_body=$(jq -n \
      --arg action "rules.update" \
      --arg id "$existing_rule_id" \
      --argjson value "$rule_value" \
      '{action: $action, id: $id, value: $value}')
  else
    request_body=$(jq -n \
      --arg action "rules.insert" \
      --argjson value "$rule_value" \
      '{action: $action, id: null, value: $value}')
  fi
  
  log_debug "Request body: $request_body"
  
  local response
  response=$(api_request "PATCH" "$endpoint" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    return 0
  else
    log_error "Failed to $action rule (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
}

# Create or update the allowlist rule with a custom name (for chunked rules)
update_allowlist_rule_with_name() {
  local project_id="$1"
  local ips_json="$2"
  local action="$3"  # "insert" or "update"
  local existing_rule_id="${4:-}"
  local custom_name="${5:-$RULE_NAME}"
  local hostname="${RULE_HOSTNAME:-}"
  
  local endpoint
  endpoint=$(build_firewall_endpoint "$project_id")
  
  # Build conditions array using mode-specific operator
  local conditions
  conditions=$(build_ip_conditions "$ips_json" "$RULE_IP_OP" "$hostname")
  
  # Build the rule value with custom name and mode-specific action
  local rule_value
  rule_value=$(jq -n \
    --arg name "$custom_name" \
    --arg description "$RULE_DESCRIPTION" \
    --arg rule_action "$RULE_ACTION" \
    --argjson conditions "$conditions" \
    '{
      name: $name,
      description: $description,
      active: true,
      conditionGroup: [{conditions: $conditions}],
      action: {
        mitigate: {
          action: $rule_action
        }
      }
    }')
  
  # Build the request body
  local request_body
  if [ "$action" = "update" ] && [ -n "$existing_rule_id" ]; then
    request_body=$(jq -n \
      --arg action "rules.update" \
      --arg id "$existing_rule_id" \
      --argjson value "$rule_value" \
      '{action: $action, id: $id, value: $value}')
  else
    request_body=$(jq -n \
      --arg action "rules.insert" \
      --argjson value "$rule_value" \
      '{action: $action, id: null, value: $value}')
  fi
  
  log_debug "Request body: $request_body"
  
  local response
  response=$(api_request "PATCH" "$endpoint" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    return 0
  else
    log_error "Failed to $action rule (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
}

# Disable the allowlist rule (set active=false)
disable_allowlist_rule() {
  local project_id="$1"
  local rule_id="$2"
  
  local endpoint
  endpoint=$(build_firewall_endpoint "$project_id")
  
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    '{action: "rules.update", id: $id, value: {active: false}}')
  
  local response
  response=$(api_request "PATCH" "$endpoint" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    return 0
  else
    log_error "Failed to disable rule (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
}

# Remove the allowlist rule with retry logic
remove_allowlist_rule() {
  local project_id="$1"
  local rule_id="$2"
  local max_retries="${3:-5}"
  
  local endpoint
  endpoint=$(build_firewall_endpoint "$project_id")
  
  # IMPORTANT: Vercel API requires "value: null" even for deletions
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    '{action: "rules.remove", id: $id, value: null}')
  
  local retry=0
  local delay=2  # Start with 2 seconds for retries
  local max_delay=60  # Cap at 60 seconds
  
  while [ "$retry" -lt "$max_retries" ]; do
    local response
    response=$(api_request "PATCH" "$endpoint" "$request_body")
    
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
      return 0
    fi
    
    # Check for retryable errors
    local error_code
    error_code=$(echo "$body" | jq -r '.error.code // empty' 2>/dev/null)
    
    # Retry on internal errors or 5xx status codes
    if [ "$error_code" = "FIREWALL_INTERNAL_ERROR" ] || [[ "$http_code" =~ ^5 ]]; then
      retry=$((retry + 1))
      if [ "$retry" -lt "$max_retries" ]; then
        log_warn "Vercel error (HTTP $http_code) removing rule $rule_id, retrying in ${delay}s... (attempt $((retry+1))/$max_retries)"
        sleep "$delay"
        # Exponential backoff with jitter
        delay=$((delay * 2 + RANDOM % 5))
        [ "$delay" -gt "$max_delay" ] && delay="$max_delay"
        continue
      fi
    fi
    
    log_error "Failed to remove rule $rule_id (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  done
  
  log_error "Failed to remove rule $rule_id after $max_retries attempts"
  return 1
}

# =============================================================================
# CSV Parsing (Optimized)
# =============================================================================

# Fast inline IP validation using BASH_REMATCH (no subshells)
# Returns: 0 = valid IPv4, 1 = invalid, 2 = IPv6
validate_ip_fast() {
  local ip="$1"
  
  # Quick reject IPv6
  [[ "$ip" == *:* ]] && return 2
  
  # IPv4 regex check with CIDR support
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]] || return 1
  
  # Validate octets are <= 255 using BASH_REMATCH (no subprocess)
  (( BASH_REMATCH[1] <= 255 && BASH_REMATCH[2] <= 255 && 
     BASH_REMATCH[3] <= 255 && BASH_REMATCH[4] <= 255 )) || return 1
  
  return 0
}

# Parse CSV using awk for speed
# Handles: comments, header row, quoted fields, whitespace trimming
# Compatible with both BSD awk (macOS) and gawk (Linux)
parse_csv() {
  local csv_file="$1"
  local valid_ips=""
  local valid_count=0
  local error_count=0
  local line_num=0
  
  log_info "Parsing CSV file: $csv_file"
  
  # Use awk to extract IPs from CSV (handles quotes, skips comments/headers)
  local extracted_ips
  extracted_ips=$(awk -F',' '
    # Skip empty lines and comments
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    
    # Process data lines
    NF > 0 {
      ip = $1
      # Remove surrounding quotes if present
      gsub(/^[[:space:]]*"?/, "", ip)
      gsub(/"?[[:space:]]*$/, "", ip)
      # Skip header row
      if (tolower(ip) == "ip") next
      # Skip empty
      if (ip == "") next
      # Output: line_number:ip
      print NR ":" ip
    }
  ' "$csv_file")
  
  # Validate each IP (fast inline validation)
  while IFS=':' read -r line_num ip; do
    [ -z "$ip" ] && continue
    
    local validation_result
    validate_ip_fast "$ip"
    validation_result=$?
    
    if [ $validation_result -eq 2 ]; then
      log_error "Line $line_num: IPv6 not supported - $ip"
      ((error_count++))
      continue
    elif [ $validation_result -eq 1 ]; then
      log_error "Line $line_num: Invalid IP format - $ip"
      ((error_count++))
      continue
    fi
    
    # Append to valid IPs (newline-separated)
    valid_ips+="${ip}"$'\n'
    ((valid_count++))
    
    log_debug "Line $line_num: $ip"
    
  done <<< "$extracted_ips"
  
  log_info "Parsed $valid_count valid IPs ($error_count errors)"
  
  if [ "$error_count" -gt 0 ]; then
    log_warn "Some IPs had validation errors. Review the errors above."
  fi
  
  # Convert to JSON array in a single jq call (fast!)
  if [ -n "$valid_ips" ]; then
    printf '%s' "$valid_ips" | jq -R -s 'split("\n") | map(select(length > 0))'
  else
    echo "[]"
  fi
}

# =============================================================================
# Commands
# =============================================================================

cmd_apply() {
  local csv_file="$1"
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  if [ ! -f "$csv_file" ]; then
    log_error "CSV file not found: $csv_file"
    exit 1
  fi
  
  # Parse CSV
  local ips_json
  ips_json=$(parse_csv "$csv_file")
  
  local ip_count
  ip_count=$(echo "$ips_json" | jq 'length')
  
  if [ "$ip_count" -eq 0 ]; then
    log_error "No valid IPs found in CSV"
    exit 1
  fi
  
  # Check for IP limit and offer optimization
  local needs_chunking=false
  local rules_needed=1
  local conditions_needed=1
  
  if [ "$ip_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
    log_warn "IP count ($ip_count) exceeds limit ($MAX_IPS_PER_CONDITION per rule)"
    echo ""
    
    # Offer CIDR optimization
    if [ "${SKIP_OPTIMIZE:-false}" != "true" ]; then
      log_info "Attempting CIDR optimization to reduce IP count..."
      local optimized_json
      optimized_json=$(optimize_ip_list "$ips_json")
      local optimized_count
      optimized_count=$(echo "$optimized_json" | jq 'length')
      
      if [ "$optimized_count" -lt "$ip_count" ]; then
        local reduction=$((ip_count - optimized_count))
        log_info "CIDR optimization reduced entries from $ip_count to $optimized_count (-$reduction)"
        ips_json="$optimized_json"
        ip_count="$optimized_count"
      else
        log_info "No CIDR optimization possible (IPs are not contiguous)"
      fi
    fi
    
    # Check if we still need to split the list across conditions/rules
    if [ "$ip_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
      if [ "$RULE_IP_OP" = "ninc" ]; then
        # Allowlist/deny: split across ANDed conditions inside ONE rule.
        # Sibling rules OR, so splitting a "ninc" allowlist across rules denies
        # every request (see build_ip_conditions). Never chunk this mode.
        # RULE_HOSTNAME consumes one of the 65 condition slots in the group, so
        # the effective ceiling drops by one slice when it is set.
        local allowlist_ceiling="$MAX_ALLOWLIST_IPS"
        if [ -n "${RULE_HOSTNAME:-}" ]; then
          allowlist_ceiling=$(( (MAX_CONDITIONS_PER_GROUP - 1) * MAX_IPS_PER_CONDITION ))
        fi
        if [ "$ip_count" -gt "$allowlist_ceiling" ]; then
          log_error "IP count ($ip_count) exceeds the allowlist ceiling of $allowlist_ceiling entries."
          log_error ""
          log_error "A deny/allowlist rule must keep every 'ninc' slice in ONE condition group"
          log_error "($MAX_CONDITIONS_PER_GROUP conditions x $MAX_IPS_PER_CONDITION IPs = $MAX_ALLOWLIST_IPS entries max), because"
          log_error "conditions AND together while rules and condition groups OR together."
          log_error "Splitting further would deny ALL traffic, including allowlisted IPs."
          if [ -n "${RULE_HOSTNAME:-}" ]; then
            log_error ""
            log_error "RULE_HOSTNAME is set, which spends one condition slot on the host match,"
            log_error "lowering the ceiling from $MAX_ALLOWLIST_IPS to $allowlist_ceiling."
          fi
          log_error ""
          log_error "Going above the ceiling requires a bypass-rules + terminal-deny topology,"
          log_error "which this script does not implement."
          log_error ""
          log_error "Recommended: run '$0 optimize <csv_file> optimized-ips.csv' first to"
          log_error "CIDR-aggregate the list, then apply the optimized CSV."
          audit_log "ALLOWLIST_REFUSED_OVER_CEILING" "ip_count=$ip_count ceiling=$allowlist_ceiling hostname=${RULE_HOSTNAME:-none}"
          exit 1
        fi
        conditions_needed=$(( (ip_count + MAX_IPS_PER_CONDITION - 1) / MAX_IPS_PER_CONDITION ))
        log_warn "Will create 1 rule with $conditions_needed ANDed conditions (max $MAX_IPS_PER_CONDITION IPs each)"
      else
        # Bypass: positive matching ("inc") ORs correctly across sibling rules.
        needs_chunking=true
        rules_needed=$(( (ip_count + MAX_IPS_PER_CONDITION - 1) / MAX_IPS_PER_CONDITION ))
        log_warn "Will create $rules_needed separate rules (max $MAX_IPS_PER_CONDITION IPs each)"
        if [ "$rules_needed" -gt "$MAX_RULES_PRO_PLAN" ]; then
          log_warn "=============================================="
          log_warn "$rules_needed rules exceeds the Pro plan cap of $MAX_RULES_PRO_PLAN custom rules per project."
          log_warn "(Caps: 3 Hobby / $MAX_RULES_PRO_PLAN Pro / 1000 Enterprise.)"
          log_warn "The apply will likely fail with an opaque HTTP 400 partway through."
          log_warn "Run '$0 optimize <csv_file> optimized-ips.csv' first to reduce the entry count."
          log_warn "=============================================="
        fi
      fi
    fi
  fi
  
  echo ""
  log_info "Project ID: $project_id"
  [ -n "${TEAM_ID:-}" ] && log_info "Team ID: $TEAM_ID"
  log_info "Rule mode: $CURRENT_RULE_MODE"
  log_info "Rule name: $RULE_NAME"
  log_info "IPs to allowlist: $ip_count"
  [ "$needs_chunking" = true ] && log_info "Rules to create: $rules_needed"
  [ "$conditions_needed" -gt 1 ] && log_info "Conditions in rule: $conditions_needed (ANDed, single condition group)"
  log_info "Hostname scope: ${RULE_HOSTNAME:-project-wide}"
  echo ""
  
  # Preview
  log_info "Preview (first 10 IPs):"
  echo "$ips_json" | jq '.[0:10]'
  echo ""
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    echo "=============================================="
    echo "  DRY RUN - No changes made"
    echo "=============================================="
    echo ""
    echo "Mode: $CURRENT_RULE_MODE"
    if [ "$needs_chunking" = true ]; then
      echo "Would create $rules_needed rules with $ip_count total IPs."
    elif [ "$conditions_needed" -gt 1 ]; then
      echo "Would create/update 1 rule with $ip_count IPs across $conditions_needed ANDed conditions."
    else
      echo "Would create/update rule with $ip_count IPs."
    fi
    echo ""
    echo "Ordering: new rule(s) are created FIRST; any superseded auto-managed rules"
    echo "          are removed only AFTER that succeeds."
    echo ""
    if [ "$CURRENT_RULE_MODE" = "bypass" ]; then
      echo "EFFECT: Listed IPs will BYPASS WAF/security checks."
      echo "        All other traffic flows normally through security rules."
    else
      echo "EFFECT: All traffic from IPs NOT in this list will be BLOCKED."
    fi
    echo ""
    echo "To apply changes, run without DRY_RUN=true"
    exit 0
  fi
  
  # Get current config
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    # If we can't get config, assume no rules exist and proceed with insert
    log_warn "Could not fetch current config. Will attempt to create new rule."
    config="{}"
  fi
  
  log_debug "Firewall config response: $(echo "$config" | jq -c '.' 2>/dev/null || echo "$config")"
  
  # Check for existing rules and clean up
  local all_rules
  all_rules=$(find_allowlist_rules "$config")
  local existing_rule_count
  existing_rule_count=$(echo "$all_rules" | jq 'length' 2>/dev/null || echo "0")
  
  log_debug "Found $existing_rule_count existing rule(s) with our name"
  
  local action="insert"
  local existing_rule_id=""
  
  # For multi-rule scenarios, always clean up and recreate
  if [ "$needs_chunking" = true ] && [ "$existing_rule_count" -gt 0 ]; then
    log_info "Found $existing_rule_count existing rule(s). Will remove and recreate with new chunking."
    action="insert"
  elif [ "$existing_rule_count" -gt 1 ]; then
    # Multiple rules found - clean up duplicates
    log_warn "Found $existing_rule_count duplicate rules. Will clean up and create fresh rule."
    action="insert"
  elif [ "$existing_rule_count" -eq 1 ] && [ "$needs_chunking" = false ]; then
    # Single rule found and we only need one - update it
    local existing_rule
    existing_rule=$(echo "$all_rules" | jq -c '.[0]')
    existing_rule_id=$(echo "$existing_rule" | jq -r '.id')
    local existing_ip_count
    existing_ip_count=$(echo "$existing_rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value | length' 2>/dev/null || echo "0")
    
    log_info "Found existing allowlist rule (ID: $existing_rule_id)"
    log_info "Current IP count: $existing_ip_count"
    action="update"
  else
    log_info "No existing allowlist rule found. Will create new rule(s)."
  fi
  
  # Confirm
  echo ""
  echo "=============================================="
  echo "  WARNING"
  echo "=============================================="
  echo ""
  echo "Mode: $CURRENT_RULE_MODE"
  echo ""
  if [ "$needs_chunking" = true ]; then
    echo "This will CREATE $rules_needed rules."
  elif [ "$action" = "update" ]; then
    echo "This will UPDATE the existing rule."
  else
    echo "This will CREATE a new rule."
  fi
  if [ "$action" = "insert" ] && [ "$existing_rule_count" -gt 0 ]; then
    echo "$existing_rule_count existing rule(s) will then be REPLACED - they are removed"
    echo "only AFTER the new rule(s) are created, so a failure never leaves the"
    echo "project unprotected."
  fi
  echo ""
  if [ "$CURRENT_RULE_MODE" = "bypass" ]; then
    echo "EFFECT: Listed IPs will BYPASS WAF/security checks."
    echo "        All other traffic flows normally through security rules."
  else
    echo "EFFECT: All traffic from IPs NOT in this list will be BLOCKED."
  fi
  echo ""
  echo "IPs to allowlist: $ip_count"
  echo ""
  read -p "Are you sure you want to proceed? Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo ""
    echo "Aborted. No changes were made."
    exit 1
  fi
  
  # Apply the rule(s)
  log_info "Applying allowlist rule(s)..."
  
  local mode_upper
  mode_upper=$(echo "$CURRENT_RULE_MODE" | tr '[:lower:]' '[:upper:]')
  local created_count=0
  
  if [ "$needs_chunking" = true ]; then
    # Create chunked rules
    local chunk_start=0
    local chunk_num=1
    local success_count=0
    
    while [ "$chunk_start" -lt "$ip_count" ]; do
      local chunk_ips
      chunk_ips=$(echo "$ips_json" | jq ".[$chunk_start:$((chunk_start + MAX_IPS_PER_CONDITION))]")
      local chunk_size
      chunk_size=$(echo "$chunk_ips" | jq 'length')
      
      log_info "Creating rule $chunk_num/$rules_needed ($chunk_size IPs)..."
      
      # Create rule with part number in name
      local part_suffix=" (Part $chunk_num/$rules_needed)"
      if update_allowlist_rule_with_name "$project_id" "$chunk_ips" "insert" "" "${RULE_NAME}${part_suffix}"; then
        ((success_count++))
        log_debug "Rule $chunk_num created successfully"
      else
        log_error "Failed to create rule $chunk_num"
      fi
      
      chunk_start=$((chunk_start + MAX_IPS_PER_CONDITION))
      ((chunk_num++))
      rate_limit_sleep
    done
    
    # A partial create must not trigger removal: dropping the old rules would
    # leave the IPs of the missing chunks with no coverage at all
    if [ "$success_count" -ne "$rules_needed" ]; then
      log_error "Only $success_count of $rules_needed rules were created"
      echo ""
      echo "=============================================="
      echo "  INCOMPLETE - NO RULES WERE REMOVED"
      echo "=============================================="
      echo ""
      echo "Current project state:"
      echo "  - $success_count newly created rule(s) named '${RULE_NAME} (Part N/$rules_needed)'"
      echo "  - $existing_rule_count pre-existing auto-managed rule(s), left UNTOUCHED"
      echo ""
      echo "Nothing was removed, so existing coverage is intact."
      echo ""
      echo "Next steps:"
      echo "  1. $0 show                     # inspect what is in place now"
      echo "  2. Remove the $success_count partial rule(s) via the Vercel dashboard, or"
      echo "     $0 purge                    # remove ALL auto-managed rules, then re-apply"
      echo "  3. Re-run apply once the API is healthy"
      echo ""
      audit_log "${mode_upper}_INSERT_CHUNKED_PARTIAL" "ip_count=$ip_count rules_created=$success_count rules_needed=$rules_needed removed=0"
      exit 1
    fi
    
    created_count="$success_count"
    log_info "Created $created_count rule(s) successfully."
  else
    # Single rule
    if ! update_allowlist_rule "$project_id" "$ips_json" "$action" "$existing_rule_id"; then
      log_error "Failed to $action rule"
      if [ "$action" = "insert" ] && [ "$existing_rule_count" -gt 0 ]; then
        echo ""
        echo "$existing_rule_count existing auto-managed rule(s) were left in place - nothing was removed."
        echo "The project's current protection is unchanged. Re-run apply once the API is healthy."
        echo ""
      fi
      audit_log "${mode_upper}_$(echo "$action" | tr '[:lower:]' '[:upper:]')_FAILED" "ip_count=$ip_count removed=0"
      exit 1
    fi
    
    created_count=1
    log_info "Rule ${action}ed successfully."
  fi
  
  # Replace stale rules only AFTER the new rule(s) exist. Removing first would be
  # fail-OPEN in deny mode: a failed insert would leave the project with no
  # allowlist rule at all. Overlapping instead keeps deny mode fail-CLOSED (the
  # old rules keep blocking) and is idempotent in bypass mode.
  # $all_rules was captured from the config fetched BEFORE any insert, so it can
  # only ever contain pre-existing rule IDs - never the rule just created.
  local removal_failures=0
  local removed_count=0
  if [ "$action" = "insert" ] && [ "$existing_rule_count" -gt 0 ]; then
    if [ "${SKIP_REMOVAL:-false}" = "true" ]; then
      log_warn "SKIP_REMOVAL=true - Skipping removal of $existing_rule_count existing rule(s)"
      log_warn "You may have duplicate rules. Clean up manually in Vercel dashboard."
    else
      log_info "Removing $existing_rule_count superseded rule(s)..."
      for rule_id in $(echo "$all_rules" | jq -r '.[].id'); do
        if remove_allowlist_rule "$project_id" "$rule_id" 3; then
          log_info "Removed rule: $rule_id"
          ((removed_count++))
        else
          log_warn "Failed to remove rule: $rule_id (will continue anyway)"
          ((removal_failures++))
        fi
        # Brief delay between removals
        sleep 1
      done
      
      if [ "$removal_failures" -gt 0 ]; then
        log_warn "$removal_failures rule(s) could not be removed. You may need to remove them manually via Vercel dashboard."
        log_warn "The new rule(s) are already active, so these stale rules are now redundant."
        echo ""
        read -p "Continue? (yes/no): " CONTINUE
        if [ "$CONTINUE" != "yes" ]; then
          echo "Aborted. New rule(s) remain in place; remove the stale rules manually."
          exit 1
        fi
      fi
    fi
  fi
  
  echo ""
  echo "=============================================="
  echo "  SUCCESS"
  echo "=============================================="
  echo ""
  if [ "$needs_chunking" = true ]; then
    log_info "Created $created_count rules successfully! (mode: $CURRENT_RULE_MODE)"
    log_info "Total whitelisted IPs: $ip_count"
  else
    log_info "Rule ${action}ed successfully! (mode: $CURRENT_RULE_MODE)"
    log_info "Whitelisted IPs: $ip_count"
    [ "$conditions_needed" -gt 1 ] && log_info "Packed into $conditions_needed ANDed conditions in a single rule."
  fi
  [ "$removed_count" -gt 0 ] && log_info "Removed $removed_count superseded rule(s)."
  if [ "$CURRENT_RULE_MODE" = "bypass" ]; then
    log_info "Listed IPs will bypass WAF/security checks."
  else
    log_info "All other traffic will be BLOCKED."
  fi
  
  if [ "$needs_chunking" = true ]; then
    audit_log "${mode_upper}_INSERT_CHUNKED" "ip_count=$ip_count rules=$created_count removed=$removed_count"
  else
    audit_log "${mode_upper}_$(echo "$action" | tr '[:lower:]' '[:upper:]')" "ip_count=$ip_count removed=$removed_count"
  fi
}

cmd_show() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching WAF rules for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local all_rules
  all_rules=$(find_allowlist_rules "$config")
  local rule_count
  rule_count=$(echo "$all_rules" | jq 'length' 2>/dev/null || echo "0")
  
  echo ""
  echo "=============================================="
  echo "  WAF Rules for $project_id"
  echo "=============================================="
  echo ""
  
  if [ "$rule_count" -eq 0 ]; then
    echo "No auto-managed WAF rules found."
    echo ""
    echo "Use './vercel-bulk-waf-rules.sh apply vendor-ips.csv' to create one."
  else
    echo "Found $rule_count auto-managed rule(s):"
    echo ""
    
    # Iterate through each rule
    echo "$all_rules" | jq -c '.[]' | while read -r rule; do
      local rule_id
      rule_id=$(echo "$rule" | jq -r '.id')
      local rule_name
      rule_name=$(echo "$rule" | jq -r '.name')
      local active
      active=$(echo "$rule" | jq -r '.active')
      local ips
      ips=$(echo "$rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value' 2>/dev/null)
      local ip_count
      ip_count=$(echo "$ips" | jq 'length' 2>/dev/null || echo "0")
      local hostname
      hostname=$(echo "$rule" | jq -r '.conditionGroup[0].conditions[] | select(.type == "host") | .value // empty' 2>/dev/null)
      local action
      action=$(echo "$rule" | jq -r '.action.mitigate.action // "unknown"' 2>/dev/null)
      
      # Determine rule type from name
      local rule_type="unknown"
      if [[ "$rule_name" == *"Bypass"* ]]; then
        rule_type="bypass"
      elif [[ "$rule_name" == *"Allowlist"* ]]; then
        rule_type="allowlist (deny others)"
      fi
      
      echo "----------------------------------------------"
      echo "Rule:        $rule_name"
      echo "ID:          $rule_id"
      echo "Type:        $rule_type"
      echo "Status:      $([ "$active" = "true" ] && echo "ACTIVE" || echo "DISABLED")"
      echo "IP Count:    $ip_count"
      echo "Scope:       ${hostname:-project-wide}"
      echo ""
      echo "IPs:"
      if [ -n "$ips" ] && [ "$ips" != "null" ]; then
        echo "$ips" | jq -r '.[]' 2>/dev/null | while read -r ip; do
          echo "  - $ip"
        done
      else
        echo "  (none)"
      fi
      echo ""
    done
  fi
}

cmd_disable() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching WAF rules for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local all_rules
  all_rules=$(find_allowlist_rules "$config")
  local rule_count
  rule_count=$(echo "$all_rules" | jq 'length' 2>/dev/null || echo "0")
  
  if [ "$rule_count" -eq 0 ]; then
    log_error "No auto-managed WAF rules found"
    exit 1
  fi
  
  # Filter to only active rules
  local active_rules
  active_rules=$(echo "$all_rules" | jq '[.[] | select(.active == true)]')
  local active_count
  active_count=$(echo "$active_rules" | jq 'length' 2>/dev/null || echo "0")
  
  if [ "$active_count" -eq 0 ]; then
    log_info "All $rule_count rule(s) are already disabled"
    exit 0
  fi
  
  echo ""
  echo "Found $active_count active rule(s) to disable:"
  echo ""
  echo "$active_rules" | jq -r '.[] | "  - \(.name) (\(.id))"'
  echo ""
  log_warn "This will DISABLE $active_count rule(s)."
  log_warn "Traffic restrictions will be lifted until rules are re-enabled."
  echo ""
  read -p "Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 1
  fi
  
  local success_count=0
  for rule_id in $(echo "$active_rules" | jq -r '.[].id'); do
    if disable_allowlist_rule "$project_id" "$rule_id"; then
      log_info "Disabled rule: $rule_id"
      audit_log "RULE_DISABLED" "rule_id=$rule_id"
      ((success_count++))
    else
      log_error "Failed to disable rule: $rule_id"
    fi
    sleep 1
  done
  
  log_info "Disabled $success_count of $active_count rule(s)"
}

cmd_remove() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching WAF rules for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local all_rules
  all_rules=$(find_allowlist_rules "$config")
  local rule_count
  rule_count=$(echo "$all_rules" | jq 'length' 2>/dev/null || echo "0")
  
  if [ "$rule_count" -eq 0 ]; then
    log_error "No auto-managed WAF rules found"
    exit 1
  fi
  
  # If multiple rules, suggest using purge instead
  if [ "$rule_count" -gt 1 ]; then
    echo ""
    echo "Found $rule_count auto-managed rule(s):"
    echo ""
    echo "$all_rules" | jq -r '.[] | "  - \(.name) (\(.id))"'
    echo ""
    log_warn "Multiple rules found. Use 'purge' to remove all, or set RULE_MODE to target specific type."
    log_info "Example: RULE_MODE=bypass ./vercel-bulk-waf-rules.sh remove"
    exit 1
  fi
  
  local rule
  rule=$(echo "$all_rules" | jq -c '.[0]')
  local rule_id
  rule_id=$(echo "$rule" | jq -r '.id')
  local rule_name
  rule_name=$(echo "$rule" | jq -r '.name')
  
  echo ""
  echo "Found rule: $rule_name"
  echo "ID: $rule_id"
  echo ""
  log_warn "This will PERMANENTLY DELETE this rule."
  log_warn "Traffic restrictions will be lifted after deletion."
  echo ""
  read -p "Type 'DELETE' to confirm: " CONFIRM
  if [ "$CONFIRM" != "DELETE" ]; then
    echo "Aborted."
    exit 1
  fi
  
  if remove_allowlist_rule "$project_id" "$rule_id"; then
    log_info "Rule removed successfully: $rule_name"
    audit_log "RULE_REMOVED" "rule_id=$rule_id rule_name=$rule_name"
  else
    log_error "Failed to remove rule"
    exit 1
  fi
}

# Remove ALL rules managed by this tool (including chunked parts)
cmd_purge() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  local delay="${PURGE_DELAY:-1}"
  local max_retries="${PURGE_RETRIES:-5}"
  local disable_first="${PURGE_DISABLE_FIRST:-false}"
  local reverse_order="${PURGE_REVERSE:-false}"
  
  log_info "Fetching firewall configuration for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  # Find ALL rules matching our naming pattern
  local all_rules
  all_rules=$(find_allowlist_rules "$config")
  
  local rule_count
  rule_count=$(echo "$all_rules" | jq 'length' 2>/dev/null || echo "0")
  
  if [ "$rule_count" -eq 0 ]; then
    log_info "No auto-managed WAF rules found."
    log_info "Only rules with names starting with 'IP Bypass - Auto-managed' or 'IP Allowlist - Auto-managed' would be removed."
    exit 0
  fi
  
  echo ""
  echo "=============================================="
  echo "  Auto-Managed Rules Found"
  echo "=============================================="
  echo ""
  log_info "Found $rule_count rule(s) managed by this tool:"
  echo ""
  
  # Show all matching rules
  echo "$all_rules" | jq -r '.[] | "  - \(.id): \(.name) (active=\(.active))"'
  
  echo ""
  log_warn "This will PERMANENTLY DELETE all $rule_count rule(s) listed above."
  log_warn "Only auto-managed rules (IP Bypass/Allowlist) will be removed."
  log_warn "Pre-existing rules with other names are NOT affected."
  echo ""
  log_info "Options: delay=${delay}s, retries=${max_retries}, disable_first=${disable_first}, reverse=${reverse_order}"
  echo ""
  
  if [ "${DRY_RUN:-false}" = "true" ]; then
    echo "=============================================="
    echo "  DRY RUN - No changes made"
    echo "=============================================="
    echo ""
    echo "Would remove $rule_count rule(s)."
    echo ""
    echo "Tuning options (set via environment variables):"
    echo "  PURGE_DELAY=10        - Longer delay between deletions"
    echo "  PURGE_RETRIES=10      - More retries per rule"
    echo "  PURGE_DISABLE_FIRST=true - Disable rules before removing"
    echo "  PURGE_REVERSE=true    - Delete in reverse order (Part 6 first)"
    exit 0
  fi
  
  read -p "Type 'PURGE' to confirm deletion of all $rule_count rules: " CONFIRM
  if [ "$CONFIRM" != "PURGE" ]; then
    echo "Aborted."
    exit 1
  fi
  
  echo ""
  
  # Get rule IDs (optionally in reverse order)
  local rule_ids
  if [ "$reverse_order" = "true" ]; then
    log_info "Processing rules in reverse order..."
    rule_ids=$(echo "$all_rules" | jq -r '.[].id' | tac 2>/dev/null || echo "$all_rules" | jq -r '[.[].id] | reverse | .[]')
  else
    rule_ids=$(echo "$all_rules" | jq -r '.[].id')
  fi
  
  # Optionally disable all rules first
  if [ "$disable_first" = "true" ]; then
    log_info "Disabling all $rule_count rule(s) first..."
    echo ""
    for rule_id in $rule_ids; do
      if [ -n "$rule_id" ] && [ "$rule_id" != "null" ]; then
        log_info "  Disabling: $rule_id..."
        disable_allowlist_rule "$project_id" "$rule_id" 2>/dev/null || true
        sleep "$delay"
      fi
    done
    echo ""
    log_info "All rules disabled. Waiting 3s before removal..."
    sleep 3
  fi
  
  log_info "Removing $rule_count rule(s)..."
  echo ""
  
  local success_count=0
  local fail_count=0
  
  for rule_id in $rule_ids; do
    if [ -n "$rule_id" ] && [ "$rule_id" != "null" ]; then
      local rule_name
      rule_name=$(echo "$all_rules" | jq -r --arg id "$rule_id" '.[] | select(.id == $id) | .name')
      
      log_info "Removing: $rule_name ($rule_id)..."
      
      if remove_allowlist_rule "$project_id" "$rule_id" "$max_retries"; then
        ((success_count++))
        log_info "  Removed successfully"
        audit_log "ALLOWLIST_PURGE_REMOVED" "rule_id=$rule_id rule_name=$rule_name"
      else
        ((fail_count++))
        log_warn "  Failed to remove (may need manual cleanup)"
      fi
      
      # Delay between deletions
      log_debug "Waiting ${delay}s before next operation..."
      sleep "$delay"
    fi
  done
  
  echo ""
  echo "=============================================="
  echo "  Purge Complete"
  echo "=============================================="
  echo ""
  log_info "Successfully removed: $success_count rule(s)"
  
  if [ "$fail_count" -gt 0 ]; then
    log_warn "Failed to remove: $fail_count rule(s)"
    log_warn ""
    log_warn "Troubleshooting tips:"
    log_warn "  1. Wait a few minutes and try again (Vercel API may be overloaded)"
    log_warn "  2. Try: PURGE_DELAY=10 PURGE_RETRIES=10 ./vercel-bulk-waf-rules.sh purge"
    log_warn "  3. Try: PURGE_DISABLE_FIRST=true ./vercel-bulk-waf-rules.sh purge"
    log_warn "  4. Try: PURGE_REVERSE=true ./vercel-bulk-waf-rules.sh purge"
    log_warn "  5. Delete manually via Vercel dashboard"
    audit_log "ALLOWLIST_PURGE_PARTIAL" "success=$success_count failed=$fail_count"
    exit 1
  fi
  
  audit_log "ALLOWLIST_PURGE_COMPLETE" "removed=$success_count"
}

cmd_backup() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  local backup_dir="${BACKUP_DIR:-./backups}"
  
  log_info "Creating backup of firewall configuration..."
  
  # Create backup directory
  mkdir -p "$backup_dir"
  chmod 700 "$backup_dir"
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local timestamp
  timestamp=$(date +"%Y%m%d-%H%M%S")
  local backup_file="${backup_dir}/backup-${project_id}-${timestamp}.json"
  
  # Build backup structure
  jq -n \
    --arg project_id "$project_id" \
    --arg team_id "${TEAM_ID:-}" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg user "${USER:-unknown}" \
    --argjson config "$config" \
    '{
      metadata: {
        project_id: $project_id,
        team_id: $team_id,
        backup_timestamp: $timestamp,
        backup_user: $user,
        type: "firewall_config"
      },
      config: $config
    }' > "$backup_file"
  
  chmod 600 "$backup_file"
  
  log_info "Backup created: $backup_file"
  audit_log "BACKUP_CREATED" "file=$backup_file"
}

# Read-only check for the pre-2.1.0 split-allowlist outage bug.
#
# Outage signature: a "ninc" (NOT IN) allowlist split across ORing containers.
# Because sibling rules and sibling condition groups OR together, a disjoint
# split denies every address (each one is absent from at least one slice).
# Exit codes: 0 = OK/INFO, 2 = VULNERABLE (greppable for CI).
cmd_audit() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Auditing WAF rules for the split-allowlist outage bug..."
  
  local config
  if ! config=$(get_firewall_config "$project_id"); then
    exit 1
  fi
  
  local managed_rules
  managed_rules=$(find_allowlist_rules "$config")
  
  # Only deny/allowlist rules can carry the bug; bypass rules OR correctly.
  local allowlist_rules
  allowlist_rules=$(echo "$managed_rules" | jq -c --arg prefix "$ALLOWLIST_RULE_NAME" \
    '[.[] | select(.name | startswith($prefix))]' 2>/dev/null || echo "[]")
  
  local allowlist_count
  allowlist_count=$(echo "$allowlist_rules" | jq 'length' 2>/dev/null || echo "0")
  
  echo ""
  echo "=============================================="
  echo "  Allowlist Audit for $project_id"
  echo "=============================================="
  echo ""
  
  if [ "$allowlist_count" -eq 0 ]; then
    echo "RESULT: INFO"
    echo ""
    echo "No auto-managed allowlist rules found ('$ALLOWLIST_RULE_NAME')."
    echo "Nothing to audit."
    audit_log "AUDIT_INFO" "allowlist_rules=0"
    exit 0
  fi
  
  # Active deny rules that negate an IP set - the pieces of a split allowlist
  local denying_rules
  denying_rules=$(echo "$allowlist_rules" | jq -c '
    [.[]
     | select(.active == true)
     | select(.action.mitigate.action == "deny")
     | select([.conditionGroup[]?.conditions[]?
               | select(.type == "ip_address" and .op == "ninc")] | length > 0)]' 2>/dev/null || echo "[]")
  
  local denying_count
  denying_count=$(echo "$denying_rules" | jq 'length' 2>/dev/null || echo "0")
  
  # Group-level variant: one rule, multiple groups, a negated IP set in any group
  local multi_group_rules
  multi_group_rules=$(echo "$denying_rules" | jq -c '
    [.[]
     | select((.conditionGroup | length) > 1)
     | select([.conditionGroup[] | select([.conditions[]?
               | select(.type == "ip_address" and .op == "ninc")] | length > 0)] | length > 0)]' 2>/dev/null || echo "[]")
  
  local multi_group_count
  multi_group_count=$(echo "$multi_group_rules" | jq 'length' 2>/dev/null || echo "0")
  
  local vulnerable=false
  local variant=""
  local offending="[]"
  
  if [ "$denying_count" -ge 2 ]; then
    vulnerable=true
    variant="sibling rules"
    offending="$denying_rules"
  elif [ "$multi_group_count" -ge 1 ]; then
    vulnerable=true
    variant="condition groups"
    offending="$multi_group_rules"
  fi
  
  if [ "$vulnerable" = false ]; then
    echo "RESULT: OK"
    echo ""
    echo "Found $allowlist_count auto-managed allowlist rule(s); no split-allowlist pattern detected."
    echo "$allowlist_rules" | jq -r '.[] | "  - \(.name) (\(.id)) active=\(.active)"'
    audit_log "AUDIT_OK" "allowlist_rules=$allowlist_count denying_rules=$denying_count"
    exit 0
  fi
  
  local distinct_ips
  distinct_ips=$(echo "$offending" | jq '
    [.[] | .conditionGroup[]?.conditions[]?
     | select(.type == "ip_address" and .op == "ninc") | .value[]?] | unique | length' 2>/dev/null || echo "0")
  
  echo "RESULT: VULNERABLE"
  echo ""
  echo "A 'ninc' (NOT IN) allowlist is split across ORing $variant."
  echo "Sibling rules and sibling condition groups OR together, so every address"
  echo "is absent from at least one slice and matches a deny. ALL traffic is being"
  echo "blocked, including the allowlisted IPs."
  echo ""
  echo "Offending rules:"
  echo "$offending" | jq -r '.[] | "  - \(.name) (\(.id)) groups=\(.conditionGroup | length) active=\(.active)"'
  echo ""
  echo "Distinct IPs/CIDRs across offending rules: $distinct_ips"
  echo ""
  echo "REMEDIATION:"
  echo "  If the site is currently DOWN, stop the bleeding first:"
  echo "    $0 disable      # deactivate the managed rule(s)"
  echo "    $0 remove       # or remove a single rule"
  echo "    $0 purge        # or remove ALL auto-managed rules"
  echo ""
  echo "  Then re-apply with this version (>= $SCRIPT_VERSION), which packs the list"
  echo "  into ONE rule with ANDed conditions:"
  echo "    DRY_RUN=true RULE_MODE=deny $0 apply <csv_file>"
  echo "    RULE_MODE=deny $0 apply <csv_file>"
  echo ""
  echo "  If the list exceeds $MAX_ALLOWLIST_IPS entries, run '$0 optimize <csv_file>' first."
  echo ""
  audit_log "AUDIT_VULNERABLE" "variant=$variant rules=$denying_count distinct_ips=$distinct_ips"
  exit 2
}

cmd_optimize() {
  local csv_file="$1"
  local output_file="${2:-}"
  
  if [ ! -f "$csv_file" ]; then
    log_error "CSV file not found: $csv_file"
    exit 1
  fi
  
  log_info "Analyzing IPs for CIDR optimization..."
  echo ""
  
  # Parse CSV to get IPs
  local ips_json
  ips_json=$(parse_csv "$csv_file")
  
  local original_count
  original_count=$(echo "$ips_json" | jq 'length')
  
  if [ "$original_count" -eq 0 ]; then
    log_error "No valid IPs found in CSV"
    exit 1
  fi
  
  log_info "Original IP count: $original_count"
  
  # Optimize IPs to CIDRs
  local optimized_json
  optimized_json=$(optimize_ip_list "$ips_json")
  
  local optimized_count
  optimized_count=$(echo "$optimized_json" | jq 'length')
  
  local reduction
  reduction=$((original_count - optimized_count))
  local reduction_pct
  if [ "$original_count" -gt 0 ]; then
    reduction_pct=$((reduction * 100 / original_count))
  else
    reduction_pct=0
  fi
  
  echo ""
  echo "=============================================="
  echo "  CIDR Optimization Results"
  echo "=============================================="
  echo ""
  echo "  Original entries:  $original_count"
  echo "  Optimized entries: $optimized_count"
  echo "  Reduction:         $reduction entries ($reduction_pct%)"
  echo ""
  
  # Check if we're still over the limit (packing differs per mode)
  if [ "$optimized_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
    local chunks_needed=$(( (optimized_count + MAX_IPS_PER_CONDITION - 1) / MAX_IPS_PER_CONDITION ))
    log_warn "Still exceeds $MAX_IPS_PER_CONDITION entries per condition."
    log_warn "deny/allowlist mode:  1 rule with $chunks_needed ANDed conditions (ceiling: $MAX_ALLOWLIST_IPS entries)."
    if [ "$optimized_count" -gt "$MAX_ALLOWLIST_IPS" ]; then
      log_warn "  -> $optimized_count entries EXCEEDS the $MAX_ALLOWLIST_IPS allowlist ceiling. 'apply' will refuse in deny mode."
    fi
    log_warn "bypass mode:          $chunks_needed separate rules (Pro plan caps custom rules at $MAX_RULES_PRO_PLAN)."
  else
    log_info "Optimized list fits in a single $MAX_IPS_PER_CONDITION-entry condition!"
  fi
  
  echo ""
  
  # Show sample of optimized list
  log_info "Optimized entries (first 20):"
  echo "$optimized_json" | jq -r '.[0:20][]'
  
  local cidr_count
  cidr_count=$(echo "$optimized_json" | jq '[.[] | select(contains("/"))] | length')
  local single_count=$((optimized_count - cidr_count))
  
  echo ""
  log_info "CIDR ranges: $cidr_count, Individual IPs: $single_count"
  
  # Output to file if specified
  if [ -n "$output_file" ]; then
    echo ""
    log_info "Writing optimized list to: $output_file"
    
    # Write as CSV with comments
    {
      echo "# Optimized IP Allowlist"
      echo "# Generated from: $csv_file"
      echo "# Original: $original_count entries, Optimized: $optimized_count entries"
      echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
      echo "#"
      echo "# ip,vendor_name,notes"
      echo "$optimized_json" | jq -r '.[]' | while read -r entry; do
        echo "$entry,Optimized,Auto-aggregated CIDR"
      done
    } > "$output_file"
    
    log_info "Done! Use './vercel-bulk-waf-rules.sh apply $output_file' to apply."
  else
    echo ""
    log_info "To save optimized list, run:"
    echo "  $0 optimize $csv_file optimized-ips.csv"
  fi
}

cmd_setup() {
  local project_dir="${1:-$(pwd)}"
  
  echo ""
  echo "=============================================="
  echo "  Vercel Bulk WAF Rules - Setup"
  echo "=============================================="
  echo ""
  echo "Uses the 'vercel api' CLI command (v50.5.1+)"
  echo "Version: $SCRIPT_VERSION"
  echo ""
  
  # Check for .vercel/project.json
  local vercel_config=""
  local dir="$project_dir"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/.vercel/project.json" ]; then
      vercel_config="$dir/.vercel/project.json"
      break
    fi
    dir=$(dirname "$dir")
  done
  
  if [ -z "$vercel_config" ]; then
    log_warn "No .vercel/project.json found in $project_dir or parent directories."
    echo ""
    echo "To enable auto-detection, run 'vercel link' in your project directory:"
    echo ""
    echo "  cd /path/to/your/vercel/project"
    echo "  vercel link"
    echo ""
    echo "Or set environment variables manually:"
    echo ""
    echo "  export PROJECT_ID=\"prj_xxxxx\"          # Get from Vercel dashboard"
    echo "  export TEAM_ID=\"team_xxxxx\"            # Optional, for team projects"
    echo ""
    echo "Authentication options:"
    echo "  Option 1: Run 'vercel login' (recommended for local use)"
    echo "  Option 2: export VERCEL_TOKEN=\"xxx\"  (required for CI/CD)"
    echo ""
    return 0
  fi
  
  log_info "Found Vercel config: $vercel_config"
  echo ""
  
  local project_id
  local org_id
  project_id=$(jq -r '.projectId // empty' "$vercel_config" 2>/dev/null)
  org_id=$(jq -r '.orgId // empty' "$vercel_config" 2>/dev/null)
  
  echo "Detected configuration:"
  [ -n "$project_id" ] && echo "  PROJECT_ID: $project_id"
  [ -n "$org_id" ] && echo "  TEAM_ID:    $org_id"
  echo ""
  
  echo "----------------------------------------------"
  echo "Setup Options:"
  echo "----------------------------------------------"
  echo ""
  echo "Option 1: Auto-detect (recommended)"
  echo ""
  echo "  The script auto-detects PROJECT_ID and TEAM_ID from .vercel/project.json."
  echo "  For local use, just run 'vercel login' first."
  echo ""
  echo "  vercel login"
  echo "  ./vercel-bulk-waf-rules.sh apply vendor-ips.csv"
  echo ""
  
  echo "Option 2: CI/CD with VERCEL_TOKEN"
  echo ""
  [ -n "$project_id" ] && echo "  export PROJECT_ID=\"$project_id\""
  [ -n "$org_id" ] && echo "  export TEAM_ID=\"$org_id\""
  echo "  export VERCEL_TOKEN=\"your-token-here\""
  echo "  ./vercel-bulk-waf-rules.sh apply vendor-ips.csv"
  echo ""
  
  echo "----------------------------------------------"
  echo ""
  echo "Create a token at: https://vercel.com/account/tokens"
  echo "Required scopes: read:project, write:project"
  echo ""
}

show_usage() {
  cat << EOF
Vercel Bulk WAF Rules
Version: $SCRIPT_VERSION

Bulk manage Vercel WAF rules via CSV using the 'vercel api' CLI (v50.5.1+).

DESCRIPTION:
  Create and manage WAF rules with two modes:

  DENY MODE (default):   Block all traffic EXCEPT from whitelisted IPs
                         Use case: Private apps, vendor-only access

  BYPASS MODE:           Bypass WAF/security checks for whitelisted IPs  
                         Use case: Public apps with vendor integrations
                         (webhooks, scanners, bots, etc.)

USAGE:
  $0 setup                        Show environment setup instructions
  $0 apply <csv_file>             Create/update rule with IPs from CSV
  $0 optimize <csv_file> [output] Optimize IPs into CIDR ranges
  $0 show                         Show current firewall rules
  $0 audit                        Check for the split-allowlist outage bug (read-only)
  $0 disable                      Disable rule temporarily
  $0 remove                       Remove a single rule
  $0 purge                        Remove ALL auto-managed rules
  $0 backup                       Export current firewall configuration
  $0 --help                       Show this help message

OPTIONS:
  --help                  Show this help message

ENVIRONMENT VARIABLES:
  VERCEL_TOKEN   (optional) Vercel API token - if not set, uses 'vercel login' auth
  PROJECT_ID     (auto)     Auto-detected from .vercel/project.json, or set manually
  TEAM_ID        (auto)     Auto-detected from .vercel/project.json, or set manually
  TEAM_SLUG      (optional) Team slug (alternative to TEAM_ID)
  RULE_MODE      (optional) "deny" (default) or "bypass" - only needed for 'apply'
  RULE_HOSTNAME  (optional) Hostname pattern for scoped rules (e.g., "api.example.com")
  DRY_RUN        (optional) Set to "true" for preview mode
  AUDIT_LOG      (optional) Path to audit log file
  DEBUG          (optional) Set to "true" for verbose output
  BACKUP_DIR     (optional) Directory for backups (default: ./backups)

  Note: PROJECT_ID and TEAM_ID are auto-detected from .vercel/project.json
        if you've run 'vercel link' in your project. Run '$0 setup' for help.

AUTHENTICATION:
  This script supports two authentication methods:

  1. Vercel CLI login (recommended for local use):
     $ vercel login
     $ ./vercel-bulk-waf-rules.sh show

  2. VERCEL_TOKEN (required for CI/CD):
     $ export VERCEL_TOKEN="your-token-here"
     $ ./vercel-bulk-waf-rules.sh show

CSV FORMAT:
  ip,vendor_name,notes
  1.2.3.4,Acme Corp,Payment gateway
  5.6.7.0/24,Partner Inc,API integration

EXAMPLES:
  # First time setup (local)
  cd /path/to/your/vercel/project
  vercel link                                    # Creates .vercel/project.json
  vercel login                                   # Authenticate
  ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  # CI/CD setup
  export VERCEL_TOKEN="your-token"
  export PROJECT_ID="prj_xxx"
  ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  # DENY MODE (default) - Block all except allowlisted IPs
  ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  # BYPASS MODE - Bypass WAF for allowlisted IPs (public apps)
  RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  # Preview changes (dry run)
  DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  # Show current configuration
  ./vercel-bulk-waf-rules.sh show

  # Audit for the split-allowlist outage bug (exit 0 = OK, 2 = VULNERABLE)
  ./vercel-bulk-waf-rules.sh audit

  # Disable rule temporarily
  ./vercel-bulk-waf-rules.sh disable

  # Remove ALL auto-managed rules (safe - only removes rules created by this tool)
  ./vercel-bulk-waf-rules.sh purge

  # Scope to specific hostname
  RULE_HOSTNAME="api.crocs.com" ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

RULE MODES:
  RULE_MODE=deny (default):
    - Rule name: "IP Allowlist - Auto-managed"
    - Logic: Block IPs NOT in the list
    - Effect: ONLY allowlisted IPs can reach the app
    - Use for: Private/internal apps, vendor-only access

  RULE_MODE=bypass:
    - Rule name: "IP Bypass - Auto-managed"
    - Logic: Bypass WAF for IPs IN the list
    - Effect: All traffic flows, but listed IPs skip security checks
    - Use for: Public apps with vendor integrations (webhooks, scanners, bots)

EOF
}

# =============================================================================
# Dependency Check
# =============================================================================

check_dependencies() {
  # Check for jq
  if ! command -v jq &> /dev/null; then
    log_error "Required dependency: jq"
    log_error "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
  fi
  
  # Check for bc
  if ! command -v bc &> /dev/null; then
    log_error "Required dependency: bc"
    exit 1
  fi
  
  # Check for vercel CLI (with npx fallback)
  if command -v vercel &> /dev/null; then
    VERCEL_CMD="vercel"
    local version
    version=$(vercel --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    log_debug "Using vercel CLI: $version"
  elif command -v npx &> /dev/null; then
    VERCEL_CMD="npx vercel@latest"
    log_info "Using npx vercel@latest (install vercel globally for faster execution)"
  else
    log_error "vercel CLI required. Install with: npm i -g vercel"
    log_error "Or ensure npx is available (comes with npm)"
    exit 1
  fi
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Check dependencies first
  check_dependencies
  
  if [ $# -eq 0 ]; then
    show_usage
    exit 1
  fi
  
  local command="$1"
  shift
  
  # Setup command doesn't require auth
  if [ "$command" = "setup" ]; then
    cmd_setup "$@"
    exit 0
  fi
  
  # Optimize command doesn't require auth (local operation)
  if [ "$command" = "optimize" ]; then
    if [ -z "${1:-}" ]; then
      log_error "CSV file required"
      echo "Usage: $0 optimize <csv_file> [output_file.csv]"
      exit 1
    fi
    cmd_optimize "$1" "${2:-}"
    exit 0
  fi
  
  # Help doesn't require anything
  if [ "$command" = "--help" ] || [ "$command" = "-h" ]; then
    show_usage
    exit 0
  fi
  
  # Auto-detect PROJECT_ID and TEAM_ID from .vercel/project.json
  auto_detect_vercel_config "$(pwd)" 2>/dev/null || true
  
  # Validate authentication for all other commands
  if ! validate_auth; then
    exit 1
  fi
  
  # Resolve team slug from team ID (some API endpoints prefer slug)
  resolve_team_slug
  echo ""
  
  case "$command" in
    apply)
      # Only apply needs rule mode selection (creates/updates rules)
      configure_rule_mode
      if [ -z "${1:-}" ]; then
        log_error "CSV file required"
        echo "Usage: $0 apply <csv_file>"
        exit 1
      fi
      cmd_apply "$1"
      ;;
    show)
      cmd_show
      ;;
    audit)
      cmd_audit
      ;;
    disable)
      cmd_disable
      ;;
    remove)
      cmd_remove
      ;;
    purge)
      cmd_purge
      ;;
    backup)
      cmd_backup
      ;;
    *)
      log_error "Unknown command: $command"
      show_usage
      exit 1
      ;;
  esac
}

# Skip execution when sourced, so tests can exercise helpers directly
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
