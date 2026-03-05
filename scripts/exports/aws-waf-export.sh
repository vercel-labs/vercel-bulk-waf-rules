#!/bin/bash
# =============================================================================
# AWS WAF Export Script
# =============================================================================
#
# Exports IP addresses and CIDR ranges from AWS WAF v2 (WAFV2) IP Sets
# to CSV format compatible with Vercel Firewall.
#
# The exported IPs can be used with Vercel WAF in any mode:
#   - deny mode:   Block all traffic except from exported IPs
#   - bypass mode: Skip WAF checks for exported IPs
#
# IMPORTANT:
# - Requires AWS CLI v2 with wafv2 support
# - Uses standard AWS credential chain (AWS_PROFILE, env vars, IAM roles, SSO)
# - Required IAM permissions: wafv2:ListIPSets, wafv2:GetIPSet, wafv2:ListWebACLs,
#   wafv2:GetWebACL, sts:GetCallerIdentity
# - AWS WAF Classic is EOL (Sept 2025) — use WAFV2 only
#
# Usage:
#   ./aws-waf-export.sh --list-ip-sets                       List all IP Sets
#   ./aws-waf-export.sh --list-web-acls                      List all Web ACLs
#   ./aws-waf-export.sh --ip-set <name> <id>                 Export specific IP Set
#   ./aws-waf-export.sh --all-ip-sets                        Export all IP Sets
#   ./aws-waf-export.sh --web-acl <name> <id>                Export IPs from Web ACL
#   ./aws-waf-export.sh --help                               Show help
#
# Global flags:
#   --scope REGIONAL|CLOUDFRONT   WAF scope (default: REGIONAL)
#   --include-ipv6                Include IPv6 addresses (skipped by default)
#
# Environment variables:
#   AWS_PROFILE (optional): AWS CLI named profile
#   AWS_DEFAULT_REGION (optional): AWS region for REGIONAL scope
#   AWS_REGION (optional): Alternative region variable
#   OUTPUT_FILE (optional): Output CSV file path (default: aws_waf_ips.csv)
#   DRY_RUN (optional): Set to "true" for preview mode
#   DEBUG (optional): Set to "true" for verbose output
#   AUDIT_LOG (optional): Path to audit log file
#
# Security Notes:
#   - Uses standard AWS credential chain (never hardcode credentials)
#   - All API calls go through the AWS CLI with TLS
#   - Store credentials via AWS SSO, IAM roles, or env vars
#   - Never commit AWS credentials to version control
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="aws-waf-export.sh"

# Default configuration
readonly DEFAULT_SCOPE="REGIONAL"
readonly DEFAULT_LIMIT=100

# Rate limiting (AWS API throttle protection)
readonly RATE_LIMIT_DELAY_MS=100
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly INITIAL_RETRY_DELAY=2

# Exit codes (matching other export scripts)
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

# Script start time for elapsed calculation
SCRIPT_START_TIME=$(date +%s)

# =============================================================================
# Logging Functions (matching akamai-export.sh / fastly-export.sh pattern)
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
    local msg="$1"
    msg=$(echo "$msg" | sed -E 's/(AccessKeyId|SecretAccessKey|SessionToken|token|password|secret|key)=[^&[:space:]]*/\1=[REDACTED]/gi')
    echo -e "${BLUE}[DEBUG]${NC} $msg" >&2
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

  if ! command -v aws &> /dev/null; then
    missing+=("aws-cli")
  fi

  if ! command -v jq &> /dev/null; then
    missing+=("jq")
  fi

  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required dependencies: ${missing[*]}"
    log_error "Please install them and try again."
    log_error ""
    log_error "Installation:"
    log_error "  macOS:  brew install awscli jq"
    log_error "  Ubuntu: sudo apt-get install awscli jq"
    log_error "  Alpine: apk add aws-cli jq"
    log_error "  pip:    pip install awscli"
    exit $EXIT_MISSING_DEPS
  fi

  # Check AWS CLI version (require v2+)
  local aws_version
  aws_version=$(aws --version 2>&1 | head -1)
  log_debug "AWS CLI version: $aws_version"

  local major_version
  major_version=$(echo "$aws_version" | sed -E 's|^aws-cli/([0-9]+)\..*|\1|')

  if [ "${major_version:-0}" -lt 2 ] 2>/dev/null; then
    log_error "AWS CLI v2+ is required (found: $aws_version)"
    log_error ""
    log_error "Upgrade AWS CLI:"
    log_error "  macOS:  brew upgrade awscli"
    log_error "  pip:    pip install --upgrade awscli"
    log_error "  See:    https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit $EXIT_MISSING_DEPS
  fi

  # Check optional dependency
  if ! command -v bc &> /dev/null; then
    log_warn "bc not found - rate limiting will use 1s minimum delay"
  fi

  log_debug "Dependencies check passed: aws (v2+), jq"
}

# =============================================================================
# AWS Credential Validation
# =============================================================================

validate_aws_credentials() {
  log_info "Validating AWS credentials..."

  local response
  if ! response=$(aws sts get-caller-identity --output json --no-cli-pager 2>&1); then
    log_error "AWS credential validation failed"
    log_error ""
    log_error "Error: $response"
    log_error ""
    log_error "Configure AWS credentials using one of these methods:"
    log_error ""
    log_error "  Option 1: AWS CLI named profile"
    log_error "    aws configure --profile myprofile"
    log_error "    export AWS_PROFILE=myprofile"
    log_error ""
    log_error "  Option 2: Environment variables"
    log_error "    export AWS_ACCESS_KEY_ID=AKIA..."
    log_error "    export AWS_SECRET_ACCESS_KEY=..."
    log_error "    export AWS_DEFAULT_REGION=us-east-1"
    log_error ""
    log_error "  Option 3: AWS SSO"
    log_error "    aws configure sso"
    log_error "    aws sso login --profile myprofile"
    log_error "    export AWS_PROFILE=myprofile"
    log_error ""
    log_error "  Option 4: IAM Role (EC2/ECS/Lambda)"
    log_error "    Attach an IAM role with wafv2:* permissions"
    log_error ""
    log_error "  Required IAM permissions:"
    log_error "    wafv2:ListIPSets"
    log_error "    wafv2:GetIPSet"
    log_error "    wafv2:ListWebACLs"
    log_error "    wafv2:GetWebACL"
    log_error "    sts:GetCallerIdentity"
    exit $EXIT_MISSING_CREDENTIALS
  fi

  local account_id
  account_id=$(echo "$response" | jq -r '.Account // "unknown"')
  local arn
  arn=$(echo "$response" | jq -r '.Arn // "unknown"')
  local user_id
  user_id=$(echo "$response" | jq -r '.UserId // "unknown"')

  log_info "Authenticated as:"
  log_info "  Account: $account_id"
  log_info "  ARN:     $arn"
  log_info ""

  audit_log "AWS_AUTH" "account=$account_id arn=$arn user_id=$user_id"
}

# =============================================================================
# AWS WAF API Helpers
# =============================================================================

# Build --scope and --region args based on WAF scope
resolve_scope_args() {
  local scope="$1"
  local args=(--scope "$scope")

  if [ "$scope" = "CLOUDFRONT" ]; then
    args+=(--region us-east-1)
  elif [ -n "${AWS_DEFAULT_REGION:-${AWS_REGION:-}}" ]; then
    args+=(--region "${AWS_DEFAULT_REGION:-${AWS_REGION:-}}")
  fi

  echo "${args[@]}"
}

# Wrapper for aws wafv2 commands with retry logic
aws_waf_request() {
  local subcommand="$1"
  shift
  local attempt=1
  local delay=$INITIAL_RETRY_DELAY

  log_debug "AWS request: aws wafv2 $subcommand $*"

  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    local response
    if response=$(aws wafv2 "$subcommand" "$@" --output json --no-cli-pager 2>&1); then
      rate_limit_sleep
      echo "$response"
      return 0
    fi

    # Check if retryable
    if echo "$response" | grep -qi "ThrottlingException\|Rate exceeded\|TooManyRequestsException"; then
      log_warn "Rate limited on attempt $attempt/$MAX_RETRIES. Waiting ${RATE_LIMIT_BACKOFF_SEC}s..."
      audit_log "RATE_LIMITED" "command=$subcommand attempt=$attempt"
      sleep "$RATE_LIMIT_BACKOFF_SEC"
      ((attempt++))
      continue
    fi

    if echo "$response" | grep -qi "InternalErrorException\|ServiceException"; then
      log_warn "Server error on attempt $attempt/$MAX_RETRIES. Retrying in ${delay}s..."
      sleep "$delay"
      delay=$((delay * 2))
      ((attempt++))
      continue
    fi

    # Non-retryable error
    if echo "$response" | grep -qi "AccessDeniedException"; then
      log_error "Access denied. Required IAM permissions:"
      log_error "  wafv2:ListIPSets, wafv2:GetIPSet"
      log_error "  wafv2:ListWebACLs, wafv2:GetWebACL"
      log_error "  sts:GetCallerIdentity"
    elif echo "$response" | grep -qi "WAFNonexistentItemException"; then
      log_error "Resource not found. Check the Name and ID."
    elif echo "$response" | grep -qi "WAFInvalidParameterException"; then
      log_error "Invalid parameter. Check --scope (REGIONAL or CLOUDFRONT) and resource identifiers."
    else
      log_error "AWS CLI error: $response"
    fi

    audit_log "API_ERROR" "command=$subcommand error=$(echo "$response" | head -1)"
    return 1
  done

  log_error "Max retries ($MAX_RETRIES) exceeded for: aws wafv2 $subcommand"
  audit_log "API_MAX_RETRIES" "command=$subcommand attempts=$MAX_RETRIES"
  return 1
}

# =============================================================================
# Discovery Functions
# =============================================================================

# List all IP Sets with pagination
list_ip_sets() {
  local scope="$1"

  log_info "Fetching IP Sets (scope: $scope)..."

  local scope_args
  scope_args=$(resolve_scope_args "$scope")

  local all_ip_sets="[]"
  local next_marker=""
  local page=1

  while true; do
    local cmd_args=($scope_args --limit $DEFAULT_LIMIT)
    if [ -n "$next_marker" ]; then
      cmd_args+=(--next-marker "$next_marker")
    fi

    log_debug "Fetching page $page..."

    local response
    if ! response=$(aws_waf_request list-ip-sets "${cmd_args[@]}"); then
      log_error "Failed to fetch IP Sets"
      return 1
    fi

    # Merge results
    local page_sets
    page_sets=$(echo "$response" | jq '.IPSets // []')
    all_ip_sets=$(echo "$all_ip_sets $page_sets" | jq -s '.[0] + .[1]')

    # Check for next page
    next_marker=$(echo "$response" | jq -r '.NextMarker // empty')
    if [ -z "$next_marker" ]; then
      break
    fi

    ((page++))
  done

  local count
  count=$(echo "$all_ip_sets" | jq 'length')

  echo ""
  echo "=============================================="
  echo "  AWS WAF IP Sets (scope: $scope)"
  echo "=============================================="
  echo ""

  if [ "$count" -eq 0 ]; then
    echo "No IP Sets found."
  else
    echo "$all_ip_sets" | jq -r '.[] | "ID:   \(.Id)\n  Name: \(.Name)\n  Desc: \(.Description // "N/A")\n  Lock: \(.LockToken)\n  ARN:  \(.ARN)\n"'
  fi

  echo ""
  log_info "Found $count IP Set(s)"
  echo ""
  log_info "To export an IP Set, run:"
  echo "  ./aws-waf-export.sh --ip-set <name> <id> --scope $scope"

  audit_log "LIST_IP_SETS" "scope=$scope count=$count"
}

# List all Web ACLs
list_web_acls() {
  local scope="$1"

  log_info "Fetching Web ACLs (scope: $scope)..."

  local scope_args
  scope_args=$(resolve_scope_args "$scope")

  local all_acls="[]"
  local next_marker=""
  local page=1

  while true; do
    local cmd_args=($scope_args --limit $DEFAULT_LIMIT)
    if [ -n "$next_marker" ]; then
      cmd_args+=(--next-marker "$next_marker")
    fi

    log_debug "Fetching page $page..."

    local response
    if ! response=$(aws_waf_request list-web-acls "${cmd_args[@]}"); then
      log_error "Failed to fetch Web ACLs"
      return 1
    fi

    local page_acls
    page_acls=$(echo "$response" | jq '.WebACLs // []')
    all_acls=$(echo "$all_acls $page_acls" | jq -s '.[0] + .[1]')

    next_marker=$(echo "$response" | jq -r '.NextMarker // empty')
    if [ -z "$next_marker" ]; then
      break
    fi

    ((page++))
  done

  local count
  count=$(echo "$all_acls" | jq 'length')

  echo ""
  echo "=============================================="
  echo "  AWS WAF Web ACLs (scope: $scope)"
  echo "=============================================="
  echo ""

  if [ "$count" -eq 0 ]; then
    echo "No Web ACLs found."
  else
    echo "$all_acls" | jq -r '.[] | "ID:   \(.Id)\n  Name: \(.Name)\n  Desc: \(.Description // "N/A")\n  Lock: \(.LockToken)\n  ARN:  \(.ARN)\n"'
  fi

  echo ""
  log_info "Found $count Web ACL(s)"
  echo ""
  log_info "To scan a Web ACL for IP Sets, run:"
  echo "  ./aws-waf-export.sh --web-acl <name> <id> --scope $scope"

  audit_log "LIST_WEB_ACLS" "scope=$scope count=$count"
}

# Walk nested statements in a Web ACL rule to find IPSetReferenceStatement ARNs
# Uses recursive jq to handle And/Or/Not nesting
extract_ip_set_arns_from_rules() {
  local rules_json="$1"

  # Recursively walk all statement types to find IPSetReferenceStatement
  echo "$rules_json" | jq -r '
    def walk_statement:
      if . == null then empty
      elif .IPSetReferenceStatement then .IPSetReferenceStatement.ARN
      elif .AndStatement then .AndStatement.Statements[] | walk_statement
      elif .OrStatement then .OrStatement.Statements[] | walk_statement
      elif .NotStatement then .NotStatement.Statement | walk_statement
      elif .RateBasedStatement then .RateBasedStatement.ScopeDownStatement | walk_statement
      elif .ManagedRuleGroupStatement then empty
      elif .RuleGroupReferenceStatement then empty
      else empty
      end;
    .[] |
    .Statement | walk_statement
  ' 2>/dev/null | sort -u
}

# Scan a Web ACL to find all referenced IP Sets
scan_web_acl_ips() {
  local name="$1"
  local id="$2"
  local scope="$3"

  local scope_args
  scope_args=$(resolve_scope_args "$scope")

  log_info "Scanning Web ACL: $name ($id)"
  log_info "Scope: $scope"
  log_info ""

  local response
  if ! response=$(aws_waf_request get-web-acl --name "$name" --id "$id" $scope_args); then
    log_error "Failed to fetch Web ACL: $name"
    return 1
  fi

  local acl_name
  acl_name=$(echo "$response" | jq -r '.WebACL.Name // "Unknown"')
  local acl_desc
  acl_desc=$(echo "$response" | jq -r '.WebACL.Description // "N/A"')
  local rule_count
  rule_count=$(echo "$response" | jq '.WebACL.Rules | length')

  log_info "Web ACL: $acl_name"
  log_info "Description: $acl_desc"
  log_info "Rules: $rule_count"
  log_info ""

  # Extract rules JSON
  local rules_json
  rules_json=$(echo "$response" | jq '.WebACL.Rules')

  # Find all IPSetReferenceStatement ARNs
  local ip_set_arns
  ip_set_arns=$(extract_ip_set_arns_from_rules "$rules_json")

  if [ -z "$ip_set_arns" ]; then
    log_warn "No IP Set references found in Web ACL rules"
    log_warn "This Web ACL may not use IP-based rules"
    return 0
  fi

  local arn_count
  arn_count=$(echo "$ip_set_arns" | wc -l | tr -d ' ')

  echo ""
  echo "=============================================="
  echo "  Referenced IP Sets ($arn_count found)"
  echo "=============================================="
  echo ""

  while IFS= read -r arn; do
    [ -z "$arn" ] && continue

    # Extract name and id from ARN
    # ARN format: arn:aws:wafv2:<region>:<account>:<scope>/ipset/<name>/<id>
    local ip_set_name
    ip_set_name=$(echo "$arn" | sed -E 's|.*/ipset/([^/]+)/.*|\1|')
    local ip_set_id
    ip_set_id=$(echo "$arn" | sed -E 's|.*/ipset/[^/]+/(.+)$|\1|')

    echo "ARN:  $arn"
    echo "  Name: $ip_set_name"
    echo "  ID:   $ip_set_id"

    # Fetch the IP Set to show summary
    local ip_set_response
    if ip_set_response=$(aws_waf_request get-ip-set --name "$ip_set_name" --id "$ip_set_id" $scope_args 2>/dev/null); then
      local addr_count
      addr_count=$(echo "$ip_set_response" | jq '.IPSet.Addresses | length')
      local ip_version
      ip_version=$(echo "$ip_set_response" | jq -r '.IPSet.IPAddressVersion // "IPV4"')
      echo "  Version: $ip_version"
      echo "  Addresses: $addr_count"
    fi
    echo ""
  done <<< "$ip_set_arns"

  log_info "To export all IPs from this Web ACL, run:"
  echo "  ./aws-waf-export.sh --web-acl $name $id --scope $scope"

  audit_log "SCAN_WEB_ACL" "name=$name id=$id scope=$scope ip_sets=$arn_count"
}

# =============================================================================
# Export Functions
# =============================================================================

# Export a single IP Set to CSV
export_ip_set() {
  local name="$1"
  local id="$2"
  local scope="$3"
  local include_ipv6="$4"
  local output_file="${OUTPUT_FILE:-aws_waf_ips.csv}"

  local scope_args
  scope_args=$(resolve_scope_args "$scope")

  log_info "=============================================="
  log_info "  AWS WAF IP Set Export"
  log_info "=============================================="
  log_info ""
  log_info "IP Set name: $name"
  log_info "IP Set ID:   $id"
  log_info "Scope:       $scope"
  log_info "Output file: $output_file"
  log_info ""

  audit_log "EXPORT_IP_SET_START" "name=$name id=$id scope=$scope output=$output_file"

  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export IP Set: $name ($id)"
    log_info "Would write to: $output_file"
    log_info ""
    log_info "Remove DRY_RUN=true to perform actual export."
    audit_log "EXPORT_DRY_RUN" "name=$name id=$id scope=$scope"
    return 0
  fi

  # Fetch the IP Set
  local response
  if ! response=$(aws_waf_request get-ip-set --name "$name" --id "$id" $scope_args); then
    log_error "Failed to fetch IP Set: $name ($id)"
    return 1
  fi

  # Extract metadata
  local ip_set_name
  ip_set_name=$(echo "$response" | jq -r '.IPSet.Name // "Unknown"')
  local description
  description=$(echo "$response" | jq -r '.IPSet.Description // ""')
  local ip_version
  ip_version=$(echo "$response" | jq -r '.IPSet.IPAddressVersion // "IPV4"')
  local addr_count
  addr_count=$(echo "$response" | jq '.IPSet.Addresses | length')

  log_info "Name:        $ip_set_name"
  log_info "Description: ${description:-N/A}"
  log_info "IP Version:  $ip_version"
  log_info "Addresses:   $addr_count"
  log_info ""

  # Check for IPv6
  if [ "$ip_version" = "IPV6" ] && [ "$include_ipv6" != "true" ]; then
    log_warn "IP Set '$ip_set_name' contains IPv6 addresses"
    log_warn "Vercel WAF supports IPv4 only. Skipping this IP Set."
    log_warn "Use --include-ipv6 flag to include IPv6 addresses anyway."
    audit_log "EXPORT_SKIPPED_IPV6" "name=$name id=$id ip_version=$ip_version"
    return 0
  fi

  if [ "$ip_version" = "IPV6" ]; then
    log_warn "Including IPv6 addresses (--include-ipv6 flag set)"
    log_warn "Note: Vercel WAF may not support IPv6 addresses"
  fi

  if [ "$addr_count" -eq 0 ]; then
    log_warn "IP Set '$ip_set_name' has no addresses"
    return 0
  fi

  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    log_error "Check file permissions and disk space."
    exit $EXIT_FILE_ERROR
  fi

  # Write entries
  local exported_count=0
  local skipped_ipv6=0

  while IFS= read -r ip; do
    [ -z "$ip" ] && continue

    # Check if IPv6 in a mixed scenario (shouldn't happen per AWS docs, but be safe)
    if echo "$ip" | grep -q ':' && [ "$include_ipv6" != "true" ]; then
      ((skipped_ipv6++))
      continue
    fi

    local note="${ip_set_name}"
    [ -n "$description" ] && note="${ip_set_name} - ${description}"
    # Escape commas in notes
    note=$(echo "$note" | sed 's/,/;/g')
    echo "\"$ip\",\"$note\",\"ip_set\",\"\"" >> "$output_file"
    ((exported_count++))
  done < <(echo "$response" | jq -r '.IPSet.Addresses[]' 2>/dev/null)

  local elapsed
  elapsed=$(get_elapsed_time)

  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  IP Set name:      $ip_set_name"
  log_info "  IP version:       $ip_version"
  log_info "  IPs exported:     $exported_count"
  if [ "$skipped_ipv6" -gt 0 ]; then
    log_info "  IPv6 skipped:     $skipped_ipv6"
  fi
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
  echo "  DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply $output_file"

  audit_log "EXPORT_IP_SET_COMPLETE" "name=$name id=$id ips=$exported_count skipped_ipv6=$skipped_ipv6 elapsed=${elapsed}s"
}

# Export ALL IP Sets from a given scope
export_all_ip_sets() {
  local scope="$1"
  local include_ipv6="$2"
  local output_file="${OUTPUT_FILE:-aws_waf_ips.csv}"

  local scope_args
  scope_args=$(resolve_scope_args "$scope")

  log_info "=============================================="
  log_info "  AWS WAF - Export All IP Sets"
  log_info "=============================================="
  log_info ""
  log_info "Scope:       $scope"
  log_info "Output file: $output_file"
  log_info ""

  audit_log "EXPORT_ALL_START" "scope=$scope output=$output_file"

  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export all IP Sets from scope: $scope"
    log_info "Would write to: $output_file"
    log_info ""
    log_info "Remove DRY_RUN=true to perform actual export."
    audit_log "EXPORT_ALL_DRY_RUN" "scope=$scope"
    return 0
  fi

  # Collect all IP Sets via pagination
  local all_ip_sets="[]"
  local next_marker=""

  while true; do
    local cmd_args=($scope_args --limit $DEFAULT_LIMIT)
    if [ -n "$next_marker" ]; then
      cmd_args+=(--next-marker "$next_marker")
    fi

    local response
    if ! response=$(aws_waf_request list-ip-sets "${cmd_args[@]}"); then
      log_error "Failed to list IP Sets"
      return 1
    fi

    local page_sets
    page_sets=$(echo "$response" | jq '.IPSets // []')
    all_ip_sets=$(echo "$all_ip_sets $page_sets" | jq -s '.[0] + .[1]')

    next_marker=$(echo "$response" | jq -r '.NextMarker // empty')
    if [ -z "$next_marker" ]; then
      break
    fi
  done

  local set_count
  set_count=$(echo "$all_ip_sets" | jq 'length')

  if [ "$set_count" -eq 0 ]; then
    log_warn "No IP Sets found in scope: $scope"
    return 0
  fi

  log_info "Found $set_count IP Set(s) to export"
  log_info ""

  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    log_error "Check file permissions and disk space."
    exit $EXIT_FILE_ERROR
  fi

  local total_exported=0
  local total_skipped_ipv6=0
  local sets_exported=0
  local sets_skipped=0

  # Iterate over each IP Set
  local i=0
  while [ "$i" -lt "$set_count" ]; do
    local set_name
    set_name=$(echo "$all_ip_sets" | jq -r ".[$i].Name")
    local set_id
    set_id=$(echo "$all_ip_sets" | jq -r ".[$i].Id")

    log_info "[$((i + 1))/$set_count] Fetching IP Set: $set_name ($set_id)"

    local ip_response
    if ! ip_response=$(aws_waf_request get-ip-set --name "$set_name" --id "$set_id" $scope_args); then
      log_warn "  Failed to fetch IP Set: $set_name - skipping"
      ((sets_skipped++))
      ((i++))
      continue
    fi

    local ip_version
    ip_version=$(echo "$ip_response" | jq -r '.IPSet.IPAddressVersion // "IPV4"')
    local addr_count
    addr_count=$(echo "$ip_response" | jq '.IPSet.Addresses | length')
    local description
    description=$(echo "$ip_response" | jq -r '.IPSet.Description // ""')

    # Skip IPv6 unless flag set
    if [ "$ip_version" = "IPV6" ] && [ "$include_ipv6" != "true" ]; then
      log_warn "  Skipping IPv6 IP Set: $set_name ($addr_count addresses)"
      ((sets_skipped++))
      ((i++))
      continue
    fi

    local set_exported=0

    while IFS= read -r ip; do
      [ -z "$ip" ] && continue

      if echo "$ip" | grep -q ':' && [ "$include_ipv6" != "true" ]; then
        ((total_skipped_ipv6++))
        continue
      fi

      local note="${set_name}"
      [ -n "$description" ] && note="${set_name} - ${description}"
      note=$(echo "$note" | sed 's/,/;/g')
      echo "\"$ip\",\"$note\",\"ip_set\",\"\"" >> "$output_file"
      ((set_exported++))
    done < <(echo "$ip_response" | jq -r '.IPSet.Addresses[]' 2>/dev/null)

    log_info "  Exported $set_exported addresses ($ip_version)"
    total_exported=$((total_exported + set_exported))
    ((sets_exported++))
    ((i++))
  done

  local elapsed
  elapsed=$(get_elapsed_time)

  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  IP Sets exported:  $sets_exported"
  log_info "  IP Sets skipped:   $sets_skipped"
  log_info "  Total IPs:         $total_exported"
  if [ "$total_skipped_ipv6" -gt 0 ]; then
    log_info "  IPv6 skipped:      $total_skipped_ipv6"
  fi
  log_info "  Time elapsed:      ${elapsed}s"
  log_info "  Output file:       $output_file"
  log_info "  Output size:       $(wc -l < "$output_file" | tr -d ' ') lines"
  log_info ""

  # Show sample
  if [ "$total_exported" -gt 0 ]; then
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
  fi

  echo ""
  log_info "Next step: Import to Vercel"
  echo "  DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply $output_file"

  audit_log "EXPORT_ALL_COMPLETE" "scope=$scope sets_exported=$sets_exported sets_skipped=$sets_skipped ips=$total_exported elapsed=${elapsed}s"
}

# Export all IPs referenced by a specific Web ACL
export_web_acl_ips() {
  local name="$1"
  local id="$2"
  local scope="$3"
  local include_ipv6="$4"
  local output_file="${OUTPUT_FILE:-aws_waf_ips.csv}"

  local scope_args
  scope_args=$(resolve_scope_args "$scope")

  log_info "=============================================="
  log_info "  AWS WAF Web ACL IP Export"
  log_info "=============================================="
  log_info ""
  log_info "Web ACL name: $name"
  log_info "Web ACL ID:   $id"
  log_info "Scope:        $scope"
  log_info "Output file:  $output_file"
  log_info ""

  audit_log "EXPORT_WEB_ACL_START" "name=$name id=$id scope=$scope output=$output_file"

  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    log_info "=============================================="
    log_info "  DRY RUN - No changes made"
    log_info "=============================================="
    log_info ""
    log_info "Would export IPs from Web ACL: $name ($id)"
    log_info "Would write to: $output_file"
    log_info ""
    log_info "Remove DRY_RUN=true to perform actual export."
    audit_log "EXPORT_WEB_ACL_DRY_RUN" "name=$name id=$id scope=$scope"
    return 0
  fi

  # Fetch the Web ACL
  local response
  if ! response=$(aws_waf_request get-web-acl --name "$name" --id "$id" $scope_args); then
    log_error "Failed to fetch Web ACL: $name ($id)"
    return 1
  fi

  local acl_name
  acl_name=$(echo "$response" | jq -r '.WebACL.Name // "Unknown"')
  local acl_desc
  acl_desc=$(echo "$response" | jq -r '.WebACL.Description // "N/A"')
  local rule_count
  rule_count=$(echo "$response" | jq '.WebACL.Rules | length')

  log_info "Web ACL: $acl_name"
  log_info "Description: $acl_desc"
  log_info "Rules: $rule_count"
  log_info ""

  # Extract rules and find IP Set ARNs
  local rules_json
  rules_json=$(echo "$response" | jq '.WebACL.Rules')

  local ip_set_arns
  ip_set_arns=$(extract_ip_set_arns_from_rules "$rules_json")

  if [ -z "$ip_set_arns" ]; then
    log_warn "No IP Set references found in Web ACL rules"
    log_warn "This Web ACL may not contain IP-based rules"
    return 0
  fi

  local arn_count
  arn_count=$(echo "$ip_set_arns" | wc -l | tr -d ' ')

  log_info "Found $arn_count IP Set reference(s) in Web ACL rules"
  log_info ""

  # Write CSV header
  if ! echo "ip,notes,mode,created_on" > "$output_file" 2>/dev/null; then
    log_error "Failed to write to output file: $output_file"
    log_error "Check file permissions and disk space."
    exit $EXIT_FILE_ERROR
  fi

  local total_exported=0
  local total_skipped_ipv6=0
  local sets_processed=0

  # Resolve each ARN to an IP Set and export
  while IFS= read -r arn; do
    [ -z "$arn" ] && continue

    # Extract name and id from ARN
    local ip_set_name
    ip_set_name=$(echo "$arn" | sed -E 's|.*/ipset/([^/]+)/.*|\1|')
    local ip_set_id
    ip_set_id=$(echo "$arn" | sed -E 's|.*/ipset/[^/]+/(.+)$|\1|')

    ((sets_processed++))
    log_info "[$sets_processed/$arn_count] Fetching IP Set: $ip_set_name ($ip_set_id)"

    local ip_response
    if ! ip_response=$(aws_waf_request get-ip-set --name "$ip_set_name" --id "$ip_set_id" $scope_args); then
      log_warn "  Failed to fetch IP Set: $ip_set_name - skipping"
      continue
    fi

    local ip_version
    ip_version=$(echo "$ip_response" | jq -r '.IPSet.IPAddressVersion // "IPV4"')
    local addr_count
    addr_count=$(echo "$ip_response" | jq '.IPSet.Addresses | length')
    local description
    description=$(echo "$ip_response" | jq -r '.IPSet.Description // ""')

    # Skip IPv6 unless flag set
    if [ "$ip_version" = "IPV6" ] && [ "$include_ipv6" != "true" ]; then
      log_warn "  Skipping IPv6 IP Set: $ip_set_name ($addr_count addresses)"
      continue
    fi

    local set_exported=0

    while IFS= read -r ip; do
      [ -z "$ip" ] && continue

      if echo "$ip" | grep -q ':' && [ "$include_ipv6" != "true" ]; then
        ((total_skipped_ipv6++))
        continue
      fi

      local note="${ip_set_name}"
      [ -n "$description" ] && note="${ip_set_name} - ${description}"
      note=$(echo "$note" | sed 's/,/;/g')
      echo "\"$ip\",\"$note\",\"ip_set\",\"\"" >> "$output_file"
      ((set_exported++))
    done < <(echo "$ip_response" | jq -r '.IPSet.Addresses[]' 2>/dev/null)

    log_info "  Exported $set_exported addresses ($ip_version)"
    total_exported=$((total_exported + set_exported))
  done <<< "$ip_set_arns"

  local elapsed
  elapsed=$(get_elapsed_time)

  log_info ""
  log_info "=============================================="
  log_info "  Export Summary"
  log_info "=============================================="
  log_info ""
  log_info "  Web ACL:          $acl_name"
  log_info "  IP Sets resolved: $sets_processed"
  log_info "  Total IPs:        $total_exported"
  if [ "$total_skipped_ipv6" -gt 0 ]; then
    log_info "  IPv6 skipped:     $total_skipped_ipv6"
  fi
  log_info "  Time elapsed:     ${elapsed}s"
  log_info "  Output file:      $output_file"
  log_info "  Output size:      $(wc -l < "$output_file" | tr -d ' ') lines"
  log_info ""

  # Show sample
  if [ "$total_exported" -gt 0 ]; then
    log_info "First 5 entries:"
    head -6 "$output_file" | tail -5
  fi

  echo ""
  log_info "Next step: Import to Vercel"
  echo "  DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply $output_file"

  audit_log "EXPORT_WEB_ACL_COMPLETE" "name=$name id=$id sets=$sets_processed ips=$total_exported elapsed=${elapsed}s"
}

# =============================================================================
# Help & Usage
# =============================================================================

show_help() {
  cat << 'EOF'
AWS WAF Export Script
Version: 1.0.0

Exports IP addresses and CIDR ranges from AWS WAF v2 (WAFV2) IP Sets
to CSV format compatible with Vercel Firewall.

The exported IPs can be used with Vercel WAF in any mode:
  - deny mode:   Block all traffic except from exported IPs
  - bypass mode: Skip WAF checks for exported IPs

USAGE:
  ./aws-waf-export.sh --list-ip-sets                       List all IP Sets
  ./aws-waf-export.sh --list-web-acls                      List all Web ACLs
  ./aws-waf-export.sh --ip-set <name> <id>                 Export specific IP Set
  ./aws-waf-export.sh --all-ip-sets                        Export all IP Sets
  ./aws-waf-export.sh --web-acl <name> <id>                Export IPs from Web ACL
  ./aws-waf-export.sh --help                               Show this help

GLOBAL FLAGS:
  --scope REGIONAL|CLOUDFRONT   WAF scope (default: REGIONAL)
                                Use CLOUDFRONT for CloudFront distributions
                                Use REGIONAL for ALB, API Gateway, AppSync, etc.
  --include-ipv6                Include IPv6 addresses in export
                                (skipped by default — Vercel WAF is IPv4 only)

ENVIRONMENT VARIABLES:
  AWS_PROFILE         (optional) AWS CLI named profile
  AWS_DEFAULT_REGION  (optional) AWS region for REGIONAL scope
  AWS_REGION          (optional) Alternative region variable
  AWS_ACCESS_KEY_ID   (optional) AWS access key (not recommended for local use)
  AWS_SECRET_ACCESS_KEY (optional) AWS secret key (not recommended for local use)
  OUTPUT_FILE         (optional) Output CSV file path (default: aws_waf_ips.csv)
  DRY_RUN             (optional) Set to "true" for preview mode
  DEBUG               (optional) Set to "true" for verbose output
  AUDIT_LOG           (optional) Path to audit log file

PREREQUISITES:
  1. Install AWS CLI v2:
     https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

  2. Configure credentials (choose one):

     a) AWS SSO (recommended):
        aws configure sso
        aws sso login --profile myprofile
        export AWS_PROFILE=myprofile

     b) Named profile:
        aws configure --profile myprofile
        export AWS_PROFILE=myprofile

     c) Environment variables:
        export AWS_ACCESS_KEY_ID=AKIA...
        export AWS_SECRET_ACCESS_KEY=...
        export AWS_DEFAULT_REGION=us-east-1

     d) IAM Role (EC2/ECS/Lambda):
        Attach role with required permissions

  3. Required IAM permissions:
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

EXAMPLES:
  # List all IP Sets (regional)
  ./aws-waf-export.sh --list-ip-sets

  # List all IP Sets (CloudFront — global)
  ./aws-waf-export.sh --list-ip-sets --scope CLOUDFRONT

  # Export a specific IP Set
  ./aws-waf-export.sh --ip-set my-allowlist abc12345-def6-7890-abcd-ef1234567890

  # Export all IP Sets in a region
  AWS_DEFAULT_REGION=us-west-2 ./aws-waf-export.sh --all-ip-sets

  # Export IPs referenced by a Web ACL
  ./aws-waf-export.sh --web-acl my-web-acl abc12345-def6-7890-abcd-ef1234567890

  # Export to custom file
  OUTPUT_FILE="vendor_ips.csv" ./aws-waf-export.sh --ip-set my-list abc123

  # Dry run (preview without writing)
  DRY_RUN=true ./aws-waf-export.sh --ip-set my-list abc123

  # Debug mode (verbose output)
  DEBUG=true ./aws-waf-export.sh --list-ip-sets

  # Include IPv6 addresses
  ./aws-waf-export.sh --all-ip-sets --include-ipv6

  # Use specific AWS profile
  AWS_PROFILE=production ./aws-waf-export.sh --list-ip-sets

  # CloudFront scope with audit logging
  AUDIT_LOG="./aws-waf-export.log" ./aws-waf-export.sh --all-ip-sets --scope CLOUDFRONT

OUTPUT FORMAT:
  CSV with columns: ip,notes,mode,created_on
  Compatible with vercel-bulk-waf-rules.sh

  Example:
    ip,notes,mode,created_on
    "10.0.0.0/8","my-allowlist - Internal network","ip_set",""
    "192.168.1.0/24","my-allowlist - Internal network","ip_set",""

EXIT CODES:
  0  - Success
  1  - Missing dependencies (aws-cli, jq)
  2  - Missing AWS credentials
  3  - Invalid AWS credentials
  4  - API error (non-retryable)
  5  - Rate limited (after max retries)
  6  - Invalid arguments
  7  - File I/O error
  8  - Network error

MIGRATION WORKFLOW:
  # Step 1: List available IP Sets
  ./aws-waf-export.sh --list-ip-sets

  # Step 2: Export the desired IP Set(s)
  ./aws-waf-export.sh --ip-set my-allowlist abc12345-...

  # Step 3: Preview import to Vercel (choose your mode)
  DRY_RUN=true RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply aws_waf_ips.csv

  # Step 4: Apply to Vercel
  RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply aws_waf_ips.csv

IAM POLICY:
  Minimal IAM policy for read-only export:

  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "WAFExportReadOnly",
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

NOTE:
  - AWS WAF Classic is EOL (September 2025). This script only supports WAFV2.
  - CLOUDFRONT scope always uses us-east-1 region (AWS requirement).
  - IPv6 addresses are skipped by default (Vercel WAF is IPv4 only).

For detailed documentation, see: docs/aws-waf-export.md
EOF
}

# =============================================================================
# Main Entry Point
# =============================================================================

main() {
  # Check dependencies first
  check_dependencies

  if [ $# -eq 0 ]; then
    show_help
    exit $EXIT_INVALID_ARGS
  fi

  # Parse global flags first (--scope, --include-ipv6)
  local scope="$DEFAULT_SCOPE"
  local include_ipv6=false
  local args=()

  while [ $# -gt 0 ]; do
    case "$1" in
      --scope)
        scope="${2:-}"
        if [ -z "$scope" ]; then
          log_error "Missing value for --scope (expected REGIONAL or CLOUDFRONT)"
          exit $EXIT_INVALID_ARGS
        fi
        if [ "$scope" != "REGIONAL" ] && [ "$scope" != "CLOUDFRONT" ]; then
          log_error "Invalid scope: $scope (expected REGIONAL or CLOUDFRONT)"
          exit $EXIT_INVALID_ARGS
        fi
        shift 2
        ;;
      --include-ipv6)
        include_ipv6=true
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  # Restore positional args
  if [ ${#args[@]} -gt 0 ]; then
    set -- "${args[@]}"
  else
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
    --list-ip-sets)
      validate_aws_credentials
      list_ip_sets "$scope"
      ;;
    --list-web-acls)
      validate_aws_credentials
      list_web_acls "$scope"
      ;;
    --ip-set)
      if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
        log_error "Usage: --ip-set <name> <id> [--scope REGIONAL|CLOUDFRONT]"
        log_error ""
        log_error "To find available IP Sets, run:"
        log_error "  ./aws-waf-export.sh --list-ip-sets"
        exit $EXIT_INVALID_ARGS
      fi
      validate_aws_credentials
      export_ip_set "$2" "$3" "$scope" "$include_ipv6"
      ;;
    --all-ip-sets)
      validate_aws_credentials
      export_all_ip_sets "$scope" "$include_ipv6"
      ;;
    --web-acl)
      if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
        log_error "Usage: --web-acl <name> <id> [--scope REGIONAL|CLOUDFRONT]"
        log_error ""
        log_error "To find available Web ACLs, run:"
        log_error "  ./aws-waf-export.sh --list-web-acls"
        exit $EXIT_INVALID_ARGS
      fi
      validate_aws_credentials
      export_web_acl_ips "$2" "$3" "$scope" "$include_ipv6"
      ;;
    *)
      log_error "Unknown command: $1"
      log_error "Run with --help for usage information"
      exit $EXIT_INVALID_ARGS
      ;;
  esac
}

main "$@"
