#!/bin/bash
# =============================================================================
# AWS WAF E2E Test Setup
# =============================================================================
#
# Creates test AWS WAF resources for e2e testing the aws-waf-export.sh script.
#
# Resources created (all REGIONAL scope by default):
#   1. IP Set: e2e-test-allowlist-v4   (IPV4, 5 addresses)
#   2. IP Set: e2e-test-blocklist-v4   (IPV4, 3 addresses)
#   3. IP Set: e2e-test-ipv6-only      (IPV6, 2 addresses)
#   4. IP Set: e2e-test-empty          (IPV4, 0 addresses)
#   5. Web ACL: e2e-test-web-acl       (references IP Sets #1 and #2)
#
# State is saved to .test-state.json for use by run-tests.sh and teardown.sh.
#
# Usage:
#   ./setup.sh                          Create resources in default region
#   ./setup.sh --region us-west-2       Create resources in specific region
#   ./setup.sh --scope CLOUDFRONT       Create resources in CLOUDFRONT scope
#
# Prerequisites:
#   - AWS CLI v2 with wafv2 support
#   - jq
#   - Valid AWS credentials with wafv2:* and sts:GetCallerIdentity permissions
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly STATE_FILE="$SCRIPT_DIR/.test-state.json"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Default configuration
DEFAULT_SCOPE="REGIONAL"
DEFAULT_REGION="${AWS_DEFAULT_REGION:-${AWS_REGION:-us-east-1}}"

# Test resource definitions
readonly ALLOWLIST_NAME="e2e-test-allowlist-v4"
readonly BLOCKLIST_NAME="e2e-test-blocklist-v4"
readonly IPV6_NAME="e2e-test-ipv6-only"
readonly EMPTY_NAME="e2e-test-empty"
readonly WEB_ACL_NAME="e2e-test-web-acl"

readonly ALLOWLIST_IPS='["192.0.2.1/32","192.0.2.2/32","192.0.2.3/32","198.51.100.0/24","203.0.113.0/24"]'
readonly BLOCKLIST_IPS='["10.0.0.1/32","10.0.0.2/32","172.16.0.0/16"]'
readonly IPV6_IPS='["2001:db8::/32","2001:db8:1::/48"]'
readonly EMPTY_IPS='[]'

# =============================================================================
# Logging Functions
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
    log_error "Install with: brew install awscli jq"
    exit 1
  fi

  log_debug "Dependencies check passed: aws, jq"
}

validate_aws_credentials() {
  log_info "Validating AWS credentials..."

  local response
  if ! response=$(aws sts get-caller-identity --output json --no-cli-pager 2>&1); then
    log_error "AWS credential validation failed"
    log_error "$response"
    log_error ""
    log_error "Configure credentials: aws configure or export AWS_PROFILE=..."
    exit 2
  fi

  local account_id
  account_id=$(echo "$response" | jq -r '.Account // "unknown"')
  local arn
  arn=$(echo "$response" | jq -r '.Arn // "unknown"')

  log_info "Authenticated as:"
  log_info "  Account: $account_id"
  log_info "  ARN:     $arn"
  log_info ""
}

# =============================================================================
# Resource Discovery (Idempotency)
# =============================================================================

# Check if an IP Set already exists by name. Returns the ID if found, empty otherwise.
find_ip_set_by_name() {
  local name="$1"
  local scope="$2"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "$REGION" ]; then
    scope_args+=(--region "$REGION")
  fi

  local response
  if ! response=$(aws wafv2 list-ip-sets "${scope_args[@]}" --limit 100 --output json --no-cli-pager 2>&1); then
    log_debug "Failed to list IP Sets: $response"
    echo ""
    return
  fi

  local match
  match=$(echo "$response" | jq -r --arg name "$name" '.IPSets[] | select(.Name == $name) | .Id' 2>/dev/null)
  echo "${match:-}"
}

# Check if a Web ACL already exists by name. Returns the ID if found, empty otherwise.
find_web_acl_by_name() {
  local name="$1"
  local scope="$2"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "$REGION" ]; then
    scope_args+=(--region "$REGION")
  fi

  local response
  if ! response=$(aws wafv2 list-web-acls "${scope_args[@]}" --limit 100 --output json --no-cli-pager 2>&1); then
    log_debug "Failed to list Web ACLs: $response"
    echo ""
    return
  fi

  local match
  match=$(echo "$response" | jq -r --arg name "$name" '.WebACLs[] | select(.Name == $name) | .Id' 2>/dev/null)
  echo "${match:-}"
}

# Get the ARN for an existing IP Set
get_ip_set_arn() {
  local name="$1"
  local id="$2"
  local scope="$3"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "$REGION" ]; then
    scope_args+=(--region "$REGION")
  fi

  local response
  response=$(aws wafv2 get-ip-set --name "$name" --id "$id" "${scope_args[@]}" --output json --no-cli-pager 2>&1)
  echo "$response" | jq -r '.IPSet.ARN // empty'
}

# =============================================================================
# Resource Creation Functions
# =============================================================================

create_ip_set() {
  local name="$1"
  local ip_version="$2"
  local addresses="$3"
  local scope="$4"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "$REGION" ]; then
    scope_args+=(--region "$REGION")
  fi

  # Check if already exists
  local existing_id
  existing_id=$(find_ip_set_by_name "$name" "$scope")

  if [ -n "$existing_id" ]; then
    log_warn "IP Set '$name' already exists (ID: $existing_id) — skipping creation"
    local arn
    arn=$(get_ip_set_arn "$name" "$existing_id" "$scope")
    echo "{\"id\": \"$existing_id\", \"arn\": \"$arn\"}"
    return 0
  fi

  log_info "Creating IP Set: $name ($ip_version, $(echo "$addresses" | jq 'length') addresses)"

  local response
  if ! response=$(aws wafv2 create-ip-set \
    --name "$name" \
    --ip-address-version "$ip_version" \
    --addresses "$addresses" \
    "${scope_args[@]}" \
    --output json --no-cli-pager 2>&1); then
    log_error "Failed to create IP Set '$name': $response"
    return 1
  fi

  local id
  id=$(echo "$response" | jq -r '.Summary.Id')
  local arn
  arn=$(echo "$response" | jq -r '.Summary.ARN')

  log_info "  Created: $name (ID: $id)"
  log_debug "  ARN: $arn"

  echo "{\"id\": \"$id\", \"arn\": \"$arn\"}"
}

create_web_acl() {
  local name="$1"
  local scope="$2"
  local allowlist_arn="$3"
  local blocklist_arn="$4"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "$REGION" ]; then
    scope_args+=(--region "$REGION")
  fi

  # Check if already exists
  local existing_id
  existing_id=$(find_web_acl_by_name "$name" "$scope")

  if [ -n "$existing_id" ]; then
    log_warn "Web ACL '$name' already exists (ID: $existing_id) — skipping creation"
    local scope_args_get=()
    scope_args_get+=(--scope "$scope")
    if [ "$scope" = "CLOUDFRONT" ]; then
      scope_args_get+=(--region us-east-1)
    elif [ -n "$REGION" ]; then
      scope_args_get+=(--region "$REGION")
    fi
    local get_response
    get_response=$(aws wafv2 get-web-acl --name "$name" --id "$existing_id" "${scope_args_get[@]}" --output json --no-cli-pager 2>&1)
    local arn
    arn=$(echo "$get_response" | jq -r '.WebACL.ARN // empty')
    echo "{\"id\": \"$existing_id\", \"arn\": \"$arn\"}"
    return 0
  fi

  log_info "Creating Web ACL: $name"
  log_info "  Rule 1: allow-vendor-ips → $allowlist_arn"
  log_info "  Rule 2: block-bad-ips → $blocklist_arn"

  local response
  if ! response=$(aws wafv2 create-web-acl \
    --name "$name" \
    "${scope_args[@]}" \
    --default-action '{"Allow": {}}' \
    --visibility-config '{"SampledRequestsEnabled": false, "CloudWatchMetricsEnabled": false, "MetricName": "e2eTestWebAcl"}' \
    --rules "[
      {
        \"Name\": \"allow-vendor-ips\",
        \"Priority\": 1,
        \"Statement\": {
          \"IPSetReferenceStatement\": {
            \"ARN\": \"$allowlist_arn\"
          }
        },
        \"Action\": {\"Allow\": {}},
        \"VisibilityConfig\": {\"SampledRequestsEnabled\": false, \"CloudWatchMetricsEnabled\": false, \"MetricName\": \"allowVendorIps\"}
      },
      {
        \"Name\": \"block-bad-ips\",
        \"Priority\": 2,
        \"Statement\": {
          \"IPSetReferenceStatement\": {
            \"ARN\": \"$blocklist_arn\"
          }
        },
        \"Action\": {\"Block\": {}},
        \"VisibilityConfig\": {\"SampledRequestsEnabled\": false, \"CloudWatchMetricsEnabled\": false, \"MetricName\": \"blockBadIps\"}
      }
    ]" \
    --output json --no-cli-pager 2>&1); then
    log_error "Failed to create Web ACL '$name': $response"
    return 1
  fi

  local id
  id=$(echo "$response" | jq -r '.Summary.Id')
  local arn
  arn=$(echo "$response" | jq -r '.Summary.ARN')

  log_info "  Created: $name (ID: $id)"
  log_debug "  ARN: $arn"

  echo "{\"id\": \"$id\", \"arn\": \"$arn\"}"
}

# =============================================================================
# Main
# =============================================================================

main() {
  local scope="$DEFAULT_SCOPE"
  REGION="$DEFAULT_REGION"

  # Parse arguments
  while [ $# -gt 0 ]; do
    case "$1" in
      --scope)
        scope="${2:-}"
        if [ -z "$scope" ]; then
          log_error "Missing value for --scope"
          exit 1
        fi
        shift 2
        ;;
      --region)
        REGION="${2:-}"
        if [ -z "$REGION" ]; then
          log_error "Missing value for --region"
          exit 1
        fi
        shift 2
        ;;
      --help|-h)
        echo "Usage: ./setup.sh [--scope REGIONAL|CLOUDFRONT] [--region us-east-1]"
        exit 0
        ;;
      *)
        log_error "Unknown argument: $1"
        exit 1
        ;;
    esac
  done

  echo ""
  echo "=============================================="
  echo "  AWS WAF E2E Test Setup"
  echo "=============================================="
  echo ""
  log_info "Scope:  $scope"
  log_info "Region: $REGION"
  log_info ""

  # Preflight checks
  check_dependencies
  validate_aws_credentials

  # Create IP Sets
  log_info "Creating test IP Sets..."
  log_info ""

  local allowlist_result
  allowlist_result=$(create_ip_set "$ALLOWLIST_NAME" "IPV4" "$ALLOWLIST_IPS" "$scope")
  local allowlist_id
  allowlist_id=$(echo "$allowlist_result" | jq -r '.id')
  local allowlist_arn
  allowlist_arn=$(echo "$allowlist_result" | jq -r '.arn')

  local blocklist_result
  blocklist_result=$(create_ip_set "$BLOCKLIST_NAME" "IPV4" "$BLOCKLIST_IPS" "$scope")
  local blocklist_id
  blocklist_id=$(echo "$blocklist_result" | jq -r '.id')
  local blocklist_arn
  blocklist_arn=$(echo "$blocklist_result" | jq -r '.arn')

  local ipv6_result
  ipv6_result=$(create_ip_set "$IPV6_NAME" "IPV6" "$IPV6_IPS" "$scope")
  local ipv6_id
  ipv6_id=$(echo "$ipv6_result" | jq -r '.id')
  local ipv6_arn
  ipv6_arn=$(echo "$ipv6_result" | jq -r '.arn')

  local empty_result
  empty_result=$(create_ip_set "$EMPTY_NAME" "IPV4" "$EMPTY_IPS" "$scope")
  local empty_id
  empty_id=$(echo "$empty_result" | jq -r '.id')
  local empty_arn
  empty_arn=$(echo "$empty_result" | jq -r '.arn')

  log_info ""

  # Create Web ACL
  log_info "Creating test Web ACL..."
  log_info ""

  local web_acl_result
  web_acl_result=$(create_web_acl "$WEB_ACL_NAME" "$scope" "$allowlist_arn" "$blocklist_arn")
  local web_acl_id
  web_acl_id=$(echo "$web_acl_result" | jq -r '.id')
  local web_acl_arn
  web_acl_arn=$(echo "$web_acl_result" | jq -r '.arn')

  log_info ""

  # Save state file
  log_info "Saving state to $STATE_FILE"

  local created_at
  created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  jq -n \
    --arg scope "$scope" \
    --arg region "$REGION" \
    --arg created_at "$created_at" \
    --arg allowlist_id "$allowlist_id" \
    --arg allowlist_arn "$allowlist_arn" \
    --arg blocklist_id "$blocklist_id" \
    --arg blocklist_arn "$blocklist_arn" \
    --arg ipv6_id "$ipv6_id" \
    --arg ipv6_arn "$ipv6_arn" \
    --arg empty_id "$empty_id" \
    --arg empty_arn "$empty_arn" \
    --arg web_acl_id "$web_acl_id" \
    --arg web_acl_arn "$web_acl_arn" \
    '{
      scope: $scope,
      region: $region,
      created_at: $created_at,
      ip_sets: {
        "e2e-test-allowlist-v4": { id: $allowlist_id, arn: $allowlist_arn },
        "e2e-test-blocklist-v4": { id: $blocklist_id, arn: $blocklist_arn },
        "e2e-test-ipv6-only": { id: $ipv6_id, arn: $ipv6_arn },
        "e2e-test-empty": { id: $empty_id, arn: $empty_arn }
      },
      web_acls: {
        "e2e-test-web-acl": { id: $web_acl_id, arn: $web_acl_arn }
      }
    }' > "$STATE_FILE"

  log_info ""

  # Print summary
  echo ""
  echo "=============================================="
  echo "  Setup Complete"
  echo "=============================================="
  echo ""
  echo "  IP Sets:"
  echo "    $ALLOWLIST_NAME  → $allowlist_id"
  echo "    $BLOCKLIST_NAME  → $blocklist_id"
  echo "    $IPV6_NAME       → $ipv6_id"
  echo "    $EMPTY_NAME      → $empty_id"
  echo ""
  echo "  Web ACLs:"
  echo "    $WEB_ACL_NAME    → $web_acl_id"
  echo ""
  echo "  State file: $STATE_FILE"
  echo ""
  log_info "Run tests with: ./run-tests.sh"
  log_info "Clean up with:  ./teardown.sh"
  echo ""
}

main "$@"
