#!/bin/bash
# =============================================================================
# AWS WAF E2E Test Teardown
# =============================================================================
#
# Deletes all test AWS WAF resources created by setup.sh.
#
# Reads .test-state.json for resource IDs and deletes in correct order:
#   1. Web ACLs (must be deleted before IP Sets they reference)
#   2. IP Sets
#
# Usage:
#   ./teardown.sh                  Delete resources listed in state file
#   ./teardown.sh --force          Find and delete all e2e-test-* resources
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
# Deletion Functions
# =============================================================================

delete_web_acl() {
  local name="$1"
  local id="$2"
  local scope="$3"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "${REGION:-}" ]; then
    scope_args+=(--region "$REGION")
  fi

  log_info "Deleting Web ACL: $name ($id)"

  # Get current LockToken
  local get_response
  if ! get_response=$(aws wafv2 get-web-acl --name "$name" --id "$id" "${scope_args[@]}" --output json --no-cli-pager 2>&1); then
    log_warn "  Web ACL not found or already deleted: $name"
    return 0
  fi

  local lock_token
  lock_token=$(echo "$get_response" | jq -r '.LockToken')

  if ! aws wafv2 delete-web-acl --name "$name" --id "$id" --lock-token "$lock_token" "${scope_args[@]}" --no-cli-pager 2>&1; then
    log_error "  Failed to delete Web ACL: $name"
    return 1
  fi

  log_info "  Deleted: $name"
}

delete_ip_set() {
  local name="$1"
  local id="$2"
  local scope="$3"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "${REGION:-}" ]; then
    scope_args+=(--region "$REGION")
  fi

  log_info "Deleting IP Set: $name ($id)"

  # Get current LockToken
  local get_response
  if ! get_response=$(aws wafv2 get-ip-set --name "$name" --id "$id" "${scope_args[@]}" --output json --no-cli-pager 2>&1); then
    log_warn "  IP Set not found or already deleted: $name"
    return 0
  fi

  local lock_token
  lock_token=$(echo "$get_response" | jq -r '.LockToken')

  if ! aws wafv2 delete-ip-set --name "$name" --id "$id" --lock-token "$lock_token" "${scope_args[@]}" --no-cli-pager 2>&1; then
    log_error "  Failed to delete IP Set: $name"
    return 1
  fi

  log_info "  Deleted: $name"
}

# =============================================================================
# Force Mode — discover and delete all e2e-test-* resources
# =============================================================================

force_teardown() {
  local scope="${1:-REGIONAL}"
  local scope_args=()

  scope_args+=(--scope "$scope")
  if [ "$scope" = "CLOUDFRONT" ]; then
    scope_args+=(--region us-east-1)
  elif [ -n "${REGION:-}" ]; then
    scope_args+=(--region "$REGION")
  fi

  log_warn "Force mode: discovering all e2e-test-* resources..."
  log_info ""

  local deleted_count=0

  # Delete Web ACLs first
  log_info "Scanning for e2e-test-* Web ACLs..."
  local acl_response
  if acl_response=$(aws wafv2 list-web-acls "${scope_args[@]}" --limit 100 --output json --no-cli-pager 2>&1); then
    local acl_matches
    acl_matches=$(echo "$acl_response" | jq -r '.WebACLs[] | select(.Name | startswith("e2e-test-")) | "\(.Name)\t\(.Id)"' 2>/dev/null)

    if [ -n "$acl_matches" ]; then
      while IFS=$'\t' read -r name id; do
        [ -z "$name" ] && continue
        if delete_web_acl "$name" "$id" "$scope"; then
          ((deleted_count++))
        fi
      done <<< "$acl_matches"
    else
      log_info "  No e2e-test-* Web ACLs found"
    fi
  fi

  log_info ""

  # Delete IP Sets
  log_info "Scanning for e2e-test-* IP Sets..."
  local ip_response
  if ip_response=$(aws wafv2 list-ip-sets "${scope_args[@]}" --limit 100 --output json --no-cli-pager 2>&1); then
    local ip_matches
    ip_matches=$(echo "$ip_response" | jq -r '.IPSets[] | select(.Name | startswith("e2e-test-")) | "\(.Name)\t\(.Id)"' 2>/dev/null)

    if [ -n "$ip_matches" ]; then
      while IFS=$'\t' read -r name id; do
        [ -z "$name" ] && continue
        if delete_ip_set "$name" "$id" "$scope"; then
          ((deleted_count++))
        fi
      done <<< "$ip_matches"
    else
      log_info "  No e2e-test-* IP Sets found"
    fi
  fi

  # Clean up state file if it exists
  if [ -f "$STATE_FILE" ]; then
    rm -f "$STATE_FILE"
    log_info ""
    log_info "Removed state file: $STATE_FILE"
  fi

  echo ""
  log_info "Force teardown complete. Deleted $deleted_count resource(s)."
}

# =============================================================================
# Main
# =============================================================================

main() {
  local force=false
  local scope=""
  REGION=""

  # Parse arguments
  while [ $# -gt 0 ]; do
    case "$1" in
      --force)
        force=true
        shift
        ;;
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
        echo "Usage: ./teardown.sh [--force] [--scope REGIONAL|CLOUDFRONT] [--region us-east-1]"
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
  echo "  AWS WAF E2E Test Teardown"
  echo "=============================================="
  echo ""

  # Force mode — discover and delete
  if [ "$force" = true ]; then
    local force_scope="${scope:-REGIONAL}"
    if [ -z "$REGION" ]; then
      REGION="${AWS_DEFAULT_REGION:-${AWS_REGION:-us-east-1}}"
    fi
    log_info "Scope:  $force_scope"
    log_info "Region: $REGION"
    log_info ""
    force_teardown "$force_scope"
    return 0
  fi

  # Normal mode — read state file
  if [ ! -f "$STATE_FILE" ]; then
    log_error "State file not found: $STATE_FILE"
    log_error ""
    log_error "Either run setup.sh first, or use --force to discover and delete"
    log_error "all e2e-test-* resources:"
    log_error ""
    log_error "  ./teardown.sh --force [--scope REGIONAL] [--region us-east-1]"
    exit 1
  fi

  # Read state
  local state
  state=$(cat "$STATE_FILE")

  local state_scope
  state_scope=$(echo "$state" | jq -r '.scope')
  REGION=$(echo "$state" | jq -r '.region')

  # Allow scope override
  if [ -n "$scope" ]; then
    state_scope="$scope"
  fi

  log_info "Scope:  $state_scope"
  log_info "Region: $REGION"
  log_info ""

  local deleted_count=0

  # Step 1: Delete Web ACLs first
  log_info "Deleting Web ACLs..."
  local web_acl_names
  web_acl_names=$(echo "$state" | jq -r '.web_acls | keys[]' 2>/dev/null)

  if [ -n "$web_acl_names" ]; then
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      local id
      id=$(echo "$state" | jq -r --arg n "$name" '.web_acls[$n].id')
      if delete_web_acl "$name" "$id" "$state_scope"; then
        ((deleted_count++))
      fi
    done <<< "$web_acl_names"
  fi

  log_info ""

  # Step 2: Delete IP Sets
  log_info "Deleting IP Sets..."
  local ip_set_names
  ip_set_names=$(echo "$state" | jq -r '.ip_sets | keys[]' 2>/dev/null)

  if [ -n "$ip_set_names" ]; then
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      local id
      id=$(echo "$state" | jq -r --arg n "$name" '.ip_sets[$n].id')
      if delete_ip_set "$name" "$id" "$state_scope"; then
        ((deleted_count++))
      fi
    done <<< "$ip_set_names"
  fi

  # Remove state file
  rm -f "$STATE_FILE"
  log_info ""
  log_info "Removed state file: $STATE_FILE"

  # Summary
  echo ""
  echo "=============================================="
  echo "  Teardown Complete"
  echo "=============================================="
  echo ""
  echo "  Deleted $deleted_count resource(s)"
  echo ""
}

main "$@"
