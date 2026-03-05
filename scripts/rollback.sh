#!/bin/bash
# =============================================================================
# Vercel IP Allowlist Rollback Script
# =============================================================================
#
# Backup, restore, and manage IP allowlist firewall rules.
#
# Usage:
#   ./rollback.sh backup                    # Create backup of current config
#   ./rollback.sh show                      # Show current allowlist rule
#   ./rollback.sh restore <backup_file>     # Restore from backup
#   ./rollback.sh enable                    # Enable the allowlist rule
#   ./rollback.sh disable                   # Disable the allowlist rule
#   ./rollback.sh remove                    # Remove the allowlist rule
#
# Environment variables:
#   VERCEL_TOKEN (required): Vercel API token
#   PROJECT_ID (required): Project ID
#   TEAM_ID (optional): Team ID
#   BACKUP_DIR (optional): Directory for backups (default: ./backups)
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly API_BASE="https://api.vercel.com"
readonly BACKUP_DIR="${BACKUP_DIR:-./backups}"
readonly MAX_RETRIES=3
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly RULE_NAME="IP Allowlist - Auto-managed"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# =============================================================================
# Utility Functions
# =============================================================================

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
  if [ "${DEBUG:-false}" = "true" ]; then
    echo -e "${BLUE}[DEBUG]${NC} $1"
  fi
}

# Build team query parameter
get_team_param() {
  if [ -n "${TEAM_ID:-}" ]; then
    echo "teamId=${TEAM_ID}"
  elif [ -n "${TEAM_SLUG:-}" ]; then
    echo "slug=${TEAM_SLUG}"
  else
    echo ""
  fi
}

# Build query string
build_query_string() {
  local project_id="$1"
  local team_param
  team_param=$(get_team_param)
  
  if [ -n "$team_param" ]; then
    echo "?projectId=${project_id}&${team_param}"
  else
    echo "?projectId=${project_id}"
  fi
}

# =============================================================================
# API Functions
# =============================================================================

api_request() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"
  local attempt=1
  
  while [ $attempt -le $MAX_RETRIES ]; do
    local response
    local http_code
    
    if [ -n "$data" ]; then
      response=$(curl -s -w "\n%{http_code}" -X "$method" "${API_BASE}${endpoint}" \
        -H "Authorization: Bearer ${VERCEL_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$data")
    else
      response=$(curl -s -w "\n%{http_code}" -X "$method" "${API_BASE}${endpoint}" \
        -H "Authorization: Bearer ${VERCEL_TOKEN}" \
        -H "Content-Type: application/json")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" -eq 429 ]; then
      log_warn "Rate limited. Backing off for ${RATE_LIMIT_BACKOFF_SEC}s..."
      sleep "$RATE_LIMIT_BACKOFF_SEC"
      ((attempt++))
      continue
    fi
    
    echo "$body"
    echo "$http_code"
    return 0
  done
  
  echo "Max retries exceeded"
  echo "429"
  return 1
}

# Get current firewall configuration
get_firewall_config() {
  local project_id="$1"
  local query_string
  query_string=$(build_query_string "$project_id")
  
  local response
  response=$(api_request "GET" "/v1/security/firewall/config/active${query_string}")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -ne 200 ]; then
    log_error "Failed to get firewall config (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
  
  echo "$body"
}

# Find allowlist rule
find_allowlist_rule() {
  local config="$1"
  
  local rule
  rule=$(echo "$config" | jq -c --arg name "$RULE_NAME" '.rules[] | select(.name == $name)' 2>/dev/null || echo "")
  
  if [ -n "$rule" ]; then
    echo "$rule"
    return 0
  fi
  
  return 1
}

# Update rule active state
update_rule_state() {
  local project_id="$1"
  local rule_id="$2"
  local active="$3"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    --argjson active "$active" \
    '{action: "rules.update", id: $id, value: {active: $active}}')
  
  local response
  response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  
  if [ "$http_code" -eq 200 ]; then
    return 0
  else
    return 1
  fi
}

# Remove rule
remove_rule() {
  local project_id="$1"
  local rule_id="$2"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    '{action: "rules.remove", id: $id}')
  
  local response
  response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  
  if [ "$http_code" -eq 200 ]; then
    return 0
  else
    return 1
  fi
}

# Insert rule from backup
insert_rule() {
  local project_id="$1"
  local rule_json="$2"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  # Remove id field from rule (will be auto-generated)
  local rule_value
  rule_value=$(echo "$rule_json" | jq 'del(.id)')
  
  local request_body
  request_body=$(jq -n \
    --argjson value "$rule_value" \
    '{action: "rules.insert", id: null, value: $value}')
  
  local response
  response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  
  if [ "$http_code" -eq 200 ]; then
    return 0
  else
    return 1
  fi
}

# =============================================================================
# Commands
# =============================================================================

cmd_backup() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Creating backup of firewall configuration for project $project_id..."
  
  # Create backup directory with secure permissions
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  
  # Get config
  local config
  config=$(get_firewall_config "$project_id")
  
  if [ $? -ne 0 ]; then
    log_error "Failed to fetch firewall configuration"
    exit 1
  fi
  
  local rule_count
  rule_count=$(echo "$config" | jq '.rules | length' 2>/dev/null || echo "0")
  
  # Create backup file
  local timestamp
  timestamp=$(date +"%Y%m%d-%H%M%S")
  local backup_file="${BACKUP_DIR}/backup-${project_id}-${timestamp}.json"
  
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
        type: "firewall_config",
        rule_count: ($config.rules | length)
      },
      config: $config
    }' > "$backup_file"
  
  # Set secure permissions
  chmod 600 "$backup_file"
  
  echo ""
  log_info "Backup created successfully!"
  log_info "Rules backed up: $rule_count"
  log_info "Backup file: $backup_file"
}

cmd_show() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching firewall configuration for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  
  if [ $? -ne 0 ]; then
    log_error "Failed to fetch firewall configuration"
    exit 1
  fi
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  echo ""
  echo "=============================================="
  echo "  IP Allowlist Configuration"
  echo "=============================================="
  echo ""
  echo "Project: $project_id"
  echo ""
  
  if [ -z "$rule" ]; then
    echo "Status: No allowlist rule configured"
    echo ""
    echo "Use './vercel-bulk-waf-rules.sh apply vendor-ips.csv' to create one."
  else
    local rule_id
    rule_id=$(echo "$rule" | jq -r '.id')
    local active
    active=$(echo "$rule" | jq -r '.active')
    local name
    name=$(echo "$rule" | jq -r '.name')
    
    # Get IPs from condition
    local ips
    ips=$(echo "$rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value' 2>/dev/null || echo "[]")
    local ip_count
    ip_count=$(echo "$ips" | jq 'length' 2>/dev/null || echo "0")
    
    # Get hostname if scoped
    local hostname
    hostname=$(echo "$rule" | jq -r '.conditionGroup[0].conditions[] | select(.type == "host") | .value // empty' 2>/dev/null || echo "")
    
    echo "Rule Name:   $name"
    echo "Rule ID:     $rule_id"
    echo "Status:      $([ "$active" = "true" ] && echo -e "${GREEN}ACTIVE${NC}" || echo -e "${YELLOW}DISABLED${NC}")"
    echo "IP Count:    $ip_count"
    echo "Scope:       ${hostname:-project-wide}"
    echo ""
    
    if [ "$ip_count" -gt 0 ]; then
      echo "Whitelisted IPs:"
      echo "$ips" | jq -r '.[]' | head -20 | while read -r ip; do
        echo "  - $ip"
      done
      if [ "$ip_count" -gt 20 ]; then
        echo "  ... and $((ip_count - 20)) more"
      fi
    fi
  fi
  
  echo ""
  
  # Show other rules summary
  local other_rules
  other_rules=$(echo "$config" | jq --arg name "$RULE_NAME" '[.rules[] | select(.name != $name)]')
  local other_count
  other_count=$(echo "$other_rules" | jq 'length')
  
  if [ "$other_count" -gt 0 ]; then
    echo "Other Firewall Rules: $other_count"
    echo "$other_rules" | jq -r '.[] | "  - \(.name) (\(if .active then "active" else "disabled" end))"'
    echo ""
  fi
}

cmd_restore() {
  local backup_file="$1"
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  if [ ! -f "$backup_file" ]; then
    log_error "Backup file not found: $backup_file"
    exit 1
  fi
  
  log_info "Restoring allowlist rule from $backup_file..."
  
  # Validate backup file
  local backup_project
  backup_project=$(jq -r '.metadata.project_id' "$backup_file")
  local backup_type
  backup_type=$(jq -r '.metadata.type' "$backup_file")
  
  if [ "$backup_type" != "firewall_config" ]; then
    log_error "Invalid backup file type: $backup_type"
    exit 1
  fi
  
  # Find allowlist rule in backup
  local backed_up_rule
  backed_up_rule=$(jq -c --arg name "$RULE_NAME" '.config.rules[] | select(.name == $name)' "$backup_file" 2>/dev/null || echo "")
  
  if [ -z "$backed_up_rule" ]; then
    log_error "No allowlist rule found in backup"
    exit 1
  fi
  
  local ip_count
  ip_count=$(echo "$backed_up_rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value | length' 2>/dev/null || echo "0")
  
  echo ""
  echo "Backup details:"
  echo "  Backup project: $backup_project"
  echo "  Restore to:     $project_id"
  echo "  IP count:       $ip_count"
  echo "  Backup time:    $(jq -r '.metadata.backup_timestamp' "$backup_file")"
  echo ""
  
  if [ "$backup_project" != "$project_id" ]; then
    log_warn "Backup is for project $backup_project but restoring to $project_id"
  fi
  
  read -p "Continue with restore? (yes/no): " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 1
  fi
  
  # Check if rule already exists
  local config
  config=$(get_firewall_config "$project_id")
  
  local existing_rule
  existing_rule=$(find_allowlist_rule "$config" || echo "")
  
  if [ -n "$existing_rule" ]; then
    local existing_id
    existing_id=$(echo "$existing_rule" | jq -r '.id')
    log_warn "Existing allowlist rule found (ID: $existing_id)"
    read -p "Remove existing rule before restore? (yes/no): " REMOVE_EXISTING
    if [ "$REMOVE_EXISTING" = "yes" ]; then
      if remove_rule "$project_id" "$existing_id"; then
        log_info "Removed existing rule"
      else
        log_error "Failed to remove existing rule"
        exit 1
      fi
    else
      log_error "Cannot restore with existing rule in place"
      exit 1
    fi
  fi
  
  # Insert the backed-up rule
  if insert_rule "$project_id" "$backed_up_rule"; then
    log_info "Allowlist rule restored successfully!"
    log_info "IPs restored: $ip_count"
  else
    log_error "Failed to restore rule"
    exit 1
  fi
}

cmd_enable() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching allowlist rule..."
  
  local config
  config=$(get_firewall_config "$project_id")
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  if [ -z "$rule" ]; then
    log_error "No allowlist rule found"
    exit 1
  fi
  
  local rule_id
  rule_id=$(echo "$rule" | jq -r '.id')
  local active
  active=$(echo "$rule" | jq -r '.active')
  
  if [ "$active" = "true" ]; then
    log_info "Rule is already enabled"
    exit 0
  fi
  
  echo ""
  log_warn "This will ENABLE the allowlist rule."
  log_warn "All traffic from IPs NOT in the whitelist will be BLOCKED."
  echo ""
  read -p "Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 1
  fi
  
  if update_rule_state "$project_id" "$rule_id" true; then
    log_info "Allowlist rule enabled successfully"
  else
    log_error "Failed to enable rule"
    exit 1
  fi
}

cmd_disable() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching allowlist rule..."
  
  local config
  config=$(get_firewall_config "$project_id")
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  if [ -z "$rule" ]; then
    log_error "No allowlist rule found"
    exit 1
  fi
  
  local rule_id
  rule_id=$(echo "$rule" | jq -r '.id')
  local active
  active=$(echo "$rule" | jq -r '.active')
  
  if [ "$active" = "false" ]; then
    log_info "Rule is already disabled"
    exit 0
  fi
  
  echo ""
  log_warn "This will DISABLE the allowlist rule."
  log_warn "All traffic will be allowed until the rule is re-enabled."
  echo ""
  read -p "Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 1
  fi
  
  if update_rule_state "$project_id" "$rule_id" false; then
    log_info "Allowlist rule disabled successfully"
  else
    log_error "Failed to disable rule"
    exit 1
  fi
}

cmd_remove() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching allowlist rule..."
  
  local config
  config=$(get_firewall_config "$project_id")
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  if [ -z "$rule" ]; then
    log_error "No allowlist rule found"
    exit 1
  fi
  
  local rule_id
  rule_id=$(echo "$rule" | jq -r '.id')
  
  # Create backup first
  log_info "Creating backup before removal..."
  cmd_backup
  
  echo ""
  log_warn "This will PERMANENTLY DELETE the allowlist rule."
  log_warn "All traffic will be allowed after deletion."
  echo ""
  read -p "Type 'DELETE' to confirm: " CONFIRM
  if [ "$CONFIRM" != "DELETE" ]; then
    echo "Aborted."
    exit 1
  fi
  
  if remove_rule "$project_id" "$rule_id"; then
    log_info "Allowlist rule removed successfully"
  else
    log_error "Failed to remove rule"
    exit 1
  fi
}

show_usage() {
  cat << EOF
Vercel IP Allowlist Rollback Script

USAGE:
  $0 backup                    Create backup of current firewall config
  $0 show                      Display current allowlist rule
  $0 restore <backup_file>     Restore allowlist rule from backup
  $0 enable                    Enable the allowlist rule
  $0 disable                   Disable the allowlist rule (keeps config)
  $0 remove                    Remove the allowlist rule (creates backup first)
  $0 --help                    Show this help message

ENVIRONMENT VARIABLES:
  VERCEL_TOKEN   (required) Vercel API token
  PROJECT_ID     (required) Project ID
  TEAM_ID        (optional) Team ID
  TEAM_SLUG      (optional) Team slug (alternative to TEAM_ID)
  BACKUP_DIR     (optional) Backup directory (default: ./backups)
  DEBUG          (optional) Set to "true" for verbose output

EXAMPLES:
  # Create backup
  PROJECT_ID=prj_xxx ./rollback.sh backup

  # Show current state
  PROJECT_ID=prj_xxx ./rollback.sh show

  # Restore from backup
  PROJECT_ID=prj_xxx ./rollback.sh restore backups/backup-prj_xxx-20260126-143000.json

  # Disable temporarily (keeps IPs configured)
  PROJECT_ID=prj_xxx ./rollback.sh disable

  # Re-enable
  PROJECT_ID=prj_xxx ./rollback.sh enable

  # Remove completely (creates backup first)
  PROJECT_ID=prj_xxx ./rollback.sh remove

EOF
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Check dependencies
  if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null; then
    log_error "Required dependencies: curl, jq"
    exit 1
  fi
  
  # Check token
  if [ -z "${VERCEL_TOKEN:-}" ]; then
    log_error "VERCEL_TOKEN environment variable is not set"
    exit 1
  fi
  
  if [ $# -eq 0 ]; then
    show_usage
    exit 1
  fi
  
  case "$1" in
    backup)
      cmd_backup
      ;;
    show)
      cmd_show
      ;;
    restore)
      if [ -z "${2:-}" ]; then
        log_error "Backup file required"
        echo "Usage: $0 restore <backup_file>"
        exit 1
      fi
      cmd_restore "$2"
      ;;
    enable)
      cmd_enable
      ;;
    disable)
      cmd_disable
      ;;
    remove)
      cmd_remove
      ;;
    --help|-h)
      show_usage
      exit 0
      ;;
    *)
      log_error "Unknown command: $1"
      show_usage
      exit 1
      ;;
  esac
}

main "$@"
