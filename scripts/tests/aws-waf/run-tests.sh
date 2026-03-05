#!/bin/bash
# =============================================================================
# AWS WAF E2E Tests
# =============================================================================
#
# End-to-end tests for the aws-waf-export.sh script.
# Runs against real AWS WAF resources created by setup.sh.
#
# Prerequisites:
#   - Run setup.sh first to create test resources
#   - .test-state.json must exist in this directory
#   - Valid AWS credentials
#
# Usage:
#   ./run-tests.sh                  Run all tests
#   ./run-tests.sh --filter help    Run only tests matching "help"
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly STATE_FILE="$SCRIPT_DIR/.test-state.json"
readonly EXPORT_SCRIPT="$SCRIPT_DIR/../../exports/aws-waf-export.sh"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILURES=()

# Temp directory for test outputs
TEST_TMPDIR=""

# State variables (loaded from .test-state.json)
STATE_SCOPE=""
STATE_REGION=""
ALLOWLIST_ID=""
BLOCKLIST_ID=""
IPV6_ID=""
EMPTY_ID=""
WEB_ACL_ID=""

# Optional filter
TEST_FILTER=""

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

# =============================================================================
# Test Framework
# =============================================================================

run_test() {
  local test_name="$1"
  local test_func="$2"

  # Apply filter if set
  if [ -n "$TEST_FILTER" ]; then
    if ! echo "$test_name" | grep -qi "$TEST_FILTER"; then
      return 0
    fi
  fi

  TESTS_RUN=$((TESTS_RUN + 1))
  local start_time
  start_time=$(date +%s)

  # Clean temp dir before each test
  rm -rf "$TEST_TMPDIR"/*

  if $test_func; then
    local elapsed=$(( $(date +%s) - start_time ))
    echo -e "  ${GREEN}✓${NC} $test_name ${BLUE}(${elapsed}s)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    local elapsed=$(( $(date +%s) - start_time ))
    echo -e "  ${RED}✗${NC} $test_name ${BLUE}(${elapsed}s)${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILURES+=("$test_name")
  fi
}

print_summary() {
  echo ""
  echo "=============================================="
  echo "  AWS WAF Export - E2E Test Results"
  echo "=============================================="
  echo ""
  echo "  $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed"
  if [ ${#FAILURES[@]} -gt 0 ]; then
    echo ""
    echo "  Failed tests:"
    for f in "${FAILURES[@]}"; do
      echo "    - $f"
    done
  fi
  echo ""
  [ $TESTS_FAILED -eq 0 ]
}

# =============================================================================
# Assert Helpers
# =============================================================================

assert_exit_code() {
  local expected="$1"
  local actual="$2"
  if [ "$expected" != "$actual" ]; then
    log_error "Expected exit code $expected, got $actual"
    return 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! echo "$haystack" | grep -q "$needle"; then
    log_error "Expected output to contain: $needle"
    return 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if echo "$haystack" | grep -q "$needle"; then
    log_error "Expected output NOT to contain: $needle"
    return 1
  fi
}

assert_file_exists() {
  if [ ! -f "$1" ]; then
    log_error "Expected file to exist: $1"
    return 1
  fi
}

assert_file_not_exists() {
  if [ -f "$1" ]; then
    log_error "Expected file NOT to exist: $1"
    return 1
  fi
}

assert_line_count() {
  local file="$1"
  local expected="$2"
  local actual
  actual=$(wc -l < "$file" | tr -d ' ')
  if [ "$actual" != "$expected" ]; then
    log_error "Expected $expected lines, got $actual in $file"
    return 1
  fi
}

assert_csv_columns() {
  if ! head -1 "$1" | grep -q "^ip,notes,mode,created_on"; then
    log_error "Expected CSV header: ip,notes,mode,created_on"
    log_error "Got: $(head -1 "$1")"
    return 1
  fi
}

assert_csv_data_rows() {
  local file="$1"
  local expected="$2"
  local actual
  # Data rows = total lines minus header
  local total
  total=$(wc -l < "$file" | tr -d ' ')
  actual=$((total - 1))
  if [ "$actual" != "$expected" ]; then
    log_error "Expected $expected data rows, got $actual in $file"
    return 1
  fi
}

# =============================================================================
# Helper: run export script and capture output/exit code
# =============================================================================

run_export() {
  local output_file="$TEST_TMPDIR/output.csv"
  local stdout_file="$TEST_TMPDIR/stdout.txt"
  local stderr_file="$TEST_TMPDIR/stderr.txt"
  local exit_code=0

  # Build env vars
  local env_prefix="OUTPUT_FILE=$output_file"

  # Run the export script
  env $env_prefix "$EXPORT_SCRIPT" --scope "$STATE_SCOPE" "$@" \
    > "$stdout_file" 2> "$stderr_file" || exit_code=$?

  echo "$exit_code"
}

run_export_with_env() {
  local env_vars="$1"
  shift
  local stdout_file="$TEST_TMPDIR/stdout.txt"
  local stderr_file="$TEST_TMPDIR/stderr.txt"
  local exit_code=0

  env $env_vars "$EXPORT_SCRIPT" --scope "$STATE_SCOPE" "$@" \
    > "$stdout_file" 2> "$stderr_file" || exit_code=$?

  echo "$exit_code"
}

get_stdout() {
  cat "$TEST_TMPDIR/stdout.txt" 2>/dev/null || true
}

get_stderr() {
  cat "$TEST_TMPDIR/stderr.txt" 2>/dev/null || true
}

get_all_output() {
  cat "$TEST_TMPDIR/stdout.txt" "$TEST_TMPDIR/stderr.txt" 2>/dev/null || true
}

# =============================================================================
# Test Cases
# =============================================================================

test_help() {
  local exit_code=0
  "$EXPORT_SCRIPT" --help > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  local output
  output=$(get_all_output)
  assert_contains "$output" "Usage" || return 1
}

test_version() {
  local exit_code=0
  "$EXPORT_SCRIPT" --version > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  local output
  output=$(get_all_output)
  assert_contains "$output" "aws-waf-export.sh" || return 1
}

test_invalid_command() {
  local exit_code=0
  "$EXPORT_SCRIPT" --foobar > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 6 "$exit_code" || return 1
}

test_missing_args() {
  local exit_code=0
  "$EXPORT_SCRIPT" --ip-set > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 6 "$exit_code" || return 1
}

test_list_ip_sets() {
  local exit_code
  exit_code=$(run_export --list-ip-sets)

  assert_exit_code 0 "$exit_code" || return 1

  local output
  output=$(get_all_output)
  assert_contains "$output" "e2e-test-allowlist-v4" || return 1
  assert_contains "$output" "e2e-test-blocklist-v4" || return 1
  assert_contains "$output" "e2e-test-ipv6-only" || return 1
  assert_contains "$output" "e2e-test-empty" || return 1
}

test_list_web_acls() {
  local exit_code
  exit_code=$(run_export --list-web-acls)

  assert_exit_code 0 "$exit_code" || return 1

  local output
  output=$(get_all_output)
  assert_contains "$output" "e2e-test-web-acl" || return 1
}

test_export_single_ip_set() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-allowlist-v4" "$ALLOWLIST_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file" || return 1
  assert_csv_columns "$output_file" || return 1
  assert_csv_data_rows "$output_file" 5 || return 1

  # Verify all 5 IPs present
  local content
  content=$(cat "$output_file")
  assert_contains "$content" "192.0.2.1/32" || return 1
  assert_contains "$content" "192.0.2.2/32" || return 1
  assert_contains "$content" "192.0.2.3/32" || return 1
  assert_contains "$content" "198.51.100.0/24" || return 1
  assert_contains "$content" "203.0.113.0/24" || return 1

  # Verify 4 CSV columns per row
  local col_count
  col_count=$(tail -1 "$output_file" | awk -F',' '{print NF}')
  if [ "$col_count" -ne 4 ]; then
    log_error "Expected 4 CSV columns, got $col_count"
    return 1
  fi
}

test_export_all_ip_sets() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --all-ip-sets \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file" || return 1
  assert_csv_columns "$output_file" || return 1

  # Should have 8 data rows: 5 (allowlist) + 3 (blocklist)
  # IPv6 set skipped (no --include-ipv6), empty set has 0 addresses
  assert_csv_data_rows "$output_file" 8 || return 1
}

test_export_web_acl() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --web-acl "e2e-test-web-acl" "$WEB_ACL_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file" || return 1
  assert_csv_columns "$output_file" || return 1

  # Web ACL references allowlist (5) + blocklist (3) = 8 data rows
  assert_csv_data_rows "$output_file" 8 || return 1
}

test_ipv6_skip() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-ipv6-only" "$IPV6_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  # Should exit 0 (graceful skip)
  assert_exit_code 0 "$exit_code" || return 1

  # stderr should mention skipping IPv6
  local stderr_output
  stderr_output=$(get_stderr)
  assert_contains "$stderr_output" "IPv6" || return 1

  # CSV should either not exist or have header only
  if [ -f "$output_file" ]; then
    local data_rows
    local total
    total=$(wc -l < "$output_file" | tr -d ' ')
    data_rows=$((total - 1))
    if [ "$data_rows" -gt 0 ]; then
      log_error "Expected 0 data rows for skipped IPv6 set, got $data_rows"
      return 1
    fi
  fi
}

test_ipv6_include() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --include-ipv6 \
    --ip-set "e2e-test-ipv6-only" "$IPV6_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file" || return 1
  assert_csv_columns "$output_file" || return 1
  assert_csv_data_rows "$output_file" 2 || return 1
}

test_empty_ip_set() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-empty" "$EMPTY_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  # Should exit 0 (graceful handling of empty set)
  assert_exit_code 0 "$exit_code" || return 1

  # CSV may or may not be created. If created, it should have header only or 0 data rows
  if [ -f "$output_file" ]; then
    local total
    total=$(wc -l < "$output_file" | tr -d ' ')
    local data_rows=$((total - 1))
    if [ "$data_rows" -gt 0 ]; then
      log_error "Expected 0 data rows for empty IP Set, got $data_rows"
      return 1
    fi
  fi
}

test_dry_run() {
  local output_file="$TEST_TMPDIR/dryrun.csv"
  local exit_code=0

  env DRY_RUN=true OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-allowlist-v4" "$ALLOWLIST_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_not_exists "$output_file" || return 1

  # Output should mention dry run
  local output
  output=$(get_all_output)
  assert_contains "$output" "DRY RUN" || return 1
}

test_custom_output_file() {
  local custom_path="/tmp/e2e-custom-$(date +%s).csv"
  local exit_code=0

  env OUTPUT_FILE="$custom_path" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-allowlist-v4" "$ALLOWLIST_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$custom_path" || return 1
  assert_csv_columns "$custom_path" || return 1
  assert_csv_data_rows "$custom_path" 5 || return 1

  # Clean up custom file
  rm -f "$custom_path"
}

test_csv_format() {
  local output_file="$TEST_TMPDIR/output.csv"
  local exit_code=0

  env OUTPUT_FILE="$output_file" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-allowlist-v4" "$ALLOWLIST_ID" \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file" || return 1

  # Verify exact header
  local header
  header=$(head -1 "$output_file")
  if [ "$header" != "ip,notes,mode,created_on" ]; then
    log_error "Expected header: ip,notes,mode,created_on"
    log_error "Got: $header"
    return 1
  fi

  # Verify every data row has exactly 4 fields
  local bad_rows=0
  while IFS= read -r line; do
    local field_count
    field_count=$(echo "$line" | awk -F',' '{print NF}')
    if [ "$field_count" -ne 4 ]; then
      log_error "Row has $field_count fields (expected 4): $line"
      ((bad_rows++))
    fi
  done < <(tail -n +2 "$output_file")

  if [ "$bad_rows" -gt 0 ]; then
    return 1
  fi
}

test_idempotent() {
  local output_file_1="$TEST_TMPDIR/run1.csv"
  local output_file_2="$TEST_TMPDIR/run2.csv"
  local exit_code=0

  # First run
  env OUTPUT_FILE="$output_file_1" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-allowlist-v4" "$ALLOWLIST_ID" \
    > /dev/null 2>&1 || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file_1" || return 1

  # Second run
  exit_code=0
  env OUTPUT_FILE="$output_file_2" "$EXPORT_SCRIPT" \
    --scope "$STATE_SCOPE" \
    --ip-set "e2e-test-allowlist-v4" "$ALLOWLIST_ID" \
    > /dev/null 2>&1 || exit_code=$?

  assert_exit_code 0 "$exit_code" || return 1
  assert_file_exists "$output_file_2" || return 1

  # Diff the outputs — must be identical
  if ! diff -q "$output_file_1" "$output_file_2" > /dev/null 2>&1; then
    log_error "Outputs differ between two runs"
    diff "$output_file_1" "$output_file_2" >&2 || true
    return 1
  fi
}

test_invalid_scope() {
  local exit_code=0
  "$EXPORT_SCRIPT" --scope INVALID --list-ip-sets \
    > "$TEST_TMPDIR/stdout.txt" 2> "$TEST_TMPDIR/stderr.txt" || exit_code=$?

  assert_exit_code 6 "$exit_code" || return 1
}

# =============================================================================
# Setup & Teardown
# =============================================================================

setup_test_env() {
  # Verify state file exists
  if [ ! -f "$STATE_FILE" ]; then
    log_error "State file not found: $STATE_FILE"
    log_error "Run setup.sh first to create test resources."
    exit 1
  fi

  # Verify export script exists
  if [ ! -f "$EXPORT_SCRIPT" ]; then
    log_error "Export script not found: $EXPORT_SCRIPT"
    exit 1
  fi

  # Load state
  local state
  state=$(cat "$STATE_FILE")

  STATE_SCOPE=$(echo "$state" | jq -r '.scope')
  STATE_REGION=$(echo "$state" | jq -r '.region')
  ALLOWLIST_ID=$(echo "$state" | jq -r '.ip_sets["e2e-test-allowlist-v4"].id')
  BLOCKLIST_ID=$(echo "$state" | jq -r '.ip_sets["e2e-test-blocklist-v4"].id')
  IPV6_ID=$(echo "$state" | jq -r '.ip_sets["e2e-test-ipv6-only"].id')
  EMPTY_ID=$(echo "$state" | jq -r '.ip_sets["e2e-test-empty"].id')
  WEB_ACL_ID=$(echo "$state" | jq -r '.web_acls["e2e-test-web-acl"].id')

  # Set region env var for the export script
  export AWS_DEFAULT_REGION="$STATE_REGION"

  # Validate IDs loaded
  if [ -z "$ALLOWLIST_ID" ] || [ "$ALLOWLIST_ID" = "null" ]; then
    log_error "Failed to load allowlist ID from state file"
    exit 1
  fi
  if [ -z "$WEB_ACL_ID" ] || [ "$WEB_ACL_ID" = "null" ]; then
    log_error "Failed to load Web ACL ID from state file"
    exit 1
  fi

  # Create temp directory
  TEST_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/aws-waf-e2e.XXXXXX")

  log_info "Test environment:"
  log_info "  Scope:       $STATE_SCOPE"
  log_info "  Region:      $STATE_REGION"
  log_info "  Allowlist:   $ALLOWLIST_ID"
  log_info "  Blocklist:   $BLOCKLIST_ID"
  log_info "  IPv6 Set:    $IPV6_ID"
  log_info "  Empty Set:   $EMPTY_ID"
  log_info "  Web ACL:     $WEB_ACL_ID"
  log_info "  Temp dir:    $TEST_TMPDIR"
  log_info ""
}

cleanup_test_env() {
  if [ -n "$TEST_TMPDIR" ] && [ -d "$TEST_TMPDIR" ]; then
    rm -rf "$TEST_TMPDIR"
  fi
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Parse arguments
  while [ $# -gt 0 ]; do
    case "$1" in
      --filter)
        TEST_FILTER="${2:-}"
        shift 2
        ;;
      --help|-h)
        echo "Usage: ./run-tests.sh [--filter <pattern>]"
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
  echo "  AWS WAF Export - E2E Tests"
  echo "=============================================="
  echo ""

  # Setup
  setup_test_env
  trap cleanup_test_env EXIT

  # Run tests
  echo "Running tests..."
  echo ""

  echo "  CLI basics:"
  run_test "help flag shows usage" test_help
  run_test "version flag shows version" test_version
  run_test "invalid command exits 6" test_invalid_command
  run_test "missing args exits 6" test_missing_args
  run_test "invalid scope exits 6" test_invalid_scope
  echo ""

  echo "  Discovery:"
  run_test "list-ip-sets shows all test IP Sets" test_list_ip_sets
  run_test "list-web-acls shows test Web ACL" test_list_web_acls
  echo ""

  echo "  Export — single IP Set:"
  run_test "export single IP Set (5 IPs)" test_export_single_ip_set
  run_test "CSV format is correct" test_csv_format
  run_test "custom output file path" test_custom_output_file
  run_test "dry run produces no CSV" test_dry_run
  run_test "idempotent: two runs produce same output" test_idempotent
  echo ""

  echo "  Export — bulk:"
  run_test "export all IP Sets (8 IPs, skips IPv6/empty)" test_export_all_ip_sets
  run_test "export Web ACL resolves referenced IP Sets" test_export_web_acl
  echo ""

  echo "  Edge cases:"
  run_test "IPv6 IP Set is skipped by default" test_ipv6_skip
  run_test "IPv6 IP Set included with --include-ipv6" test_ipv6_include
  run_test "empty IP Set handled gracefully" test_empty_ip_set
  echo ""

  # Summary
  print_summary
}

main "$@"
