#!/bin/bash
# =============================================================================
# Allowlist Decomposition Tests
# =============================================================================
#
# Offline tests for how vercel-bulk-waf-rules.sh decomposes a large IP list
# into WAF rule conditions. No network, no credentials, no AWS/Vercel calls.
#
# The main script is sourced (its `main` is guarded by a BASH_SOURCE check) and
# api_request is stubbed, so the real PATCH request body is captured and
# asserted against.
#
# Regression guarded: a "ninc" (NOT IN) allowlist MUST stay in ONE rule with ONE
# condition group. Conditions AND; rules and condition groups OR. Splitting the
# negated list across ORing containers denies every request - a total outage.
#
# Usage:
#   ./run-tests.sh                  Run all tests
#   ./run-tests.sh --filter 150     Run only tests matching "150"
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly TARGET_SCRIPT="$SCRIPT_DIR/../../vercel-bulk-waf-rules.sh"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILURES=()

# Temp directory for captured request bodies
TEST_TMPDIR=""
CAPTURED_BODY=""
REQUEST_LOG=""
INSERT_COUNT_FILE=""

# Optional filter
TEST_FILTER=""

# =============================================================================
# Target Script
# =============================================================================

# Provides log_* helpers, colors, MAX_* constants and the functions under test.
# Its `main` is guarded by a BASH_SOURCE check, so sourcing runs nothing.
# shellcheck source=../../vercel-bulk-waf-rules.sh
source "$TARGET_SCRIPT"

# =============================================================================
# Offline Stubs
# =============================================================================

# Fault injection knobs, honoured by the api_request stub below
FAIL_INSERT_AFTER=-1   # -1 = never fail; N = fail every insert after N successes
FAIL_REMOVALS=false
# Id the stub reports for inserted rules; must never show up in a remove call
readonly NEW_RULE_ID="rule_NEWLY_CREATED"

# Capture the PATCH body instead of calling the Vercel API, log the request
# sequence so ordering can be asserted, and optionally simulate API failures.
api_request() {
  local body="${3:-}"
  printf '%s' "$body" > "$CAPTURED_BODY"

  local act
  act=$(echo "$body" | jq -r '.action // "none"' 2>/dev/null || echo "none")
  local id
  id=$(echo "$body" | jq -r '.id // "null"' 2>/dev/null || echo "null")

  if [ -n "$REQUEST_LOG" ]; then
    echo "$act $id" >> "$REQUEST_LOG"
  fi

  if [ "$act" = "rules.insert" ]; then
    local inserts=0
    if [ -n "$INSERT_COUNT_FILE" ]; then
      printf 'x' >> "$INSERT_COUNT_FILE"
      inserts=$(wc -c < "$INSERT_COUNT_FILE" | tr -d ' ')
    fi
    if [ "$FAIL_INSERT_AFTER" -ge 0 ] && [ "$inserts" -gt "$FAIL_INSERT_AFTER" ]; then
      echo '{"error":{"code":"FIREWALL_INTERNAL_ERROR","message":"simulated insert failure"}}'
      echo "500"
      return 0
    fi
    echo "{\"id\":\"$NEW_RULE_ID\"}"
    echo "200"
    return 0
  fi

  # 403 is not retried by remove_allowlist_rule, so the stub fails fast
  if [ "$act" = "rules.remove" ] && [ "$FAIL_REMOVALS" = "true" ]; then
    echo '{"error":{"code":"FORBIDDEN","message":"simulated removal failure"}}'
    echo "403"
    return 0
  fi

  echo "{}"
  echo "200"
}

# =============================================================================
# Test Framework
# =============================================================================

run_test() {
  local test_name="$1"
  local test_func="$2"

  if [ -n "$TEST_FILTER" ]; then
    if ! echo "$test_name" | grep -qi "$TEST_FILTER"; then
      return 0
    fi
  fi

  TESTS_RUN=$((TESTS_RUN + 1))
  rm -rf "${TEST_TMPDIR:?}"/*

  if $test_func; then
    echo -e "  ${GREEN}✓${NC} $test_name"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "  ${RED}✗${NC} $test_name"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILURES+=("$test_name")
  fi
}

print_summary() {
  echo ""
  echo "=============================================="
  echo "  Allowlist Decomposition - Test Results"
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
  [ "$TESTS_FAILED" -eq 0 ]
}

# =============================================================================
# Assert Helpers
# =============================================================================

assert_equals() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [ "$expected" != "$actual" ]; then
    log_error "$label: expected '$expected', got '$actual'"
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

# =============================================================================
# Fixtures
# =============================================================================

# Deterministic, non-contiguous IPs so CIDR optimization cannot collapse them
make_ips() {
  local count="$1"
  jq -n --argjson n "$count" '[range(0; $n) | "10.\(. / 16384 | floor).\((. / 128 | floor) % 128).\((. % 128) * 2)"]'
}

# Drive the real rule builder and return the captured PATCH request body
capture_rule_body() {
  local ips_json="$1"
  update_allowlist_rule "prj_test" "$ips_json" "insert" "" > /dev/null
  cat "$CAPTURED_BODY"
}

# =============================================================================
# Core Assertion: allowlist decomposition invariants
# =============================================================================

assert_decomposition() {
  local count="$1"
  local hostname="${2:-}"

  local ips
  ips=$(make_ips "$count")

  local actual_input_count
  actual_input_count=$(echo "$ips" | jq 'length')
  assert_equals "fixture size" "$count" "$actual_input_count" || return 1

  RULE_HOSTNAME="$hostname"
  local body
  body=$(capture_rule_body "$ips")
  RULE_HOSTNAME=""

  local value
  value=$(echo "$body" | jq '.value')

  # Exactly one condition group: groups OR, which would reintroduce the outage
  assert_equals "conditionGroup count" "1" "$(echo "$value" | jq '.conditionGroup | length')" || return 1

  local expected_ip_conditions=$(( (count + MAX_IPS_PER_CONDITION - 1) / MAX_IPS_PER_CONDITION ))
  local expected_conditions="$expected_ip_conditions"
  [ -n "$hostname" ] && expected_conditions=$((expected_ip_conditions + 1))

  assert_equals "condition count" "$expected_conditions" \
    "$(echo "$value" | jq '.conditionGroup[0].conditions | length')" || return 1

  # Every ip_address condition negates the set
  assert_equals "non-ninc ip conditions" "0" \
    "$(echo "$value" | jq '[.conditionGroup[0].conditions[] | select(.type == "ip_address") | select(.op != "ninc")] | length')" || return 1

  # No slice exceeds the server cap
  assert_equals "oversized slices" "0" \
    "$(echo "$value" | jq --argjson max "$MAX_IPS_PER_CONDITION" '[.conditionGroup[0].conditions[] | select(.type == "ip_address") | select((.value | length) > $max)] | length')" || return 1

  # Union of all slices equals the input set, with nothing dropped or duplicated
  local emitted
  emitted=$(echo "$value" | jq -c '[.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value[]]')
  assert_equals "total emitted entries (no drops/dupes)" "$count" "$(echo "$emitted" | jq 'length')" || return 1
  assert_equals "distinct emitted entries" "$count" "$(echo "$emitted" | jq 'unique | length')" || return 1
  assert_equals "union equals input" "true" \
    "$(jq -n --argjson a "$emitted" --argjson b "$ips" '($a | sort) == ($b | sort)')" || return 1

  # Action and naming: one rule means no "(Part N/M)" suffix
  assert_equals "action" "deny" "$(echo "$value" | jq -r '.action.mitigate.action')" || return 1
  assert_equals "rule name" "$RULE_NAME" "$(echo "$value" | jq -r '.name')" || return 1

  if [ -n "$hostname" ]; then
    assert_equals "host condition first" "host" \
      "$(echo "$value" | jq -r '.conditionGroup[0].conditions[0].type')" || return 1
    assert_equals "host value" "$hostname" \
      "$(echo "$value" | jq -r '.conditionGroup[0].conditions[0].value')" || return 1
  fi
}

# =============================================================================
# Tests
# =============================================================================

test_deny_1()     { assert_decomposition 1; }
test_deny_75()    { assert_decomposition 75; }
test_deny_76()    { assert_decomposition 76; }
test_deny_150()   { assert_decomposition 150; }
test_deny_4875()  { assert_decomposition 4875; }

test_deny_150_hostname() { assert_decomposition 150 "api.example.com"; }

# 75 or fewer entries must keep producing exactly the pre-2.1.0 single condition
test_deny_75_unchanged_shape() {
  local ips
  ips=$(make_ips 75)
  local body
  body=$(capture_rule_body "$ips")
  assert_equals "conditions" "1" "$(echo "$body" | jq '.value.conditionGroup[0].conditions | length')" || return 1
  assert_equals "ips in condition" "75" "$(echo "$body" | jq '.value.conditionGroup[0].conditions[0].value | length')" || return 1
}

# Bypass mode still packs into one group here; sibling-rule chunking is handled
# by cmd_apply and is semantically correct for positive ("inc") matching
test_bypass_75_single_condition() {
  local saved_op="$RULE_IP_OP"
  local saved_action="$RULE_ACTION"
  RULE_IP_OP="inc"
  RULE_ACTION="bypass"

  local body
  body=$(capture_rule_body "$(make_ips 75)")

  RULE_IP_OP="$saved_op"
  RULE_ACTION="$saved_action"

  assert_equals "conditionGroup count" "1" "$(echo "$body" | jq '.value.conditionGroup | length')" || return 1
  assert_equals "op" "inc" "$(echo "$body" | jq -r '.value.conditionGroup[0].conditions[0].op')" || return 1
  assert_equals "action" "bypass" "$(echo "$body" | jq -r '.value.action.mitigate.action')" || return 1
}

# 4876 entries must be refused outright rather than emitting a broken rule
test_deny_4876_refused() {
  local csv="$TEST_TMPDIR/over-ceiling.csv"
  {
    echo "ip,vendor_name,notes"
    make_ips 4876 | jq -r '.[] | "\(.),Test,over-ceiling"'
  } > "$csv"

  local out
  local code=0
  out=$( (SKIP_OPTIMIZE=true PROJECT_ID="prj_test" cmd_apply "$csv") 2>&1 ) || code=$?

  assert_equals "exit code" "1" "$code" || { echo "$out" >&2; return 1; }
  assert_contains "$out" "exceeds the allowlist ceiling of $MAX_ALLOWLIST_IPS entries" || return 1
  assert_contains "$out" "bypass-rules + terminal-deny topology" || return 1
  assert_contains "$out" "optimize" || return 1
}

# RULE_HOSTNAME spends one of the 65 condition slots, so the ceiling drops to
# 4800. This must refuse in preflight: stale-rule removal runs before the insert,
# so letting a 66-condition rule reach the API would strip the existing allowlist
# and then fail, leaving the project with no deny rule at all (fail-open).
test_deny_hostname_lowers_ceiling() {
  local csv="$TEST_TMPDIR/over-ceiling-host.csv"
  local scoped_ceiling=$(( (MAX_CONDITIONS_PER_GROUP - 1) * MAX_IPS_PER_CONDITION ))
  {
    echo "ip,vendor_name,notes"
    make_ips $(( scoped_ceiling + 1 )) | jq -r '.[] | "\(.),Test,over-scoped-ceiling"'
  } > "$csv"

  local out
  local code=0
  out=$( (SKIP_OPTIMIZE=true PROJECT_ID="prj_test" RULE_HOSTNAME="example.com" cmd_apply "$csv") 2>&1 ) || code=$?

  assert_equals "exit code" "1" "$code" || { echo "$out" >&2; return 1; }
  assert_contains "$out" "exceeds the allowlist ceiling of $scoped_ceiling entries" || return 1
  assert_contains "$out" "RULE_HOSTNAME is set" || return 1
}

# The same count without a hostname is under the unscoped ceiling and must apply.
test_deny_scoped_ceiling_ok_without_hostname() {
  local scoped_ceiling=$(( (MAX_CONDITIONS_PER_GROUP - 1) * MAX_IPS_PER_CONDITION ))
  local conditions
  conditions=$(build_ip_conditions "$(make_ips $(( scoped_ceiling + 1 )))" "ninc" "")

  assert_equals "conditions" "65" "$(echo "$conditions" | jq 'length')" || return 1
}

# =============================================================================
# Audit Command Tests
# =============================================================================

# Run cmd_audit against a canned firewall config and return "<exit>|<output>"
# STUB_CONFIG is deliberately not named "config": bash uses dynamic scoping, so
# the stub would otherwise resolve cmd_audit's own unset local.
run_audit_against() {
  local STUB_CONFIG="$1"
  local out
  local code=0

  out=$(
    (
      get_firewall_config() { echo "$STUB_CONFIG"; }
      PROJECT_ID="prj_test" cmd_audit
    ) 2>&1
  ) || code=$?

  printf '%s|%s' "$code" "$out"
}

make_rule() {
  local name="$1"
  local action="$2"
  local op="$3"
  local groups="$4"
  jq -n --arg name "$name" --arg action "$action" --arg op "$op" --argjson groups "$groups" \
    '{
      id: ("rule_" + ($name | gsub("[^a-zA-Z0-9]"; ""))),
      name: $name,
      active: true,
      conditionGroup: [range(0; $groups) | {conditions: [{type: "ip_address", op: $op, value: ["1.2.3.4"]}]}],
      action: {mitigate: {action: $action}}
    }'
}

test_audit_vulnerable_sibling_rules() {
  local config
  config=$(jq -n \
    --argjson a "$(make_rule "IP Allowlist - Auto-managed (Part 1/2)" deny ninc 1)" \
    --argjson b "$(make_rule "IP Allowlist - Auto-managed (Part 2/2)" deny ninc 1)" \
    '{active: {rules: [$a, $b]}}')

  local result
  result=$(run_audit_against "$config")
  assert_equals "exit code" "2" "${result%%|*}" || return 1
  assert_contains "${result#*|}" "RESULT: VULNERABLE" || return 1
  assert_contains "${result#*|}" "sibling rules" || return 1
  assert_contains "${result#*|}" "Part 1/2" || return 1
}

test_audit_vulnerable_condition_groups() {
  local config
  config=$(jq -n \
    --argjson a "$(make_rule "IP Allowlist - Auto-managed" deny ninc 2)" \
    '{active: {rules: [$a]}}')

  local result
  result=$(run_audit_against "$config")
  assert_equals "exit code" "2" "${result%%|*}" || return 1
  assert_contains "${result#*|}" "RESULT: VULNERABLE" || return 1
  assert_contains "${result#*|}" "condition groups" || return 1
}

test_audit_ok_single_rule() {
  local config
  config=$(jq -n \
    --argjson a "$(make_rule "IP Allowlist - Auto-managed" deny ninc 1)" \
    '{active: {rules: [$a]}}')

  local result
  result=$(run_audit_against "$config")
  assert_equals "exit code" "0" "${result%%|*}" || return 1
  assert_contains "${result#*|}" "RESULT: OK" || return 1
}

# Bypass rules OR correctly, so several of them are not the outage signature
test_audit_ok_multiple_bypass_rules() {
  local config
  config=$(jq -n \
    --argjson a "$(make_rule "IP Bypass - Auto-managed (Part 1/2)" bypass inc 1)" \
    --argjson b "$(make_rule "IP Bypass - Auto-managed (Part 2/2)" bypass inc 1)" \
    '{active: {rules: [$a, $b]}}')

  local result
  result=$(run_audit_against "$config")
  assert_equals "exit code" "0" "${result%%|*}" || return 1
  assert_contains "${result#*|}" "RESULT: INFO" || return 1
}

test_audit_info_no_rules() {
  local result
  result=$(run_audit_against '{"active":{"rules":[]}}')
  assert_equals "exit code" "0" "${result%%|*}" || return 1
  assert_contains "${result#*|}" "RESULT: INFO" || return 1
}

# =============================================================================
# Insert-Then-Remove Ordering Tests
# =============================================================================

write_csv() {
  local path="$1"
  local count="$2"
  {
    echo "ip,vendor_name,notes"
    make_ips "$count" | jq -r '.[] | "\(.),Test,ordering"'
  } > "$path"
}

# Run cmd_apply against a canned config and return "<exit>|<output>".
# STUB_CONFIG avoids shadowing cmd_apply's own unset local named "config".
run_apply() {
  local STUB_CONFIG="$1"
  local csv="$2"
  local out
  local code=0

  : > "$REQUEST_LOG"
  : > "$INSERT_COUNT_FILE"

  out=$(
    (
      get_firewall_config() { echo "$STUB_CONFIG"; }
      PROJECT_ID="prj_test" SKIP_OPTIMIZE=true cmd_apply "$csv"
    ) <<< "$(printf 'yes\nyes\nyes\n')" 2>&1
  ) || code=$?

  printf '%s|%s' "$code" "$out"
}

logged_actions() { cut -d' ' -f1 < "$REQUEST_LOG"; }
removed_ids()    { awk '$1 == "rules.remove" { print $2 }' "$REQUEST_LOG" | sort; }
count_action()   { grep -c "^$1 " "$REQUEST_LOG" || true; }

config_with_stale_parts() {
  jq -n \
    --argjson a "$(make_rule "IP Allowlist - Auto-managed (Part 1/2)" deny ninc 1)" \
    --argjson b "$(make_rule "IP Allowlist - Auto-managed (Part 2/2)" deny ninc 1)" \
    '{active: {rules: [$a, $b]}}'
}

config_with_stale_bypass_parts() {
  jq -n \
    --argjson a "$(make_rule "IP Bypass - Auto-managed (Part 1/2)" bypass inc 1)" \
    --argjson b "$(make_rule "IP Bypass - Auto-managed (Part 2/2)" bypass inc 1)" \
    '{active: {rules: [$a, $b]}}'
}

# (a) insert succeeds -> stale rules removed, insert strictly precedes removals,
#     and the removal set is exactly the pre-existing ids
test_order_insert_then_remove() {
  local csv="$TEST_TMPDIR/deny-small.csv"
  write_csv "$csv" 5

  local stale
  stale=$(config_with_stale_parts)
  local expected_ids
  expected_ids=$(echo "$stale" | jq -r '.active.rules[].id' | sort)

  local result
  result=$(run_apply "$stale" "$csv")
  assert_equals "exit code" "0" "${result%%|*}" || { echo "${result#*|}" >&2; return 1; }

  assert_equals "insert count" "1" "$(count_action rules.insert)" || return 1
  assert_equals "remove count" "2" "$(count_action rules.remove)" || return 1

  # Ordering: every remove must come after the insert
  assert_equals "action sequence" "rules.insert rules.remove rules.remove" \
    "$(logged_actions | tr '\n' ' ' | sed 's/ $//')" || return 1

  assert_equals "removed ids" "$(echo "$expected_ids" | tr '\n' ' ')" \
    "$(removed_ids | tr '\n' ' ')" || return 1

  # The just-created rule is never a removal target
  if removed_ids | grep -q "$NEW_RULE_ID"; then
    log_error "Removal loop targeted the newly created rule id ($NEW_RULE_ID)"
    return 1
  fi

  assert_contains "${result#*|}" "Removed 2 superseded rule(s)" || return 1
}

# (b) insert fails -> nothing removed, non-zero exit, existing rules called out
test_order_insert_failure_removes_nothing() {
  local csv="$TEST_TMPDIR/deny-small.csv"
  write_csv "$csv" 5

  FAIL_INSERT_AFTER=0
  local result
  result=$(run_apply "$(config_with_stale_parts)" "$csv")
  FAIL_INSERT_AFTER=-1

  assert_equals "exit code" "1" "${result%%|*}" || { echo "${result#*|}" >&2; return 1; }
  assert_equals "remove count" "0" "$(count_action rules.remove)" || return 1
  assert_contains "${result#*|}" "were left in place - nothing was removed" || return 1
  assert_contains "${result#*|}" "current protection is unchanged" || return 1
}

# (c) chunked bypass partial create -> nothing removed, state spelled out
test_order_partial_chunk_removes_nothing() {
  local csv="$TEST_TMPDIR/bypass-200.csv"
  write_csv "$csv" 200

  local saved_op="$RULE_IP_OP"
  local saved_action="$RULE_ACTION"
  local saved_name="$RULE_NAME"
  local saved_mode="$CURRENT_RULE_MODE"
  RULE_IP_OP="inc"
  RULE_ACTION="bypass"
  RULE_NAME="IP Bypass - Auto-managed"
  CURRENT_RULE_MODE="bypass"
  FAIL_INSERT_AFTER=2

  local result
  result=$(run_apply "$(config_with_stale_bypass_parts)" "$csv")

  FAIL_INSERT_AFTER=-1
  RULE_IP_OP="$saved_op"
  RULE_ACTION="$saved_action"
  RULE_NAME="$saved_name"
  CURRENT_RULE_MODE="$saved_mode"

  assert_equals "exit code" "1" "${result%%|*}" || { echo "${result#*|}" >&2; return 1; }
  assert_equals "insert count" "3" "$(count_action rules.insert)" || return 1
  assert_equals "remove count" "0" "$(count_action rules.remove)" || return 1
  assert_contains "${result#*|}" "INCOMPLETE - NO RULES WERE REMOVED" || return 1
  assert_contains "${result#*|}" "2 newly created rule(s)" || return 1
  assert_contains "${result#*|}" "2 pre-existing auto-managed rule(s), left UNTOUCHED" || return 1
}

# (d) SKIP_REMOVAL=true -> new rule created, stale rules deliberately kept
test_order_skip_removal() {
  local csv="$TEST_TMPDIR/deny-small.csv"
  write_csv "$csv" 5

  SKIP_REMOVAL=true
  local result
  result=$(run_apply "$(config_with_stale_parts)" "$csv")
  SKIP_REMOVAL=false

  assert_equals "exit code" "0" "${result%%|*}" || { echo "${result#*|}" >&2; return 1; }
  assert_equals "insert count" "1" "$(count_action rules.insert)" || return 1
  assert_equals "remove count" "0" "$(count_action rules.remove)" || return 1
  assert_contains "${result#*|}" "SKIP_REMOVAL=true" || return 1
}

# A failed removal leaves the new rule in place rather than rolling back
test_order_removal_failure_keeps_new_rule() {
  local csv="$TEST_TMPDIR/deny-small.csv"
  write_csv "$csv" 5

  FAIL_REMOVALS=true
  local result
  result=$(run_apply "$(config_with_stale_parts)" "$csv")
  FAIL_REMOVALS=false

  assert_equals "insert count" "1" "$(count_action rules.insert)" || return 1
  assert_equals "remove attempts" "2" "$(count_action rules.remove)" || return 1
  assert_contains "${result#*|}" "could not be removed" || return 1
  assert_contains "${result#*|}" "new rule(s) are already active" || return 1
}

# DRY_RUN must reach no API at all and describe the create-then-replace ordering
test_dry_run_makes_no_calls() {
  local csv="$TEST_TMPDIR/deny-small.csv"
  write_csv "$csv" 5

  DRY_RUN=true
  local result
  result=$(run_apply "$(config_with_stale_parts)" "$csv")
  DRY_RUN=false

  assert_equals "exit code" "0" "${result%%|*}" || { echo "${result#*|}" >&2; return 1; }
  assert_equals "total API calls" "0" "$(wc -l < "$REQUEST_LOG" | tr -d ' ')" || return 1
  assert_contains "${result#*|}" "DRY RUN - No changes made" || return 1
  assert_contains "${result#*|}" "new rule(s) are created FIRST" || return 1
}

# =============================================================================
# Main
# =============================================================================

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --filter) TEST_FILTER="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done

  TEST_TMPDIR=$(mktemp -d)
  CAPTURED_BODY="$TEST_TMPDIR/request-body.json"
  REQUEST_LOG="$TEST_TMPDIR/request-log.txt"
  INSERT_COUNT_FILE="$TEST_TMPDIR/insert-count.txt"
  trap 'rm -rf "$TEST_TMPDIR"' EXIT

  # Configure deny/allowlist mode without prompting
  RULE_MODE="deny"
  configure_rule_mode
  RULE_HOSTNAME=""

  echo ""
  echo "Allowlist decomposition tests (offline, no credentials)"
  echo ""

  echo "  Deny mode - one rule, one group, ANDed conditions:"
  run_test "1 IP    -> 1 condition" test_deny_1
  run_test "75 IPs  -> 1 condition" test_deny_75
  run_test "76 IPs  -> 2 conditions" test_deny_76
  run_test "150 IPs -> 2 conditions" test_deny_150
  run_test "4875 IPs (ceiling) -> 65 conditions" test_deny_4875
  run_test "150 IPs + hostname -> 3 conditions" test_deny_150_hostname
  echo ""

  echo "  No regression on the working paths:"
  run_test "75 IPs keeps the pre-2.1.0 single-condition shape" test_deny_75_unchanged_shape
  run_test "bypass mode still emits inc/bypass" test_bypass_75_single_condition
  echo ""

  echo "  Ceiling enforcement:"
  run_test "4876 IPs is refused with exit 1" test_deny_4876_refused
  run_test "RULE_HOSTNAME lowers the ceiling to 4800 and refuses" test_deny_hostname_lowers_ceiling
  run_test "4801 IPs without a hostname still fits in 65 conditions" test_deny_scoped_ceiling_ok_without_hostname
  echo ""

  echo "  audit command (read-only):"
  run_test "2 deny/ninc sibling rules -> VULNERABLE (exit 2)" test_audit_vulnerable_sibling_rules
  run_test "1 rule with 2 ninc groups -> VULNERABLE (exit 2)" test_audit_vulnerable_condition_groups
  run_test "1 rule with 1 ninc group -> OK (exit 0)" test_audit_ok_single_rule
  run_test "2 bypass rules -> INFO (exit 0)" test_audit_ok_multiple_bypass_rules
  run_test "no managed rules -> INFO (exit 0)" test_audit_info_no_rules
  echo ""

  echo "  Insert-then-remove ordering (fail-closed):"
  run_test "insert succeeds -> removes only the pre-existing ids, after the insert" test_order_insert_then_remove
  run_test "insert fails -> nothing removed, exit 1" test_order_insert_failure_removes_nothing
  run_test "partial chunked create -> nothing removed, state reported" test_order_partial_chunk_removes_nothing
  run_test "SKIP_REMOVAL=true -> new rule created, stale rules kept" test_order_skip_removal
  run_test "removal failure -> new rule kept, operator warned" test_order_removal_failure_keeps_new_rule
  run_test "DRY_RUN -> zero API calls, describes new ordering" test_dry_run_makes_no_calls
  echo ""

  print_summary
}

main "$@"
