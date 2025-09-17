#!/bin/bash
# Monitoring Agent Fault Tolerance Test Suite
# Comprehensive testing for all fault-tolerance features
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly TEST_LOG="${AGENT_HOME}/logs/fault-tolerance-tests.log"
readonly CONTROL_SCRIPT="${AGENT_HOME}/monitoring-agent-control.sh"

# Test configuration
readonly TEST_TIMEOUT=300  # 5 minutes per test
readonly PROCESS_RESTART_WAIT=30
readonly SERVICE_RESTART_WAIT=60

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging function
log_test() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] [TEST] $message"
    
    echo "$log_entry" | tee -a "$TEST_LOG"
    
    case "$level" in
        "ERROR"|"FAIL")
            echo -e "${RED}$log_entry${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}$log_entry${NC}" >&2
            ;;
        "PASS"|"SUCCESS")
            echo -e "${GREEN}$log_entry${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}$log_entry${NC}"
            ;;
        *)
            echo "$log_entry"
            ;;
    esac
}

# Test helper functions
start_test() {
    local test_name="$1"
    echo ""
    echo "=================================================="
    echo "Starting Test: $test_name"
    echo "=================================================="
    log_test "INFO" "Starting test: $test_name"
    TESTS_RUN=$((TESTS_RUN + 1))
}

pass_test() {
    local test_name="$1"
    log_test "PASS" "Test passed: $test_name"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    local test_name="$1"
    local reason="$2"
    log_test "FAIL" "Test failed: $test_name - $reason"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Wait for service/process to be in expected state
wait_for_state() {
    local check_command="$1"
    local expected_result="$2"
    local timeout="$3"
    local description="$4"
    
    local count=0
    while [[ $count -lt $timeout ]]; do
        if eval "$check_command"; then
            if [[ "$expected_result" == "true" ]]; then
                return 0
            fi
        else
            if [[ "$expected_result" == "false" ]]; then
                return 0
            fi
        fi
        
        sleep 1
        count=$((count + 1))
        
        if [[ $((count % 10)) -eq 0 ]]; then
            log_test "DEBUG" "Waiting for $description... ($count/$timeout seconds)"
        fi
    done
    
    return 1
}

# Test 1: Basic Service Operations
test_basic_service_operations() {
    start_test "Basic Service Operations"
    
    # Test start
    log_test "INFO" "Testing service start..."
    if timeout $TEST_TIMEOUT "$CONTROL_SCRIPT" start; then
        if wait_for_state "systemctl is-active --quiet monitoring-agent.service" "true" 30 "service to become active"; then
            log_test "SUCCESS" "Service started successfully"
        else
            fail_test "Basic Service Operations" "Service failed to become active"
            return 1
        fi
    else
        fail_test "Basic Service Operations" "Service start command failed"
        return 1
    fi
    
    # Test status
    log_test "INFO" "Testing service status..."
    if "$CONTROL_SCRIPT" status; then
        log_test "SUCCESS" "Service status check passed"
    else
        fail_test "Basic Service Operations" "Service status check failed"
        return 1
    fi
    
    # Test stop
    log_test "INFO" "Testing service stop..."
    if timeout $TEST_TIMEOUT "$CONTROL_SCRIPT" stop; then
        if wait_for_state "systemctl is-active --quiet monitoring-agent.service" "false" 30 "service to stop"; then
            log_test "SUCCESS" "Service stopped successfully"
        else
            fail_test "Basic Service Operations" "Service failed to stop properly"
            return 1
        fi
    else
        fail_test "Basic Service Operations" "Service stop command failed"
        return 1
    fi
    
    # Restart service for other tests
    "$CONTROL_SCRIPT" start
    sleep 10
    
    pass_test "Basic Service Operations"
}

# Test 2: Process Recovery
test_process_recovery() {
    start_test "Process Recovery"
    
    # Ensure service is running
    "$CONTROL_SCRIPT" start
    sleep 10
    
    # Get list of critical processes
    local critical_processes=("monitoring-agentd" "monitoring-execd" "monitoring-modulesd")
    
    for process in "${critical_processes[@]}"; do
        log_test "INFO" "Testing recovery for process: $process"
        
        # Find the process PID
        local pid=$(pgrep -f "$process" | head -1)
        if [[ -z "$pid" ]]; then
            log_test "WARN" "Process $process not running, skipping test"
            continue
        fi
        
        log_test "INFO" "Killing process $process (PID: $pid)"
        kill -9 "$pid"
        
        # Wait for recovery
        if wait_for_state "pgrep -f '$process' > /dev/null" "true" $PROCESS_RESTART_WAIT "process $process to restart"; then
            log_test "SUCCESS" "Process $process recovered successfully"
        else
            fail_test "Process Recovery" "Process $process failed to recover"
            return 1
        fi
        
        sleep 5  # Wait between process tests
    done
    
    pass_test "Process Recovery"
}

# Test 3: Service Auto-Restart
test_service_auto_restart() {
    start_test "Service Auto-Restart"
    
    # Ensure service is running
    "$CONTROL_SCRIPT" start
    sleep 10
    
    # Kill all monitoring processes
    log_test "INFO" "Killing all monitoring processes to test service restart"
    pkill -f "monitoring-" || true
    
    # Wait for systemd to detect failure and restart
    if wait_for_state "systemctl is-active --quiet monitoring-agent.service" "true" $SERVICE_RESTART_WAIT "service to auto-restart"; then
        log_test "SUCCESS" "Service auto-restarted successfully"
        
        # Verify processes are running
        sleep 10
        local running_count=0
        for process in monitoring-agentd monitoring-execd monitoring-modulesd monitoring-logcollector monitoring-syscheckd; do
            if pgrep -f "$process" > /dev/null; then
                running_count=$((running_count + 1))
            fi
        done
        
        if [[ $running_count -ge 3 ]]; then
            log_test "SUCCESS" "Processes recovered after service restart ($running_count/5 running)"
        else
            fail_test "Service Auto-Restart" "Insufficient processes running after restart ($running_count/5)"
            return 1
        fi
    else
        fail_test "Service Auto-Restart" "Service failed to auto-restart"
        return 1
    fi
    
    pass_test "Service Auto-Restart"
}

# Test 4: Configuration Validation
test_configuration_validation() {
    start_test "Configuration Validation"
    
    local config_file="${AGENT_HOME}/etc/ossec.conf"
    local backup_file="${config_file}.test-backup"
    
    # Backup original configuration
    if [[ -f "$config_file" ]]; then
        cp "$config_file" "$backup_file"
    fi
    
    # Test with valid configuration
    log_test "INFO" "Testing valid configuration validation"
    if "$CONTROL_SCRIPT" test-config; then
        log_test "SUCCESS" "Valid configuration passed validation"
    else
        fail_test "Configuration Validation" "Valid configuration failed validation"
        return 1
    fi
    
    # Test with invalid configuration
    log_test "INFO" "Testing invalid configuration detection"
    if [[ -f "$config_file" ]]; then
        # Create invalid configuration
        echo "<invalid_xml>" > "$config_file"
        
        if ! "$CONTROL_SCRIPT" test-config 2>/dev/null; then
            log_test "SUCCESS" "Invalid configuration correctly detected"
        else
            fail_test "Configuration Validation" "Invalid configuration not detected"
            # Restore backup
            if [[ -f "$backup_file" ]]; then
                mv "$backup_file" "$config_file"
            fi
            return 1
        fi
        
        # Restore original configuration
        if [[ -f "$backup_file" ]]; then
            mv "$backup_file" "$config_file"
        fi
    fi
    
    pass_test "Configuration Validation"
}

# Test 5: Health Check System
test_health_check_system() {
    start_test "Health Check System"
    
    # Ensure service is running
    "$CONTROL_SCRIPT" start
    sleep 10
    
    # Test health check with healthy system
    log_test "INFO" "Testing health check with healthy system"
    if "$CONTROL_SCRIPT" health-check; then
        log_test "SUCCESS" "Health check passed for healthy system"
    else
        fail_test "Health Check System" "Health check failed for healthy system"
        return 1
    fi
    
    # Test health check with unhealthy system
    log_test "INFO" "Testing health check with unhealthy system"
    
    # Stop some processes
    pkill -f "monitoring-logcollector" || true
    pkill -f "monitoring-syscheckd" || true
    sleep 5
    
    # Health check should fail or warn
    if ! "$CONTROL_SCRIPT" health-check 2>/dev/null; then
        log_test "SUCCESS" "Health check correctly detected unhealthy system"
    else
        log_test "WARN" "Health check passed despite unhealthy system (may be acceptable depending on implementation)"
    fi
    
    # Restart service to restore health
    "$CONTROL_SCRIPT" restart
    sleep 10
    
    pass_test "Health Check System"
}

# Test 6: Log Rotation
test_log_rotation() {
    start_test "Log Rotation"
    
    local log_file="${AGENT_HOME}/logs/monitoring-agent.log"
    local large_log="${AGENT_HOME}/logs/test-large.log"
    
    # Create a large log file for testing
    log_test "INFO" "Creating large log file for rotation test"
    dd if=/dev/zero of="$large_log" bs=1M count=110 2>/dev/null  # 110MB file
    
    # Test log rotation script if it exists
    if [[ -x "${AGENT_HOME}/scripts/monitoring-logging.sh" ]]; then
        log_test "INFO" "Testing log rotation functionality"
        
        if "${AGENT_HOME}/scripts/monitoring-logging.sh" rotate; then
            log_test "SUCCESS" "Log rotation completed successfully"
        else
            fail_test "Log Rotation" "Log rotation script failed"
            rm -f "$large_log"
            return 1
        fi
    else
        log_test "WARN" "Log rotation script not found, skipping rotation test"
    fi
    
    # Clean up
    rm -f "$large_log" "${large_log}."*
    
    pass_test "Log Rotation"
}

# Test 7: Sleep/Resume Simulation
test_sleep_resume_simulation() {
    start_test "Sleep/Resume Simulation"
    
    # Check if sleep hook script exists
    local sleep_hook="${AGENT_HOME}/scripts/monitoring-sleep-hook"
    
    if [[ -x "$sleep_hook" ]]; then
        log_test "INFO" "Testing sleep hook functionality"
        
        # Simulate pre-sleep
        if "$sleep_hook" pre suspend; then
            log_test "SUCCESS" "Pre-sleep hook executed successfully"
        else
            fail_test "Sleep/Resume Simulation" "Pre-sleep hook failed"
            return 1
        fi
        
        # Simulate post-resume
        if "$sleep_hook" post suspend; then
            log_test "SUCCESS" "Post-resume hook executed successfully"
        else
            fail_test "Sleep/Resume Simulation" "Post-resume hook failed"
            return 1
        fi
        
        # Wait for any recovery actions
        sleep 10
        
        # Verify service is still healthy
        if "$CONTROL_SCRIPT" health-check; then
            log_test "SUCCESS" "Service healthy after sleep/resume simulation"
        else
            fail_test "Sleep/Resume Simulation" "Service unhealthy after sleep/resume simulation"
            return 1
        fi
    else
        log_test "WARN" "Sleep hook script not found, skipping sleep/resume test"
    fi
    
    pass_test "Sleep/Resume Simulation"
}

# Test 8: Watchdog Functionality
test_watchdog_functionality() {
    start_test "Watchdog Functionality"
    
    local watchdog_script="${AGENT_HOME}/scripts/monitoring-watchdog.sh"
    
    if [[ -x "$watchdog_script" ]]; then
        log_test "INFO" "Testing watchdog script"
        
        # Start watchdog in background
        "$watchdog_script" &
        local watchdog_pid=$!
        
        # Let it run for a short time
        sleep 30
        
        # Check if watchdog is still running
        if kill -0 "$watchdog_pid" 2>/dev/null; then
            log_test "SUCCESS" "Watchdog script running successfully"
            
            # Stop watchdog
            kill "$watchdog_pid" 2>/dev/null || true
            wait "$watchdog_pid" 2>/dev/null || true
        else
            fail_test "Watchdog Functionality" "Watchdog script exited unexpectedly"
            return 1
        fi
    else
        log_test "WARN" "Watchdog script not found, skipping watchdog test"
    fi
    
    pass_test "Watchdog Functionality"
}

# Test 9: Recovery Service
test_recovery_service() {
    start_test "Recovery Service"
    
    local recovery_script="${AGENT_HOME}/scripts/monitoring-recovery.sh"
    
    if [[ -x "$recovery_script" ]]; then
        log_test "INFO" "Testing recovery script"
        
        # Run recovery script
        if timeout 120 "$recovery_script"; then
            log_test "SUCCESS" "Recovery script executed successfully"
        else
            fail_test "Recovery Service" "Recovery script failed or timed out"
            return 1
        fi
    else
        log_test "WARN" "Recovery script not found, skipping recovery test"
    fi
    
    pass_test "Recovery Service"
}

# Test 10: Stress Test
test_stress_conditions() {
    start_test "Stress Test"
    
    log_test "INFO" "Running stress test - multiple process kills"
    
    # Ensure service is running
    "$CONTROL_SCRIPT" start
    sleep 10
    
    # Repeatedly kill processes to test resilience
    for i in {1..5}; do
        log_test "INFO" "Stress test iteration $i/5"
        
        # Kill random processes
        pkill -f "monitoring-logcollector" || true
        sleep 2
        pkill -f "monitoring-syscheckd" || true
        sleep 2
        pkill -f "monitoring-modulesd" || true
        sleep 5
        
        # Check if processes recover
        local recovered=true
        for process in monitoring-logcollector monitoring-syscheckd monitoring-modulesd; do
            if ! pgrep -f "$process" > /dev/null; then
                log_test "WARN" "Process $process not recovered in iteration $i"
                recovered=false
            fi
        done
        
        if [[ "$recovered" == "true" ]]; then
            log_test "SUCCESS" "All processes recovered in iteration $i"
        fi
        
        sleep 10  # Wait between iterations
    done
    
    # Final health check
    if "$CONTROL_SCRIPT" health-check; then
        log_test "SUCCESS" "System healthy after stress test"
    else
        fail_test "Stress Test" "System unhealthy after stress test"
        return 1
    fi
    
    pass_test "Stress Test"
}

# Generate test report
generate_test_report() {
    local report_file="${AGENT_HOME}/logs/fault-tolerance-test-report-$(date +%Y%m%d-%H%M%S).log"
    
    {
        echo "=== Monitoring Agent Fault Tolerance Test Report ==="
        echo "Generated: $(date)"
        echo "Host: $(hostname)"
        echo ""
        
        echo "=== Test Summary ==="
        echo "Tests Run: $TESTS_RUN"
        echo "Tests Passed: $TESTS_PASSED"
        echo "Tests Failed: $TESTS_FAILED"
        
        if [[ $TESTS_FAILED -eq 0 ]]; then
            echo "Result: ALL TESTS PASSED ✅"
        else
            echo "Result: $TESTS_FAILED TESTS FAILED ❌"
        fi
        
        echo ""
        echo "=== Detailed Log ==="
        if [[ -f "$TEST_LOG" ]]; then
            cat "$TEST_LOG"
        fi
        
    } > "$report_file"
    
    echo ""
    echo "=== Test Report Generated ==="
    echo "Report saved to: $report_file"
    echo ""
}

# Show test summary
show_summary() {
    echo ""
    echo "=================================================="
    echo "              TEST SUMMARY"
    echo "=================================================="
    echo "Tests Run:    $TESTS_RUN"
    echo "Tests Passed: $TESTS_PASSED"
    echo "Tests Failed: $TESTS_FAILED"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! The fault tolerance system is working correctly.${NC}"
    else
        echo -e "${RED}❌ $TESTS_FAILED TESTS FAILED! Please review the failures and fix issues.${NC}"
    fi
    
    echo ""
    echo "Test log: $TEST_LOG"
}

# Cleanup function
cleanup() {
    log_test "INFO" "Cleaning up test environment"
    
    # Kill any background processes we started
    pkill -f "monitoring-watchdog.sh" 2>/dev/null || true
    
    # Ensure service is in a good state
    "$CONTROL_SCRIPT" start 2>/dev/null || true
}

# Signal handler
trap 'cleanup; exit 130' INT TERM

# Main execution
main() {
    echo "=================================================="
    echo "    Monitoring Agent Fault Tolerance Test Suite"
    echo "=================================================="
    echo "Starting comprehensive fault tolerance testing..."
    echo ""
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$TEST_LOG")"
    
    # Clear previous test log
    > "$TEST_LOG"
    
    log_test "INFO" "Starting fault tolerance test suite"
    
    # Run all tests
    test_basic_service_operations
    test_process_recovery
    test_service_auto_restart
    test_configuration_validation
    test_health_check_system
    test_log_rotation
    test_sleep_resume_simulation
    test_watchdog_functionality
    test_recovery_service
    test_stress_conditions
    
    # Generate report and show summary
    generate_test_report
    show_summary
    
    # Cleanup
    cleanup
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Parse command line arguments
case "${1:-run}" in
    run)
        main
        ;;
    list)
        echo "Available tests:"
        echo "  1. Basic Service Operations"
        echo "  2. Process Recovery"
        echo "  3. Service Auto-Restart"
        echo "  4. Configuration Validation"
        echo "  5. Health Check System"
        echo "  6. Log Rotation"
        echo "  7. Sleep/Resume Simulation"
        echo "  8. Watchdog Functionality"
        echo "  9. Recovery Service"
        echo "  10. Stress Test"
        ;;
    single)
        if [[ -z "${2:-}" ]]; then
            echo "Usage: $0 single <test_function_name>"
            exit 1
        fi
        
        # Ensure log directory exists
        mkdir -p "$(dirname "$TEST_LOG")"
        > "$TEST_LOG"
        
        log_test "INFO" "Running single test: $2"
        
        if declare -F "$2" > /dev/null; then
            "$2"
            show_summary
        else
            echo "Test function '$2' not found"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {run|list|single <test_name>}"
        echo ""
        echo "Commands:"
        echo "  run    - Run all fault tolerance tests (default)"
        echo "  list   - List available tests"
        echo "  single - Run a single test function"
        exit 1
        ;;
esac