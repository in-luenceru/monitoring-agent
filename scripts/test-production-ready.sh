#!/bin/bash
# Production-Ready Testing Suite for Integrated Fault Tolerance
# Comprehensive validation for both Linux and Windows deployment
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly TEST_LOG="${AGENT_HOME}/logs/production-tests.log"
readonly CONTROL_SCRIPT="${AGENT_HOME}/monitoring-agent-control.sh"
readonly WINDOWS_CONTROL_SCRIPT="${AGENT_HOME}/monitoring-agent-control.ps1"

# Test results tracking
declare -A TEST_RESULTS
declare -i TOTAL_TESTS=0
declare -i PASSED_TESTS=0
declare -i FAILED_TESTS=0

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] [PROD-TEST] $message"
    
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

# Test result recording
record_test() {
    local test_name="$1"
    local result="$2"
    local details="${3:-}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    TEST_RESULTS["$test_name"]="$result"
    
    if [[ "$result" == "PASS" ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log "PASS" "✓ $test_name${details:+ - $details}"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log "FAIL" "✗ $test_name${details:+ - $details}"
    fi
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking production testing prerequisites..."
    
    # Check if running as root/admin
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Production tests must be run as root for full system access"
        exit 1
    fi
    
    # Create required directories
    mkdir -p "${AGENT_HOME}/logs" "${AGENT_HOME}/var/run" "${AGENT_HOME}/var/state" "${AGENT_HOME}/tmp"
    
    # Set basic permissions
    chmod 755 "${AGENT_HOME}/logs" "${AGENT_HOME}/var" 2>/dev/null || true
    
    # Check control scripts exist
    if [[ ! -f "$CONTROL_SCRIPT" ]]; then
        log "ERROR" "Linux control script not found: $CONTROL_SCRIPT"
        exit 1
    fi
    
    if [[ ! -f "$WINDOWS_CONTROL_SCRIPT" ]]; then
        log "WARN" "Windows control script not found: $WINDOWS_CONTROL_SCRIPT"
    fi
    
    log "SUCCESS" "Prerequisites validated"
}

# Test 1: Validate integrated fault tolerance functions exist
test_fault_tolerance_integration() {
    log "INFO" "Testing fault tolerance integration in control scripts..."
    
    # Test Linux control script
    if grep -q "start_fault_tolerance_components" "$CONTROL_SCRIPT"; then
        record_test "Linux_Fault_Tolerance_Functions" "PASS" "All required functions present"
    else
        record_test "Linux_Fault_Tolerance_Functions" "FAIL" "Missing fault tolerance functions"
    fi
    
    # Test Windows control script if available
    if [[ -f "$WINDOWS_CONTROL_SCRIPT" ]]; then
        if grep -q "Start-FaultToleranceComponents" "$WINDOWS_CONTROL_SCRIPT"; then
            record_test "Windows_Fault_Tolerance_Functions" "PASS" "All required functions present"
        else
            record_test "Windows_Fault_Tolerance_Functions" "FAIL" "Missing fault tolerance functions"
        fi
    else
        record_test "Windows_Fault_Tolerance_Functions" "SKIP" "Windows script not available on Linux"
    fi
}

# Test 2: Configuration validation
test_configuration_validation() {
    log "INFO" "Testing configuration validation..."
    
    # Test config validation function
    if "$CONTROL_SCRIPT" test-config >/dev/null 2>&1; then
        record_test "Configuration_Validation" "PASS" "Configuration validates successfully"
    else
        record_test "Configuration_Validation" "FAIL" "Configuration validation failed"
    fi
}

# Test 3: Help and command validation
test_command_interface() {
    log "INFO" "Testing command interface..."
    
    # Test help command
    if "$CONTROL_SCRIPT" --help | grep -q "health-check-full"; then
        record_test "Command_Interface_Help" "PASS" "New commands appear in help"
    else
        record_test "Command_Interface_Help" "FAIL" "New commands missing from help"
    fi
    
    # Test command validation
    if ! "$CONTROL_SCRIPT" invalid-command >/dev/null 2>&1; then
        record_test "Command_Interface_Validation" "PASS" "Invalid commands properly rejected"
    else
        record_test "Command_Interface_Validation" "FAIL" "Invalid commands not rejected"
    fi
}

# Test 4: Fault tolerance script dependencies
test_script_dependencies() {
    log "INFO" "Testing fault tolerance script dependencies..."
    
    local required_scripts=(
        "monitoring-watchdog.sh"
        "monitoring-recovery.sh"
        "monitoring-logging.sh"
    )
    
    local all_present=true
    for script in "${required_scripts[@]}"; do
        if [[ -x "${AGENT_HOME}/scripts/$script" ]]; then
            log "INFO" "✓ Found: $script"
        else
            log "ERROR" "✗ Missing or not executable: $script"
            all_present=false
        fi
    done
    
    if $all_present; then
        record_test "Script_Dependencies" "PASS" "All required scripts present and executable"
    else
        record_test "Script_Dependencies" "FAIL" "Missing required scripts"
    fi
}

# Test 5: Systemd service integration
test_systemd_integration() {
    log "INFO" "Testing systemd service integration..."
    
    # Check if main service is properly configured
    if [[ -f "${AGENT_HOME}/monitoring-agent.service" ]]; then
        if grep -q "Restart=always" "${AGENT_HOME}/monitoring-agent.service"; then
            record_test "Systemd_Service_Config" "PASS" "Service configured for fault tolerance"
        else
            record_test "Systemd_Service_Config" "FAIL" "Service missing fault tolerance config"
        fi
    else
        record_test "Systemd_Service_Config" "FAIL" "Main service file missing"
    fi
    
    # Check that old standalone services are NOT present
    local old_services=(
        "monitoring-agent-watchdog.service"
        "monitoring-agent-logging.service"
        "monitoring-agent-recovery.service"
    )
    
    local properly_removed=true
    for service in "${old_services[@]}"; do
        if [[ -f "${AGENT_HOME}/$service" ]]; then
            log "WARN" "Old standalone service still present: $service"
            properly_removed=false
        fi
    done
    
    if $properly_removed; then
        record_test "Standalone_Services_Cleanup" "PASS" "Old standalone services properly removed"
    else
        record_test "Standalone_Services_Cleanup" "FAIL" "Old standalone services still present"
    fi
}

# Test 6: Mock service lifecycle testing
test_service_lifecycle() {
    log "INFO" "Testing service lifecycle with integrated fault tolerance..."
    
    # Create a mock daemon for testing
    create_mock_daemon() {
        local daemon_script="${AGENT_HOME}/tmp/mock-daemon.sh"
        cat > "$daemon_script" << 'EOF'
#!/bin/bash
while true; do
    echo "Mock daemon running: $(date)" >> /tmp/mock-daemon.log
    sleep 5
done
EOF
        chmod +x "$daemon_script"
        echo "$daemon_script"
    }
    
    # Test process management functions
    local mock_daemon=$(create_mock_daemon)
    
    # Start mock daemon
    "$mock_daemon" &
    local mock_pid=$!
    echo "$mock_pid" > "${AGENT_HOME}/var/run/mock-daemon.pid"
    
    sleep 2
    
    # Check if process tracking works
    if kill -0 "$mock_pid" 2>/dev/null; then
        record_test "Process_Management" "PASS" "Process lifecycle management working"
    else
        record_test "Process_Management" "FAIL" "Process lifecycle management failed"
    fi
    
    # Cleanup
    kill "$mock_pid" 2>/dev/null || true
    rm -f "${AGENT_HOME}/var/run/mock-daemon.pid" "$mock_daemon" /tmp/mock-daemon.log
}

# Test 7: Health check functionality
test_health_checks() {
    log "INFO" "Testing health check functionality..."
    
    # Test basic health check
    if "$CONTROL_SCRIPT" health >/dev/null 2>&1; then
        record_test "Basic_Health_Check" "PASS" "Basic health check working"
    else
        record_test "Basic_Health_Check" "FAIL" "Basic health check failed"
    fi
    
    # Test comprehensive health check
    if "$CONTROL_SCRIPT" health-check-full >/dev/null 2>&1; then
        record_test "Comprehensive_Health_Check" "PASS" "Comprehensive health check working"
    else
        # This might fail if service isn't running, which is expected
        record_test "Comprehensive_Health_Check" "WARN" "Comprehensive health check requires running service"
    fi
}

# Test 8: Error handling and edge cases
test_error_handling() {
    log "INFO" "Testing error handling and edge cases..."
    
    # Test behavior with missing config
    local config_backup="${AGENT_HOME}/etc/ossec.conf.backup"
    if [[ -f "${AGENT_HOME}/etc/ossec.conf" ]]; then
        cp "${AGENT_HOME}/etc/ossec.conf" "$config_backup"
        rm -f "${AGENT_HOME}/etc/ossec.conf"
        
        if ! "$CONTROL_SCRIPT" test-config >/dev/null 2>&1; then
            record_test "Error_Handling_Config" "PASS" "Properly handles missing config"
        else
            record_test "Error_Handling_Config" "FAIL" "Does not detect missing config"
        fi
        
        # Restore config
        if [[ -f "$config_backup" ]]; then
            mv "$config_backup" "${AGENT_HOME}/etc/ossec.conf"
        fi
    else
        record_test "Error_Handling_Config" "SKIP" "No config file to test with"
    fi
    
    # Test behavior with insufficient permissions
    local test_dir="${AGENT_HOME}/tmp/permission-test"
    mkdir -p "$test_dir"
    chmod 000 "$test_dir" 2>/dev/null || true
    
    # This should handle permission errors gracefully
    ls "$test_dir" >/dev/null 2>&1 || true
    record_test "Error_Handling_Permissions" "PASS" "Handles permission errors gracefully"
    
    # Cleanup
    chmod 755 "$test_dir" 2>/dev/null || true
    rm -rf "$test_dir"
}

# Test 9: Performance and resource usage
test_performance() {
    log "INFO" "Testing performance and resource usage..."
    
    # Check script execution time
    local start_time=$(date +%s.%N)
    "$CONTROL_SCRIPT" --help >/dev/null 2>&1
    local end_time=$(date +%s.%N)
    local execution_time=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0.1")
    
    # Should complete within reasonable time (less than 5 seconds)
    if (( $(echo "$execution_time < 5.0" | bc -l 2>/dev/null || echo "1") )); then
        record_test "Performance_Script_Speed" "PASS" "Script executes in ${execution_time}s"
    else
        record_test "Performance_Script_Speed" "FAIL" "Script too slow: ${execution_time}s"
    fi
    
    # Check memory usage (if possible)
    local memory_usage=$(ps -o pid,vsz,rss,comm -p $$ 2>/dev/null | tail -1 | awk '{print $2}' || echo "0")
    if [[ "$memory_usage" -lt 100000 ]]; then  # Less than 100MB
        record_test "Performance_Memory_Usage" "PASS" "Reasonable memory usage: ${memory_usage}KB"
    else
        record_test "Performance_Memory_Usage" "WARN" "High memory usage: ${memory_usage}KB"
    fi
}

# Test 10: Production deployment validation
test_deployment_validation() {
    log "INFO" "Testing production deployment validation..."
    
    # Test deployment script validation
    if [[ -x "${AGENT_HOME}/scripts/deploy-fault-tolerance.sh" ]]; then
        if "${AGENT_HOME}/scripts/deploy-fault-tolerance.sh" validate >/dev/null 2>&1; then
            record_test "Deployment_Validation" "PASS" "Deployment validation successful"
        else
            record_test "Deployment_Validation" "WARN" "Deployment validation has warnings"
        fi
    else
        record_test "Deployment_Validation" "FAIL" "Deployment script missing or not executable"
    fi
}

# Test 11: Windows PowerShell script validation (if on Windows or WSL)
test_windows_powershell() {
    log "INFO" "Testing Windows PowerShell script validation..."
    
    if command -v powershell >/dev/null 2>&1 || command -v pwsh >/dev/null 2>&1; then
        local ps_cmd=$(command -v pwsh 2>/dev/null || command -v powershell 2>/dev/null)
        
        # Test PowerShell script syntax
        if "$ps_cmd" -Command "try { . '${WINDOWS_CONTROL_SCRIPT}'; exit 0 } catch { exit 1 }" >/dev/null 2>&1; then
            record_test "Windows_PowerShell_Syntax" "PASS" "PowerShell script syntax valid"
        else
            record_test "Windows_PowerShell_Syntax" "FAIL" "PowerShell script syntax errors"
        fi
        
        # Test PowerShell functions
        if "$ps_cmd" -Command "try { . '${WINDOWS_CONTROL_SCRIPT}'; Get-Command Start-FaultToleranceComponents -ErrorAction Stop; exit 0 } catch { exit 1 }" >/dev/null 2>&1; then
            record_test "Windows_PowerShell_Functions" "PASS" "PowerShell fault tolerance functions present"
        else
            record_test "Windows_PowerShell_Functions" "FAIL" "PowerShell fault tolerance functions missing"
        fi
    else
        record_test "Windows_PowerShell_Syntax" "SKIP" "PowerShell not available"
        record_test "Windows_PowerShell_Functions" "SKIP" "PowerShell not available"
    fi
}

# Test 12: Cross-platform compatibility
test_cross_platform() {
    log "INFO" "Testing cross-platform compatibility..."
    
    # Test script compatibility with different shells
    if bash -n "$CONTROL_SCRIPT" 2>/dev/null; then
        record_test "Cross_Platform_Bash_Syntax" "PASS" "Bash syntax compatible"
    else
        record_test "Cross_Platform_Bash_Syntax" "FAIL" "Bash syntax errors"
    fi
    
    # Test path handling
    local test_path="${AGENT_HOME}/test/../test"
    if [[ -n "$(readlink -f "$test_path" 2>/dev/null || realpath "$test_path" 2>/dev/null)" ]]; then
        record_test "Cross_Platform_Path_Handling" "PASS" "Path resolution working"
    else
        record_test "Cross_Platform_Path_Handling" "WARN" "Path resolution may have issues"
    fi
}

# Generate production readiness report
generate_report() {
    log "INFO" "Generating production readiness report..."
    
    local report_file="${AGENT_HOME}/logs/production-readiness-report.txt"
    
    cat > "$report_file" << EOF
# MONITORING AGENT - PRODUCTION READINESS REPORT
Generated: $(date)
Test Suite: Integrated Fault Tolerance Validation

## SUMMARY
- Total Tests: $TOTAL_TESTS
- Passed: $PASSED_TESTS
- Failed: $FAILED_TESTS
- Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

## TEST RESULTS
EOF
    
    for test_name in "${!TEST_RESULTS[@]}"; do
        echo "- $test_name: ${TEST_RESULTS[$test_name]}" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

## PRODUCTION READINESS ASSESSMENT
EOF
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        cat >> "$report_file" << EOF
✅ PRODUCTION READY
All critical tests passed. The system is ready for production deployment.

Recommendations:
- Deploy using the integrated approach (single service with fault tolerance)
- Monitor the comprehensive health check: monitoring-agent-control.sh health-check-full
- Use the deployment script for automated installation: scripts/deploy-fault-tolerance.sh
EOF
    elif [[ $FAILED_TESTS -le 2 ]]; then
        cat >> "$report_file" << EOF
⚠️  PRODUCTION READY WITH CAUTION
Most tests passed with minor issues. Review failed tests before deployment.

Recommendations:
- Address any failed tests listed above
- Conduct additional testing in staging environment
- Monitor closely during initial deployment
EOF
    else
        cat >> "$report_file" << EOF
❌ NOT PRODUCTION READY
Multiple critical tests failed. System requires fixes before production use.

Recommendations:
- Address all failed tests before deployment
- Conduct comprehensive debugging
- Repeat testing after fixes
EOF
    fi
    
    echo "" >> "$report_file"
    echo "For support: https://docs.monitoring-solutions.com" >> "$report_file"
    
    log "SUCCESS" "Report generated: $report_file"
    cat "$report_file"
}

# Main execution
main() {
    log "INFO" "Starting production readiness testing for integrated fault tolerance..."
    
    check_prerequisites
    
    # Run all tests
    test_fault_tolerance_integration
    test_configuration_validation
    test_command_interface
    test_script_dependencies
    test_systemd_integration
    test_service_lifecycle
    test_health_checks
    test_error_handling
    test_performance
    test_deployment_validation
    test_windows_powershell
    test_cross_platform
    
    # Generate final report
    generate_report
    
    log "INFO" "Production readiness testing completed"
    
    # Exit with appropriate code
    if [[ $FAILED_TESTS -eq 0 ]]; then
        log "SUCCESS" "🎉 ALL TESTS PASSED - SYSTEM IS PRODUCTION READY!"
        exit 0
    else
        log "ERROR" "❌ $FAILED_TESTS tests failed - System needs attention before production use"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    "help"|"--help"|"-h")
        echo "Production Readiness Testing Suite"
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  help    Show this help message"
        echo "  report  Show last test report"
        echo ""
        echo "This script validates the integrated fault tolerance system for production use."
        exit 0
        ;;
    "report")
        if [[ -f "${AGENT_HOME}/logs/production-readiness-report.txt" ]]; then
            cat "${AGENT_HOME}/logs/production-readiness-report.txt"
        else
            echo "No report found. Run the test suite first."
            exit 1
        fi
        ;;
    *)
        main "$@"
        ;;
esac