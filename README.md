# Monitoring Agent - Complete Installation & Management Guide

## 📖 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Platform-Specific Features](#platform-specific-features)
  - [Linux/Unix Features](#linux-unix-features)
  - [Windows Features](#windows-features)
- [Monitoring Manager Setup with Docker](#monitoring-manager-setup-with-docker)
- [Agent Enrollment](#agent-enrollment)
- [Agent Management](#agent-management)
- [Fault Tolerance & Recovery](#fault-tolerance--recovery)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

---

## Overview

The **Monitoring Agent** is a professional security monitoring solution that provides:

- 🏠 **Self-Contained**: Everything works within a single directory
- 🚀 **Auto-Setup**: Automatic initialization and configuration
- 🔐 **Interactive Enrollment**: Guided enrollment with validation
- 📝 **Auto-Configuration**: Configuration files updated automatically
- 🐳 **Docker Ready**: Works seamlessly with containerized Monitoring managers
- 🔄 **Cross-Platform**: Full support for Linux/Unix and Windows
- 🛡️ **Fault Tolerant**: Advanced monitoring, watchdog, and auto-recovery
- 🔧 **Permission Bypass**: Built-in bypass mechanisms for restricted environments

---

## Quick Start

### Linux/Unix
```bash
# Extract and setup
tar -xzf monitoring-agent.tar.gz
cd monitoring-agent

# Make script executable
chmod +x monitoring-agent-control.sh

# Interactive enrollment
./monitoring-agent-control.sh enroll <MANAGER_IP>

# Start agent
./monitoring-agent-control.sh start
```

### Windows
```powershell
# Extract monitoring agent files
cd monitoring-agent

# Interactive enrollment (run as Administrator)
.\monitoring-agent-control.ps1 enroll <MANAGER_IP>

# Start agent with fault tolerance
.\monitoring-agent-control.ps1 start

# Install as Windows service (optional)
.\monitoring-agent-control.ps1 install-service
```

### 4. Verify Connection
```bash
# Test connectivity
./monitoring-agent-control.sh test-connection
./monitoring-agent-control.sh status
```

---

## System Requirements

### Linux Requirements
- **OS**: Ubuntu 18.04+, CentOS 7+, Debian 9+, RHEL 7+
- **Memory**: 512MB RAM minimum, 1GB+ recommended
- **Storage**: 1GB free space minimum, 5GB+ recommended
- **Network**: Outbound TCP port 1514 to manager
- **Tools**: bash, sed, awk, nc (netcat)

### Windows Requirements
- **OS**: Windows Server 2016+, Windows 10+
- **PowerShell**: Version 5.1 or higher
- **Memory**: 1GB RAM minimum, 2GB+ recommended
- **Storage**: 2GB free space minimum, 5GB+ recommended
- **Network**: Outbound TCP port 1514 to manager

---

## Installation

### Method 1: Self-Contained Directory (Recommended)

**No system-wide installation required!**

#### Linux
```bash
# Download and extract
wget https://releases.monitoring-solutions.com/monitoring-agent-linux.tar.gz
tar -xzf monitoring-agent-linux.tar.gz
cd monitoring-agent

# Ready to use
./monitoring-agent-control.sh --help
```

#### Windows
```powershell
# Download and extract
Invoke-WebRequest -Uri "https://releases.monitoring-solutions.com/monitoring-agent-windows.zip" -OutFile "monitoring-agent.zip"
Expand-Archive monitoring-agent.zip
cd monitoring-agent

# Ready to use
.\monitoring-agent-control.ps1 -Help
```

---

## Platform-Specific Features

### Linux/Unix Features

#### Fault Tolerance System
- **Process Watchdog**: Monitors and restarts failed processes automatically
- **Boot Recovery**: Automatically restarts agent after system reboot
- **Health Monitoring**: Continuous health checks with alerting
- **Signal Handling**: Graceful shutdown on system signals

#### Permission Bypass
- **LD_PRELOAD Bypass**: Automatic bypass for restricted environments
- **Auto-Detection**: Automatically loads bypass library if available
- **User/Group Emulation**: Works with any user/group configuration

#### Service Integration
- **Systemd Service**: Automatic installation of systemd service
- **Auto-startup**: Configured for automatic startup on boot
- **Service Recovery**: Automatic restart on service failure

#### Enhanced Logging
- **Structured Logging**: Comprehensive logging with levels
- **Log Rotation**: Automatic log rotation to prevent disk space issues
- **Health Reports**: Regular health status reports

### Windows Features

#### Fault Tolerance System
- **Process Watchdog**: PowerShell-based process monitoring and restart
- **Boot Recovery**: Windows Task Scheduler-based boot recovery
- **Health Monitoring**: Continuous health checks with Windows Event Log integration
- **Service Recovery**: Advanced Windows service recovery configuration

#### Permission Bypass
- **DLL Injection**: Windows DLL-based permission bypass
- **API Hooking**: Hooks Windows API calls for enhanced access
- **Process Privilege**: Automatic privilege escalation for monitoring processes
- **File System Bypass**: Bypasses file system restrictions

#### Windows Service Integration
- **Windows Service**: Full Windows service with recovery options
- **Service Control Manager**: Integration with Windows SCM
- **Auto-startup**: Delayed startup for system stability
- **Power Management**: Handles system suspend/resume events
- **Task Scheduler**: Backup scheduling for critical functions

#### Enhanced Features
- **Event Log Integration**: Writes to Windows Event Log
- **Power Event Handling**: Responds to system power events
- **Registry Integration**: Stores configuration in Windows Registry
- **WMI Integration**: Uses WMI for system information

#### Windows-Specific Commands
```powershell
# Install as Windows service
.\monitoring-agent-control.ps1 install-service

# Remove Windows service
.\monitoring-agent-control.ps1 uninstall-service

# Run in service mode
.\monitoring-agent-control.ps1 service-mode

# Comprehensive health check
.\monitoring-agent-control.ps1 health-check-full

# Test fault tolerance
.\monitoring-agent-control.ps1 health-check-full
```

---

## Monitoring Manager Setup with Docker

### Prerequisites
```bash
# Install Docker and Docker Compose
sudo apt update
sudo apt install docker.io docker-compose

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker
```

### Method 1: Single Node Docker Setup

```bash
# Create Monitoring directory
mkdir monitoring-docker && cd monitoring-docker

# Download docker-compose file
curl -so docker-compose.yml https://packages.wazuh.com/4.12/docker/docker-compose.yml

# Start Monitoring manager
sudo docker-compose up -d
```

### Method 2: Quick Single Container

```bash
# Run Monitoring manager in single container
sudo docker run -d \
  --name monitoring-manager \
  -p 1514:1514/tcp \
  -p 1515:1515 \
  -p 514:514/udp \
  -p 55000:55000 \
  -e INDEXER_URL=https://wazuh.indexer:9200 \
  -e INDEXER_USERNAME=admin \
  -e INDEXER_PASSWORD=SecretPassword \
  -e FILEBEAT_SSL_VERIFICATION_MODE=full \
  wazuh/wazuh-manager:4.12.0
```

### Docker Manager Commands

```bash
# Check manager status
sudo docker ps | grep monitoring

# View manager logs
sudo docker logs monitoring-manager

# Get manager IP (for agent enrollment)
sudo docker inspect monitoring-manager | grep IPAddress

# Access manager shell
sudo docker exec -it monitoring-manager /bin/bash

# Manage agents from Docker
sudo docker exec -it monitoring-manager /var/ossec/bin/manage_agents

#List active agent that are connected to manager
sudo docker exec -it monitoring-manager /var/ossec/bin/agent_control -l

# Stop manager
sudo docker stop monitoring-manager

# Start manager
sudo docker start monitoring-manager

# Remove manager (data will be lost)
sudo docker rm -f monitoring-manager
```

### Get Manager IP for Agent Enrollment

```bash
# Method 1: Docker inspect
MANAGER_IP=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' monitoring-manager)
echo "Manager IP: $MANAGER_IP"

# Method 2: Check all networks
sudo docker network ls
sudo docker network inspect bridge | grep -A 3 monitoring

# Method 3: Use localhost if port forwarding
MANAGER_IP="127.0.0.1"  # If using -p 1514:1514
```

---

## Agent Enrollment

**Important**: The monitoring agent uses **user-specified agent names** instead of system hostnames. This ensures consistent agent identification regardless of the underlying system hostname.

### Step 1: Get Client Key from Manager

#### Docker Manager
```bash
# Access manager container
sudo docker exec -it wazuh-manager /bin/bash

# Inside container, manage agents
/var/ossec/bin/manage_agents

# Follow prompts:
# A) Add agent
# Enter agent name (e.g., myserver, webserver, database-01)
# ⚠️  IMPORTANT: Use descriptive names, NOT system hostnames
# Enter agent IP (use 'any' for flexibility)
# Get agent ID and key

# E) Extract key for the agent
# Copy the complete base64 key

# L) List agents (to verify creation)
```

#### Physical Manager
```bash
# On manager server
sudo /var/ossec/bin/manage_agents

# Follow same process as above
```

### Step 2: Enroll Agent (Interactive)

```bash
# Start enrollment process
./monitoring-agent-control.sh enroll <MANAGER_IP:port>

# Example with Docker manager
./monitoring-agent-control.sh enroll 172.17.0.2:1514
```

**Interactive Process:**
```
====================================================
Client Key Required
====================================================
Please provide the client key obtained from the Monitoring manager.
You can get this key by running on the manager:
  sudo /var/ossec/bin/manage_agents -l

The key should be in format:
  001 agent-name 192.168.1.100 abc123...def456

Enter the complete client key line: _
```

**Important Notes:**
- ✅ **Agent Name Override**: The enrollment process uses the manager-configured agent name, NOT the system hostname
- ✅ **Auto-Enrollment Disabled**: Prevents automatic registration with hostname to ensure consistent naming
- ✅ **Manual Key Required**: Only pre-configured agent keys are accepted (no auto-generation)

**Paste your key:** `001 myserver ANY abcd1234567890...`

The enrollment will:
- ✅ Validate key format
- ✅ Update `ossec.conf` with manager IP
- ✅ Create `client.keys` with correct IP
- ✅ Configure enrollment settings to disable auto-enrollment
- ✅ Offer to start agent immediately

### Enrollment Configuration

The agent automatically configures the following settings in `etc/ossec.conf` to ensure proper manual enrollment:

```xml
<client>
  <server>
    <address>MANAGER_IP</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <enrollment>
    <enabled>no</enabled>
  </enrollment>
  <!-- Other client settings... -->
</client>
```

**Key Benefits:**
- 🚫 **No Auto-Enrollment**: Prevents automatic registration with system hostname
- 🏷️ **Manual Agent Names**: Uses descriptive names configured on manager
- 🔐 **Key-Based Only**: Only accepts pre-configured authentication keys

### Step 3: Verification

```bash
# Check enrollment
cat etc/client.keys
cat etc/ossec.conf | grep -A3 server

# Test connectivity
./monitoring-agent-control.sh test-connection
```

---

## Agent Management

### Essential Commands

```bash
# Check status
./monitoring-agent-control.sh status

# Start agent (with auto-setup)
./monitoring-agent-control.sh start

# Stop agent
./monitoring-agent-control.sh stop

# Restart agent
./monitoring-agent-control.sh restart

# View logs
./monitoring-agent-control.sh logs [lines] [follow]

# Examples:
./monitoring-agent-control.sh logs 100        # Last 100 lines
./monitoring-agent-control.sh logs 50 true    # Follow mode
```

### Health and Connectivity

```bash
# Health check
./monitoring-agent-control.sh health

# Test connectivity to manager
./monitoring-agent-control.sh test-connection

# Show detailed help
./monitoring-agent-control.sh --help
```

### Configuration Management

```bash
# Backup configuration
./monitoring-agent-control.sh backup

# Restore from backup
./monitoring-agent-control.sh restore <backup_path>

# Configure firewall
./monitoring-agent-control.sh configure-firewall <manager_ip>
```

---

## Fault Tolerance & Recovery

### Overview
The monitoring agent includes comprehensive fault tolerance and recovery mechanisms to ensure maximum uptime and reliability.

### Fault Tolerance Features

#### Process Monitoring
- **Automatic Process Restart**: Failed processes are automatically restarted
- **Restart Limits**: Configurable restart attempts to prevent infinite loops
- **Cooldown Periods**: Intelligent delays between restart attempts
- **Health Monitoring**: Continuous monitoring of process health

#### Boot Recovery
- **State Persistence**: Remembers running state across reboots
- **Automatic Startup**: Restarts agent automatically after system reboot
- **Configuration Validation**: Verifies configuration before starting
- **Dependency Checks**: Ensures all requirements are met before startup

#### Watchdog System
- **Multi-Level Monitoring**: Monitors both individual processes and overall health
- **Background Operation**: Runs independently from main agent processes
- **Self-Healing**: Can recover from its own failures
- **Escalation Paths**: Multiple recovery strategies based on failure type

### Fault Tolerance Commands

#### Linux/Unix
```bash
# Check comprehensive health (including fault tolerance)
./monitoring-agent-control.sh health-check-full

# Manually restart a specific process
./monitoring-agent-control.sh restart-process <process_name>

# Check boot recovery status
./scripts/monitoring-boot-recovery.sh status

# Test watchdog functionality
./scripts/monitoring-watchdog.sh health

# View fault tolerance logs
tail -f logs/monitoring-watchdog.log
tail -f logs/boot-recovery.log
```

#### Windows
```powershell
# Check comprehensive health (including fault tolerance)
.\monitoring-agent-control.ps1 health-check-full

# Manually restart a specific process
.\monitoring-agent-control.ps1 restart-process <process_name>

# Check boot recovery status
.\scripts\windows\monitoring-boot-recovery.ps1 status

# Test watchdog functionality
.\scripts\windows\monitoring-watchdog.ps1 health

# View fault tolerance logs
Get-Content logs\monitoring-watchdog.log -Tail 50 -Wait
Get-Content logs\boot-recovery.log -Tail 50 -Wait
```

### Monitoring Fault Tolerance Health

#### Health Check Reports
```bash
# Basic health check
./monitoring-agent-control.sh health
# ✓ All agent processes running
# ✓ Configuration valid
# ✓ Manager connectivity OK

# Comprehensive health check with fault tolerance
./monitoring-agent-control.sh health-check-full
# ✓ All agent processes running
# ✓ Configuration valid
# ✓ Manager connectivity OK
# ✓ Watchdog process active
# ✓ Boot recovery configured
# ✓ Recovery monitoring active
# ✓ Restart counters: 0 total restarts
```

#### Log Analysis
```bash
# View health reports
grep "Health report" logs/monitoring-watchdog.log
grep "Recovery Status" logs/boot-recovery.log

# Check restart counts
find var/state -name "restart_count_*" -exec cat {} \;

# View recent recovery actions
grep "restart\|recovery" logs/monitoring-*.log | tail -20
```

### Fault Tolerance Configuration

#### Restart Limits
```bash
# Default settings (configurable in scripts)
MAX_RESTART_ATTEMPTS=5     # per process per hour
RESTART_WINDOW=3600        # 1 hour in seconds
CHECK_INTERVAL=30          # health check interval in seconds
```

#### Boot Recovery Settings
```bash
# Configuration files
var/state/was_running      # Agent running state
var/state/startup_time     # Last startup timestamp
var/state/restart_count_*  # Per-process restart counters
```

#### Bypass Integration
- **Automatic Loading**: Bypass libraries loaded automatically during recovery
- **State Preservation**: Bypass state maintained across restarts
- **Recovery Integration**: Bypass status included in health checks

---

## Troubleshooting

### Common Issues

#### 1. **Agent Naming Issues**

**Problem**: Agent appears with system hostname instead of configured name
```bash
# On manager, agent shows as system hostname (e.g., "ubuntu-server")
# Instead of configured name (e.g., "web-server-01")
```

**Solution**: Ensure auto-enrollment is disabled and use manual enrollment
```bash
# 1. Remove auto-enrolled agent from manager
sudo docker exec -it monitoring-manager /var/ossec/bin/manage_agents
# Choose (R)emove, enter agent ID with hostname

# 2. Stop agent and re-enroll with proper configuration
./monitoring-agent-control.sh stop
./monitoring-agent-control.sh enroll <MANAGER_IP>
# Enter the pre-configured client key with correct agent name

# 3. Verify enrollment configuration
grep -A5 "enrollment" etc/ossec.conf
# Should show: <enabled>no</enabled>
```

#### 2. **Enrollment Issues**

**Problem**: IP mismatch in client key
```bash
# Client key shows different IP than manager
001 agent 192.168.1.100 key...  # Key IP
Manager IP: 172.17.0.2           # Actual manager IP
```

**Solution**: Our enrollment automatically handles this
```bash
# Re-enroll with correct manager IP
./monitoring-agent-control.sh enroll 172.17.0.2:1514
# Enter the same client key - IP will be corrected automatically
```

#### 2. **Connection Failed**

**Check manager accessibility:**
```bash
# Test port connectivity
nc -zv <MANAGER_IP> 1514

# Example with Docker manager
nc -zv 172.17.0.2 1514
```

**Check manager status:**
```bash
# Docker manager
sudo docker logs monitoring-manager
sudo docker exec -it monitoring-manager /var/ossec/bin/monitoring-control status

# Physical manager
sudo /var/ossec/bin/monitoring-control status
```

#### 3. **Agent Won't Start**

**Check logs:**
```bash
# Agent logs
./monitoring-agent-control.sh logs 100

# Individual daemon logs
ls logs/
cat logs/monitoring-*.log
```

**Check permissions:**
```bash
# Fix permissions
./monitoring-agent-control.sh setup
chmod +x bin/*
```

**Check configuration:**
```bash
# Validate config
./monitoring-agent-control.sh health
```

#### 4. **Docker Manager Issues**

**Manager not accessible:**
```bash
# Check if container is running
sudo docker ps | grep monitoring

# Check container IP
sudo docker inspect monitoring-manager | grep IPAddress

# Check port mapping
sudo docker port monitoring-manager

# Restart container
sudo docker restart monitoring-manager
```

### Debug Mode

```bash
# Enable debug logging
./monitoring-agent-control.sh -d status
./monitoring-agent-control.sh -d start
```

### Log Files

```bash
# Main agent log
tail -f logs/monitoring-agent.log

# Individual daemon logs
tail -f logs/monitoring-agentd.log
tail -f logs/monitoring-modulesd.log
tail -f logs/monitoring-logcollector.log
```

---

## Windows Agent Support

### Windows Installation

```powershell
# Download and extract (PowerShell)
Invoke-WebRequest -Uri "https://releases.monitoring-solutions.com/monitoring-agent-windows.zip" -OutFile "monitoring-agent.zip"
Expand-Archive -Path "monitoring-agent.zip" -DestinationPath "C:\monitoring-agent"
cd C:\monitoring-agent

# Make executable (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Windows Enrollment

```powershell
# PowerShell enrollment (same process as Linux)
.\monitoring-agent-control.ps1 enroll <MANAGER_IP:PORT>

# Example
.\monitoring-agent-control.ps1 enroll 172.17.0.2:1514
```

### Windows Configuration

The Windows agent uses the same configuration approach:

**File Locations:**
- Configuration: `etc\ossec.conf`
- Client Keys: `etc\client.keys`
- Logs: `logs\`

**Key Settings (same as Linux):**
```xml
<enrollment>
  <enabled>no</enabled>
</enrollment>
```

**Important Notes for Windows:**
- ✅ **Same Manual Naming**: Uses manager-configured names, not Windows hostname
- ✅ **PowerShell Scripts**: `.ps1` equivalent scripts for Windows
- ✅ **Same Enrollment Process**: Identical interactive enrollment
- ✅ **Auto-Enrollment Disabled**: Prevents hostname-based registration

### Windows Troubleshooting

```powershell
# Check agent status
.\monitoring-agent-control.ps1 status

# Test connectivity
.\monitoring-agent-control.ps1 test-connection

# View logs
.\monitoring-agent-control.ps1 logs 50

# Windows firewall configuration
netsh advfirewall firewall add rule name="Monitoring Agent" dir=out action=allow protocol=TCP remoteport=1514
```

---

## Advanced Configuration

### File Structure

```
monitoring-agent/
├── monitoring-agent-control.sh     # Main control script
├── .setup_complete                 # Setup marker
├── bin/                            # Agent binaries
│   ├── monitoring-agentd          # Main agent daemon
│   ├── monitoring-modulesd        # Module manager
│   ├── monitoring-logcollector    # Log collector
│   └── ...
├── etc/
│   ├── ossec.conf                 # Main configuration
│   ├── client.keys               # Agent authentication
│   └── ossec.conf.backup.*       # Auto-backups
├── logs/                          # Log files
├── var/                           # Runtime data
│   ├── run/                      # PID files
│   └── ...
└── docs/                          # Documentation
```

### Environment Variables

```bash
# Monitoring Agent compatibility
export WAZUH_HOME="/path/to/monitoring-agent"
export OSSEC_HOME="/path/to/monitoring-agent"

# Debug mode
export DEBUG=1
```

### Systemd Service (Optional)

```bash
# For system-wide installation (requires root)
sudo ./monitoring-agent-control.sh setup

# Enable service
sudo systemctl enable monitoring-agent
sudo systemctl start monitoring-agent
```

### Firewall Configuration

```bash
# Automatic firewall setup
./monitoring-agent-control.sh configure-firewall <MANAGER_IP> [PORT]

# Manual iptables rule
sudo iptables -A OUTPUT -p tcp -d <MANAGER_IP> --dport 1514 -j ACCEPT

# Manual UFW rule
sudo ufw allow out 1514/tcp
```

---

## Support and Documentation

### Getting Help

```bash
# Show all commands
./monitoring-agent-control.sh --help

# Version information
./monitoring-agent-control.sh --version

# Health check
./monitoring-agent-control.sh health
```

### Resources

- **Documentation**: See `docs/` directory
- **Logs**: Check `logs/` directory for troubleshooting
- **Backups**: Stored in `backup/` directory
- **Support**: support@monitoring-solutions.com

### Quick Reference

| Command | Description |
|---------|-------------|
| `enroll <ip:port>` | Interactive enrollment |
| `start` | Start agent (auto-setup) |
| `stop` | Stop agent |
| `status` | Show status |
| `test-connection` | Test manager connectivity |
| `logs [n]` | Show logs |
| `health` | Health check |
| `backup` | Backup config |

---

*Last updated: September 15, 2025*  
*Version: 1.0.0*  
*Copyright © 2025 Monitoring Solutions Inc.*
