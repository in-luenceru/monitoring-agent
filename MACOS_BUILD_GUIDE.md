# Monitoring Agent - macOS Build Guide

## Overview

This guide covers building the **Monitoring Agent** for macOS (both Intel and Apple Silicon), fully rebranded from the original Wazuh agent. All references to "Wazuh" have been replaced with "Monitoring Agent" / "Monitoring Solutions Inc." branding throughout the build system.

## Rebranding Summary

| Component | Original (Wazuh) | Rebranded (Monitoring Agent) |
|---|---|---|
| **Package Name** | `wazuh-agent-VERSION.pkg` | `monitoring-agent-VERSION.pkg` |
| **Service Identifier** | `com.wazuh.agent` | `com.monitoring.agent` |
| **Package Identifier** | `com.wazuh.pkg.wazuh-agent` | `com.monitoring.pkg.monitoring-agent` |
| **LaunchDaemon** | `/Library/LaunchDaemons/com.wazuh.agent.plist` | `/Library/LaunchDaemons/com.monitoring.agent.plist` |
| **StartupItems** | `/Library/StartupItems/WAZUH/` | `/Library/StartupItems/MONITORING/` |
| **Control Script** | `wazuh-control` | `monitoring-control` |
| **System User/Group** | `wazuh` / `wazuh` | `monitoring` / `monitoring` |
| **Manufacturer** | Wazuh Inc. | Monitoring Solutions Inc. |
| **Install Path** | `/Library/Ossec` | `/Library/Ossec` (unchanged for compatibility) |
| **Source Repository** | `https://github.com/wazuh/wazuh` | (local build) |

## Files Modified/Created

### New Monitoring Agent Files (recommended for fresh builds):
- `packages/macos/generate_monitoring_packages.sh` — Main package generation script
- `packages/macos/package_files/build_monitoring.sh` — Build script
- `packages/macos/package_files/preinstall_monitoring.sh` — Pre-install script
- `packages/macos/package_files/postinstall_monitoring.sh` — Post-install script
- `packages/macos/package_files/introduction_monitoring.txt` — Installer welcome text
- `packages/macos/uninstall_monitoring.sh` — Uninstall script
- `packages/macos/specs/build-info-monitoring.json` — Package metadata
- `src/init/darwin-init-monitoring.sh` — LaunchDaemon/StartupItems init
- `src/init/darwin-addusers-monitoring.sh` — macOS user/group creation

### Original Files (also updated in-place):
- `packages/macos/generate_wazuh_packages.sh` — Updated with monitoring branding
- `packages/macos/package_files/build.sh` — Updated
- `packages/macos/package_files/preinstall.sh` — Updated
- `packages/macos/package_files/postinstall.sh` — Updated
- `packages/macos/package_files/introduction.txt` — Updated
- `packages/macos/uninstall.sh` — Updated
- `packages/macos/specs/build-info.json` — Updated
- `src/init/darwin-init.sh` — Updated
- `src/init/darwin-addusers.sh` — Updated
- `src/init/darwin-delete-oldusers.sh` — Updated

### Source Code (already rebranded):
- `src/headers/defs.h` — `__ossec_name = "Monitoring"`, `__author = "Risknox.ai."`
- `src/win32/os_win.h` — Monitoring Agent references
- `bin/monitoring-control` — Control script (already renamed)
- `bin/monitoring-agentd`, `monitoring-auth`, `monitoring-execd`, etc. — All renamed

## Prerequisites

### macOS Build Machine Requirements:
- macOS 11+ (Big Sur or later recommended)
- Xcode Command Line Tools
- Homebrew
- GCC 11+
- CMake
- munkipkg (for .pkg creation)

### Install Dependencies:
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Run the dependency installer
sudo ./packages/macos/generate_monitoring_packages.sh -i

# Or install manually
brew install cmake gcc
# For ARM64 builds also:
brew install binutils autoconf automake libtool

# Install munkipkg
git clone https://github.com/munki/munki-pkg.git ~/Developer/munki-pkg
sudo ln -s "$HOME/Developer/munki-pkg/munkipkg" /usr/local/bin/munkipkg
```

## Building the Package

### Basic Build (Intel):
```bash
sudo ./packages/macos/generate_monitoring_packages.sh -a intel64 -j 4
```

### Build for Apple Silicon (ARM64):
```bash
sudo ./packages/macos/generate_monitoring_packages.sh -a arm64 -j 4
```

### Build with Debug Symbols:
```bash
sudo ./packages/macos/generate_monitoring_packages.sh -a arm64 -j 4 -d
```

### Build with Checksums:
```bash
sudo ./packages/macos/generate_monitoring_packages.sh -a arm64 -j 4 -c
```

### Build with Signing:
```bash
sudo ./packages/macos/generate_monitoring_packages.sh \
    -a arm64 -j 4 \
    --keychain "/path/to/keychain.keychain-db" \
    --keychain-password "your_password" \
    --application-certificate "Developer ID Application: Your Name (TEAM_ID)" \
    --installer-certificate "Developer ID Installer: Your Name (TEAM_ID)"
```

### Build with Notarization:
```bash
sudo ./packages/macos/generate_monitoring_packages.sh \
    -a arm64 -j 4 \
    --keychain "/path/to/keychain.keychain-db" \
    --keychain-password "your_password" \
    --application-certificate "Developer ID Application: Your Name (TEAM_ID)" \
    --installer-certificate "Developer ID Installer: Your Name (TEAM_ID)" \
    --notarize \
    --developer-id "your@apple.id" \
    --team-id "YOUR_TEAM_ID" \
    --altool-password "app-specific-password"
```

### Stage/Release Build:
```bash
sudo ./packages/macos/generate_monitoring_packages.sh -a arm64 -j 4 --is_stage
```

## Output

Packages are created in `packages/macos/output/`:
- `monitoring-agent-VERSION-REVISION.ARCH.pkg` (release)
- `monitoring-agent_VERSION-REVISION_ARCH_COMMITHASH.pkg` (development)
- `monitoring-agent-debug-symbols-VERSION-REVISION.ARCH-macos.zip` (debug symbols)

## Installation on macOS

```bash
# Install
sudo installer -pkg monitoring-agent-VERSION-REVISION.arm64.pkg -target /

# Check status
sudo /Library/Ossec/bin/monitoring-control status

# Start
sudo /Library/Ossec/bin/monitoring-control start

# Stop
sudo /Library/Ossec/bin/monitoring-control stop
```

## Uninstalling

```bash
sudo ./packages/macos/uninstall_monitoring.sh
# or
sudo /Library/Ossec/bin/monitoring-control stop
sudo rm -rf /Library/Ossec
sudo rm -f /Library/LaunchDaemons/com.monitoring.agent.plist
sudo rm -rf /Library/StartupItems/MONITORING
sudo dscl . -delete /Users/monitoring
sudo dscl . -delete /Groups/monitoring
sudo pkgutil --forget com.monitoring.pkg.monitoring-agent
```

## Verification

After building, verify the rebranding:
```bash
# Check package name
ls packages/macos/output/

# Check the package identifier
pkgutil --pkg-info com.monitoring.pkg.monitoring-agent

# Check LaunchDaemon
cat /Library/LaunchDaemons/com.monitoring.agent.plist

# Check service status
sudo /Library/Ossec/bin/monitoring-control status

# Check system user
dscl . -read /Users/monitoring

# Verify no wazuh references in installed files
grep -r "wazuh" /Library/Ossec/bin/ 2>/dev/null || echo "No wazuh references found"
```

## Comparison with Windows Build

The macOS rebranding follows the same pattern as the Windows build:

| Aspect | Windows | macOS |
|---|---|---|
| **Service** | `MonitoringSvc` | `com.monitoring.agent` (LaunchDaemon) |
| **Control** | `monitoring-agent-control.ps1` | `monitoring-control` |
| **Installer** | `monitoring-agent.msi` | `monitoring-agent.pkg` |
| **Install Path** | `C:\Program Files\monitoring-agent\` | `/Library/Ossec/` |
| **Executables** | `monitoring-agent.exe` | `monitoring-agentd`, `monitoring-control`, etc. |
| **User** | SYSTEM | `monitoring` |
| **Company** | Monitoring Solutions Inc. | Monitoring Solutions Inc. |

## Troubleshooting

### "munkipkg not found"
```bash
sudo ./packages/macos/generate_monitoring_packages.sh -i
```

### "This script must be run as root"
```bash
sudo ./packages/macos/generate_monitoring_packages.sh [options]
```

### Build fails on ARM64
Ensure you have the correct architecture tools:
```bash
brew install binutils autoconf automake libtool cmake
```

### Signing issues
Make sure the keychain is unlocked and certificates are valid:
```bash
security find-identity -v -p codesigning
```
