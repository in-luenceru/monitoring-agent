# Building Monitoring Agent for Windows with Docker

This guide provides step-by-step instructions for building the fully rebranded **Monitoring Agent** for Windows using Docker. The Docker approach ensures a consistent build environment and eliminates dependency installation issues.

## 📋 Prerequisites

Before starting, ensure you have:

- **Docker Desktop** installed and running
- **Git** (if cloning from repository)
- **8GB+ RAM** available for the build process
- **20GB+ free disk space** for Docker images and build artifacts

## 🐳 Docker Build Environment

The build uses an Ubuntu 22.04 container with:
- MinGW cross-compiler (`gcc-mingw-w64`, `g++-mingw-w64`)
- NSIS installer generator
- Wine for Windows compatibility testing
- CMake 3.18.3
- All necessary build dependencies

## 🚀 Quick Start Build

### Option 1: Using the Build Script (Recommended)

```bash
# Navigate to the Windows package directory
cd "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1\packages\windows"

# Make the script executable (if on WSL/Linux)
chmod +x generate_compiled_windows_agent.sh

# Build the Monitoring Agent
bash generate_compiled_windows_agent.sh -o monitoring-agent-4.13.1-windows.zip -j 4 -d
```

### Option 2: Direct Docker Commands

```bash
# Build the Docker image
docker build -t monitoring-agent-builder:latest .

# Run the build container
docker run -it --rm \
  -v "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1:/local-src" \
  -v "C:\MonitoringAgent\Build:/shared" \
  monitoring-agent-builder:latest 4 no monitoring-agent-4.13.1.zip 1 "DigiCert Assured ID Root CA"
```

## 📝 Build Script Parameters

### generate_compiled_windows_agent.sh Options:

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `-o, --output` | **[Required]** Output package name | - | `monitoring-agent-4.13.1.zip` |
| `-j, --jobs` | Number of parallel compilation jobs | `4` | `-j 8` |
| `-d, --debug` | Build with debug symbols | `no` | `-d` |
| `-s, --store` | Output directory path | Current directory | `-s /output` |
| `-t, --trust_verification` | Trust verification level | `1` | `-t 0` |
| `-c, --ca_name` | CA name for trust verification | `DigiCert Assured ID Root CA` | `-c "Custom CA"` |
| `--sources` | Local source code path | `../../src` | `--sources /custom/path` |
| `--dont-build-docker` | Use existing Docker image | Build new | `--dont-build-docker` |
| `--tag` | Docker image tag | `latest` | `--tag v4.13.1` |

## 🛠️ Detailed Build Process

### Step 1: Prepare Build Environment

```bash
# Create output directory
mkdir -p "C:\MonitoringAgent\Build"

# Navigate to Windows package directory
cd "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1\packages\windows"
```

### Step 2: Build with Debug Information (Recommended for Development)

```bash
bash generate_compiled_windows_agent.sh \
  -o monitoring-agent-4.13.1-debug.zip \
  -j 8 \
  -d \
  -s "C:\MonitoringAgent\Build" \
  --sources "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1"
```

### Step 3: Build Production Release

```bash
bash generate_compiled_windows_agent.sh \
  -o monitoring-agent-4.13.1-release.zip \
  -j 8 \
  -s "C:\MonitoringAgent\Build" \
  --sources "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1"
```

## 📦 Build Output Structure

After successful build, you'll find in your output directory:

```
C:\MonitoringAgent\Build\
├── monitoring-agent-4.13.1.zip
│   └── wazuh-4.13.1/
│       ├── VERSION.json                    # Version information with commit hash
│       └── src/
│           ├── win32/
│           │   ├── monitoring-agent.exe          # Main agent executable
│           │   ├── monitoring-agent-eventchannel.exe  # Event channel version
│           │   ├── manage_agents.exe             # Agent management tool
│           │   ├── agent-auth.exe                # Authentication tool
│           │   ├── setup-windows.exe             # Windows setup utility
│           │   ├── setup-syscheck.exe            # Syscheck setup
│           │   ├── setup-iis.exe                 # IIS setup
│           │   └── os_win32ui.exe                # Windows UI
│           └── etc/
│               └── ossec.conf                    # Default configuration
```

## 🏗️ Advanced Build Options

### Custom Build with Specific Compiler Options

```bash
# Build with custom compiler flags
docker run -it --rm \
  -v "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1:/local-src" \
  -v "C:\MonitoringAgent\Build:/shared" \
  -e CFLAGS="-O3 -DMONITORING_AGENT" \
  -e LDFLAGS="-static-libgcc -static-libstdc++" \
  monitoring-agent-builder:latest 8 no monitoring-agent-optimized.zip 1 "Custom CA"
```

### Building from Different Branch (if using Git)

```bash
bash generate_compiled_windows_agent.sh \
  -b v4.13.1 \
  -o monitoring-agent-4.13.1-stable.zip \
  -j 4
```

### Building with Custom Trust Verification

```bash
bash generate_compiled_windows_agent.sh \
  -o monitoring-agent-no-trust.zip \
  -j 4 \
  -t 0 \
  -c "Monitoring Solutions Root CA"
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. Docker Build Fails
```bash
# Clean Docker cache and rebuild
docker system prune -f
docker build --no-cache -t monitoring-agent-builder:latest .
```

#### 2. Permission Issues (Windows)
```bash
# Run PowerShell as Administrator
# Enable WSL integration in Docker Desktop
# Ensure Docker has access to your drives
```

#### 3. Out of Memory During Build
```bash
# Reduce parallel jobs
bash generate_compiled_windows_agent.sh -o output.zip -j 2

# Increase Docker memory limit in Docker Desktop settings
```

#### 4. MinGW Compilation Errors
```bash
# Update Docker image with latest packages
docker pull ubuntu:22.04
docker build --no-cache -t monitoring-agent-builder:latest .
```

### Debugging Build Issues

```bash
# Interactive debugging session
docker run -it --rm \
  -v "C:\Users\ANANDHU\Downloads\wazuh-4.13.1\wazuh-4.13.1:/local-src" \
  -v "C:\MonitoringAgent\Build:/shared" \
  monitoring-agent-builder:latest bash

# Inside container:
cd /local-src
make -C src deps TARGET=winagent DEBUG=1
make -C src TARGET=winagent DEBUG=1 VERBOSE=1
```

## 🧪 Testing the Built Agent

### Extract and Verify Build

```bash
# Extract the built package
cd "C:\MonitoringAgent\Build"
tar -xf monitoring-agent-4.13.1.zip

# Verify executables
cd wazuh-4.13.1/src/win32
file monitoring-agent.exe  # Should show: PE32 executable
strings monitoring-agent.exe | grep -i monitoring  # Verify branding
```

### Quick Functionality Test

```bash
# Test agent help (using Wine in Docker)
docker run -it --rm \
  -v "C:\MonitoringAgent\Build:/build" \
  monitoring-agent-builder:latest \
  wine /build/wazuh-4.13.1/src/win32/monitoring-agent.exe --help
```

## 📋 Build Checklist

Before building, ensure:

- [ ] All rebranding changes are committed
- [ ] Docker Desktop is running with sufficient resources
- [ ] Output directory has write permissions
- [ ] Source code directory is properly mounted
- [ ] Network connectivity for package downloads

After building, verify:

- [ ] All executables are present in output
- [ ] File sizes are reasonable (monitoring-agent.exe ~10-20MB)
- [ ] No "Wazuh" strings in executable names
- [ ] VERSION.json contains correct commit hash
- [ ] Configuration files are included

## 🎯 Production Deployment

After successful build:

1. **Extract executables** from the ZIP package
2. **Create MSI installer** using the monitoring-installer.wxs
3. **Sign executables** (optional) with code signing certificate
4. **Test installation** on clean Windows system
5. **Verify service registration** as "MonitoringSvc"
6. **Validate process name** shows as "monitoring-agent.exe"

## 💡 Tips for Optimal Builds

- **Use SSD storage** for faster I/O during compilation
- **Allocate 8GB+ RAM** to Docker for parallel builds
- **Enable WSL2** on Windows for better Docker performance
- **Clean Docker cache** periodically to avoid space issues
- **Build during off-peak hours** for consistent performance

---

## 🏆 Success!

You now have a fully functional, rebranded **Monitoring Agent** for Windows that:
- ✅ Contains zero "Wazuh" references visible to users
- ✅ Shows as "monitoring-agent.exe" in Task Manager
- ✅ Installs as "Monitoring Agent" service
- ✅ Maintains all original Wazuh functionality
- ✅ Is ready for production deployment

Your Windows Monitoring Agent is ready for distribution!