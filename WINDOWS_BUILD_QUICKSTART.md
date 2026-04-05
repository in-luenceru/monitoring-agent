# Windows Build Quick Start Guide

## 🎯 Simple Build (No Signatures Required)

### Option 1: Complete Build and Package (Recommended)

Run this single command from the `src/` directory:

```batch
build-and-package.bat 4.13.1 1
```

This will:
- ✅ Build the Windows agent
- ✅ Create MSI installer
- ✅ Package everything for distribution
- ✅ **No signatures or certificates needed!**

### Option 2: Build Only

```batch
build-windows-unsigned.bat
```

Then create installer:

```batch
cd win32
monitoring-installer-build-msi.bat 4.13.1 1
```

## 📦 What You Get

After running `build-and-package.bat`:

```
monitoring-agent-windows-4.13.1-1/
├── monitoring-agent-4.13.1-1.msi         ← Install this!
├── monitoring-agent.exe
├── monitoring-agent-eventchannel.exe
├── agent-auth.exe
├── manage_agents.exe
├── *.dll files
├── ossec.conf.sample
├── README.txt
└── INSTALL.md
```

## 🚀 Installation

### End User Installation

1. Give them the **MSI file**: `monitoring-agent-4.13.1-1.msi`
2. They run it as Administrator
3. Done!

### Silent Installation

```batch
msiexec /i monitoring-agent-4.13.1-1.msi /quiet MONITORING_MANAGER="192.168.1.100" MONITORING_REGISTRATION_PASSWORD="password"
```

## ❓ FAQ

### Q: Do I need Wazuh's signature?

**A: No!** You cannot use Wazuh's signature (it's their private key). You have two options:

1. **Development** (Easiest): Build with signature checks disabled
   ```batch
   build-and-package.bat 4.13.1 1
   ```

2. **Production**: Get your own certificate and sign the executables
   - See `win32/SIGNATURE_VERIFICATION_GUIDE.md` for details

### Q: Will the agent work without signatures?

**A: Yes!** When built with `IMAGE_TRUST_CHECKS=0`, signature verification is disabled. The agent works perfectly.

### Q: Is this secure?

**A: For development, yes. For production:**
- Development builds: Signature checks disabled = OK for testing
- Production builds: Should have signatures enabled + proper code signing certificate

### Q: How do I build for production?

Use the normal build process with signatures:

```batch
REM 1. Build normally (signature checks enabled)
make TARGET=winagent IMAGE_TRUST_CHECKS=1

REM 2. Sign all executables
cd win32
sign-executables-improved.bat "C:\path\to\cert.pfx" "password"

REM 3. Build signed MSI
monitoring-installer-build-msi.bat 4.13.1 1
```

### Q: What's the difference between the build options?

| Build Type | Signature Checks | When to Use |
|------------|------------------|-------------|
| `IMAGE_TRUST_CHECKS=0` | Disabled | Development, testing, no certificate available |
| `IMAGE_TRUST_CHECKS=1` | Warnings only | Development with certificates |
| `IMAGE_TRUST_CHECKS=2` | Enforced | Production with valid certificates |

## 🛠️ Build Scripts Reference

| Script | Purpose | Location |
|--------|---------|----------|
| `build-and-package.bat` | Complete build + packaging | `src/` |
| `build-windows-unsigned.bat` | Build only (no signatures) | `src/` |
| `monitoring-installer-build-msi.bat` | Create MSI installer | `src/win32/` |
| `sign-executables-improved.bat` | Sign executables (optional) | `src/win32/` |

## 📋 Complete Build Process

### From Linux/WSL

```bash
cd /home/anandhu/Desktop/monitoring_agent/src
./build-windows-unsigned.sh
```

### From Windows

```batch
cd C:\path\to\monitoring_agent\src
build-and-package.bat 4.13.1 1
```

## ✅ Verification

After building, verify the MSI was created:

```batch
cd win32
dir monitoring-agent-*.msi
```

Test installation on a Windows VM or test machine.

## 🎁 Distribution

Send to users:
1. **Just the MSI**: `win32/monitoring-agent-4.13.1-1.msi`
2. **Or the full package**: `monitoring-agent-windows-4.13.1-1.zip`

They can install with:
```batch
monitoring-agent-4.13.1-1.msi
```

## 🔑 Summary

**The easiest way to build and package:**

```batch
cd src
build-and-package.bat 4.13.1 1
```

**You'll get a working MSI installer without needing any certificates or signatures!**

This is perfect for:
- ✅ Development
- ✅ Testing
- ✅ Internal deployments
- ✅ Learning the system

For production deployments, consider getting a code signing certificate.
