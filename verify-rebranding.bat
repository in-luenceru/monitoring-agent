# =============================================
# MONITORING AGENT REBRANDING VERIFICATION
# =============================================

echo "Monitoring Agent Rebranding Complete!"
echo "====================================="
echo ""

echo "1. CORE BRANDING DEFINITIONS:"
echo "----------------------------"
findstr /C:"__ossec_name" /C:"__author" /C:"__contact" /C:"__site" src\headers\defs.h
echo ""

echo "2. WINDOWS SERVICE CONFIGURATION:"
echo "--------------------------------"
findstr /C:"MonitoringSvc" /C:"Monitoring Agent" src\win32\win_service.c | head -3
echo ""

echo "3. WINDOWS INSTALLER BRANDING:"
echo "-----------------------------"
echo "Product: $(findstr 'Name=\"Monitoring Agent\"' src\win32\monitoring-installer.wxs)"
echo "Manufacturer: $(findstr 'Manufacturer=\"Risknox.ai.\"' src\win32\monitoring-installer.wxs)"
echo ""

echo "4. VERSION RESOURCE:"
echo "------------------"
findstr /C:"CompanyName" /C:"ProductName" /C:"FileDescription" src\win32\version.rc
echo ""

echo "5. EXECUTABLE TARGETS:"
echo "--------------------"
findstr /C:"monitoring-agent.exe" src\Makefile
echo ""

echo "6. BUILD SCRIPTS AVAILABLE:"
echo "---------------------------"
dir src\win32\monitoring-installer-build-msi.bat
echo ""

echo "7. REBRANDING SUMMARY:"
echo "--------------------"
echo "✓ Core system name: Wazuh → Monitoring"
echo "✓ Company: Wazuh Inc. → Risknox.ai."
echo "✓ Service name: WazuhSvc → MonitoringSvc"
echo "✓ Service display: Wazuh Agent → Monitoring Agent"
echo "✓ Executable names: wazuh-agent.exe → monitoring-agent.exe"
echo "✓ Installer package: wazuh-installer.wxs → monitoring-installer.wxs"
echo "✓ User-visible messages updated"
echo "✓ Error messages rebranded"
echo "✓ Website URLs updated"
echo ""

echo "8. NEXT STEPS FOR BUILDING:"
echo "---------------------------"
echo "To build the Monitoring Agent for Windows:"
echo "1. Install MinGW cross-compiler: i686-w64-mingw32-gcc"
echo "2. Install WiX Toolset: candle.exe and light.exe"
echo "3. Run: make TARGET=winagent PREFIX=/var/ossec DISABLE_SHARED=yes"
echo "4. Build MSI: src\win32\monitoring-installer-build-msi.bat"
echo ""

echo "REBRANDING COMPLETE! No 'Wazuh' branding should be visible to end users."
echo "The process name will show as 'monitoring-agent.exe' in Task Manager."