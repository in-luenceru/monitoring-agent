; RiskNoX Monitoring Agent - Windows Installer
; This installer packages the complete monitoring agent with all dependencies
; Professional installer with Wazuh-style UI and comprehensive file inclusion

;--------------------------------
; Include Modern UI and additional plugins
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

; Basic service management using built-in commands
; Note: Advanced plugins (nsProcess, SimpleSC) are optional
; Fallback to built-in Windows commands for compatibility

;--------------------------------
; General Configuration
!define PRODUCT_NAME "RiskNoX Monitoring Agent"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_REVISION "1"
!define PRODUCT_PUBLISHER "RiskNoX Security Solutions"
!define PRODUCT_WEB_SITE "https://risknox.com"
!define PRODUCT_SUPPORT_URL "https://support.risknox.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\monitoring-agent.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"
!define SERVICE_NAME "RiskNoXSupervisor"

; Version Information
VIProductVersion "1.0.0.1"
VIAddVersionKey ProductName "${PRODUCT_NAME}"
VIAddVersionKey CompanyName "${PRODUCT_PUBLISHER}"
VIAddVersionKey LegalCopyright "2024 - ${PRODUCT_PUBLISHER}"
VIAddVersionKey FileDescription "RiskNoX Monitoring Agent Installer"
VIAddVersionKey FileVersion "${PRODUCT_VERSION}"
VIAddVersionKey ProductVersion "${PRODUCT_VERSION}"
VIAddVersionKey InternalName "RiskNoX Agent"
VIAddVersionKey OriginalFilename "RiskNoX-Monitoring-Agent-Installer.exe"

; Set compression
SetCompressor /SOLID lzma

; Name and file
Name "${PRODUCT_NAME} v${PRODUCT_VERSION}"
BrandingText "Copyright (C) 2024, ${PRODUCT_PUBLISHER}"
OutFile "RiskNoX-Monitoring-Agent-Installer.exe"

; Default installation folder
InstallDir "$PROGRAMFILES64\RiskNoX\MonitoringAgent"

; Get installation folder from registry if available
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""

; Request application privileges for Windows Vista/7/8/10/11
RequestExecutionLevel admin

; Show installation details
ShowInstDetails show
ShowUninstDetails show

;--------------------------------
; Variables
Var StartMenuFolder
Var is_upgrade
Var suricata_selected
Var pwsh7_path

;--------------------------------
; Interface Settings (Professional Wazuh-style UI)
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Header image
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\nsis.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${NSISDIR}\Contrib\Graphics\Header\nsis.bmp"
!define MUI_HEADERIMAGE_RIGHT

; Welcome page image
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\win.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\win.bmp"

; Finish page settings
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

;--------------------------------
; Pages (Professional Wazuh-style layout)

; Welcome page with custom text
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PRODUCT_NAME} and its components.$\r$\n$\r$\nThe installer includes:$\r$\n• Core monitoring agent with file integrity monitoring$\r$\n• Network intrusion detection with Suricata IDS$\r$\n• Active response capabilities$\r$\n• Service supervisor with advanced protection$\r$\n• Management tools and utilities$\r$\n$\r$\nClick Next to continue with the installation."
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "LICENSE"

; Components page with enhanced descriptions
!define MUI_COMPONENTSPAGE_TEXT_TOP "Select the components you want to install. The Core Monitoring Agent is required, while other components provide additional security capabilities."
!define MUI_COMPONENTSPAGE_TEXT_COMPLIST "Select components to install:"
!define MUI_COMPONENTSPAGE_TEXT_INSTTYPE "Choose the type of install:"
!define MUI_COMPONENTSPAGE_TEXT_DESCRIPTION_TITLE "Component Description"
!define MUI_COMPONENTSPAGE_TEXT_DESCRIPTION_INFO "Position your mouse over a component to see its description."
!insertmacro MUI_PAGE_COMPONENTS

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Start menu page
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM" 
!define MUI_STARTMENUPAGE_REGISTRY_KEY "${PRODUCT_UNINST_KEY}" 
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "NSIS:StartMenuDir"
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder

; Installation page
!insertmacro MUI_PAGE_INSTFILES

; Finish page with run option
!define MUI_FINISHPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Configure RiskNoX Service (Launch Configuration Wizard)"
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchServiceConfig"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\INSTALLATION-GUIDE.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "View Installation Guide"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
; Languages
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Installer Functions

; Check if we're running as administrator and find PowerShell 7
Function .onInit
  ; Initialize variables
  StrCpy $is_upgrade "no"
  StrCpy $suricata_selected "no"
  StrCpy $pwsh7_path ""
  
  ; Check administrator privileges
  UserInfo::GetAccountType
  pop $0
  ${If} $0 != "admin"
    MessageBox MB_ICONSTOP "Administrator privileges required!$\r$\n$\r$\nPlease right-click the installer and select 'Run as administrator'."
    SetErrorLevel 740 ; ERROR_ELEVATION_REQUIRED
    Quit
  ${EndIf}
  
  ; Check if 64-bit OS
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This application requires a 64-bit version of Windows.$\r$\n$\r$\n32-bit Windows is not supported."
    Abort
  ${EndIf}
  
  ; Check Windows version (Windows 10 or later required)
  ${If} ${AtMostWin2008R2}
    MessageBox MB_ICONSTOP "Windows 10 or later is required.$\r$\n$\r$\nYour current Windows version is not supported."
    Abort
  ${EndIf}
  
  ; Find PowerShell 7
  Call FindPowerShell7
  
  ; Check if upgrading existing installation
  ReadRegStr $0 HKLM "${PRODUCT_UNINST_KEY}" "DisplayName"
  ${If} $0 != ""
    StrCpy $is_upgrade "yes"
    MessageBox MB_YESNO "An existing installation of ${PRODUCT_NAME} was found.$\r$\n$\r$\nDo you want to upgrade the existing installation?" IDYES upgrade_continue
    Abort
    upgrade_continue:
  ${EndIf}
  
  ; Stop existing service if running
  ${If} $is_upgrade == "yes"
    Call StopExistingService
  ${EndIf}
FunctionEnd

; Function to find PowerShell 7
Function FindPowerShell7
  ; Try common PowerShell 7 locations
  StrCpy $pwsh7_path ""
  
  ; Check Program Files
  IfFileExists "$PROGRAMFILES\PowerShell\7\pwsh.exe" 0 check_pf86
  StrCpy $pwsh7_path "$PROGRAMFILES\PowerShell\7\pwsh.exe"
  DetailPrint "Found PowerShell 7 at: $pwsh7_path"
  Return
  
  check_pf86:
  IfFileExists "$PROGRAMFILES32\PowerShell\7\pwsh.exe" 0 check_windowsapps
  StrCpy $pwsh7_path "$PROGRAMFILES32\PowerShell\7\pwsh.exe"
  DetailPrint "Found PowerShell 7 at: $pwsh7_path"
  Return
  
  check_windowsapps:
  ; Check Windows Apps directory (Microsoft Store version)
  IfFileExists "$LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe" 0 fallback_powershell
  StrCpy $pwsh7_path "$LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe"
  DetailPrint "Found PowerShell 7 at: $pwsh7_path"
  Return
  
  fallback_powershell:
  ; Fallback to Windows PowerShell 5.1
  StrCpy $pwsh7_path "powershell.exe"
  DetailPrint "PowerShell 7 not found, using Windows PowerShell 5.1"
FunctionEnd

; Function to stop existing service
Function StopExistingService
  DetailPrint "Checking for existing RiskNoX service..."
  
  ; Use sc command to check if service exists and stop it
  ExecWait '"sc" query "${SERVICE_NAME}"' $0
  ${If} $0 = 0
    DetailPrint "Found existing service, stopping..."
    ExecWait '"sc" stop "${SERVICE_NAME}"' $0
    ${If} $0 = 0
      DetailPrint "Service stopped successfully"
    ${Else}
      DetailPrint "Service stop returned code: $0 (may already be stopped)"
    ${EndIf}
    ; Wait a moment for service to fully stop
    Sleep 2000
  ${Else}
    DetailPrint "No existing service found"
  ${EndIf}
  
  service_stop_done:
FunctionEnd

; Launch service configuration after installation using PowerShell 7
Function LaunchServiceConfig
  DetailPrint "Launching RiskNoX service installation..."
  
  ${If} $pwsh7_path != ""
    ${If} $pwsh7_path == "powershell.exe"
      ; Using Windows PowerShell 5.1
      ExecWait '"$pwsh7_path" -WindowStyle Normal -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" install' $0
    ${Else}
      ; Using PowerShell 7
      ExecWait '"$pwsh7_path" -WindowStyle Normal -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" install' $0
    ${EndIf}
    
    ${If} $0 != 0
      MessageBox MB_ICONEXCLAMATION "Service installation encountered issues (exit code: $0).$\r$\n$\r$\nPlease check the logs in the installation directory and run the configuration manually if needed.$\r$\n$\r$\nTo configure manually:$\r$\n1. Open PowerShell as Administrator$\r$\n2. Navigate to: $INSTDIR$\r$\n3. Run: .\RiskNoXServiceControl.ps1 install"
    ${Else}
      MessageBox MB_ICONINFORMATION "RiskNoX Monitoring Agent has been installed and configured successfully!$\r$\n$\r$\nNext steps:$\r$\n• Configure agent enrollment: .\RiskNoXServiceControl.ps1 configure$\r$\n• Start the service: .\RiskNoXServiceControl.ps1 start -Password 'RiskNoX@2024'$\r$\n• Check status: .\RiskNoXServiceControl.ps1 status$\r$\n$\r$\nShortcuts have been created in the Start Menu for easy access."
    ${EndIf}
  ${Else}
    MessageBox MB_ICONEXCLAMATION "PowerShell not found. Please install PowerShell 7 or run the configuration manually."
  ${EndIf}
FunctionEnd

;--------------------------------
; Installer Sections

; Core Components (Required) - Complete file inclusion
Section "Core Monitoring Agent (Required)" SecCore
  SectionIn RO  ; Read-only, cannot be deselected
  
  SetOutPath "$INSTDIR"
  SetOverwrite on
  
  ; Main executable files - ALL agent executables
  File "monitoring-agent.exe"
  File /nonfatal "monitoring-agent-original.exe"
  File /nonfatal "monitoring-agent-eventchannel.exe"
  File /nonfatal "MonitoringAgentService.exe"
  File "agent-auth.exe"
  File "manage_agents.exe"
  File /nonfatal "win32ui.exe"
  
  ; Core Python scripts - Backend services
  File "backend_server.py"
  File "service_control_backend.py"
  File "agent_poll.py"
  
  ; ALL PowerShell management scripts
  File "RiskNoXServiceControl.ps1"
  File "UnifiedAgentControl.ps1"
  File "RiskNoX-Control.ps1"
  File "MonitoringAgentControl.ps1"
  File "RiskNoX-Agent-Installer.ps1"
  File "MonitoringAgentAutoStart.ps1"
  File "RobustAutoStart.ps1"
  File "SetupAutoStartup.ps1"
  
  ; Security and password management scripts
  File "change-password.ps1"
  File "test-password-protection.ps1"
  File "test-web-blocking.ps1"
  
  ; ALL DLL libraries - Critical system libraries
  File "dbsync.dll"
  File "libfimdb.dll"
  File "libgcc_s_dw2-1.dll"
  File "libstdc++-6.dll"
  File "libwazuhext.dll"
  File "libwazuhshared.dll"
  File "libwinpthread-1.dll"
  File "rsync.dll"
  File "syscollector.dll"
  File "sysinfo.dll"
  
  ; Configuration files - ALL config files
  File "ossec.conf"
  File /nonfatal "ossec.conf.original"
  File /nonfatal "ossec.conf.new"
  File "internal_options.conf"
  File "local_internal_options.conf"
  File "vista_sec.txt"
  File "wpk_root.pem"
  File "VERSION.json"
  File "profile-10.template"
  
  ; Batch files and startup scripts - ALL startup mechanisms
  File "auto-start-wrapper.bat"
  File "InstallAndStart-RiskNoX.bat"
  
  ; Windows setup utilities - ALL setup tools
  File /nonfatal "setup-iis.exe"
  File /nonfatal "setup-syscheck.exe"  
  File /nonfatal "setup-windows.exe"
  
  ; Documentation and help files
  File "help.txt"
  File /nonfatal "help.txt.original"
  File "ReadMe.txt"
  File "changes.txt"
  File "INSTALLATION-GUIDE.md"
  
  ; State files - Current state information
  File /nonfatal "monitoring-agent.state"
  File /nonfatal "monitoring-.state"
  File /nonfatal "wazuh-agent.state"
  File /nonfatal "monitoring-logcollector.state"
  File /nonfatal "monitoring-agent.pid"
  File /nonfatal "ossec.log"
  
  ; Calculate and log current time for installation record
  ${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
  FileOpen $7 "$INSTDIR\install.log" w
  FileWrite $7 "RiskNoX Monitoring Agent installed on $2-$1-$0 at $4:$5:$6$\r$\n"
  FileClose $7
SectionEnd

; Configuration System - ALL configuration files and settings
Section "Configuration System" SecConfig
  SetOutPath "$INSTDIR\config"
  File "config\services.yml"
  File "config\settings.json" 
  File "config\process_inventory.json"
  File /nonfatal "config\supervisor_token.txt"
  File /nonfatal "config\.service_password"
SectionEnd

; Service Supervisor - Complete supervisor system
Section "Service Supervisor" SecSupervisor
  SetOutPath "$INSTDIR\supervisor"
  File "supervisor\supervisor.py"
  File "supervisor\supervisor.spec"
  File "supervisor\requirements.txt"
  File "supervisor\remote_control_auth.py"
  
  SetOutPath "$INSTDIR\dist"
  File /nonfatal "dist\supervisor.exe"
  
  ; Create supervisor directory structure
  CreateDirectory "$INSTDIR\dist\logs"
  CreateDirectory "$INSTDIR\dist\state"
  CreateDirectory "$INSTDIR\logs"
SectionEnd

; Management Tools - ALL tools and utilities
Section "Management Tools and Utilities" SecTools
  SetOutPath "$INSTDIR\tools"
  
  ; ALL PowerShell tool scripts
  File "tools\build.ps1"
  File "tools\deploy.ps1"
  File "tools\download_nssm.ps1"
  File "tools\enroll-agent.ps1"
  File "tools\install-dependencies.ps1"
  File "tools\install_service.ps1"
  File "tools\protect_service.ps1"
  File "tools\refresh-creds.ps1"
  File "tools\restart.ps1"
  File "tools\start.ps1"
  File "tools\status-enhanced.ps1"
  File "tools\status.ps1"
  File "tools\stop.ps1"
  File "tools\test-non-admin-access.ps1"
  File "tools\test-service-protection.ps1"
  File "tools\uninstall_service.ps1"
  File "tools\unprotect_service.ps1"
  
  ; NSSM Service Manager - Complete NSSM installation
  SetOutPath "$INSTDIR\tools\nssm"
  File "tools\nssm\ChangeLog.txt"
  File "tools\nssm\README.txt"
  
  SetOutPath "$INSTDIR\tools\nssm\win64"
  File "tools\nssm\win64\nssm.exe"
  
  SetOutPath "$INSTDIR\tools\nssm\win32"
  File "tools\nssm\win32\nssm.exe"
  
  ; NSSM source files (if present)
  SetOutPath "$INSTDIR\tools\nssm\src"
  File /nonfatal /r "tools\nssm\src\*.*"
SectionEnd

; Active Response System - Complete active response
Section "Active Response System" SecActiveResponse
  SetOutPath "$INSTDIR\active-response"
  
  ; Active response binaries and scripts
  SetOutPath "$INSTDIR\active-response\bin"
  File /r "active-response\bin\*.*"
  
  ; Create active response log
  FileOpen $0 "$INSTDIR\active-response\active-responses.log" w
  FileClose $0
SectionEnd

; Shared Resources - ALL shared files
Section "Shared Resources and Libraries" SecShared
  SetOutPath "$INSTDIR\shared"
  File /r "shared\*.*"
SectionEnd

; Detection Ruleset - Complete rule system
Section "Detection Rules and Decoders" SecRuleset
  SetOutPath "$INSTDIR\ruleset"
  File /r "ruleset\*.*"
SectionEnd

; Queue System - Message processing queues
Section "Message Queue System" SecQueue
  ; Create comprehensive queue directory structure
  CreateDirectory "$INSTDIR\queue"
  CreateDirectory "$INSTDIR\queue\agents"
  CreateDirectory "$INSTDIR\queue\agent-info"
  CreateDirectory "$INSTDIR\queue\alerts"
  CreateDirectory "$INSTDIR\queue\diff"
  CreateDirectory "$INSTDIR\queue\diff\local"
  CreateDirectory "$INSTDIR\queue\fts"
  CreateDirectory "$INSTDIR\queue\rootcheck"
  CreateDirectory "$INSTDIR\queue\syscheck"
  CreateDirectory "$INSTDIR\queue\fim"
  CreateDirectory "$INSTDIR\queue\fim\db"
  CreateDirectory "$INSTDIR\queue\syscollector"
  CreateDirectory "$INSTDIR\queue\syscollector\db"
  CreateDirectory "$INSTDIR\queue\logcollector"
  
  ; Copy any existing queue files
  SetOutPath "$INSTDIR\queue"
  File /nonfatal /r "queue\*.*"
SectionEnd

; State Management - Runtime state system
Section "State Management System" SecState
  CreateDirectory "$INSTDIR\state"
  CreateDirectory "$INSTDIR\state\global"
  CreateDirectory "$INSTDIR\state\agents"
  
  ; Copy existing state files
  SetOutPath "$INSTDIR\state"
  File /nonfatal /r "state\*.*"
SectionEnd

; Registry System - Agent registration
Section "Registry and Identification System" SecRids
  CreateDirectory "$INSTDIR\rids"
  
  ; Copy any existing registry files
  SetOutPath "$INSTDIR\rids"
  File /nonfatal /r "rids\*.*"
SectionEnd

; Build System - Development tools (Optional)
Section /o "Build System and Development Tools" SecBuild
  SetOutPath "$INSTDIR\build"
  File /nonfatal /r "build\*.*"
SectionEnd

; Vendor Libraries - Third-party components
Section "Vendor Libraries and Dependencies" SecVendor
  SetOutPath "$INSTDIR\vendor"
  File /nonfatal /r "vendor\*.*"
SectionEnd

; Sample Configurations - Example configs
Section "Sample Configurations and Templates" SecSamples
  SetOutPath "$INSTDIR\samples"
  File /nonfatal /r "samples\*.*"
SectionEnd

; Suricata Network IDS - Complete Suricata installation
Section "Suricata Network IDS/IPS (Recommended)" SecSuricata
  ; Set flag for post-installation handling
  StrCpy $suricata_selected "yes"
  
  SetOutPath "$INSTDIR\suricata"
  
  ; Main Suricata control and management
  File "suricata\SuricataControl.ps1"
  File /nonfatal "suricata\SuricataControl.ps1.backup"
  
  ; Suricata binaries and executables
  SetOutPath "$INSTDIR\suricata\bin"
  File /nonfatal "suricata\bin\*.*"
  
  ; Suricata configuration files
  SetOutPath "$INSTDIR\suricata\etc"
  File /nonfatal "suricata\etc\*.*"
  
  ; Suricata detection rules
  SetOutPath "$INSTDIR\suricata\rules"
  File /nonfatal "suricata\rules\*.*"
  
  ; Create Suricata runtime directories
  CreateDirectory "$INSTDIR\suricata\log"
  CreateDirectory "$INSTDIR\suricata\cache"
  CreateDirectory "$INSTDIR\suricata\cache\sgh"
  
  ; Copy existing log files if present
  SetOutPath "$INSTDIR\suricata\log"
  File /nonfatal "suricata\log\*.*"
  
  DetailPrint "Suricata Network IDS installed successfully"
SectionEnd

; Npcap Network Driver - Network packet capture
Section "Npcap Network Packet Capture (Required for Suricata)" SecNpcap
  SetOutPath "$INSTDIR\npcap"
  File /nonfatal /r "npcap\*.*"
  
  DetailPrint "Npcap network capture components installed"
SectionEnd

; Temporary and Backup directories
Section -AdditionalDirectories
  ; Create additional required directories
  CreateDirectory "$INSTDIR\bookmarks"
  CreateDirectory "$INSTDIR\incoming"
  CreateDirectory "$INSTDIR\tmp"
  CreateDirectory "$INSTDIR\upgrade"
  CreateDirectory "$INSTDIR\wodles"
SectionEnd

;--------------------------------
; Post-Installation Setup and Registry Configuration

Section -AdditionalIcons
  SetOutPath $INSTDIR
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
  CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
  
  ; Main management shortcuts
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\RiskNoX Service Control.lnk" '"$pwsh7_path"' '-ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" status' "$INSTDIR\monitoring-agent.exe" 0
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\RiskNoX Agent Configuration.lnk" '"$pwsh7_path"' '-ExecutionPolicy Bypass -File "$INSTDIR\UnifiedAgentControl.ps1" status' "$INSTDIR\monitoring-agent.exe" 0
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Agent Manager.lnk" "$INSTDIR\win32ui.exe" "" "$INSTDIR\win32ui.exe" 0
  
  ; Configuration and documentation
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Installation Guide.lnk" "$INSTDIR\INSTALLATION-GUIDE.md"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Edit Configuration.lnk" "$INSTDIR\ossec.conf"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\View Logs.lnk" "explorer.exe" '"$INSTDIR\logs"'
  
  ; Suricata shortcuts (if installed)
  ${If} $suricata_selected == "yes"
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Suricata Control.lnk" '"$pwsh7_path"' '-ExecutionPolicy Bypass -File "$INSTDIR\suricata\SuricataControl.ps1"' "$INSTDIR\monitoring-agent.exe" 0
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Suricata Configuration.lnk" "$INSTDIR\suricata\etc\suricata.yaml"
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Suricata Logs.lnk" "explorer.exe" '"$INSTDIR\suricata\log"'
  ${EndIf}
  
  ; Utility shortcuts
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Installation Folder.lnk" "explorer.exe" '"$INSTDIR"'
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall RiskNoX Agent.lnk" "$INSTDIR\uninst.exe"
  !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

Section -Post
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninst.exe"
  
  ; Registry entries for application
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "Path" "$INSTDIR"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "Version" "${PRODUCT_VERSION}"
  
  ; Uninstall registry entries
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME} v${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "HelpLink" "${PRODUCT_SUPPORT_URL}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "InstallDate" "$2$1$0"
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoModify" 1
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoRepair" 1
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "VersionMajor" 1
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "VersionMinor" 0
  
  ; Calculate installed size
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
  
  ; Create logs directory with proper structure
  CreateDirectory "$INSTDIR\logs"
  CreateDirectory "$INSTDIR\logs\archives"
  
  ; Set file permissions using icacls (built-in Windows tool)
  DetailPrint "Setting file permissions for service operation..."
  ; Grant SYSTEM account full access
  ExecWait 'icacls "$INSTDIR" /grant "SYSTEM:(OI)(CI)F" /T /Q' $0
  ; Grant Administrators full access  
  ExecWait 'icacls "$INSTDIR" /grant "Administrators:(OI)(CI)F" /T /Q' $0
  ; Grant Users read and execute access
  ExecWait 'icacls "$INSTDIR" /grant "Users:(OI)(CI)RX" /T /Q' $0
  
  ; Create Windows Event Log source for proper logging
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}" "EventMessageFile" "$INSTDIR\monitoring-agent.exe"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}" "TypesSupported" 7
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}" "CategoryMessageFile" "$INSTDIR\monitoring-agent.exe"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}" "CategoryCount" 3
  
  ; Create installation completion marker with timestamp
  FileOpen $0 "$INSTDIR\.installation-complete" w
  FileWrite $0 "Installation completed at $(^Date) $(^Time)$\r$\n"
  FileWrite $0 "Version: ${PRODUCT_VERSION}$\r$\n"
  FileWrite $0 "PowerShell Path: $pwsh7_path$\r$\n"
  FileWrite $0 "Installation Directory: $INSTDIR$\r$\n"
  FileWrite $0 "Suricata Selected: $suricata_selected$\r$\n"
  FileWrite $0 "Upgrade Installation: $is_upgrade$\r$\n"
  FileClose $0
SectionEnd

;--------------------------------
; Section Descriptions (Wazuh-style detailed descriptions)

; Language strings for comprehensive component descriptions
LangString DESC_SecCore ${LANG_ENGLISH} "Core monitoring agent that provides file integrity monitoring, log analysis, rootkit detection, and central management capabilities. This component is required and cannot be deselected."

LangString DESC_SecConfig ${LANG_ENGLISH} "Configuration management system that handles agent settings, service configuration, and runtime parameters. Includes configuration files and management utilities."

LangString DESC_SecSupervisor ${LANG_ENGLISH} "Service supervisor system that manages and monitors all agent processes. Provides process management, automatic restart capabilities, and service protection features."

LangString DESC_SecTools ${LANG_ENGLISH} "Comprehensive management tools and utilities including PowerShell scripts for installation, configuration, monitoring, and maintenance. Includes NSSM service manager."

LangString DESC_SecActiveResponse ${LANG_ENGLISH} "Active response system for automated threat response and mitigation. Enables the agent to automatically respond to security events and take protective actions."

LangString DESC_SecShared ${LANG_ENGLISH} "Shared resources and libraries including detection databases, configuration templates, and common utilities used by multiple components."

LangString DESC_SecRuleset ${LANG_ENGLISH} "Complete detection rules and decoders for log analysis, security event detection, and compliance monitoring. Includes CIS benchmarks and security policies."

LangString DESC_SecQueue ${LANG_ENGLISH} "Message queue system for event processing and data handling. Manages communication between agent components and event storage."

LangString DESC_SecState ${LANG_ENGLISH} "State management system that tracks agent runtime state, process status, and operational data. Ensures proper agent functionality and recovery."

LangString DESC_SecRids ${LANG_ENGLISH} "Registry and identification system for agent registration, authentication, and unique identification within the monitoring infrastructure."

LangString DESC_SecSuricata ${LANG_ENGLISH} "Advanced network intrusion detection and prevention system. Monitors network traffic for malicious activity, security threats, and policy violations. Automatically starts after installation when selected."

LangString DESC_SecNpcap ${LANG_ENGLISH} "Network packet capture library required for network monitoring and Suricata IDS functionality. Provides low-level network access capabilities."

LangString DESC_SecVendor ${LANG_ENGLISH} "Third-party vendor libraries and dependencies including antivirus engines, security tools, and external security components."

LangString DESC_SecSamples ${LANG_ENGLISH} "Sample configuration files, templates, and examples for customizing agent behavior and testing different monitoring scenarios."

LangString DESC_SecBuild ${LANG_ENGLISH} "Build system and development tools for customizing and extending the monitoring agent. Includes development utilities and build scripts (optional for most users)."

; Assign language strings to sections with enhanced descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecConfig} $(DESC_SecConfig)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSupervisor} $(DESC_SecSupervisor)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTools} $(DESC_SecTools)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecActiveResponse} $(DESC_SecActiveResponse)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShared} $(DESC_SecShared)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRuleset} $(DESC_SecRuleset)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecQueue} $(DESC_SecQueue)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecState} $(DESC_SecState)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRids} $(DESC_SecRids)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSuricata} $(DESC_SecSuricata)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecNpcap} $(DESC_SecNpcap)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecVendor} $(DESC_SecVendor)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSamples} $(DESC_SecSamples)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecBuild} $(DESC_SecBuild)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
; Uninstaller Functions (Enhanced Wazuh-style)

Function un.onInit
  ; Check administrator privileges
  UserInfo::GetAccountType
  pop $0
  ${If} $0 != "admin"
    MessageBox MB_ICONSTOP "Administrator privileges required for uninstallation!$\r$\n$\r$\nPlease right-click and select 'Run as administrator'."
    SetErrorLevel 740
    Quit
  ${EndIf}
  
  ; Confirmation with detailed information
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove ${PRODUCT_NAME} and all of its components?$\r$\n$\r$\nThis will remove:$\r$\n• All monitoring agent files$\r$\n• Service configuration$\r$\n• Log files and data$\r$\n• Registry entries$\r$\n• Start Menu shortcuts$\r$\n$\r$\nThis action cannot be undone." IDYES +2
  Abort
FunctionEnd

Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "${PRODUCT_NAME} was successfully removed from your computer.$\r$\n$\r$\nAll components have been uninstalled and the system has been cleaned."
FunctionEnd

;--------------------------------
; Uninstaller Section (Comprehensive cleanup)

Section Uninstall
  ; Stop Suricata if it's running
  IfFileExists "$INSTDIR\suricata\SuricataControl.ps1" 0 SkipSuricataStop
    DetailPrint "Stopping Suricata Network IDS..."
    nsExec::ExecToLog 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$INSTDIR\suricata\SuricataControl.ps1" stop'
    Pop $0
    ${If} $0 == 0
      DetailPrint "Suricata stopped successfully"
    ${Else}
      DetailPrint "Suricata stop completed (exit code: $0)"
    ${EndIf}
    Sleep 2000
  SkipSuricataStop:

  ; Stop and remove service using PowerShell 7 if available, fallback to PowerShell 5.1
  DetailPrint "Stopping and removing RiskNoX service..."
  
  ; Try to find PowerShell 7 for uninstallation
  StrCpy $1 ""
  IfFileExists "$PROGRAMFILES\PowerShell\7\pwsh.exe" 0 check_pf86_uninstall
  StrCpy $1 "$PROGRAMFILES\PowerShell\7\pwsh.exe"
  Goto run_uninstall_service
  
  check_pf86_uninstall:
  IfFileExists "${PROGRAMFILES32}\PowerShell\7\pwsh.exe" 0 check_windowsapps_uninstall
  StrCpy $1 "${PROGRAMFILES32}\PowerShell\7\pwsh.exe"
  Goto run_uninstall_service
  
  check_windowsapps_uninstall:
  IfFileExists "$LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe" 0 fallback_powershell_uninstall
  StrCpy $1 "$LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe"
  Goto run_uninstall_service
  
  fallback_powershell_uninstall:
  StrCpy $1 "powershell.exe"
  
  run_uninstall_service:
  ExecWait '"$1" -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" uninstall' $0
  ${If} $0 == 0
    DetailPrint "Service uninstalled successfully"
  ${Else}
    DetailPrint "Service uninstall completed with code: $0"
  ${EndIf}

  ; Ensure processes are not running
  DetailPrint "Checking for running processes..."
  
  ; Check and terminate running processes using taskkill
  DetailPrint "Checking for running agent processes..."
  
  ; Terminate manage_agents.exe
  ExecWait 'tasklist /FI "IMAGENAME eq manage_agents.exe" 2>NUL | find /I /N "manage_agents.exe"' $0
  ${If} $0 = 0
    DetailPrint "Terminating manage_agents.exe..."
    ExecWait 'taskkill /F /IM "manage_agents.exe" /T' $0
    Sleep 1000
  ${EndIf}
  
  ; Terminate win32ui.exe  
  ExecWait 'tasklist /FI "IMAGENAME eq win32ui.exe" 2>NUL | find /I /N "win32ui.exe"' $0
  ${If} $0 = 0
    DetailPrint "Terminating win32ui.exe..."
    ExecWait 'taskkill /F /IM "win32ui.exe" /T' $0
    Sleep 1000
  ${EndIf}
  
  ; Terminate monitoring-agent.exe
  ExecWait 'tasklist /FI "IMAGENAME eq monitoring-agent.exe" 2>NUL | find /I /N "monitoring-agent.exe"' $0
  ${If} $0 = 0
    DetailPrint "Terminating monitoring-agent.exe..."
    ExecWait 'taskkill /F /IM "monitoring-agent.exe" /T' $0
    Sleep 1000
  ${EndIf}

  ; Remove ALL files systematically
  DetailPrint "Removing application files..."
  
  ; Remove main executable files
  Delete "$INSTDIR\*.exe"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\*.py"
  Delete "$INSTDIR\*.ps1"
  Delete "$INSTDIR\*.bat"
  Delete "$INSTDIR\*.conf"
  Delete "$INSTDIR\*.txt"
  Delete "$INSTDIR\*.json"
  Delete "$INSTDIR\*.pem"
  Delete "$INSTDIR\*.state"
  Delete "$INSTDIR\*.log"
  Delete "$INSTDIR\*.template"
  Delete "$INSTDIR\*.md"
  Delete "$INSTDIR\*.pid"
  Delete "$INSTDIR\*.yaml"
  Delete "$INSTDIR\*.yml"
  Delete "$INSTDIR\*.mgc"
  Delete "$INSTDIR\*.*"

  ; Remove ALL directories comprehensively
  DetailPrint "Removing component directories..."
  RMDir /r "$INSTDIR\active-response"
  RMDir /r "$INSTDIR\backup_*"
  RMDir /r "$INSTDIR\bookmarks"  
  RMDir /r "$INSTDIR\build"
  RMDir /r "$INSTDIR\config"
  RMDir /r "$INSTDIR\dist"
  RMDir /r "$INSTDIR\incoming"
  RMDir /r "$INSTDIR\logs"
  RMDir /r "$INSTDIR\npcap"
  RMDir /r "$INSTDIR\queue"
  RMDir /r "$INSTDIR\rids"
  RMDir /r "$INSTDIR\ruleset"
  RMDir /r "$INSTDIR\samples"
  RMDir /r "$INSTDIR\shared"
  RMDir /r "$INSTDIR\state"
  RMDir /r "$INSTDIR\supervisor"
  RMDir /r "$INSTDIR\suricata"
  RMDir /r "$INSTDIR\tmp"
  RMDir /r "$INSTDIR\tools"
  RMDir /r "$INSTDIR\upgrade"
  RMDir /r "$INSTDIR\vendor"
  RMDir /r "$INSTDIR\wodles"

  ; Remove uninstaller
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\.installation-complete"

  ; Remove shortcuts comprehensively
  DetailPrint "Removing shortcuts..."
  !insertmacro MUI_STARTMENU_GETFOLDER "Application" $StartMenuFolder
  Delete "$SMPROGRAMS\$StartMenuFolder\*.*"
  RMDir "$SMPROGRAMS\$StartMenuFolder"
  
  ; Remove any additional shortcuts that might exist
  Delete "$SMPROGRAMS\RiskNoX Monitoring Agent\*.*"
  RMDir "$SMPROGRAMS\RiskNoX Monitoring Agent"

  ; Clean registry entries completely
  DetailPrint "Cleaning registry entries..."
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}"
  DeleteRegKey HKLM "SOFTWARE\RiskNoX"
  DeleteRegKey HKLM "SOFTWARE\${PRODUCT_PUBLISHER}"

  ; Remove installation directories
  DetailPrint "Removing installation directory..."
  RMDir "$INSTDIR"
  RMDir "$PROGRAMFILES64\RiskNoX"
  
  ; Final cleanup - remove any leftover files
  RMDir /r "$APPDATA\RiskNoX"
  RMDir /r "$LOCALAPPDATA\RiskNoX"

  SetAutoClose true
  DetailPrint "Uninstallation completed successfully"
SectionEnd