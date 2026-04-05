; Unified Security Agent Installer
; RiskNoX Monitoring Agent + Suricata IDS + Supervisor Service
; Auto-installs and starts all services after installation

!define PRODUCT_NAME "Unified Security Agent"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "RiskNoX Security"
!define PRODUCT_WEB_SITE "https://risknox.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\monitoring-agent.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; Modern UI
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "WinVer.nsh"

; Variables
Var pwsh7_path

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "install.ico"
!define MUI_UNICON "uninstall.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP_NOSTRETCH
!define MUI_WELCOMEFINISHPAGE_BITMAP_NOSTRETCH

; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page  
!insertmacro MUI_PAGE_LICENSE "LICENSE"

; Components page
!insertmacro MUI_PAGE_COMPONENTS

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Instfiles page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Start Unified Security Agent Service"
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchServiceStart"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "RisknoxSecurityAgent-${PRODUCT_VERSION}-Setup.exe"
InstallDir "$PROGRAMFILES64\RiskNoX\RiskNoXSecurityAgent"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin

; Version Information
VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "FileDescription" "Unified Security Agent Installer"
VIAddVersionKey "LegalCopyright" "© 2025 ${PRODUCT_PUBLISHER}"

; Check if running as administrator
Function .onInit
  UserInfo::GetAccountType
  pop $0
  ${If} $0 != "admin"
    MessageBox MB_ICONSTOP "Administrator rights required! Please run as Administrator."
    SetErrorLevel 740 ;ERROR_ELEVATION_REQUIRED
    Quit
  ${EndIf}
  
  ; Check Windows version
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "This software requires Windows 10 or later."
    Abort
  ${EndIf}
  
  ; Detect PowerShell 7
  Call DetectPowerShell7
FunctionEnd

; Detect PowerShell 7 installation
Function DetectPowerShell7
  ClearErrors
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\31ab5147-9a97-4452-8443-d9709f0516e1" "InstallLocation"
  ${If} ${Errors}
    ; Try alternative detection
    ${If} ${FileExists} "$PROGRAMFILES\PowerShell\7\pwsh.exe"
      StrCpy $pwsh7_path "$PROGRAMFILES\PowerShell\7\pwsh.exe"
    ${ElseIf} ${FileExists} "C:\Program Files\PowerShell\7\pwsh.exe"
      StrCpy $pwsh7_path "C:\Program Files\PowerShell\7\pwsh.exe"
    ${Else}
      ; Fall back to Windows PowerShell 5.1
      StrCpy $pwsh7_path "powershell.exe"
      DetailPrint "PowerShell 7 not found, using Windows PowerShell 5.1"
    ${EndIf}
  ${Else}
    StrCpy $pwsh7_path "$0\pwsh.exe"
    DetailPrint "Found PowerShell 7 at: $pwsh7_path"
  ${EndIf}
FunctionEnd

; Stop existing service before installation
Function StopExistingService
  DetailPrint "Checking for existing RiskNoX services..."
  
  ; Use sc command to check if service exists and stop it
  ExecWait '"sc" query "RiskNoXSupervisor"' $0
  ${If} $0 = 0
    DetailPrint "Found existing service, stopping..."
    ExecWait '"sc" stop "RiskNoXSupervisor"' $0
    ${If} $0 = 0
      DetailPrint "Service stopped successfully"
    ${Else}
      DetailPrint "Service stop returned code: $0 (may already be stopped)"
    ${EndIf}
    ; Wait a moment for service to fully stop
    Sleep 3000
  ${Else}
    DetailPrint "No existing service found"
  ${EndIf}
FunctionEnd

; Launch service installation and start after installation
Function LaunchServiceStart
  DetailPrint "Launching Unified Security Agent service installation and startup..."
  
  ${If} $pwsh7_path != ""
    ${If} $pwsh7_path == "powershell.exe"
      ; Using Windows PowerShell 5.1
      ExecWait '"$pwsh7_path" -WindowStyle Normal -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" install' $0
    ${Else}
      ; Using PowerShell 7
      ExecWait '"$pwsh7_path" -WindowStyle Normal -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" install' $0
    ${EndIf}
    
    ${If} $0 != 0
      MessageBox MB_ICONEXCLAMATION "Service installation encountered issues (exit code: $0).$\r$\n$\r$\nPlease check the logs in the installation directory and run the installation manually if needed.$\r$\n$\r$\nTo install manually:$\r$\n1. Open PowerShell as Administrator$\r$\n2. Navigate to: $INSTDIR$\r$\n3. Run: .\RiskNoXServiceControl.ps1 install"
    ${Else}
      DetailPrint "Service installation completed successfully"
      
      ; Now start the service
      DetailPrint "Starting Unified Security Agent service..."
      ${If} $pwsh7_path == "powershell.exe"
        ExecWait '"$pwsh7_path" -WindowStyle Normal -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" start -Password "RiskNoX@2024"' $1
      ${Else}
        ExecWait '"$pwsh7_path" -WindowStyle Normal -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" start -Password "RiskNoX@2024"' $1
      ${EndIf}
      
      ${If} $1 != 0
        MessageBox MB_ICONEXCLAMATION "Service start encountered issues (exit code: $1).$\r$\n$\r$\nTo start manually:$\r$\n1. Open PowerShell as Administrator$\r$\n2. Navigate to: $INSTDIR$\r$\n3. Run: .\RiskNoXServiceControl.ps1 start -Password RiskNoX@2024"
      ${Else}
        MessageBox MB_ICONINFORMATION "Unified Security Agent installed and started successfully!$\r$\n$\r$\nManaged Services:$\r$\n• Monitoring Agent$\r$\n• Suricata Network IDS$\r$\n$\r$\nTo manage: Open PowerShell as Admin and navigate to $INSTDIR"
      ${EndIf}
    ${EndIf}
  ${Else}
    MessageBox MB_ICONSTOP "PowerShell not detected. Cannot start service automatically."
  ${EndIf}
FunctionEnd

; Core Components Section (Required)
Section "Core Security Agent (Required)" SecCore
  SectionIn RO
  
  Call StopExistingService
  
  SetOutPath "$INSTDIR"
  SetOverwrite on
  
  DetailPrint "Installing core monitoring agent..."
  
  ; Main executables
  File "monitoring-agent.exe"
  File /nonfatal "monitoring-agent.exe.manifest"
  File "agent-auth.exe"
  File "manage_agents.exe"
  File "win32ui.exe"
  File /nonfatal "manage_agents.exe.manifest"
  File /nonfatal "MonitoringAgentService.exe"
  
  ; Core PowerShell management scripts
  File "RiskNoXServiceControl.ps1"
  File "UnifiedAgentControl.ps1"
  
  ; All DLL libraries
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
  
  ; Configuration files
  File "ossec.conf"
  File "internal_options.conf"
  File "local_internal_options.conf"
  File "wpk_root.pem"
  File "VERSION.json"
  File "README.md"
  
  ; Icon files
  File "favicon.ico"
  File "install.ico"
  File "uninstall.ico"
  
  ; Calculate and log installation time
  ${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
  FileOpen $7 "$INSTDIR\install.log" w
  FileWrite $7 "Unified Security Agent installed on $2-$1-$0 at $4:$5:$6$\r$\n"
  FileWrite $7 "Version: ${PRODUCT_VERSION}$\r$\n"
  FileWrite $7 "Components: Monitoring Agent, Suricata IDS, Supervisor Service$\r$\n"
  FileClose $7
SectionEnd

; Configuration System
Section "Configuration System" SecConfig
  SetOutPath "$INSTDIR\config"
  File "config\services.yml"
  File "config\settings.json"
  File "config\process_inventory.json"
  File /nonfatal "config\supervisor_token.txt"
  File /nonfatal "config\.service_password"
SectionEnd

; Service Supervisor
Section "Service Supervisor" SecSupervisor
  SetOutPath "$INSTDIR\supervisor"
  File "supervisor\supervisor.py"
  File "supervisor\supervisor.spec"
  File "supervisor\requirements.txt"
  File "supervisor\remote_control_auth.py"
  
  SetOutPath "$INSTDIR\dist"
  File "dist\supervisor.exe"
  
  ; Create supervisor directory structure
  CreateDirectory "$INSTDIR\dist\logs"
  CreateDirectory "$INSTDIR\dist\state"
  CreateDirectory "$INSTDIR\logs"
SectionEnd

; Management Tools
Section "Management Tools and Utilities" SecTools
  SetOutPath "$INSTDIR\tools"
  
  ; All PowerShell tool scripts
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
  
  ; NSSM Service Manager
  SetOutPath "$INSTDIR\tools\nssm\win64"
  File "tools\nssm\win64\nssm.exe"
  
  SetOutPath "$INSTDIR\tools\nssm\win32"
  File "tools\nssm\win32\nssm.exe"
SectionEnd

; Active Response System
Section "Active Response System" SecActiveResponse
  SetOutPath "$INSTDIR\active-response\bin"
  File "active-response\bin\netsh.exe"
  File "active-response\bin\restart-monitoring.exe"
  File "active-response\bin\route-null.exe"
  
  ; Create active response log
  FileOpen $0 "$INSTDIR\active-response\active-responses.log" w
  FileClose $0
SectionEnd

; Shared Resources
Section "Shared Resources and Libraries" SecShared
  SetOutPath "$INSTDIR\shared"
  File "shared\agent.conf"
  File "shared\ar.conf"
  File "shared\cis_apache2224_rcl.txt"
  File "shared\cis_debian_linux_rcl.txt"
  File "shared\cis_mysql5-6_community_rcl.txt"
  File "shared\cis_mysql5-6_enterprise_rcl.txt"
  File "shared\cis_rhel_linux_rcl.txt"
  File "shared\cis_rhel5_linux_rcl.txt"
  File "shared\cis_rhel6_linux_rcl.txt"
  File "shared\cis_rhel7_linux_rcl.txt"
  File "shared\cis_sles11_linux_rcl.txt"
  File "shared\cis_sles12_linux_rcl.txt"
  File "shared\cis_win2012r2_domainL1_rcl.txt"
  File "shared\cis_win2012r2_domainL2_rcl.txt"
  File "shared\cis_win2012r2_memberL1_rcl.txt"
  File "shared\cis_win2012r2_memberL2_rcl.txt"
  File "shared\merged.mg"
  File "shared\rootkit_files.txt"
  File "shared\rootkit_trojans.txt"
  File "shared\system_audit_rcl.txt"
  File "shared\system_audit_ssh.txt"
  File "shared\win_applications_rcl.txt"
  File "shared\win_audit_rcl.txt"
  File "shared\win_malware_rcl.txt"
SectionEnd

; Detection Ruleset
Section "Detection Rules and Decoders" SecRuleset
  SetOutPath "$INSTDIR\ruleset\sca"
  File "ruleset\sca\cis_win11_enterprise.yml"
SectionEnd

; Suricata Network IDS
Section "Suricata Network IDS" SecSuricata
  DetailPrint "Installing Suricata Network IDS..."
  
  ; Suricata control script
  SetOutPath "$INSTDIR\suricata"
  File "suricata\SuricataControl.ps1"
  
  ; Suricata executable and binaries
  SetOutPath "$INSTDIR\suricata\bin"
  File "suricata\bin\suricata.exe"
  File "suricata\bin\batch.bat"
  File "suricata\bin\LICENSE"
  File "suricata\bin\magic.mgc"
  
  ; All Suricata DLL dependencies
  File "suricata\bin\libGeoIP-1.dll"
  File "suricata\bin\libjansson-4.dll"
  File "suricata\bin\liblz4.dll"
  File "suricata\bin\liblzma-5.dll"
  File "suricata\bin\libmaxminddb-0.dll"
  File "suricata\bin\libnspr4.dll"
  File "suricata\bin\libpcre-1.dll"
  File "suricata\bin\libpcre2-8-0.dll"
  File "suricata\bin\libplc4.dll"
  File "suricata\bin\libplds4.dll"
  File "suricata\bin\libssp-0.dll"
  File "suricata\bin\libwinpthread-1.dll"
  File "suricata\bin\libyaml-0-2.dll"
  File "suricata\bin\msvcrt.dll"
  File "suricata\bin\nss3.dll"
  File "suricata\bin\nssutil3.dll"
  File "suricata\bin\packet.dll"
  File "suricata\bin\WinDivert.dll"
  File "suricata\bin\wpcap.dll"
  File "suricata\bin\zlib1.dll"
  
  ; Include any remaining files in bin directory
  File /nonfatal /r "suricata\bin\*.*"
  
  ; Suricata configuration
  SetOutPath "$INSTDIR\suricata\etc"
  File /r "suricata\etc\*.*"
  
  ; Suricata rules
  SetOutPath "$INSTDIR\suricata\rules"
  File /r "suricata\rules\*.*"
  
  ; Create Suricata directories
  CreateDirectory "$INSTDIR\suricata\log"
  CreateDirectory "$INSTDIR\suricata\cache\sgh"
SectionEnd

; Queue System
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
SectionEnd

; State Management
Section "State Management System" SecState
  CreateDirectory "$INSTDIR\state"
  CreateDirectory "$INSTDIR\state\global"
  CreateDirectory "$INSTDIR\state\agents"
SectionEnd

; Create Start Menu shortcuts
Section -AdditionalIcons
  WriteIniStr "$INSTDIR\${PRODUCT_NAME}.url" "InternetShortcut" "URL" "${PRODUCT_WEB_SITE}"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\monitoring-agent.exe" "" "$INSTDIR\favicon.ico"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Service Control.lnk" "powershell.exe" '-ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" status' "$INSTDIR\favicon.ico"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Website.lnk" "$INSTDIR\${PRODUCT_NAME}.url" "" "$INSTDIR\favicon.ico"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "$INSTDIR\uninstall.ico"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\README.lnk" "$INSTDIR\README.md" "" "$INSTDIR\favicon.ico"
SectionEnd

; Create registry entries
Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\favicon.ico"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd

; Component descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core monitoring agent executables and libraries (Required)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecConfig} "Configuration system for services and supervisor"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSupervisor} "Service supervisor for process management"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTools} "Management tools and PowerShell utilities"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecActiveResponse} "Active response system for automated security actions"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShared} "Shared resources and security rule libraries"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRuleset} "Detection rules and compliance checks"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSuricata} "Suricata Network Intrusion Detection System"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecQueue} "Message queue system for agent communication"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecState} "State management system for persistent data"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Uninstaller
Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  ; Stop service first
  DetailPrint "Stopping Unified Security Agent service..."
  ExecWait '"sc" stop "RiskNoXSupervisor"' $0
  Sleep 3000
  
  ; Remove service
  ExecWait '"sc" delete "RiskNoXSupervisor"' $0
  
  ; Remove files and directories
  Delete "$INSTDIR\${PRODUCT_NAME}.url"
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\install.log"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\VERSION.json"
  Delete "$INSTDIR\wpk_root.pem"
  Delete "$INSTDIR\ossec.conf"
  Delete "$INSTDIR\internal_options.conf"
  Delete "$INSTDIR\local_internal_options.conf"
  Delete "$INSTDIR\favicon.ico"
  Delete "$INSTDIR\install.ico"
  Delete "$INSTDIR\uninstall.ico"
  Delete "$INSTDIR\*.exe"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\*.ps1"
  Delete "$INSTDIR\*.manifest"
  
  RMDir /r "$INSTDIR\active-response"
  RMDir /r "$INSTDIR\config"
  RMDir /r "$INSTDIR\dist"
  RMDir /r "$INSTDIR\logs"
  RMDir /r "$INSTDIR\queue"
  RMDir /r "$INSTDIR\ruleset"
  RMDir /r "$INSTDIR\shared"
  RMDir /r "$INSTDIR\state"
  RMDir /r "$INSTDIR\supervisor"
  RMDir /r "$INSTDIR\suricata"
  RMDir /r "$INSTDIR\tools"
  
  RMDir "$INSTDIR"
  
  ; Remove Start Menu entries
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Website.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Service Control.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\README.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  
  ; Remove registry entries
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd