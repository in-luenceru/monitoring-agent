; RiskNoX Monitoring Agent - Practical Installer
; NSIS Script that only includes essential files and uses nonfatal for others

!define PRODUCT_NAME "RiskNoX Monitoring Agent"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "RiskNoX Solutions"
!define PRODUCT_WEB_SITE "https://risknox.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\monitoring-agent.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"
!define SERVICE_NAME "RiskNoXAgent"

; MUI Settings
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"
!include "x64.nsh"

;--------------------------------
; Variables
Var StartMenuFolder
Var is_upgrade
Var pwsh7_path
Var suricata_selected

;--------------------------------
; Installer General Settings
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "RiskNoX-Agent-Practical.exe"
InstallDir "$PROGRAMFILES64\RiskNoX Agent"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin

;--------------------------------
; Interface Settings  
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Header image
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\nsis3-branding.bmp"

; Welcome/Finish page images
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\nsis3-branding.bmp"

;--------------------------------
; Pages
!define MUI_WELCOMEPAGE_TITLE "Welcome to RiskNoX Monitoring Agent Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of RiskNoX Monitoring Agent.$\r$\n$\r$\nRiskNoX provides comprehensive endpoint monitoring and security for your Windows systems.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "RiskNoX Agent Installation Complete"
!define MUI_FINISHPAGE_TEXT "RiskNoX Monitoring Agent has been successfully installed.$\r$\n$\r$\nThe service will start automatically and begin monitoring your system."
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
; Languages
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; PowerShell 7 Detection Function
Function DetectPowerShell7
  DetailPrint "Detecting PowerShell 7 installation..."
  
  ; Check Program Files first
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
  IfFileExists "$LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe" 0 fallback_powershell
  StrCpy $pwsh7_path "$LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe"
  DetailPrint "Found PowerShell 7 at: $pwsh7_path"
  Return
  
  fallback_powershell:
  DetailPrint "PowerShell 7 not found, using Windows PowerShell"
  StrCpy $pwsh7_path "powershell.exe"
FunctionEnd

;--------------------------------
; Stop existing service function
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
FunctionEnd

;--------------------------------
; Main Installation Section
Section "Core Agent Components" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"
  
  ; Stop any existing service first
  Call StopExistingService
  
  ; Core executable files (only if they exist)
  File /nonfatal "monitoring-agent.exe"
  File /nonfatal "monitoring-agent-original.exe"
  File /nonfatal "monitoring-agent-eventchannel.exe"
  File /nonfatal "MonitoringAgentService.exe"
  File /nonfatal "agent-auth.exe"
  File /nonfatal "manage_agents.exe"
  File /nonfatal "win32ui.exe"
  
  ; Python backend services
  File /nonfatal "backend_server.py"
  File /nonfatal "service_control_backend.py"
  File /nonfatal "agent_poll.py"
  
  ; PowerShell management scripts
  File /nonfatal "RiskNoXServiceControl.ps1"
  File /nonfatal "UnifiedAgentControl.ps1"
  File /nonfatal "RiskNoX-Control.ps1"
  File /nonfatal "MonitoringAgentControl.ps1"
  File /nonfatal "RiskNoX-Agent-Installer.ps1"
  File /nonfatal "MonitoringAgentAutoStart.ps1"
  File /nonfatal "RobustAutoStart.ps1"
  File /nonfatal "SetupAutoStartup.ps1"
  
  ; Additional utility scripts
  File /nonfatal "change-password.ps1"
  File /nonfatal "test-password-protection.ps1"
  File /nonfatal "test-web-blocking.ps1"
  
  ; DLL libraries
  File /nonfatal "dbsync.dll"
  File /nonfatal "libfimdb.dll"
  File /nonfatal "libwazuhext.dll"
  File /nonfatal "libwazuhshared.dll"
  File /nonfatal "syscollector.dll"
  File /nonfatal "sysinfo.dll"
  File /nonfatal "libgcc_s_dw2-1.dll"
  File /nonfatal "libstdc++-6.dll"
  File /nonfatal "libwinpthread-1.dll"
  File /nonfatal "rsync.dll"
  
  ; Configuration files
  File /nonfatal "ossec.conf"
  File /nonfatal "ossec.conf.original"
  File /nonfatal "ossec.conf.new"
  File /nonfatal "internal_options.conf"
  File /nonfatal "local_internal_options.conf"
  File /nonfatal "vista_sec.txt"
  File /nonfatal "wpk_root.pem"
  File /nonfatal "VERSION.json"
  File /nonfatal "profile-10.template"
  
  ; Batch and startup files
  File /nonfatal "auto-start-wrapper.bat"
  File /nonfatal "InstallAndStart-RiskNoX.bat"
  
  ; Documentation
  File /nonfatal "help.txt"
  File /nonfatal "help.txt.original"
  File /nonfatal "ReadMe.txt"
  File /nonfatal "changes.txt"
  File /nonfatal "INSTALLATION-GUIDE.md"
  
  ; License file (required)
  IfFileExists "LICENSE" 0 no_license
  File "LICENSE"
  Goto after_license
  
  no_license:
  ; Create a basic license file if none exists
  FileOpen $0 "$INSTDIR\LICENSE" w
  FileWrite $0 "RiskNoX Monitoring Agent License$\r$\n"
  FileWrite $0 "All rights reserved.$\r$\n"
  FileClose $0
  
  after_license:
  
  ; Create directory structure
  CreateDirectory "$INSTDIR\logs"
  CreateDirectory "$INSTDIR\logs\archives"
  CreateDirectory "$INSTDIR\config"
  CreateDirectory "$INSTDIR\tools"
  CreateDirectory "$INSTDIR\state"
  CreateDirectory "$INSTDIR\queue"
  CreateDirectory "$INSTDIR\rids"
  CreateDirectory "$INSTDIR\temp"
  
  ; Set file permissions using icacls
  DetailPrint "Setting file permissions for service operation..."
  ExecWait 'icacls "$INSTDIR" /grant "SYSTEM:(OI)(CI)F" /T /Q' $0
  ExecWait 'icacls "$INSTDIR" /grant "Administrators:(OI)(CI)F" /T /Q' $0
  ExecWait 'icacls "$INSTDIR" /grant "Users:(OI)(CI)RX" /T /Q' $0
  
  ; Create Windows Event Log source
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}" "EventMessageFile" "$INSTDIR\monitoring-agent.exe"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}" "TypesSupported" 7
  
  ; Create installation completion marker
  FileOpen $0 "$INSTDIR\.installation-complete" w
  FileWrite $0 "Installation completed at $(^Date) $(^Time)$\r$\n"
  FileWrite $0 "Version: ${PRODUCT_VERSION}$\r$\n"
  FileWrite $0 "PowerShell Path: $pwsh7_path$\r$\n"
  FileWrite $0 "Installation Directory: $INSTDIR$\r$\n"
  FileClose $0
  
  ; Write registry entries
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

;--------------------------------
; Service Installation Section
Section "Windows Service" SecService
  Call DetectPowerShell7
  DetailPrint "Installing RiskNoX monitoring service..."
  
  ; Install service using PowerShell script if available, otherwise use sc
  IfFileExists "$INSTDIR\RiskNoXServiceControl.ps1" 0 use_sc_command
  
  DetailPrint "Using PowerShell service installation..."
  ExecWait '"$pwsh7_path" -ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1" install' $0
  ${If} $0 = 0
    DetailPrint "Service installed successfully via PowerShell"
  ${Else}
    DetailPrint "PowerShell service installation failed, trying sc command..."
    Goto use_sc_command
  ${EndIf}
  Goto service_done
  
  use_sc_command:
  DetailPrint "Using sc command for service installation..."
  ExecWait '"sc" create "${SERVICE_NAME}" binPath= "$INSTDIR\monitoring-agent.exe" start= auto DisplayName= "${PRODUCT_NAME}"' $0
  ${If} $0 = 0
    DetailPrint "Service installed successfully"
    ExecWait '"sc" start "${SERVICE_NAME}"' $0
    DetailPrint "Service start result: $0"
  ${Else}
    DetailPrint "Service installation failed with error: $0"
  ${EndIf}
  
  service_done:
SectionEnd

;--------------------------------
; Optional Components Section  
Section "Suricata Network IDS" SecSuricata
  StrCpy $suricata_selected "true"
  SetOutPath "$INSTDIR\suricata"
  
  ; Include Suricata files if they exist
  File /nonfatal /r "suricata\*"
  
  DetailPrint "Suricata Network IDS installed"
SectionEnd

Section "Management Tools" SecTools
  SetOutPath "$INSTDIR\tools"
  
  ; Include management tools
  File /nonfatal /r "tools\*"
  
  DetailPrint "Management tools installed"
SectionEnd

;--------------------------------
; Start Menu Section
Section "Start Menu Shortcuts" SecShortcuts
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
  CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\RiskNoX Agent.lnk" "$INSTDIR\monitoring-agent.exe"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Agent Management.lnk" "$INSTDIR\manage_agents.exe"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Service Control.lnk" "$pwsh7_path" '-ExecutionPolicy Bypass -File "$INSTDIR\RiskNoXServiceControl.ps1"'
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

;--------------------------------
; Uninstaller Section
Section Uninstall
  ; Stop and remove service
  DetailPrint "Stopping and removing RiskNoX service..."
  ExecWait '"sc" stop "${SERVICE_NAME}"' $0
  Sleep 2000
  ExecWait '"sc" delete "${SERVICE_NAME}"' $0
  
  ; Terminate any running processes
  DetailPrint "Checking for running agent processes..."
  
  ExecWait 'tasklist /FI "IMAGENAME eq monitoring-agent.exe" 2>NUL | find /I /N "monitoring-agent.exe"' $0
  ${If} $0 = 0
    DetailPrint "Terminating monitoring-agent.exe..."
    ExecWait 'taskkill /F /IM "monitoring-agent.exe" /T' $0
  ${EndIf}
  
  ExecWait 'tasklist /FI "IMAGENAME eq manage_agents.exe" 2>NUL | find /I /N "manage_agents.exe"' $0
  ${If} $0 = 0
    DetailPrint "Terminating manage_agents.exe..."
    ExecWait 'taskkill /F /IM "manage_agents.exe" /T' $0
  ${EndIf}
  
  ; Remove files
  Delete "$INSTDIR\*.exe"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\*.py"
  Delete "$INSTDIR\*.ps1"
  Delete "$INSTDIR\*.bat"
  Delete "$INSTDIR\*.conf"
  Delete "$INSTDIR\*.txt"
  Delete "$INSTDIR\*.json"
  Delete "$INSTDIR\*.pem"
  Delete "$INSTDIR\*.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\.installation-complete"
  
  ; Remove directories
  RMDir /r "$INSTDIR\logs"
  RMDir /r "$INSTDIR\config"
  RMDir /r "$INSTDIR\tools"
  RMDir /r "$INSTDIR\state"
  RMDir /r "$INSTDIR\queue"
  RMDir /r "$INSTDIR\rids"
  RMDir /r "$INSTDIR\temp"
  RMDir /r "$INSTDIR\suricata"
  RMDir "$INSTDIR"
  
  ; Remove shortcuts
  !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
  Delete "$SMPROGRAMS\$StartMenuFolder\*.lnk"
  RMDir "$SMPROGRAMS\$StartMenuFolder"
  
  ; Remove registry entries
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\${SERVICE_NAME}"
SectionEnd

;--------------------------------
; Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core monitoring agent components, executables, and configuration files (required)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Install and configure the RiskNoX monitoring service for automatic startup"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSuricata} "Network Intrusion Detection System for advanced threat detection"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTools} "Administrative tools and utilities for agent management"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Create Start Menu shortcuts for easy access to agent tools"
!insertmacro MUI_FUNCTION_DESCRIPTION_END