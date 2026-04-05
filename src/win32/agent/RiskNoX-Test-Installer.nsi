; RiskNoX Monitoring Agent - Basic Test Installer
; NSIS Script for testing compilation without large files

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

;--------------------------------
; Installer General Settings
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "RiskNoX-Agent-Test.exe"
InstallDir "$PROGRAMFILES64\RiskNoX Agent"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

;--------------------------------
; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

;--------------------------------
; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder
!insertmacro MUI_PAGE_INSTFILES
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
; Main Installation Section
Section "Core Components" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"
  
  ; Create basic directory structure
  CreateDirectory "$INSTDIR\logs"
  CreateDirectory "$INSTDIR\config"
  CreateDirectory "$INSTDIR\tools"
  
  ; Create test files (instead of copying actual files)
  FileOpen $0 "$INSTDIR\monitoring-agent.exe" w
  FileWrite $0 "Test executable placeholder"
  FileClose $0
  
  FileOpen $0 "$INSTDIR\RiskNoXServiceControl.ps1" w
  FileWrite $0 "# PowerShell Service Control Script$\r$\nparam([string]$$Action)$\r$\nWrite-Host 'Service control action: ' $$Action"
  FileClose $0
  
  FileOpen $0 "$INSTDIR\ossec.conf" w
  FileWrite $0 "<!-- Test configuration file -->"
  FileClose $0
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
  ; Write registry entries
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\monitoring-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
SectionEnd

;--------------------------------
; Service Installation Section
Section "Install Service" SecService
  Call DetectPowerShell7
  DetailPrint "Installing RiskNoX service..."
  
  ; Install service using sc command
  ExecWait '"sc" create "${SERVICE_NAME}" binPath= "$INSTDIR\monitoring-agent.exe" start= auto' $0
  ${If} $0 = 0
    DetailPrint "Service installed successfully"
    ; Start the service
    ExecWait '"sc" start "${SERVICE_NAME}"' $0
    DetailPrint "Service start result: $0"
  ${Else}
    DetailPrint "Service installation failed with error: $0"
  ${EndIf}
SectionEnd

;--------------------------------
; Start Menu Section
Section "Start Menu Shortcuts" SecShortcuts
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
  CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\RiskNoX Agent.lnk" "$INSTDIR\monitoring-agent.exe"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

;--------------------------------
; Uninstaller Section
Section Uninstall
  ; Stop and remove service
  DetailPrint "Stopping and removing service..."
  ExecWait '"sc" stop "${SERVICE_NAME}"' $0
  ExecWait '"sc" delete "${SERVICE_NAME}"' $0
  
  ; Remove files
  Delete "$INSTDIR\monitoring-agent.exe"
  Delete "$INSTDIR\RiskNoXServiceControl.ps1"
  Delete "$INSTDIR\ossec.conf"
  Delete "$INSTDIR\uninstall.exe"
  
  ; Remove directories
  RMDir "$INSTDIR\logs"
  RMDir "$INSTDIR\config"
  RMDir "$INSTDIR\tools"
  RMDir "$INSTDIR"
  
  ; Remove shortcuts
  !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
  Delete "$SMPROGRAMS\$StartMenuFolder\RiskNoX Agent.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
  RMDir "$SMPROGRAMS\$StartMenuFolder"
  
  ; Remove registry entries
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd

;--------------------------------
; Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core monitoring agent components (required)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Install and start the RiskNoX monitoring service"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Create Start Menu shortcuts"
!insertmacro MUI_FUNCTION_DESCRIPTION_END