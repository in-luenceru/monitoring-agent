; include Modern UI
!include "MUI.nsh"

; standard NSIS includes
!include "LogicLib.nsh"
!include "WinVer.nsh"

; include nsProcess
!addincludedir "nsProcess"
!addplugindir "nsProcess"
!include "nsProcess.nsh"

; include SimpleSC
!addplugindir "SimpleSC"

; include GetTime
!include "FileFunc.nsh"
!insertmacro GetTime

; general
!define MUI_ICON install.ico
!define MUI_UNICON uninstall.ico
!define VERSION "4.13.1"
!define REVISION "rc1"
!define NAME "Monitoring Agent"
!define SERVICE "MonitoringSvc"

; output file
!ifndef OutFile
    !define OutFile "monitoring-suite-${VERSION}.exe"
!endif

Var is_upgrade

Name "${NAME} Windows Agent v${VERSION}"
BrandingText "Copyright (C) 2025, Monitoring Solutions Inc."
OutFile "${OutFile}"

VIProductVersion "4.13.1.0"
VIAddVersionKey ProductName "${NAME}"
VIAddVersionKey CompanyName "Monitoring Solutions Inc."
VIAddVersionKey LegalCopyright "2025 - Monitoring Solutions Inc."
VIAddVersionKey FileDescription "Monitoring Agent installer"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey InternalName "Monitoring Agent"
VIAddVersionKey OriginalFilename "${OutFile}"

InstallDir "$PROGRAMFILES\monitoring-agent"
InstallDirRegKey HKLM Software\MonitoringAgent ""

; show (un)installation details
ShowInstDetails show
ShowUninstDetails show

; do not close details pages immediately
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

; interface settings
!define MUI_ABORTWARNING

; pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_RUN "$INSTDIR\win32ui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Run Agent manager"

; page for choosing components
; Enable component descriptions
!define MUI_COMPONENTSPAGE_TEXT_COMPLIST "Select components to install:"
!define MUI_COMPONENTSPAGE_TEXT_INSTTYPE "Choose the type of install:"
!define MUI_COMPONENTSPAGE_TEXT_DESCRIPTION_TITLE "Component Description"
!define MUI_COMPONENTSPAGE_TEXT_DESCRIPTION_INFO "Position your mouse over a component to see its description."

; pages to display to user
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; these have to be defined again to work with the uninstall pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; languages
!insertmacro MUI_LANGUAGE "English"

; function to stop Monitoring Agent service if running
Function .onInit
    StrCpy $is_upgrade "no"

    ; stop service
    SimpleSC::ExistsService "${SERVICE}"
    Pop $0
    ${If} $0 = 0
        SimpleSC::ServiceIsStopped "${SERVICE}"
        Pop $0
        Pop $1
        ${If} $0 = 0
            ${If} $1 <> 1
                MessageBox MB_OKCANCEL "${NAME} is already installed and the ${SERVICE} service is running. \
                    It will be stopped before continuing." /SD IDOK IDOK ServiceStop
                SetErrorLevel 2
                Abort

                ServiceStop:
                    SimpleSC::StopService "${SERVICE}" 1 30
                    Pop $0
                    ${If} $0 <> 0
                        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                            Failure stopping the ${SERVICE} service ($0).$\r$\n$\r$\n\
                            Click Abort to stop the installation,$\r$\n\
                            Retry to try again, or$\r$\n\
                            Ignore to skip this file." /SD IDABORT IDIGNORE ServiceStopped IDRETRY ServiceStop

                        SetErrorLevel 2
                        Abort
                    ${Else}
                        StrCpy $is_upgrade "yes"
                    ${EndIf}
            ${EndIf}
        ${Else}
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure checking status of the ${SERVICE} service ($0).$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ServiceStopped IDRETRY ServiceStop

            SetErrorLevel 2
            Abort
        ${EndIf}
    ${EndIf}
    ServiceStopped:
FunctionEnd

; main install section
Section "Monitoring Agent (required)" MainSec
    ; set install type and cwd
    SectionIn RO
    SetOutPath $INSTDIR

    ; clear any errors
    ClearErrors

    ; use real date modified times
    SetDateSave off

    ; overwrite existing files
    SetOverwrite on

    ; remove diff and state files when upgrading

    Push "$INSTDIR\queue\diff\local"
    Push "last-entry"
    Push $0
    GetFunctionAddress $0 "RmFiles"
    Exch $0
    Call FindFiles

    ; create necessary directories
    CreateDirectory "$INSTDIR\bookmarks"
    CreateDirectory "$INSTDIR\logs"
    CreateDirectory "$INSTDIR\rids"
    CreateDirectory "$INSTDIR\syscheck"
    CreateDirectory "$INSTDIR\shared"
    CreateDirectory "$INSTDIR\active-response"
    CreateDirectory "$INSTDIR\active-response\bin"
    CreateDirectory "$INSTDIR\tmp"
    CreateDirectory "$INSTDIR\queue"
    CreateDirectory "$INSTDIR\queue\diff"
    CreateDirectory "$INSTDIR\queue\fim"
    CreateDirectory "$INSTDIR\queue\fim\db"
    CreateDirectory "$INSTDIR\queue\syscollector"
    CreateDirectory "$INSTDIR\queue\syscollector\db"
    CreateDirectory "$INSTDIR\queue\logcollector"
    CreateDirectory "$INSTDIR\incoming"
    CreateDirectory "$INSTDIR\upgrade"
    CreateDirectory "$INSTDIR\wodles"
    CreateDirectory "$INSTDIR\ruleset\"
    CreateDirectory "$INSTDIR\ruleset\sca"
    CreateDirectory "$INSTDIR\suricata"
    CreateDirectory "$INSTDIR\suricata\bin"
    CreateDirectory "$INSTDIR\suricata\cache"
    CreateDirectory "$INSTDIR\suricata\cache\sgh"
    CreateDirectory "$INSTDIR\suricata\etc"
    CreateDirectory "$INSTDIR\suricata\log"
    CreateDirectory "$INSTDIR\suricata\rules"
    CreateDirectory "$INSTDIR\npcap"
    CreateDirectory "$INSTDIR\clamav"
    CreateDirectory "$INSTDIR\clamav\database"
    CreateDirectory "$INSTDIR\clamav\logs"

    ; install files
    File monitoring-agent.exe
    File monitoring-agent-eventchannel.exe
    File ossec.conf
    File manage_agents.exe
    File /oname=win32ui.exe os_win32ui.exe
    File /oname=suricata_ui.exe suricata_ui.exe
    File internal_options.conf
    File default-local_internal_options.conf
    File setup-windows.exe
    File setup-syscheck.exe
    File setup-iis.exe
    File doc.html
    File favicon.ico
    File /oname=shared\rootkit_trojans.txt ..\..\ruleset\rootcheck\db\rootkit_trojans.txt
    File /oname=shared\rootkit_files.txt ..\..\ruleset\rootcheck\db\rootkit_files.txt
    File LICENSE.txt
    File /oname=shared\win_applications_rcl.txt ..\..\ruleset\rootcheck\db\win_applications_rcl.txt
    File /oname=shared\win_malware_rcl.txt ..\..\ruleset\rootcheck\db\win_malware_rcl.txt
    File /oname=shared\win_audit_rcl.txt ..\..\ruleset\rootcheck\db\win_audit_rcl.txt
    file /oname=ruleset\sca\cis_win11_enterprise.yml ..\..\ruleset\sca\windows\cis_win11_enterprise.yml
    file /oname=ruleset\sca\cis_win10_enterprisce.yml ..\..\ruleset\sca\windows\cis_win10_enterprise.yml
    File /oname=help.txt help_win.txt
    File vista_sec.txt
    File /oname=active-response\bin\route-null.exe route-null.exe
    File /oname=active-response\bin\restart-monitoring.exe restart-wazuh.exe
    File /oname=active-response\bin\netsh.exe netsh.exe
    File /oname=active-response\bin\clamav-scan.exe clamav-scan.exe
    File /oname=libwinpthread-1.dll libwinpthread-1.dll
    File /oname=libgcc_s_dw2-1.dll libgcc_s_dw2-1.dll
    File /oname=libstdc++-6.dll libstdc++-6.dll
    File agent-auth.exe
    File /oname=wpk_root.pem ..\..\etc\wpk_root.pem
    File /oname=libwazuhext.dll ..\libwazuhext.dll
    File /oname=libwazuhshared.dll ..\libwazuhshared.dll
    File /oname=dbsync.dll ..\shared_modules\dbsync\build\bin\dbsync.dll
    File /oname=rsync.dll ..\shared_modules\rsync\build\bin\rsync.dll
    File /oname=sysinfo.dll ..\data_provider\build\bin\sysinfo.dll
    File /oname=syscollector.dll ..\wazuh_modules\syscollector\build\bin\syscollector.dll
    File /oname=libfimdb.dll ..\syscheckd\build\bin\libfimdb.dll
    File /oname=queue\syscollector\norm_config.json ..\wazuh_modules\syscollector\norm_config.json
    File VERSION.json

    ; install Suricata files
    File /oname=suricata\SuricataControl.ps1 suricata\SuricataControl.ps1
    File /oname=suricata\SuricataControl.ps1.backup suricata\SuricataControl.ps1.backup
    File /oname=suricata\setup-log-clear-task.ps1 suricata\setup-log-clear-task.ps1
    File /oname=suricata\remove-log-clear-task.ps1 suricata\remove-log-clear-task.ps1
    File /oname=suricata\clear-suricata-logs.ps1 suricata\clear-suricata-logs.ps1
    
    ; install Suricata bin files
    File /oname=suricata\bin\HOW_TO_Windows.pdf suricata\bin\HOW_TO_Windows.pdf
    File /oname=suricata\bin\LICENSE suricata\bin\LICENSE
    File /oname=suricata\bin\WinDivert.dll suricata\bin\WinDivert.dll
    File /oname=suricata\bin\WinDivert64.sys suricata\bin\WinDivert64.sys
    File /oname=suricata\bin\batch.bat suricata\bin\batch.bat
    File /oname=suricata\bin\libGeoIP-1.dll suricata\bin\libGeoIP-1.dll
    File /oname=suricata\bin\libjansson-4.dll suricata\bin\libjansson-4.dll
    File /oname=suricata\bin\liblz4.dll suricata\bin\liblz4.dll
    File /oname=suricata\bin\liblzma-5.dll suricata\bin\liblzma-5.dll
    File /oname=suricata\bin\libmaxminddb-0.dll suricata\bin\libmaxminddb-0.dll
    File /oname=suricata\bin\libnspr4.dll suricata\bin\libnspr4.dll
    File /oname=suricata\bin\libpcre-1.dll suricata\bin\libpcre-1.dll
    File /oname=suricata\bin\libpcre2-8-0.dll suricata\bin\libpcre2-8-0.dll
    File /oname=suricata\bin\libplc4.dll suricata\bin\libplc4.dll
    File /oname=suricata\bin\libplds4.dll suricata\bin\libplds4.dll
    File /oname=suricata\bin\libssp-0.dll suricata\bin\libssp-0.dll
    File /oname=suricata\bin\libwinpthread-1.dll suricata\bin\libwinpthread-1.dll
    File /oname=suricata\bin\libyaml-0-2.dll suricata\bin\libyaml-0-2.dll
    File /oname=suricata\bin\magic.mgc suricata\bin\magic.mgc
    File /oname=suricata\bin\msvcrt.dll suricata\bin\msvcrt.dll
    File /oname=suricata\bin\nss3.dll suricata\bin\nss3.dll
    File /oname=suricata\bin\nssutil3.dll suricata\bin\nssutil3.dll
    File /oname=suricata\bin\packet.dll suricata\bin\packet.dll
    File /oname=suricata\bin\suricata suricata\bin\suricata
    File /oname=suricata\bin\suricata.exe suricata\bin\suricata.exe
    File /oname=suricata\bin\wpcap.dll suricata\bin\wpcap.dll
    File /oname=suricata\bin\zlib1.dll suricata\bin\zlib1.dll
    
    ; install Suricata etc files
    File /oname=suricata\etc\classification.config suricata\etc\classification.config
    File /oname=suricata\etc\reference.config suricata\etc\reference.config
    File /oname=suricata\etc\suricata.yaml suricata\etc\suricata.yaml
    File /oname=suricata\etc\threshold.config suricata\etc\threshold.config
    
    ; install Suricata rules files
    File /oname=suricata\rules\app-layer-events.rules suricata\rules\app-layer-events.rules
    File /oname=suricata\rules\decoder-events.rules suricata\rules\decoder-events.rules
    File /oname=suricata\rules\dhcp-events.rules suricata\rules\dhcp-events.rules
    File /oname=suricata\rules\dnp3-events.rules suricata\rules\dnp3-events.rules
    File /oname=suricata\rules\dns-events.rules suricata\rules\dns-events.rules
    File /oname=suricata\rules\enip-events.rules suricata\rules\enip-events.rules
    File /oname=suricata\rules\files.rules suricata\rules\files.rules
    File /oname=suricata\rules\ftp-events.rules suricata\rules\ftp-events.rules
    File /oname=suricata\rules\http-events.rules suricata\rules\http-events.rules
    File /oname=suricata\rules\http2-events.rules suricata\rules\http2-events.rules
    File /oname=suricata\rules\ipsec-events.rules suricata\rules\ipsec-events.rules
    File /oname=suricata\rules\kerberos-events.rules suricata\rules\kerberos-events.rules
    File /oname=suricata\rules\modbus-events.rules suricata\rules\modbus-events.rules
    File /oname=suricata\rules\mqtt-events.rules suricata\rules\mqtt-events.rules
    File /oname=suricata\rules\nfs-events.rules suricata\rules\nfs-events.rules
    File /oname=suricata\rules\ntp-events.rules suricata\rules\ntp-events.rules
    File /oname=suricata\rules\quick-events.rules suricata\rules\quick-events.rules
    File /oname=suricata\rules\rfb-events.rules suricata\rules\rfb-events.rules
    File /oname=suricata\rules\smb-events.rules suricata\rules\smb-events.rules
    File /oname=suricata\rules\smtp-events.rules suricata\rules\smtp-events.rules
    File /oname=suricata\rules\ssh-events.rules suricata\rules\ssh-events.rules
    File /oname=suricata\rules\stream-events.rules suricata\rules\stream-events.rules
    File /oname=suricata\rules\tls-events.rules suricata\rules\tls-events.rules
    File /oname=suricata\rules\websocket-events.rules suricata\rules\websocket-events.rules
    
    ; 
    
    ; install Npcap files
    File /oname=npcap\NpcapHelper.exe npcap\NpcapHelper.exe
    File /oname=npcap\Packet.dll npcap\Packet.dll
    File /oname=npcap\WlanHelper.exe npcap\WlanHelper.exe
    File /oname=npcap\wpcap.dll npcap\wpcap.dll

    ; install ClamAV UI
    File /oname=clamav_ui.exe ui\clamav_ui.exe
    
    ; install ClamAV control script
    File /oname=clamav\ClamAVControl.ps1 clamav\ClamAVControl.ps1
    
    ; install ClamAV schedule configuration
    File /oname=clamav\clamav_schedule.conf clamav\clamav_schedule.conf
    
    ; install ClamAV executables
    File /oname=clamav\clamd.exe vendor\clamd.exe
    File /oname=clamav\clamscan.exe vendor\clamscan.exe
    File /oname=clamav\freshclam.exe vendor\freshclam.exe
    
    ; install ClamAV configuration files
    File /oname=clamav\clamscan.conf vendor\clamscan.conf
    File /oname=clamav\freshclam.conf vendor\freshclam.conf
    
    ; install ClamAV DLLs - Core libraries
    File /oname=clamav\libclamav.dll vendor\libclamav.dll
    File /oname=clamav\libfreshclam.dll vendor\libfreshclam.dll
    File /oname=clamav\libclammspack.dll vendor\libclammspack.dll
    File /oname=clamav\libclamunrar.dll vendor\libclamunrar.dll
    File /oname=clamav\libclamunrar_iface.dll vendor\libclamunrar_iface.dll
    
    ; install ClamAV DLLs - Cryptography
    File /oname=clamav\libcrypto-3-x64.dll vendor\libcrypto-3-x64.dll
    File /oname=clamav\libssl-3-x64.dll vendor\libssl-3-x64.dll
    
    ; install ClamAV DLLs - Network
    File /oname=clamav\libcurl.dll vendor\libcurl.dll
    File /oname=clamav\libssh2.dll vendor\libssh2.dll
    File /oname=clamav\nghttp2.dll vendor\nghttp2.dll
    
    ; install ClamAV DLLs - Data processing
    File /oname=clamav\json-c.dll vendor\json-c.dll
    File /oname=clamav\libxml2.dll vendor\libxml2.dll
    File /oname=clamav\pcre2-8.dll vendor\pcre2-8.dll
    File /oname=clamav\libbz2.dll vendor\libbz2.dll
    
    ; install ClamAV DLLs - System
    File /oname=clamav\pthreadVC3.dll vendor\pthreadVC3.dll
    File /oname=clamav\pdcurses.dll vendor\pdcurses.dll
    
    ; install ClamAV DLLs - VC++ Runtime
    File /oname=clamav\concrt140.dll vendor\concrt140.dll
    File /oname=clamav\msvcp140.dll vendor\msvcp140.dll
    File /oname=clamav\msvcp140_1.dll vendor\msvcp140_1.dll
    File /oname=clamav\msvcp140_2.dll vendor\msvcp140_2.dll
    File /oname=clamav\msvcp140_atomic_wait.dll vendor\msvcp140_atomic_wait.dll
    File /oname=clamav\msvcp140_codecvt_ids.dll vendor\msvcp140_codecvt_ids.dll
    File /oname=clamav\vcruntime140.dll vendor\vcruntime140.dll
    File /oname=clamav\vcruntime140_1.dll vendor\vcruntime140_1.dll
    
    ; install ClamAV database files
    File /oname=clamav\database\bytecode.cvd vendor\database\bytecode.cvd
    File /oname=clamav\database\freshclam.dat vendor\database\freshclam.dat

    ; Create empty file active-responses.log
    FileOpen $0 "$INSTDIR\active-response\active-responses.log" w
    FileClose $0

        ; use appropriate version of "monitoring-agent.exe"
    ; Note: For 32-bit build, we don't need eventchannel version
    ; Delete "$INSTDIR\monitoring-agent.exe"
    ; Rename "$INSTDIR\monitoring-agent-eventchannel.exe" "$INSTDIR\monitoring-agent.exe"

    ; write registry keys
    WriteRegStr HKLM SOFTWARE\MonitoringAgent "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "DisplayName" "${NAME} Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "Publisher" "Monitoring Solutions Inc."
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "DisplayIcon" '"$INSTDIR\favicon.ico"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "HelpLink" "https://monitoring-solutions.com"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "URLInfoAbout" "https://monitoring-solutions.com"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "UninstallString" '"$INSTDIR\uninstall.exe"'
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "EstimatedSize" "$0"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent" "NoRepair" 1
    WriteUninstaller "uninstall.exe"

    ; get current local time
    ${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
    var /global CURRENTTIME
    StrCpy $CURRENTTIME "$2-$1-$0 $4:$5:$6"

    ; create log file
    LogInstall:
        ClearErrors
        IfFileExists "$INSTDIR\monitoring.log" LogComplete
        FileOpen $0 "$INSTDIR\monitoring.log" w
        FileClose $0
        IfErrors LogError LogComplete
    LogError:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
            Failure creating the monitoring.log file.$\r$\n$\r$\n\
            File:$\r$\n$\r$\n$INSTDIR\monitoring.log$\r$\n$\r$\n\
            Click Abort to stop the installation,$\r$\n\
            Retry to try again, or$\r$\n\
            Ignore to skip this file." /SD IDABORT IDIGNORE LogComplete IDRETRY LogInstall

        SetErrorLevel 2
        Abort
    LogComplete:
        ClearErrors

    ; rename local_internal_options.conf if it does not already exist
    ConfInstallInternal:
        ClearErrors
        IfFileExists "$INSTDIR\local_internal_options.conf" ConfPresentInternal
        Rename "$INSTDIR\default-local_internal_options.conf" "$INSTDIR\local_internal_options.conf"
        IfErrors ConfErrorInternal ConfPresentInternal
    ConfErrorInternal:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
            Failure renaming configuration file.$\r$\n$\r$\n\
            From:$\r$\n$\r$\n\
            $INSTDIR\default-local_internal_options.conf$\r$\n$\r$\n\
            To:$\r$\n$\r$\n\
            $INSTDIR\local_internal_options.conf$\r$\n$\r$\n\
            Click Abort to stop the installation,$\r$\n\
            Retry to try again, or$\r$\n\
            Ignore to skip this file." /SD IDABORT IDIGNORE ConfPresentInternal IDRETRY ConfInstallInternal

        SetErrorLevel 2
        Abort
    ConfPresentInternal:
        ClearErrors

    ; handle shortcuts
    ; https://nsis.sourceforge.net/Shortcuts_removal_fails_on_Windows_Vista
    SetShellVarContext all

    ; remove shortcuts
    Delete "$SMPROGRAMS\Monitoring Agent\Edit.lnk"
    Delete "$SMPROGRAMS\Monitoring Agent\Uninstall.lnk"
    Delete "$SMPROGRAMS\Monitoring Agent\Documentation.lnk"
    Delete "$SMPROGRAMS\Monitoring Agent\Edit Config.lnk"
    Delete "$SMPROGRAMS\Monitoring Agent\*.*"
    RMDir "$SMPROGRAMS\Monitoring Agent"

    ; create shortcuts
    CreateDirectory "$SMPROGRAMS\Monitoring Agent"
    CreateShortCut "$SMPROGRAMS\Monitoring Agent\Manage Agent.lnk" "$INSTDIR\win32ui.exe" "" "$INSTDIR\win32ui.exe" 0
    CreateShortCut "$SMPROGRAMS\Monitoring Agent\Suricata Manager.lnk" "$INSTDIR\suricata_ui.exe" "" "$INSTDIR\suricata_ui.exe" 0
    CreateShortCut "$SMPROGRAMS\Monitoring Agent\ClamAV Manager.lnk" "$INSTDIR\clamav_ui.exe" "" "$INSTDIR\clamav_ui.exe" 0
    CreateShortCut "$SMPROGRAMS\Monitoring Agent\Documentation.lnk" "$INSTDIR\doc.html" "" "$INSTDIR\doc.html" 0
    CreateShortCut "$SMPROGRAMS\Monitoring Agent\Edit Config.lnk" "$INSTDIR\ossec.conf" "" "$INSTDIR\ossec.conf" 0
    CreateShortCut "$SMPROGRAMS\Monitoring Agent\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0


    ; install Monitoring Agent service
    ServiceInstall:
        nsExec::ExecToLog '"$INSTDIR\monitoring-agent.exe" install-service'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure setting up the ${SERVICE} service.$\r$\n$\r$\n\
                Check the details for information about the error.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ServiceInstallComplete IDRETRY ServiceInstall

            SetErrorLevel 2
            Abort
        ${EndIf}
    ServiceInstallComplete:

    ; install files
    Setup:
        nsExec::ExecToLog '"$INSTDIR\setup-windows.exe" "$INSTDIR"'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure running setup-windows.exe.$\r$\n$\r$\n\
                Check the details for information about the error.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE SetupComplete IDRETRY Setup

            SetErrorLevel 2
            Abort
        ${EndIf}


    ${If} $is_upgrade == "yes"
        Goto StartService
    ${Else}
            Goto SetupComplete
        ${EndIf}

    StartService:
        SimpleSC::ExistsService "${SERVICE}"
        Pop $0
        ${If} $0 = 0
            ; StartService [name_of_service] [arguments] [timeout]
            SimpleSC::StartService "${SERVICE}" "" 30
            Pop $0
            ${If} $0 <> 0
                MessageBox MB_OK  "$\r$\n\
                    Failure starting the ${SERVICE} ($0).$\r$\n$\r$\n\
                    The service could not be started."
            ${EndIf}
        ${Else}
            MessageBox MB_OK  "$\r$\n\
                Service not found ${SERVICE} ($0).$\r$\n$\r$\n\
                The service could not be found."
            SetErrorLevel 2
            Abort
        ${EndIf}
        Goto SetupComplete

    SetupComplete:

SectionEnd

; add IIS logs
Section "Scan and monitor IIS logs (recommended)" IISLogs
    nsExec::ExecToLog '"$INSTDIR\setup-iis.exe" "$INSTDIR"'
SectionEnd

; Disable integrity checking
Section /o "Disable integrity checking (not recommended)" IntChecking
    nsExec::ExecToLog '"$INSTDIR\setup-syscheck.exe" "$INSTDIR" "disable"'
SectionEnd


; uninstall section
Section "Uninstall"

    ; make sure manage_agents.exe is not running
    ManageAgents:
        ${nsProcess::FindProcess} "manage_agents.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Found manage_agents.exe is still running.$\r$\n$\r$\n\
                Please close it before continuing.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ManageAgentsClosed IDRETRY ManageAgents

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    ManageAgentsClosed:

    ; make sure win32ui.exe is not running
    win32ui:
        ${nsProcess::FindProcess} "win32ui.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Found win32ui.exe is still running.$\r$\n$\r$\n\
                Please close it before continuing.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE win32uiClosed IDRETRY win32ui

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    win32uiClosed:

    ; make sure suricata_ui.exe is not running
    suricata_ui:
        ${nsProcess::FindProcess} "suricata_ui.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Found suricata_ui.exe is still running.$\r$\n$\r$\n\
                Please close it before continuing.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE suricata_uiClosed IDRETRY suricata_ui

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    suricata_uiClosed:

    ; unload nsProcess
    ${nsProcess::Unload}

    ; remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonitoringAgent"
    DeleteRegKey HKLM SOFTWARE\MonitoringAgent

    ; remove files and uninstaller - use wildcards for thorough cleanup
    Delete "$INSTDIR\monitoring-agent.exe"
    Delete "$INSTDIR\monitoring-agent-eventchannel.exe"
    Delete "$INSTDIR\agent-auth.exe"
    Delete "$INSTDIR\manage_agents.exe"
    Delete "$INSTDIR\win32ui.exe"
    Delete "$INSTDIR\suricata_ui.exe"
    Delete "$INSTDIR\clamav_ui.exe"
    Delete "$INSTDIR\*.conf"
    Delete "$INSTDIR\*.log"
    Delete "$INSTDIR\*.state"
    Delete "$INSTDIR\*.dll"
    Delete "$INSTDIR\*.exe"
    Delete "$INSTDIR\*.txt"
    Delete "$INSTDIR\*.html"
    Delete "$INSTDIR\*.ico"
    Delete "$INSTDIR\*.json"
    Delete "$INSTDIR\*.pem"
    Delete "$INSTDIR\uninstall.exe"

    ; remove shortcuts
    SetShellVarContext all
    Delete "$SMPROGRAMS\Monitoring Agent\*.*"
    Delete "$SMPROGRAMS\Monitoring Agent\*"
    RMDir "$SMPROGRAMS\Monitoring Agent"

    ; remove directories - use recursive deletion for complete cleanup
    RMDir /r "$INSTDIR\shared"
    RMDir /r "$INSTDIR\syscheck"
    RMDir /r "$INSTDIR\bookmarks"
    RMDir /r "$INSTDIR\logs"
    RMDir /r "$INSTDIR\rids"
    RMDir /r "$INSTDIR\active-response"
    RMDir /r "$INSTDIR\tmp"
    RMDir /r "$INSTDIR\queue"
    RMDir /r "$INSTDIR\incoming"
    RMDir /r "$INSTDIR\upgrade"
    RMDir /r "$INSTDIR\wodles"
    RMDir /r "$INSTDIR\ruleset"
    RMDir /r "$INSTDIR\suricata"
    RMDir /r "$INSTDIR\npcap"
    RMDir /r "$INSTDIR\clamav"
    RMDir /r "$INSTDIR\state"
    RMDir /r "$INSTDIR"
SectionEnd

; Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${MainSec} "Core monitoring agent that provides file integrity monitoring, log analysis, rootkit detection, and central management capabilities. This component is required."
    !insertmacro MUI_DESCRIPTION_TEXT ${IISLogs} "Automatically configures monitoring for Internet Information Services (IIS) web server logs. Recommended if you are running IIS."
    !insertmacro MUI_DESCRIPTION_TEXT ${IntChecking} "Disables file integrity checking feature. Only select this if you specifically need to disable this security feature."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function FindFiles
  Exch $R5 # callback function
  Exch
  Exch $R4 # file name
  Exch 2
  Exch $R0 # directory
  Push $R1
  Push $R2
  Push $R3
  Push $R6

  Push $R0 # first dir to search

  StrCpy $R3 1

  nextDir:
    Pop $R0
    IntOp $R3 $R3 - 1
    ClearErrors
    FindFirst $R1 $R2 "$R0\*.*"
    nextFile:
      StrCmp $R2 "." gotoNextFile
      StrCmp $R2 ".." gotoNextFile

      StrCmp $R2 $R4 0 isDir
        Call $R5
        Pop $R6
        StrCmp $R6 "stop" 0 isDir
          loop:
            StrCmp $R3 0 done
            Pop $R0
            IntOp $R3 $R3 - 1
            Goto loop

      isDir:
        IfFileExists "$R0\$R2\*.*" 0 gotoNextFile
          IntOp $R3 $R3 + 1
          Push "$R0\$R2"

  gotoNextFile:
    FindNext $R1 $R2
    IfErrors 0 nextFile

  done:
    FindClose $R1
    StrCmp $R3 0 0 nextDir

  Pop $R6
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
  Pop $R5
  Pop $R4
FunctionEnd

Function RmFiles
 StrCpy $1 $R0
 Push $1 ; route dir
 Push $2
 Push $2

  FindFirst $3 $2 "$1\*.*"
  IfErrors Exit

  Top:
   StrCmp $2 "." Next
   StrCmp $2 ".." Next
   StrCmp $2 "last-entry" Next
   IfFileExists "$1\$2\*.*" Next
    Delete "$1\$2"

   Next:
    ClearErrors
    FindNext $3 $2
    IfErrors Exit
   Goto Top

  Exit:
  FindClose $2

 Pop $3
 Pop $2
 Pop $1
 Push "go"
FunctionEnd
