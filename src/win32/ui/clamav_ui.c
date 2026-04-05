/* Copyright (C) 2026, Monitoring Solutions Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <string.h>
#include <stdio.h>
#include "clamav_ui.h"

clamav_config clam_config;
autoscan_config auto_config;
scan_progress g_scan_progress;
HWND hStatus;
HWND g_hMainWnd = NULL;
HANDLE g_hScanThread = NULL;
volatile BOOL g_bScanRunning = FALSE;

/* Global install directory - detected at runtime */
char g_InstallDir[MAX_INSTALL_PATH] = "";

/* Initialize install directory by detecting executable location */
void InitInstallDir(void) {
    char modulePath[MAX_INSTALL_PATH];
    
    /* Get the path to the current executable */
    if (GetModuleFileName(NULL, modulePath, sizeof(modulePath)) > 0) {
        /* Find the last backslash to get the directory */
        char *lastSlash = strrchr(modulePath, '\\');
        if (lastSlash) {
            *lastSlash = '\0';
            
            /* Check if we're in a subdirectory (like 'ui' or 'bin') */
            char *parentSlash = strrchr(modulePath, '\\');
            if (parentSlash) {
                /* Get the folder name */
                char *folderName = parentSlash + 1;
                
                /* If we're in ui, bin, or similar subdirectory, go up one level */
                if (_stricmp(folderName, "ui") == 0 || 
                    _stricmp(folderName, "bin") == 0 ||
                    _stricmp(folderName, "clamav") == 0) {
                    *parentSlash = '\0';
                    
                    /* Check if we need to go up one more level */
                    parentSlash = strrchr(modulePath, '\\');
                    if (parentSlash) {
                        char *grandparentFolder = parentSlash + 1;
                        if (_stricmp(grandparentFolder, "clamav") == 0) {
                            *parentSlash = '\0';
                        }
                    }
                }
            }
        }
        strncpy(g_InstallDir, modulePath, sizeof(g_InstallDir) - 1);
        g_InstallDir[sizeof(g_InstallDir) - 1] = '\0';
    } else {
        /* Fallback to a default path if we can't detect */
        strncpy(g_InstallDir, "C:\\Program Files\\monitoring-agent", sizeof(g_InstallDir) - 1);
        g_InstallDir[sizeof(g_InstallDir) - 1] = '\0';
    }
}

const char* GetInstallDir(void) {
    if (g_InstallDir[0] == '\0') {
        InitInstallDir();
    }
    return g_InstallDir;
}

/* Global variable to store last error message */
static char last_error_msg[2048] = "";

const char* clamav_get_last_error() {
    return last_error_msg;
}

/* Read schedule config file to sync UI with current schedule settings */
int ReadScheduleConfigFile(int* enabled, int* scan_type, int* interval_hours) {
    char configPath[MAX_PATH];
    char buffer[4096];
    FILE* fp;
    
    const char* installDir = GetInstallDir();
    snprintf(configPath, sizeof(configPath), "%s\\clamav\\clamav_schedule.conf", installDir);
    
    fp = fopen(configPath, "r");
    if (!fp) {
        /* No config file - return defaults */
        *enabled = 0;
        *scan_type = SCAN_TYPE_QUICK;
        *interval_hours = 24;
        return 0;
    }
    
    /* Read entire file */
    size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 1, fp);
    buffer[bytesRead] = '\0';
    fclose(fp);
    
    /* Simple JSON parsing - look for key values */
    /* Parse "enabled": true/false */
    const char* enabledPos = strstr(buffer, "\"enabled\"");
    if (enabledPos) {
        if (strstr(enabledPos, "true") && (strstr(enabledPos, "true") < strstr(enabledPos, ",")))
            *enabled = 1;
        else
            *enabled = 0;
    } else {
        *enabled = 0;
    }
    
    /* Parse "scan_type": "quick" or "full" */
    const char* scanTypePos = strstr(buffer, "\"scan_type\"");
    if (scanTypePos) {
        if (strstr(scanTypePos, "\"full\"") && (strstr(scanTypePos, "\"full\"") < (scanTypePos + 50)))
            *scan_type = SCAN_TYPE_FULL;
        else
            *scan_type = SCAN_TYPE_QUICK;
    } else {
        *scan_type = SCAN_TYPE_QUICK;
    }
    
    /* Parse "interval_hours": number */
    const char* intervalPos = strstr(buffer, "\"interval_hours\"");
    if (intervalPos) {
        const char* colonPos = strchr(intervalPos, ':');
        if (colonPos) {
            *interval_hours = atoi(colonPos + 1);
            if (*interval_hours <= 0) *interval_hours = 24;
        } else {
            *interval_hours = 24;
        }
    } else {
        *interval_hours = 24;
    }
    
    return 0;
}

/* Check if user has admin privileges */
BOOL IsUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &administratorsGroup)) {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }
    return isAdmin;
}

/* Execute PowerShell command and get output */
int execute_powershell(const char* command, char* output, size_t output_size) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hReadPipe, hWritePipe;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char cmdline[4096];
    DWORD bytesRead;
    BOOL success;

    /* Create pipe for output */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return -1;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* Setup process */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));

    /* Build command line */
    snprintf(cmdline, sizeof(cmdline),
             "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command \"%s\"",
             command);

    /* Execute */
    success = CreateProcess(NULL, cmdline, NULL, NULL, TRUE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(hWritePipe);

    if (!success) {
        CloseHandle(hReadPipe);
        return -1;
    }

    /* Read output */
    if (output && output_size > 0) {
        DWORD totalRead = 0;
        while (totalRead < output_size - 1) {
            if (!ReadFile(hReadPipe, output + totalRead,
                         output_size - totalRead - 1, &bytesRead, NULL)) {
                break;
            }
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }
        output[totalRead] = '\0';
    }

    /* Wait for process to complete - increased timeout for scans */
    WaitForSingleObject(pi.hProcess, 300000);  /* 5 minute timeout */

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return (exitCode == 0) ? 0 : -1;
}

/* Execute scan using PowerShell script */
int execute_scan(const char* scan_type, const char* custom_path) {
    char command[4096];
    char output[8192];
    const char* installDir = GetInstallDir();

    last_error_msg[0] = '\0';
    clam_config.scan_in_progress = 1;

    if (custom_path && strlen(custom_path) > 0) {
        snprintf(command, sizeof(command),
                 "$ErrorActionPreference = 'Continue'; "
                 "try { "
                 "$script = '%s\\clamav\\ClamAVControl.ps1'; "
                 "if (Test-Path $script) { "
                 "$result = & $script %s '%s' 2>&1; "
                 "Write-Output $result; "
                 "if ($LASTEXITCODE -eq 0) { Write-Output 'SUCCESS' } "
                 "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
                 "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
                 installDir, scan_type, custom_path);
    } else {
        snprintf(command, sizeof(command),
                 "$ErrorActionPreference = 'Continue'; "
                 "try { "
                 "$script = '%s\\clamav\\ClamAVControl.ps1'; "
                 "if (Test-Path $script) { "
                 "$result = & $script %s 2>&1; "
                 "Write-Output $result; "
                 "if ($LASTEXITCODE -eq 0) { Write-Output 'SUCCESS' } "
                 "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
                 "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
                 installDir, scan_type);
    }

    execute_powershell(command, output, sizeof(output));
    clam_config.scan_in_progress = 0;
    
    if (strstr(output, "SUCCESS") != NULL || strstr(output, "completed") != NULL) {
        return 0;
    }
    
    /* Store error message */
    strncpy(last_error_msg, output, sizeof(last_error_msg) - 1);
    last_error_msg[sizeof(last_error_msg) - 1] = '\0';

    return -1;
}

/* Quick scan */
int clamav_quick_scan(void) {
    return execute_scan("quickscan", NULL);
}

/* Full scan */
int clamav_full_scan(void) {
    return execute_scan("fullscan", NULL);
}

/* Custom scan */
int clamav_custom_scan(const char* path) {
    return execute_scan("customscan", path);
}

/* Read scan progress from status file */
int ReadScanProgress(scan_progress* progress) {
    char statusPath[512];
    FILE* fp;
    char buffer[2048];
    char* ptr;
    
    if (!progress) return -1;
    
    /* Initialize with defaults */
    memset(progress, 0, sizeof(scan_progress));
    
    snprintf(statusPath, sizeof(statusPath), "%s\\clamav\\logs\\clamscan_status.json", GetInstallDir());
    
    fp = fopen(statusPath, "r");
    if (!fp) {
        return -1;
    }
    
    /* Read entire file */
    size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 1, fp);
    buffer[bytesRead] = '\0';
    fclose(fp);
    
    /* Simple JSON parsing - look for key values */
    if ((ptr = strstr(buffer, "\"scanning\":")) != NULL) {
        progress->scanning = (strstr(ptr, "true") != NULL && strstr(ptr, "true") < strstr(ptr, ","));
    }
    
    if ((ptr = strstr(buffer, "\"current_folder\":")) != NULL) {
        char* start = strchr(ptr + 17, '"');
        if (start) {
            char* end = strchr(start + 1, '"');
            if (end) {
                size_t len = end - start - 1;
                if (len > sizeof(progress->current_folder) - 1) {
                    len = sizeof(progress->current_folder) - 1;
                }
                strncpy(progress->current_folder, start + 1, len);
                progress->current_folder[len] = '\0';
            }
        }
    }
    
    if ((ptr = strstr(buffer, "\"progress_percent\":")) != NULL) {
        progress->progress_percent = atoi(ptr + 19);
    }
    
    if ((ptr = strstr(buffer, "\"files_scanned\":")) != NULL) {
        progress->files_scanned = atoi(ptr + 16);
    }
    
    if ((ptr = strstr(buffer, "\"threats_found\":")) != NULL) {
        progress->threats_found = atoi(ptr + 16);
    }
    
    if ((ptr = strstr(buffer, "\"message\":")) != NULL) {
        char* start = strchr(ptr + 10, '"');
        if (start) {
            char* end = strchr(start + 1, '"');
            if (end) {
                size_t len = end - start - 1;
                if (len > sizeof(progress->message) - 1) {
                    len = sizeof(progress->message) - 1;
                }
                strncpy(progress->message, start + 1, len);
                progress->message[len] = '\0';
            }
        }
    }
    
    if ((ptr = strstr(buffer, "\"scan_type\":")) != NULL) {
        char* start = strchr(ptr + 12, '"');
        if (start) {
            char* end = strchr(start + 1, '"');
            if (end) {
                size_t len = end - start - 1;
                if (len > sizeof(progress->scan_type) - 1) {
                    len = sizeof(progress->scan_type) - 1;
                }
                strncpy(progress->scan_type, start + 1, len);
                progress->scan_type[len] = '\0';
            }
        }
    }
    
    return 0;
}

/* Scan thread procedure */
DWORD WINAPI ScanThreadProc(LPVOID lpParam) {
    scan_thread_params* params = (scan_thread_params*)lpParam;
    int result = -1;
    
    if (!params) return 1;
    
    g_bScanRunning = TRUE;
    clam_config.scan_in_progress = 1;
    
    switch (params->scan_type) {
        case SCAN_TYPE_QUICK:
            result = execute_scan("quickscan", NULL);
            break;
        case SCAN_TYPE_FULL:
            result = execute_scan("fullscan", NULL);
            break;
        case SCAN_TYPE_CUSTOM:
            result = execute_scan("customscan", params->custom_path);
            break;
    }
    
    g_bScanRunning = FALSE;
    clam_config.scan_in_progress = 0;
    
    /* Notify main window of completion */
    if (params->hwnd) {
        PostMessage(params->hwnd, WM_SCAN_COMPLETE, (WPARAM)result, 0);
    }
    
    free(params);
    return 0;
}

/* Start async scan */
void StartAsyncScan(HWND hwnd, int scan_type, const char* custom_path) {
    scan_thread_params* params;
    
    /* Check if scan already running */
    if (g_bScanRunning || g_hScanThread != NULL) {
        MessageBox(hwnd, "A scan is already in progress.", "Scan In Progress", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    /* Allocate parameters */
    params = (scan_thread_params*)malloc(sizeof(scan_thread_params));
    if (!params) {
        MessageBox(hwnd, "Failed to allocate memory for scan.", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    params->hwnd = hwnd;
    params->scan_type = scan_type;
    if (custom_path) {
        strncpy(params->custom_path, custom_path, sizeof(params->custom_path) - 1);
        params->custom_path[sizeof(params->custom_path) - 1] = '\0';
    } else {
        params->custom_path[0] = '\0';
    }
    
    /* Create thread */
    g_hScanThread = CreateThread(NULL, 0, ScanThreadProc, params, 0, NULL);
    if (!g_hScanThread) {
        free(params);
        MessageBox(hwnd, "Failed to start scan thread.", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    /* Start progress timer */
    SetTimer(hwnd, TIMER_PROGRESS, TIMER_PROGRESS_INTERVAL, NULL);
    
    g_hMainWnd = hwnd;
}

/* Stop async scan */
void StopAsyncScan(void) {
    if (g_bScanRunning) {
        clamav_stop_scan();
        g_bScanRunning = FALSE;
    }
    
    if (g_hScanThread) {
        WaitForSingleObject(g_hScanThread, 2000);
        CloseHandle(g_hScanThread);
        g_hScanThread = NULL;
    }
    
    if (g_hMainWnd) {
        KillTimer(g_hMainWnd, TIMER_PROGRESS);
    }
}

/* Stop scan */
int clamav_stop_scan(void) {
    char command[2048];
    char output[4096];
    const char* installDir = GetInstallDir();

    snprintf(command, sizeof(command),
             "$ErrorActionPreference = 'Continue'; "
             "try { "
             "$script = '%s\\clamav\\ClamAVControl.ps1'; "
             "if (Test-Path $script) { "
             "& $script stop 2>&1; Write-Output 'SUCCESS' "
             "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
             "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
             installDir);

    execute_powershell(command, output, sizeof(output));
    clam_config.scan_in_progress = 0;
    
    return (strstr(output, "SUCCESS") != NULL) ? 0 : -1;
}

/* Update database */
int clamav_update_database(void) {
    char command[2048];
    char output[8192];
    const char* installDir = GetInstallDir();

    last_error_msg[0] = '\0';

    snprintf(command, sizeof(command),
             "$ErrorActionPreference = 'Continue'; "
             "try { "
             "$script = '%s\\clamav\\ClamAVControl.ps1'; "
             "if (Test-Path $script) { "
             "$result = & $script update 2>&1; "
             "Write-Output $result; "
             "if ($LASTEXITCODE -eq 0) { Write-Output 'SUCCESS' } "
             "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
             "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
             installDir);

    execute_powershell(command, output, sizeof(output));
    
    if (strstr(output, "SUCCESS") != NULL || strstr(output, "updated") != NULL) {
        return 0;
    }
    
    strncpy(last_error_msg, output, sizeof(last_error_msg) - 1);
    last_error_msg[sizeof(last_error_msg) - 1] = '\0';

    return -1;
}

/* Get scan status */
int clamav_get_scan_status(void) {
    char command[2048];
    char output[4096];
    const char* installDir = GetInstallDir();
    
    snprintf(command, sizeof(command),
             "$ErrorActionPreference = 'Stop'; "
             "try { "
             "$script = '%s\\clamav\\ClamAVControl.ps1'; "
             "if (Test-Path $script) { "
             "$output = & $script status 2>&1; "
             "if ($output -match 'SCANNING') { Write-Output 'SCANNING' } else { Write-Output 'IDLE' } "
             "} else { Write-Output 'IDLE' } "
             "} catch { Write-Output 'IDLE' }",
             installDir);

    if (execute_powershell(command, output, sizeof(output)) >= 0) {
        if (strstr(output, "SCANNING") != NULL) {
            return 1;
        }
    }

    return 0;
}

/* Configure auto-scan */
int clamav_configure_autoscan(int enabled, int scan_type, int interval_hours) {
    char command[2048];
    char output[4096];
    const char* installDir = GetInstallDir();
    const char* scanTypeStr = (scan_type == SCAN_TYPE_FULL) ? "fullscan" : "quickscan";

    last_error_msg[0] = '\0';

    if (enabled) {
        snprintf(command, sizeof(command),
                 "$ErrorActionPreference = 'Continue'; "
                 "try { "
                 "$script = '%s\\clamav\\ClamAVControl.ps1'; "
                 "if (Test-Path $script) { "
                 "$result = & $script schedule %s %d 2>&1; "
                 "Write-Output $result; "
                 "if ($LASTEXITCODE -eq 0) { Write-Output 'SUCCESS' } "
                 "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
                 "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
                 installDir, scanTypeStr, interval_hours);
    } else {
        snprintf(command, sizeof(command),
                 "$ErrorActionPreference = 'Continue'; "
                 "try { "
                 "$script = '%s\\clamav\\ClamAVControl.ps1'; "
                 "if (Test-Path $script) { "
                 "$result = & $script unschedule 2>&1; "
                 "Write-Output $result; "
                 "if ($LASTEXITCODE -eq 0) { Write-Output 'SUCCESS' } "
                 "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
                 "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
                 installDir);
    }

    execute_powershell(command, output, sizeof(output));
    
    if (strstr(output, "SUCCESS") != NULL) {
        auto_config.enabled = enabled;
        auto_config.scan_type = scan_type;
        auto_config.interval_hours = interval_hours;
        return 0;
    }
    
    strncpy(last_error_msg, output, sizeof(last_error_msg) - 1);
    last_error_msg[sizeof(last_error_msg) - 1] = '\0';

    return -1;
}

/* Update status display */
void update_status(HWND hwnd) {
    int status = clamav_get_scan_status();
    char status_text[256];

    if (status == 1) {
        snprintf(status_text, sizeof(status_text), "Status: %s", ST_SCANNING);
        clam_config.status = ST_SCANNING;
    } else {
        snprintf(status_text, sizeof(status_text), "Status: %s", ST_IDLE);
        clam_config.status = ST_IDLE;
    }

    SetDlgItemText(hwnd, IDC_STATUS_TEXT, status_text);
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)status_text);
}

/* Browse for folder dialog */
BOOL BrowseForFolder(HWND hwnd, char* path, size_t path_size) {
    BROWSEINFO bi = {0};
    LPITEMIDLIST pidl;
    
    bi.hwndOwner = hwnd;
    bi.lpszTitle = "Select folder to scan:";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    
    pidl = SHBrowseForFolder(&bi);
    if (pidl != NULL) {
        if (SHGetPathFromIDList(pidl, path)) {
            CoTaskMemFree(pidl);
            return TRUE;
        }
        CoTaskMemFree(pidl);
    }
    return FALSE;
}

/* Auto-scan configuration dialog */
INT_PTR CALLBACK AutoScanDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    static HWND hComboInterval, hComboType, hCheckEnable;
    
    switch (Message) {
        case WM_INITDIALOG: {
            int enabled = 0, scan_type = SCAN_TYPE_QUICK, interval_hours = 24;
            int intervalIdx = 3;  /* Default: Daily */
            
            hCheckEnable = GetDlgItem(hwnd, UI_ID_ENABLE_AUTO);
            hComboInterval = GetDlgItem(hwnd, UI_ID_INTERVAL_COMBO);
            hComboType = GetDlgItem(hwnd, UI_ID_SCANTYPE_COMBO);
            
            /* Read current schedule from config file */
            ReadScheduleConfigFile(&enabled, &scan_type, &interval_hours);
            
            /* Populate interval combo */
            SendMessage(hComboInterval, CB_ADDSTRING, 0, (LPARAM)"Every Hour");
            SendMessage(hComboInterval, CB_ADDSTRING, 0, (LPARAM)"Every 6 Hours");
            SendMessage(hComboInterval, CB_ADDSTRING, 0, (LPARAM)"Every 12 Hours");
            SendMessage(hComboInterval, CB_ADDSTRING, 0, (LPARAM)"Daily");
            SendMessage(hComboInterval, CB_ADDSTRING, 0, (LPARAM)"Weekly");
            
            /* Convert interval_hours to combo index */
            if (interval_hours >= 168) intervalIdx = 4;       /* Weekly */
            else if (interval_hours >= 24) intervalIdx = 3;   /* Daily */
            else if (interval_hours >= 12) intervalIdx = 2;   /* 12 Hours */
            else if (interval_hours >= 6) intervalIdx = 1;    /* 6 Hours */
            else intervalIdx = 0;                             /* Hourly */
            
            SendMessage(hComboInterval, CB_SETCURSEL, intervalIdx, 0);
            
            /* Populate scan type combo */
            SendMessage(hComboType, CB_ADDSTRING, 0, (LPARAM)"Quick Scan");
            SendMessage(hComboType, CB_ADDSTRING, 0, (LPARAM)"Full Scan");
            SendMessage(hComboType, CB_SETCURSEL, (scan_type == SCAN_TYPE_FULL) ? 1 : 0, 0);
            
            /* Set current enabled state from config file */
            SendMessage(hCheckEnable, BM_SETCHECK, enabled ? BST_CHECKED : BST_UNCHECKED, 0);
            
            /* Update global auto_config to match file */
            auto_config.enabled = enabled;
            auto_config.scan_type = scan_type;
            auto_config.interval_hours = interval_hours;
            
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK: {
                    int enabled = (SendMessage(hCheckEnable, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    int intervalIdx = SendMessage(hComboInterval, CB_GETCURSEL, 0, 0);
                    int typeIdx = SendMessage(hComboType, CB_GETCURSEL, 0, 0);
                    
                    int intervals[] = {1, 6, 12, 24, 168};
                    int interval = intervals[intervalIdx];
                    int scanType = (typeIdx == 0) ? SCAN_TYPE_QUICK : SCAN_TYPE_FULL;
                    
                    if (clamav_configure_autoscan(enabled, scanType, interval) == 0) {
                        MessageBox(hwnd, "Auto-scan settings saved successfully.",
                                 "Success", MB_OK | MB_ICONINFORMATION);
                        EndDialog(hwnd, IDOK);
                    } else {
                        char error_msg[2048];
                        snprintf(error_msg, sizeof(error_msg),
                                "Failed to configure auto-scan.\n\n%s",
                                clamav_get_last_error());
                        MessageBox(hwnd, error_msg, "Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }
                case IDCANCEL:
                    EndDialog(hwnd, IDCANCEL);
                    break;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwnd, IDCANCEL);
            break;

        default:
            return FALSE;
    }
    return TRUE;
}

/* About Dialog */
INT_PTR CALLBACK AboutDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch (Message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case UI_ID_CLOSE:
                    EndDialog(hwnd, IDOK);
                    break;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwnd, IDOK);
            break;

        default:
            return FALSE;
    }
    return TRUE;
}

/* Main Dialog */
INT_PTR CALLBACK DlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch (Message) {
        case WM_INITDIALOG: {
            int statwidths[] = {-1};
            HMENU hMenu, hSubMenu;
            UINT menuflags = MF_STRING;

            /* Check admin access */
            clam_config.admin_access = IsUserAdmin();

            if (clam_config.admin_access == 0) {
                menuflags = MF_STRING | MF_GRAYED;
            }

            hMenu = CreateMenu();

            /* Creating scan menu */
            hSubMenu = CreatePopupMenu();
            AppendMenu(hSubMenu, menuflags, UI_MENU_SCAN_QUICK, "&Quick Scan");
            AppendMenu(hSubMenu, menuflags, UI_MENU_SCAN_FULL, "&Full Scan");
            AppendMenu(hSubMenu, menuflags, UI_MENU_SCAN_CUSTOM, "&Custom Scan...");
            AppendMenu(hSubMenu, MF_SEPARATOR, UI_MENU_NONE, "");
            AppendMenu(hSubMenu, menuflags, UI_MENU_SCAN_STOP, "&Stop Scan");
            AppendMenu(hSubMenu, MF_SEPARATOR, UI_MENU_NONE, "");
            AppendMenu(hSubMenu, MF_STRING, UI_MENU_MANAGE_EXIT, "&Exit");
            AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT_PTR)hSubMenu, "&Scan");

            /* Create settings menu */
            hSubMenu = CreatePopupMenu();
            AppendMenu(hSubMenu, menuflags, UI_MENU_UPDATE_DB, "&Update Database");
            AppendMenu(hSubMenu, MF_SEPARATOR, UI_MENU_NONE, "");
            AppendMenu(hSubMenu, menuflags, UI_MENU_AUTO_SCAN, "&Auto-Scan Settings...");
            AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT_PTR)hSubMenu, "S&ettings");

            /* Create view menu */
            hSubMenu = CreatePopupMenu();
            AppendMenu(hSubMenu, MF_STRING, UI_MENU_VIEW_LOGS, "&View Logs");
            AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT_PTR)hSubMenu, "&View");

            /* Create help menu */
            hSubMenu = CreatePopupMenu();
            AppendMenu(hSubMenu, MF_STRING, UI_MENU_HELP_ABOUT, "A&bout");
            AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT_PTR)hSubMenu, "&Help");

            SetMenu(hwnd, hMenu);

            /* Create status bar */
            hStatus = CreateWindowEx(0, STATUSCLASSNAME, NULL,
                                     WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0,
                                     hwnd, (HMENU)IDC_MAIN_STATUS,
                                     GetModuleHandle(NULL), NULL);

            SendMessage(hStatus, SB_SETPARTS,
                        sizeof(statwidths) / sizeof(int),
                        (LPARAM)statwidths);

            /* Initialize progress bar */
            SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
            SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, 0, 0);

            /* Setting the icons */
            SendMessage(hwnd, WM_SETICON, ICON_SMALL,
                        (LPARAM)LoadIcon(GetModuleHandle(NULL),
                                         MAKEINTRESOURCE(IDI_CLAMAV_ICON)));
            SendMessage(hwnd, WM_SETICON, ICON_BIG,
                        (LPARAM)LoadIcon(GetModuleHandle(NULL),
                                         MAKEINTRESOURCE(IDI_CLAMAV_ICON)));

            /* Store main window handle */
            g_hMainWnd = hwnd;

            /* Initial status update */
            update_status(hwnd);

            if (clam_config.admin_access == 0) {
                MessageBox(hwnd, "Admin access required for scanning operations.\n\n"
                           "Please run as administrator.",
                           "Admin Access Required", MB_OK | MB_ICONWARNING);
            }
            break;
        }

        case WM_TIMER:
            if (wParam == TIMER_PROGRESS) {
                /* Read progress from status file */
                scan_progress progress;
                if (ReadScanProgress(&progress) == 0) {
                    /* Update progress bar */
                    SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, progress.progress_percent, 0);
                    
                    /* Update current folder */
                    SetDlgItemText(hwnd, IDC_CURRENT_FOLDER, progress.current_folder);
                    
                    /* Update progress text */
                    char progress_text[256];
                    snprintf(progress_text, sizeof(progress_text), "%s - %d%%", 
                             progress.message[0] ? progress.message : "Scanning...",
                             progress.progress_percent);
                    SetDlgItemText(hwnd, IDC_PROGRESS_TEXT, progress_text);
                    
                    /* Update status text */
                    char status_text[256];
                    snprintf(status_text, sizeof(status_text), "Status: %s Scan in progress...",
                             progress.scan_type[0] ? progress.scan_type : "");
                    SetDlgItemText(hwnd, IDC_STATUS_TEXT, status_text);
                }
            }
            break;

        case WM_SCAN_COMPLETE: {
            /* Stop progress timer */
            KillTimer(hwnd, TIMER_PROGRESS);
            
            /* Clean up thread handle */
            if (g_hScanThread) {
                CloseHandle(g_hScanThread);
                g_hScanThread = NULL;
            }
            
            /* Reset progress bar */
            SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, 100, 0);
            SetDlgItemText(hwnd, IDC_CURRENT_FOLDER, "");
            SetDlgItemText(hwnd, IDC_PROGRESS_TEXT, "");
            
            /* Show result */
            int result = (int)wParam;
            if (result == 0) {
                SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Scan completed successfully");
                MessageBox(hwnd, "Scan completed successfully.",
                         "Scan Complete", MB_OK | MB_ICONINFORMATION);
            } else {
                char error_msg[2048];
                snprintf(error_msg, sizeof(error_msg),
                         "Scan failed.\n\n%s",
                         clamav_get_last_error());
                SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Scan failed");
                MessageBox(hwnd, error_msg, "Error", MB_OK | MB_ICONERROR);
            }
            
            update_status(hwnd);
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case UI_MENU_SCAN_QUICK:
                    if (clam_config.admin_access) {
                        SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Starting Quick Scan...");
                        SetDlgItemText(hwnd, IDC_PROGRESS_TEXT, "Initializing...");
                        SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, 0, 0);
                        StartAsyncScan(hwnd, SCAN_TYPE_QUICK, NULL);
                    }
                    break;

                case UI_MENU_SCAN_FULL:
                    if (clam_config.admin_access) {
                        SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Starting Full Scan...");
                        SetDlgItemText(hwnd, IDC_PROGRESS_TEXT, "Initializing...");
                        SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, 0, 0);
                        StartAsyncScan(hwnd, SCAN_TYPE_FULL, NULL);
                    }
                    break;

                case UI_MENU_SCAN_CUSTOM:
                    if (clam_config.admin_access) {
                        char customPath[MAX_PATH] = "";
                        if (BrowseForFolder(hwnd, customPath, sizeof(customPath))) {
                            SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Starting Custom Scan...");
                            SetDlgItemText(hwnd, IDC_PROGRESS_TEXT, "Initializing...");
                            SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, 0, 0);
                            StartAsyncScan(hwnd, SCAN_TYPE_CUSTOM, customPath);
                        }
                    }
                    break;

                case UI_MENU_SCAN_STOP:
                    if (clam_config.admin_access) {
                        if (g_bScanRunning) {
                            StopAsyncScan();
                            SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Scan stopped");
                            SetDlgItemText(hwnd, IDC_CURRENT_FOLDER, "");
                            SetDlgItemText(hwnd, IDC_PROGRESS_TEXT, "");
                            SendDlgItemMessage(hwnd, IDC_PROGRESS_BAR, PBM_SETPOS, 0, 0);
                            MessageBox(hwnd, "Scan stopped.",
                                     "Stopped", MB_OK | MB_ICONINFORMATION);
                            update_status(hwnd);
                        } else {
                            MessageBox(hwnd, "No scan is currently running.",
                                     "Info", MB_OK | MB_ICONINFORMATION);
                        }
                    }
                    break;

                case UI_MENU_UPDATE_DB:
                    if (clam_config.admin_access) {
                        SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Updating Database...");
                        if (clamav_update_database() == 0) {
                            MessageBox(hwnd, "Database updated successfully.",
                                     "Update Complete", MB_OK | MB_ICONINFORMATION);
                        } else {
                            char error_msg[2048];
                            snprintf(error_msg, sizeof(error_msg),
                                     "Database update failed.\n\n%s",
                                     clamav_get_last_error());
                            MessageBox(hwnd, error_msg, "Error", MB_OK | MB_ICONERROR);
                        }
                        update_status(hwnd);
                    }
                    break;

                case UI_MENU_AUTO_SCAN:
                    if (clam_config.admin_access) {
                        DialogBox(GetModuleHandle(NULL),
                                 MAKEINTRESOURCE(IDD_AUTOSCAN_DIALOG),
                                 hwnd, AutoScanDlgProc);
                    }
                    break;

                case UI_MENU_VIEW_LOGS: {
                    char logPath[512];
                    snprintf(logPath, sizeof(logPath), "%s\\clamav\\logs\\clamscan.log", GetInstallDir());
                    ShellExecute(hwnd, "open", "notepad.exe", logPath, NULL, SW_SHOWNORMAL);
                    break;
                }

                case UI_MENU_HELP_ABOUT:
                    MessageBox(hwnd,
                             "Antivirus Manager v1.0\n\n"
                             "Advanced antivirus engine for detecting trojans, viruses, malware & other malicious threats.\n\n"
                             "Copyright (C) 2026, Monitoring Solutions Inc.",
                             "About Antivirus Manager",
                             MB_OK | MB_ICONINFORMATION);
                    break;

                case UI_MENU_MANAGE_EXIT:
                    PostMessage(hwnd, WM_CLOSE, 0, 0);
                    break;
            }
            break;

        case WM_CLOSE:
            /* Stop any running scan before closing */
            if (g_bScanRunning) {
                StopAsyncScan();
            }
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return FALSE;
    }
    return TRUE;
}

/* Main function */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    HWND hwnd;
    MSG Msg;
    INITCOMMONCONTROLSEX icc;

    /* Initialize COM for folder browser */
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    /* Initialize common controls */
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    /* Initialize install path detection first */
    InitInstallDir();

    /* Initialize config */
    clam_config.dir = (char*)GetInstallDir();
    clam_config.admin_access = IsUserAdmin();
    clam_config.status = ST_IDLE;
    clam_config.scan_in_progress = 0;
    clam_config.threats_found = 0;
    clam_config.files_scanned = 0;

    /* Initialize auto-scan config */
    auto_config.enabled = 0;
    auto_config.scan_type = SCAN_TYPE_QUICK;
    auto_config.interval_hours = 24;
    auto_config.custom_path[0] = '\0';

    /* Create main window */
    hwnd = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_MAIN_DIALOG), NULL, DlgProc);

    if (hwnd == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error",
                   MB_ICONEXCLAMATION | MB_OK);
        CoUninitialize();
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    /* Message loop */
    while (GetMessage(&Msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessage(hwnd, &Msg)) {
            TranslateMessage(&Msg);
            DispatchMessage(&Msg);
        }
    }

    CoUninitialize();
    return Msg.wParam;
}
