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
#include <string.h>
#include <stdio.h>
#include "suricata_ui.h"

suricata_config suri_config;
HWND hStatus;
HWND g_hMainWnd = NULL;
HANDLE g_hOpThread = NULL;
volatile BOOL g_bOperationRunning = FALSE;

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
                
                /* If we're in ui, bin, or similar subdirectory, go up one or two levels */
                if (_stricmp(folderName, "ui") == 0 || 
                    _stricmp(folderName, "bin") == 0 ||
                    _stricmp(folderName, "suricata") == 0) {
                    *parentSlash = '\0';
                    
                    /* Check if we need to go up one more level (for monitoring-agent\suricata\ui) */
                    parentSlash = strrchr(modulePath, '\\');
                    if (parentSlash) {
                        char *grandparentFolder = parentSlash + 1;
                        if (_stricmp(grandparentFolder, "suricata") == 0) {
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

const char* suricata_get_last_error() {
    return last_error_msg;
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
    char cmdline[8192];  /* Increased buffer size for long commands */
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

    /* Wait for process to complete - increased timeout for Suricata start */
    WaitForSingleObject(pi.hProcess, 60000);

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return (exitCode == 0) ? 0 : -1;
}

/* Get Suricata status using PowerShell script */
int suricata_get_status() {
    char command[2048];
    char output[4096];
    const char* installDir = GetInstallDir();
    
    /* Try to find the script - handle cases where .ps1 extension might be hidden or missing */
    snprintf(command, sizeof(command),
             "$ErrorActionPreference = 'Stop'; "
             "try { "
             "$scriptPath = '%s\\suricata'; "
             "$script = $null; "
             "if (Test-Path (Join-Path $scriptPath 'SuricataControl.ps1')) { "
             "$script = Join-Path $scriptPath 'SuricataControl.ps1' } "
             "elseif (Test-Path (Join-Path $scriptPath 'SuricataControl')) { "
             "$script = Join-Path $scriptPath 'SuricataControl' } "
             "if ($script -and (Test-Path $script)) { "
             "$output = & $script status 2>&1; "
             "if ($output -match 'RUNNING' -or $output -match 'Status: RUNNING') { Write-Output 'RUNNING' } else { Write-Output 'STOPPED' } "
             "} else { Write-Output 'SCRIPT_NOT_FOUND' } "
             "} catch { Write-Output \"ERROR: $_\" }",
             installDir);

    if (execute_powershell(command, output, sizeof(output)) >= 0) {
        if (strstr(output, "RUNNING") != NULL) {
            return 1;
        } else if (strstr(output, "STOPPED") != NULL) {
            return 0;
        }
    }

    return -1;
}

/* Start Suricata using PowerShell script */
int suricata_start() {
    char command[2048];
    char output[8192];
    const char* installDir = GetInstallDir();

    last_error_msg[0] = '\0';

    /* Execute SuricataControl.ps1 start */
    snprintf(command, sizeof(command),
             "$ErrorActionPreference = 'Continue'; "
             "try { "
             "$scriptPath = '%s\\suricata'; "
             "$script = $null; "
             "if (Test-Path (Join-Path $scriptPath 'SuricataControl.ps1')) { "
             "$script = Join-Path $scriptPath 'SuricataControl.ps1' } "
             "elseif (Test-Path (Join-Path $scriptPath 'SuricataControl')) { "
             "$script = Join-Path $scriptPath 'SuricataControl' } "
             "if ($script -and (Test-Path $script)) { "
             "$result = & $script start 2>&1; "
             "Write-Output $result; "
             "if ($LASTEXITCODE -eq 0) { Write-Output 'SUCCESS'; "
             "$setupScript = Join-Path $scriptPath 'setup-log-clear-task.ps1'; "
             "if (Test-Path $setupScript) { & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $setupScript | Out-Null } } "
             "} else { "
             "$paths = @((Join-Path $scriptPath 'SuricataControl.ps1'), (Join-Path $scriptPath 'SuricataControl')); "
             "Write-Output ('SCRIPT_NOT_FOUND: Tried paths: ' + ($paths -join ', ')) "
             "} "
             "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
             installDir);

    execute_powershell(command, output, sizeof(output));
    
    if (strstr(output, "SUCCESS") != NULL || strstr(output, "started successfully") != NULL || 
        strstr(output, "already running") != NULL) {
        return 0;
    }
    
    /* Store error message */
    strncpy(last_error_msg, output, sizeof(last_error_msg) - 1);
    last_error_msg[sizeof(last_error_msg) - 1] = '\0';

    return -1;
}

/* Stop Suricata using PowerShell script with aggressive cleanup */
int suricata_stop() {
    char command[4096];
    char output[8192];
    const char* installDir = GetInstallDir();

    last_error_msg[0] = '\0';

    /* Execute SuricataControl.ps1 stop with aggressive cleanup as fallback */
    snprintf(command, sizeof(command),
             "$ErrorActionPreference = 'Continue'; "
             "try { "
             "$scriptPath = '%s\\suricata'; "
             "$script = $null; "
             "if (Test-Path (Join-Path $scriptPath 'SuricataControl.ps1')) { "
             "$script = Join-Path $scriptPath 'SuricataControl.ps1' } "
             "elseif (Test-Path (Join-Path $scriptPath 'SuricataControl')) { "
             "$script = Join-Path $scriptPath 'SuricataControl' } "
             "if ($script -and (Test-Path $script)) { "
             "$result = & $script stop 2>&1; "
             "Write-Output $result; "
             "} "
             "$rmScript = Join-Path $scriptPath 'remove-log-clear-task.ps1'; "
             "if (Test-Path $rmScript) { & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $rmScript | Out-Null } "
             /* Aggressive cleanup - always try to kill any remaining suricata.exe */
             "$procs = Get-Process -Name 'suricata' -ErrorAction SilentlyContinue; "
             "if ($procs) { "
             "$procs | Stop-Process -Force -ErrorAction SilentlyContinue; "
             "Write-Output 'Forced stop of remaining processes'; "
             "} "
             /* Also try taskkill as backup */
             "$null = cmd /c 'taskkill /F /IM suricata.exe 2>nul'; "
             /* Clean up PID file */
             "$pidFile = Join-Path '%s' 'state\\suricata.pid'; "
             "if (Test-Path $pidFile) { Remove-Item $pidFile -Force -ErrorAction SilentlyContinue } "
             /* Verify stopped */
             "Start-Sleep -Milliseconds 500; "
             "$remaining = Get-Process -Name 'suricata' -ErrorAction SilentlyContinue; "
             "if (-not $remaining) { Write-Output 'STOP_SUCCESS' } else { Write-Output 'STOP_PARTIAL' } "
             "} catch { Write-Output (\"ERROR: \" + $_.Exception.Message) }",
             installDir, installDir);

    execute_powershell(command, output, sizeof(output));
    
    if (strstr(output, "STOP_SUCCESS") != NULL || 
        strstr(output, "stopped successfully") != NULL || 
        strstr(output, "not running") != NULL ||
        strstr(output, "Suricata stopped") != NULL) {
        return 0;
    }
    
    /* Even partial success is still success if we tried */
    if (strstr(output, "STOP_PARTIAL") != NULL || strstr(output, "Forced stop") != NULL) {
        return 0;
    }
    
    /* Store error message */
    strncpy(last_error_msg, output, sizeof(last_error_msg) - 1);
    last_error_msg[sizeof(last_error_msg) - 1] = '\0';

    return -1;
}

/* Update status display */
void update_status(HWND hwnd) {
    int status = suricata_get_status();
    char status_text[256];

    if (status == 1) {
        snprintf(status_text, sizeof(status_text), "Status: %s", ST_RUNNING);
        suri_config.status = ST_RUNNING;
    } else if (status == 0) {
        snprintf(status_text, sizeof(status_text), "Status: %s", ST_STOPPED);
        suri_config.status = ST_STOPPED;
    } else {
        snprintf(status_text, sizeof(status_text), "Status: %s", ST_UNKNOWN);
        suri_config.status = ST_UNKNOWN;
    }

    SetDlgItemText(hwnd, IDC_STATUS_TEXT, status_text);
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)status_text);
}

/* Operation thread procedure for async start/stop */
DWORD WINAPI OperationThreadProc(LPVOID lpParam) {
    operation_params* params = (operation_params*)lpParam;
    int result = -1;
    
    if (!params) return 1;
    
    g_bOperationRunning = TRUE;
    
    switch (params->operation) {
        case OP_START:
            result = suricata_start();
            break;
        case OP_STOP:
            result = suricata_stop();
            break;
    }
    
    g_bOperationRunning = FALSE;
    
    /* Notify main window of completion */
    if (params->hwnd) {
        PostMessage(params->hwnd, WM_OPERATION_COMPLETE, (WPARAM)result, (LPARAM)params->operation);
    }
    
    free(params);
    return 0;
}

/* Start async operation */
void StartAsyncOperation(HWND hwnd, int operation) {
    operation_params* params;
    
    /* Check if operation already running - but first check if stale thread handle */
    if (g_hOpThread != NULL) {
        DWORD exitCode;
        if (GetExitCodeThread(g_hOpThread, &exitCode)) {
            if (exitCode == STILL_ACTIVE) {
                /* Thread is truly still running */
                MessageBox(hwnd, "An operation is already in progress.", "Please Wait", MB_OK | MB_ICONINFORMATION);
                return;
            }
            /* Thread has finished but handle wasn't cleaned up - clean it now */
            CloseHandle(g_hOpThread);
            g_hOpThread = NULL;
            g_bOperationRunning = FALSE;
        } else {
            /* GetExitCodeThread failed - assume stale handle and clean up */
            CloseHandle(g_hOpThread);
            g_hOpThread = NULL;
            g_bOperationRunning = FALSE;
        }
    }
    
    /* Double check the running flag */
    if (g_bOperationRunning) {
        MessageBox(hwnd, "An operation is already in progress.", "Please Wait", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    /* Allocate parameters */
    params = (operation_params*)malloc(sizeof(operation_params));
    if (!params) {
        MessageBox(hwnd, "Failed to allocate memory.", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    params->hwnd = hwnd;
    params->operation = operation;
    
    /* Create thread */
    g_hOpThread = CreateThread(NULL, 0, OperationThreadProc, params, 0, NULL);
    if (!g_hOpThread) {
        free(params);
        MessageBox(hwnd, "Failed to start operation.", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    g_hMainWnd = hwnd;
}

/* Dialog -- About Suricata UI */
INT_PTR CALLBACK AboutDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch (Message) {
        case WM_CREATE:
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
            suri_config.admin_access = IsUserAdmin();

            if (suri_config.admin_access == 0) {
                menuflags = MF_STRING | MF_GRAYED;
            }

            hMenu = CreateMenu();

            /* Creating management menu */
            hSubMenu = CreatePopupMenu();
            AppendMenu(hSubMenu, menuflags, UI_MENU_MANAGE_START, "&Start Service");
            AppendMenu(hSubMenu, menuflags, UI_MENU_MANAGE_STOP, "&Stop Service");
            AppendMenu(hSubMenu, MF_SEPARATOR, UI_MENU_NONE, "");
            AppendMenu(hSubMenu, menuflags, UI_MENU_MANAGE_STATUS, "&Refresh Status");
            AppendMenu(hSubMenu, MF_SEPARATOR, UI_MENU_NONE, "");
            AppendMenu(hSubMenu, MF_STRING, UI_MENU_MANAGE_EXIT, "&Exit");
            AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT_PTR)hSubMenu, "&Manage");

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

            /* Setting the icons */
            SendMessage(hwnd, WM_SETICON, ICON_SMALL,
                        (LPARAM)LoadIcon(GetModuleHandle(NULL),
                                         MAKEINTRESOURCE(IDI_SURICATA_ICON)));
            SendMessage(hwnd, WM_SETICON, ICON_BIG,
                        (LPARAM)LoadIcon(GetModuleHandle(NULL),
                                         MAKEINTRESOURCE(IDI_SURICATA_ICON)));

            /* Store main window handle */
            g_hMainWnd = hwnd;

            /* Initial status update */
            update_status(hwnd);

            if (suri_config.admin_access == 0) {
                MessageBox(hwnd, "Admin access required to start/stop Network Security service.\n\n"
                           "Please run as administrator.",
                           "Admin Access Required", MB_OK | MB_ICONWARNING);
            }
            break;
        }

        case WM_OPERATION_COMPLETE: {
            int result = (int)wParam;
            int operation = (int)lParam;
            
            /* Clean up thread handle */
            if (g_hOpThread) {
                CloseHandle(g_hOpThread);
                g_hOpThread = NULL;
            }
            
            /* Show result */
            if (operation == OP_START) {
                if (result == 0) {
                    MessageBox(hwnd, "Network Security service started successfully.",
                             "Success", MB_OK | MB_ICONINFORMATION);
                } else {
                    char error_msg[3072];
                    const char* last_error = suricata_get_last_error();
                    snprintf(error_msg, sizeof(error_msg),
                             "Failed to start Network Security service.\n\n"
                             "Error Details:\n%s\n\n"
                             "Please check:\n"
                             "1. Configuration files are present\n"
                             "2. Service binary is present\n"
                             "3. Network interfaces are available\n"
                             "4. Network capture driver is properly installed",
                             last_error && last_error[0] ? last_error : "Unknown error");
                    MessageBox(hwnd, error_msg, "Error", MB_OK | MB_ICONERROR);
                }
            } else if (operation == OP_STOP) {
                if (result == 0) {
                    MessageBox(hwnd, "Network Security service stopped successfully.",
                             "Success", MB_OK | MB_ICONINFORMATION);
                } else {
                    char error_msg[2048];
                    const char* last_error = suricata_get_last_error();
                    snprintf(error_msg, sizeof(error_msg),
                             "Failed to stop Network Security service.\n\n"
                             "Error Details:\n%s",
                             last_error && last_error[0] ? last_error : "Unknown error");
                    MessageBox(hwnd, error_msg, "Error", MB_OK | MB_ICONERROR);
                }
            }
            
            update_status(hwnd);
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case UI_MENU_MANAGE_START:
                    if (suri_config.admin_access) {
                        SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Starting service...");
                        StartAsyncOperation(hwnd, OP_START);
                    }
                    break;

                case UI_MENU_MANAGE_STOP:
                    if (suri_config.admin_access) {
                        SetDlgItemText(hwnd, IDC_STATUS_TEXT, "Status: Stopping service...");
                        StartAsyncOperation(hwnd, OP_STOP);
                    }
                    break;

                case UI_MENU_MANAGE_STATUS:
                    update_status(hwnd);
                    break;

                case UI_MENU_VIEW_LOGS: {
                    char logPath[512];
                    snprintf(logPath, sizeof(logPath), "%s\\suricata\\log\\suricata.log", GetInstallDir());
                    ShellExecute(hwnd, "open", "notepad.exe", logPath, NULL, SW_SHOWNORMAL);
                    break;
                }

                case UI_MENU_HELP_ABOUT:
                    MessageBox(hwnd,
                             "Network Security Manager v1.0\n\n"
                             "Advanced network intrusion detection and prevention system.\n\n"
                             "Copyright (C) 2026, Monitoring Solutions Inc.",
                             "About",
                             MB_OK | MB_ICONINFORMATION);
                    break;

                case UI_MENU_MANAGE_EXIT:
                    PostMessage(hwnd, WM_CLOSE, 0, 0);
                    break;
            }
            break;

        case WM_CLOSE:
            /* Wait for any running operation */
            if (g_bOperationRunning && g_hOpThread) {
                WaitForSingleObject(g_hOpThread, 5000);
                CloseHandle(g_hOpThread);
                g_hOpThread = NULL;
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

    /* Initialize common controls */
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    /* Initialize install path detection first */
    InitInstallDir();

    /* Initialize config */
    suri_config.dir = (char*)GetInstallDir();
    suri_config.admin_access = IsUserAdmin();
    suri_config.status = ST_UNKNOWN;

    /* Create main window */
    hwnd = CreateDialog(hInstance, MAKEINTRESOURCE(100), NULL, DlgProc);

    if (hwnd == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error",
                   MB_ICONEXCLAMATION | MB_OK);
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

    return Msg.wParam;
}
