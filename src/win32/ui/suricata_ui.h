/* Copyright (C) 2026, Monitoring Solutions Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SURICATA_UI_H
#define SURICATA_UI_H

#include <stdio.h>
#include <windows.h>
#include <winresrc.h>
#include <commctrl.h>

/* Default values */
#define SURICATA_SERVICE    "Suricata"

/* Dynamic path - detected at runtime */
#define MAX_INSTALL_PATH    512
extern char g_InstallDir[MAX_INSTALL_PATH];
void InitInstallDir(void);
const char* GetInstallDir(void);

/* Status messages */
#define ST_RUNNING          "Running"
#define ST_STOPPED          "Stopped"
#define ST_UNKNOWN          "Unknown"

/* Operation types for async */
#define OP_START    1
#define OP_STOP     2

/* Global Suricata config structure */
typedef struct _suricata_config {
    unsigned short int admin_access;
    char *dir;
    char *status;
} suricata_config;

/* Thread parameter structure for async operations */
typedef struct _operation_params {
    HWND hwnd;
    int operation;
} operation_params;

/** Global variables **/

/* Configuration */
extern suricata_config suri_config;

/* Status bar */
extern HWND hStatus;

/* Thread handle for async operations */
extern HANDLE g_hOpThread;
extern volatile BOOL g_bOperationRunning;

/* Custom window messages */
#define WM_OPERATION_COMPLETE   (WM_USER + 100)

/* Suricata icon */
#define IDI_SURICATA_ICON  301
#define UI_MANIFEST_ID     1

/* User input */
#define UI_ID_CLOSE         1510

/* Menu values */
#define UI_MENU_MANAGE_STOP     1701
#define UI_MENU_MANAGE_START    1702
#define UI_MENU_MANAGE_STATUS   1703
#define UI_MENU_MANAGE_EXIT     1704
#define UI_MENU_VIEW_LOGS       1705
#define UI_MENU_HELP_ABOUT      1706
#define UI_MENU_NONE            1707

/* Status window */
#define IDC_MAIN_STATUS     1801
#define IDC_STATUS_TEXT     1802

/* Functions */
int execute_powershell(const char* command, char* output, size_t output_size);
int suricata_get_status(void);
int suricata_start(void);
int suricata_stop(void);
const char* suricata_get_last_error(void);
void update_status(HWND hwnd);
BOOL IsUserAdmin(void);

/* Async operation functions */
DWORD WINAPI OperationThreadProc(LPVOID lpParam);
void StartAsyncOperation(HWND hwnd, int operation);

#endif /* SURICATA_UI_H */

