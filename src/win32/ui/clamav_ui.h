/* Copyright (C) 2026, Monitoring Solutions Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLAMAV_UI_H
#define CLAMAV_UI_H

#include <stdio.h>
#include <windows.h>
#include <winresrc.h>
#include <commctrl.h>

/* Default values */
#define CLAMAV_SERVICE    "ClamAV"

/* Dynamic path - detected at runtime */
#define MAX_INSTALL_PATH    512
extern char g_InstallDir[MAX_INSTALL_PATH];
void InitInstallDir(void);
const char* GetInstallDir(void);

/* Scan types */
#define SCAN_TYPE_QUICK     1
#define SCAN_TYPE_FULL      2
#define SCAN_TYPE_CUSTOM    3

/* Status messages */
#define ST_IDLE             "Idle"
#define ST_SCANNING         "Scanning..."
#define ST_UPDATING         "Updating Database..."
#define ST_COMPLETED        "Scan Completed"

/* Global ClamAV config structure */
typedef struct _clamav_config {
    unsigned short int admin_access;
    char *dir;
    char *status;
    int scan_in_progress;
    int threats_found;
    int files_scanned;
} clamav_config;

/* Auto-scan schedule configuration */
typedef struct _autoscan_config {
    int enabled;
    int scan_type;          /* SCAN_TYPE_QUICK or SCAN_TYPE_FULL */
    int interval_hours;     /* Interval in hours (1, 6, 12, 24, 168 for weekly) */
    char custom_path[MAX_PATH];
} autoscan_config;

/* Scan progress structure for async operations */
typedef struct _scan_progress {
    int scanning;
    char current_folder[MAX_PATH];
    int files_scanned;
    int threats_found;
    int progress_percent;
    char scan_type[32];
    char message[256];
} scan_progress;

/* Thread parameter structure */
typedef struct _scan_thread_params {
    HWND hwnd;
    int scan_type;
    char custom_path[MAX_PATH];
} scan_thread_params;

/** Global variables **/

/* Configuration */
extern clamav_config clam_config;
extern autoscan_config auto_config;
extern scan_progress g_scan_progress;

/* Status bar */
extern HWND hStatus;

/* Thread handle for async operations */
extern HANDLE g_hScanThread;
extern volatile BOOL g_bScanRunning;

/* Custom window messages */
#define WM_SCAN_COMPLETE    (WM_USER + 100)
#define WM_SCAN_PROGRESS    (WM_USER + 101)
#define WM_SCAN_ERROR       (WM_USER + 102)

/* Timer ID for progress updates */
#define TIMER_PROGRESS      1001
#define TIMER_PROGRESS_INTERVAL 500  /* 500ms */

/* ClamAV icon */
#define IDI_CLAMAV_ICON     401
#define UI_MANIFEST_ID      1

/* Dialog IDs */
#define IDD_MAIN_DIALOG     100
#define IDD_ABOUT_DIALOG    101
#define IDD_AUTOSCAN_DIALOG 102
#define IDD_CUSTOMSCAN_DLG  103

/* User input */
#define UI_ID_CLOSE         1510
#define UI_ID_BROWSE        1511
#define UI_ID_PATH_EDIT     1512
#define UI_ID_ENABLE_AUTO   1513
#define UI_ID_INTERVAL_COMBO 1514
#define UI_ID_SCANTYPE_COMBO 1515

/* Menu values */
#define UI_MENU_SCAN_QUICK      1701
#define UI_MENU_SCAN_FULL       1702
#define UI_MENU_SCAN_CUSTOM     1703
#define UI_MENU_SCAN_STOP       1704
#define UI_MENU_UPDATE_DB       1705
#define UI_MENU_AUTO_SCAN       1706
#define UI_MENU_MANAGE_EXIT     1707
#define UI_MENU_VIEW_LOGS       1708
#define UI_MENU_HELP_ABOUT      1709
#define UI_MENU_NONE            1710

/* Status window */
#define IDC_MAIN_STATUS     1801
#define IDC_STATUS_TEXT     1802
#define IDC_PROGRESS_BAR    1803
#define IDC_SCAN_INFO       1804
#define IDC_LAST_SCAN       1805
#define IDC_CURRENT_FOLDER  1806
#define IDC_PROGRESS_TEXT   1807

/* Functions */
int execute_powershell(const char* command, char* output, size_t output_size);
int clamav_quick_scan(void);
int clamav_full_scan(void);
int clamav_custom_scan(const char* path);
int clamav_stop_scan(void);
int clamav_update_database(void);
int clamav_get_scan_status(void);
int clamav_configure_autoscan(int enabled, int scan_type, int interval_hours);
const char* clamav_get_last_error(void);
void update_status(HWND hwnd);
BOOL IsUserAdmin(void);

/* Async scan functions */
DWORD WINAPI ScanThreadProc(LPVOID lpParam);
void StartAsyncScan(HWND hwnd, int scan_type, const char* custom_path);
void StopAsyncScan(void);
int ReadScanProgress(scan_progress* progress);

#endif /* CLAMAV_UI_H */

