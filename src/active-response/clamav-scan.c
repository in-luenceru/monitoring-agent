/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "active_responses.h"
#include "dll_load_notify.h"

int main (int argc, char **argv) {
    // This must be always the first instruction
    enable_dll_verification();

    (void)argc;
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
    cJSON *input_json = NULL;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Only process ADD commands (trigger scan)
    // DELETE commands are ignored as scans are one-time operations
    if (action == DELETE_COMMAND) {
        write_debug_file(argv[0], "DELETE command ignored for ClamAV scan");
        cJSON_Delete(input_json);
        return OS_SUCCESS;
    }

    // Extract scan parameters from extra_args
    const char *scan_type = "quickscan"; // Default to quick scan
    const char *scan_path = NULL;
    
    cJSON *extra_args = cJSON_GetObjectItem(input_json, "parameters");
    if (extra_args && cJSON_IsObject(extra_args)) {
        // Try to get parameters from alert data (log injection)
        cJSON *alert_node = cJSON_GetObjectItem(extra_args, "alert");
        if (alert_node && cJSON_IsObject(alert_node)) {
            cJSON *data_node = cJSON_GetObjectItem(alert_node, "data");
            if (data_node && cJSON_IsObject(data_node)) {
                cJSON *type_item = cJSON_GetObjectItem(data_node, "scan_type");
                if (type_item && cJSON_IsString(type_item)) {
                    scan_type = type_item->valuestring;
                }
                
                cJSON *path_item = cJSON_GetObjectItem(data_node, "scan_path");
                if (path_item && cJSON_IsString(path_item)) {
                    scan_path = path_item->valuestring;
                }
            }
        }

        // Fallback: Check direct parameters (if passed via active-response args)
        if (strcmp(scan_type, "quickscan") == 0) {
            cJSON *type_item = cJSON_GetObjectItem(extra_args, "scan_type");
            if (type_item && cJSON_IsString(type_item)) {
                scan_type = type_item->valuestring;
            }
            
            cJSON *path_item = cJSON_GetObjectItem(extra_args, "scan_path");
            if (path_item && cJSON_IsString(path_item)) {
                scan_path = path_item->valuestring;
            }
        }
    }

    // Validate scan type
    if (strcmp(scan_type, "quickscan") != 0 && 
        strcmp(scan_type, "fullscan") != 0 && 
        strcmp(scan_type, "customscan") != 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Invalid scan type: %s. Using quickscan.", scan_type);
        write_debug_file(argv[0], log_msg);
        scan_type = "quickscan";
    }

    // Build PowerShell command
    char ps_script[OS_MAXSTR];
    char ps_args[OS_MAXSTR];
    
    // Get the installation directory (parent of active-response directory)
    char install_dir[OS_MAXSTR];
    memset(install_dir, '\0', OS_MAXSTR);
    
    // Get the directory where this executable is located
    char *last_back = strrchr(argv[0], '\\');
    char *last_fwd = strrchr(argv[0], '/');
    char *last_slash = NULL;

    if (last_back && last_fwd) {
        last_slash = (last_back > last_fwd) ? last_back : last_fwd;
    } else if (last_back) {
        last_slash = last_back;
    } else {
        last_slash = last_fwd;
    }

    if (last_slash) {
        size_t dir_len = last_slash - argv[0];
        if (dir_len < OS_MAXSTR - 1) {
            strncpy(install_dir, argv[0], dir_len);
            install_dir[dir_len] = '\0';
        }
    }
    
    // Navigate up to installation root and locate ClamAV script
    // active-response/bin -> active-response -> root -> clamav
    snprintf(ps_script, OS_MAXSTR -1, "%s\\..\\..\\clamav\\ClamAVControl.ps1", install_dir);
    
    // Build arguments based on scan type
    if (strcmp(scan_type, "customscan") == 0 && scan_path) {
        snprintf(ps_args, OS_MAXSTR -1, 
                 "-ExecutionPolicy Bypass -NoProfile -File \"%s\" customscan \"%s\"",
                 ps_script, scan_path);
    } else {
        snprintf(ps_args, OS_MAXSTR -1, 
                 "-ExecutionPolicy Bypass -NoProfile -File \"%s\" %s",
                 ps_script, scan_type);
    }

    memset(log_msg, '\0', OS_MAXSTR);
    snprintf(log_msg, OS_MAXSTR -1, "Triggering ClamAV scan: %s", scan_type);
    write_debug_file(argv[0], log_msg);

    // Execute PowerShell command
    char *powershell_path = NULL;
    wfd_t *wfd = NULL;

    // Try to find PowerShell
    if (get_binary_path("powershell.exe", &powershell_path) < 0) {
        // Fallback to default path
        powershell_path = strdup("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    }

    // Build command array for wpopenv
    char *exec_args[10];
    int arg_idx = 0;
    
    exec_args[arg_idx++] = powershell_path;
    exec_args[arg_idx++] = "-ExecutionPolicy";
    exec_args[arg_idx++] = "Bypass";
    exec_args[arg_idx++] = "-NoProfile";
    exec_args[arg_idx++] = "-File";
    exec_args[arg_idx++] = ps_script;
    exec_args[arg_idx++] = (char *)scan_type;
    
    if (strcmp(scan_type, "customscan") == 0 && scan_path) {
        exec_args[arg_idx++] = (char *)scan_path;
    }
    
    exec_args[arg_idx] = NULL;

    wfd = wpopenv(powershell_path, exec_args, W_BIND_STDERR);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, 
                 "Unable to execute ClamAV scan: %s", strerror(errno));
        write_debug_file(argv[0], log_msg);
        os_free(powershell_path);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Read output
    char output_buf[OS_MAXSTR];
    while (fgets(output_buf, OS_MAXSTR -1, wfd->file_out)) {
        // Log PowerShell output
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "ClamAV output: %s", output_buf);
        write_debug_file(argv[0], log_msg);
    }

    wpclose(wfd);
    os_free(powershell_path);

    memset(log_msg, '\0', OS_MAXSTR);
    snprintf(log_msg, OS_MAXSTR -1, "ClamAV scan completed: %s", scan_type);
    write_debug_file(argv[0], log_msg);

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}

#endif
