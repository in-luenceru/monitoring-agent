/*/*#define _GNU_SOURCE

 * Windows Bypass Library for Monitoring Agent

 * Handles Windows execution policy and permission bypasses * Windows Bypass Library for Monitoring Agent#include <stdio.h>

 * Copyright (C) 2025, Monitoring Solutions Inc.

 * Version: 1.0.0 * Handles Windows execution policy and permission bypasses#include <stdlib.h>

 */

 * Copyright (C) 2025, Monitoring Solutions Inc.#include <string.h>

#include <windows.h>

#include <stdio.h> * Version: 1.0.0#include <pwd.h>

#include <stdlib.h>

#include <string.h> */#include <grp.h>

#include <aclapi.h>

#include <sddl.h>#include <unistd.h>



#define DLL_EXPORT __declspec(dllexport)#include <windows.h>#include <sys/types.h>



// Function prototypes#include <stdio.h>#include <dlfcn.h>

DLL_EXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

DLL_EXPORT int bypass_execution_policy(void);#include <stdlib.h>#include <errno.h>

DLL_EXPORT int enable_debug_privileges(void);

DLL_EXPORT int bypass_file_permissions(const char* filepath);#include <string.h>

DLL_EXPORT int set_environment_bypass(void);

#include <aclapi.h>// Function pointers for original functions

// Global variables

static HINSTANCE g_hInstance = NULL;#include <sddl.h>static struct passwd *(*original_getpwnam)(const char *name) = NULL;

static BOOL g_bypass_enabled = FALSE;

static struct group *(*original_getgrnam)(const char *name) = NULL;

// DLL entry point

DLL_EXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {#define DLL_EXPORT __declspec(dllexport)static int (*original_getpwnam_r)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) = NULL;

    (void)lpvReserved; // Suppress unused parameter warning

    static int (*original_getgrnam_r)(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result) = NULL;

    switch (fdwReason) {

        case DLL_PROCESS_ATTACH:// Function prototypesstatic struct passwd *(*original_getpwuid)(uid_t uid) = NULL;

            g_hInstance = hinstDLL;

            DisableThreadLibraryCalls(hinstDLL);DLL_EXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);static struct group *(*original_getgrgid)(gid_t gid) = NULL;

            // Auto-enable bypasses when DLL is loaded

            bypass_execution_policy();DLL_EXPORT int bypass_execution_policy(void);

            enable_debug_privileges();

            set_environment_bypass();DLL_EXPORT int enable_debug_privileges(void);// Static storage for fake user/group entries

            g_bypass_enabled = TRUE;

            break;DLL_EXPORT int bypass_file_permissions(const char* filepath);static struct passwd fake_user;

        case DLL_PROCESS_DETACH:

            g_bypass_enabled = FALSE;DLL_EXPORT int set_environment_bypass(void);static struct group fake_group;

            break;

    }static char user_name_buf[32] = "monitoring";

    return TRUE;

}// Global variablesstatic char user_shell_buf[64] = "/bin/bash";



// Bypass PowerShell execution policy restrictionsstatic HINSTANCE g_hInstance = NULL;static char user_dir_buf[128] = "/workspaces/monitoring-agent";

DLL_EXPORT int bypass_execution_policy(void) {

    HKEY hKey;static BOOL g_bypass_enabled = FALSE;static char group_name_buf[32] = "monitoring";

    const char* unrestricted = "Unrestricted";

    static char *group_members[] = {NULL};

    // Set execution policy for current user

    if (RegOpenKeyExA(HKEY_CURRENT_USER, // DLL entry point

                     "Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",

                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {DLL_EXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {// Environment check to enable/disable bypass

        RegSetValueExA(hKey, "ExecutionPolicy", 0, REG_SZ, 

                      (const BYTE*)unrestricted, (DWORD)strlen(unrestricted) + 1);    (void)lpvReserved; // Suppress unused parameter warningstatic int bypass_enabled() {

        RegCloseKey(hKey);

    }        static int checked = 0;

    

    // Set execution policy for local machine (requires admin)    switch (fdwReason) {    static int enabled = 1;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 

                     "Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",        case DLL_PROCESS_ATTACH:    

                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {

        RegSetValueExA(hKey, "ExecutionPolicy", 0, REG_SZ,             g_hInstance = hinstDLL;    if (!checked) {

                      (const BYTE*)unrestricted, (DWORD)strlen(unrestricted) + 1);

        RegCloseKey(hKey);            DisableThreadLibraryCalls(hinstDLL);        char *disable_bypass = getenv("DISABLE_WAZUH_BYPASS");

    }

                // Auto-enable bypasses when DLL is loaded        if (disable_bypass && strcmp(disable_bypass, "1") == 0) {

    return 0;

}            bypass_execution_policy();            enabled = 0;



// Enable debug privileges for process monitoring            enable_debug_privileges();        }

DLL_EXPORT int enable_debug_privileges(void) {

    HANDLE hToken;            set_environment_bypass();        checked = 1;

    TOKEN_PRIVILEGES tkp;

                g_bypass_enabled = TRUE;    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {

        return -1;            break;    return enabled;

    }

            case DLL_PROCESS_DETACH:}

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {

        CloseHandle(hToken);            g_bypass_enabled = FALSE;

        return -1;

    }            break;// Initialize function pointers

    

    tkp.PrivilegeCount = 1;    }static void init_original_functions() {

    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        return TRUE;    if (!original_getpwnam) {

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0)) {

        CloseHandle(hToken);}        original_getpwnam = dlsym(RTLD_NEXT, "getpwnam");

        return -1;

    }    }

    

    CloseHandle(hToken);// Bypass PowerShell execution policy restrictions    if (!original_getgrnam) {

    return (GetLastError() == ERROR_SUCCESS) ? 0 : -1;

}DLL_EXPORT int bypass_execution_policy(void) {        original_getgrnam = dlsym(RTLD_NEXT, "getgrnam");



// Bypass file permission restrictions    HKEY hKey;    }

DLL_EXPORT int bypass_file_permissions(const char* filepath) {

    if (filepath == NULL) return -1;    const char* unrestricted = "Unrestricted";    if (!original_getpwnam_r) {

    

    // Try to set file attributes to allow access            original_getpwnam_r = dlsym(RTLD_NEXT, "getpwnam_r");

    DWORD attrs = GetFileAttributesA(filepath);

    if (attrs != INVALID_FILE_ATTRIBUTES) {    // Set execution policy for current user    }

        // Remove read-only and system attributes

        attrs &= ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM);    if (RegOpenKeyExA(HKEY_CURRENT_USER,     if (!original_getgrnam_r) {

        SetFileAttributesA(filepath, attrs);

    }                     "Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",        original_getgrnam_r = dlsym(RTLD_NEXT, "getgrnam_r");

    

    // Try to take ownership of the file                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {    }

    HANDLE hFile = CreateFileA(filepath, WRITE_OWNER, 

                              FILE_SHARE_READ | FILE_SHARE_WRITE,         RegSetValueExA(hKey, "ExecutionPolicy", 0, REG_SZ,     if (!original_getpwuid) {

                              NULL, OPEN_EXISTING, 

                              FILE_ATTRIBUTE_NORMAL, NULL);                      (const BYTE*)unrestricted, (DWORD)strlen(unrestricted) + 1);        original_getpwuid = dlsym(RTLD_NEXT, "getpwuid");

    

    if (hFile != INVALID_HANDLE_VALUE) {        RegCloseKey(hKey);    }

        // Get current user SID

        HANDLE hToken;    }    if (!original_getgrgid) {

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {

            DWORD dwSize = 0;            original_getgrgid = dlsym(RTLD_NEXT, "getgrgid");

            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

                // Set execution policy for local machine (requires admin)    }

            if (dwSize > 0) {

                PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, }

                if (pTokenUser != NULL) {

                    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {                     "Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",

                        // Set owner to current user

                        SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {// Initialize fake user structure

                                        pTokenUser->User.Sid, NULL, NULL, NULL);

                    }        RegSetValueExA(hKey, "ExecutionPolicy", 0, REG_SZ, static void init_fake_user() {

                    free(pTokenUser);

                }                      (const BYTE*)unrestricted, (DWORD)strlen(unrestricted) + 1);    static int initialized = 0;

            }

            CloseHandle(hToken);        RegCloseKey(hKey);    if (initialized) return;

        }

        CloseHandle(hFile);    }    

    }

            fake_user.pw_name = user_name_buf;

    return 0;

}    return 0;    fake_user.pw_passwd = "x";



// Set environment variables for bypass}    fake_user.pw_uid = getuid(); // Use current user's UID

DLL_EXPORT int set_environment_bypass(void) {

    // Set environment variables that may help with execution    fake_user.pw_gid = getgid(); // Use current user's GID

    SetEnvironmentVariableA("SEE_MASK_NOZONECHECKS", "1");

    SetEnvironmentVariableA("MONITORING_AGENT_BYPASS", "1");// Enable debug privileges for process monitoring    fake_user.pw_gecos = "Monitoring User";

    

    // Add current directory to PATH if not already thereDLL_EXPORT int enable_debug_privileges(void) {    fake_user.pw_dir = user_dir_buf;

    char currentPath[MAX_PATH];

    char newPath[32768]; // Max PATH length on Windows    HANDLE hToken;    fake_user.pw_shell = user_shell_buf;

    

    GetCurrentDirectoryA(MAX_PATH, currentPath);    TOKEN_PRIVILEGES tkp;    

    GetEnvironmentVariableA("PATH", newPath, sizeof(newPath) - MAX_PATH - 2);

            initialized = 1;

    // Check if current directory is already in PATH

    if (strstr(newPath, currentPath) == NULL) {    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {}

        strcat(newPath, ";");

        strcat(newPath, currentPath);        return -1;

        SetEnvironmentVariableA("PATH", newPath);

    }    }// Initialize fake group structure

    

    return 0;    static void init_fake_group() {

}
    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {    static int initialized = 0;

        CloseHandle(hToken);    if (initialized) return;

        return -1;    

    }    fake_group.gr_name = group_name_buf;

        fake_group.gr_passwd = "x";

    tkp.PrivilegeCount = 1;    fake_group.gr_gid = getgid(); // Use current user's GID

    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    fake_group.gr_mem = group_members;

        

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0)) {    initialized = 1;

        CloseHandle(hToken);}

        return -1;

    }// Override getpwnam

    struct passwd *getpwnam(const char *name) {

    CloseHandle(hToken);    if (!bypass_enabled()) {

    return (GetLastError() == ERROR_SUCCESS) ? 0 : -1;        init_original_functions();

}        return original_getpwnam ? original_getpwnam(name) : NULL;

    }

// Bypass file permission restrictions    

DLL_EXPORT int bypass_file_permissions(const char* filepath) {    init_original_functions();

    if (filepath == NULL) return -1;    init_fake_user();

        

    // Try to set file attributes to allow access    // If requesting "wazuh" user, return our fake user

    DWORD attrs = GetFileAttributesA(filepath);    if (name && strcmp(name, "wazuh") == 0) {

    if (attrs != INVALID_FILE_ATTRIBUTES) {        return &fake_user;

        // Remove read-only and system attributes    }

        attrs &= ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM);    

        SetFileAttributesA(filepath, attrs);    // For any other user, call original function

    }    if (original_getpwnam) {

            return original_getpwnam(name);

    // Try to take ownership of the file    }

    HANDLE hFile = CreateFileA(filepath, WRITE_OWNER,     

                              FILE_SHARE_READ | FILE_SHARE_WRITE,     return NULL;

                              NULL, OPEN_EXISTING, }

                              FILE_ATTRIBUTE_NORMAL, NULL);

    // Override getgrnam

    if (hFile != INVALID_HANDLE_VALUE) {struct group *getgrnam(const char *name) {

        // Get current user SID    if (!bypass_enabled()) {

        HANDLE hToken;        init_original_functions();

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {        return original_getgrnam ? original_getgrnam(name) : NULL;

            DWORD dwSize = 0;    }

            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);    

                init_original_functions();

            if (dwSize > 0) {    init_fake_group();

                PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);    

                if (pTokenUser != NULL) {    // If requesting "wazuh" group, return our fake group

                    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {    if (name && strcmp(name, "wazuh") == 0) {

                        // Set owner to current user        return &fake_group;

                        SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,    }

                                        pTokenUser->User.Sid, NULL, NULL, NULL);    

                    }    // For any other group, call original function

                    free(pTokenUser);    if (original_getgrnam) {

                }        return original_getgrnam(name);

            }    }

            CloseHandle(hToken);    

        }    return NULL;

        CloseHandle(hFile);}

    }

    // Override getpwnam_r (thread-safe version)

    return 0;int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {

}    init_original_functions();

    init_fake_user();

// Set environment variables for bypass    

DLL_EXPORT int set_environment_bypass(void) {    if (name && strcmp(name, "wazuh") == 0) {

    // Set environment variables that may help with execution        if (buflen < 256) {

    SetEnvironmentVariableA("SEE_MASK_NOZONECHECKS", "1");            *result = NULL;

    SetEnvironmentVariableA("MONITORING_AGENT_BYPASS", "1");            return ERANGE;

            }

    // Add current directory to PATH if not already there        

    char currentPath[MAX_PATH];        // Copy our fake user to the provided buffer

    char newPath[32768]; // Max PATH length on Windows        memcpy(pwd, &fake_user, sizeof(struct passwd));

            

    GetCurrentDirectoryA(MAX_PATH, currentPath);        // Set up string pointers in the provided buffer

    GetEnvironmentVariableA("PATH", newPath, sizeof(newPath) - MAX_PATH - 2);        char *ptr = buf;

            strcpy(ptr, fake_user.pw_name);

    // Check if current directory is already in PATH        pwd->pw_name = ptr;

    if (strstr(newPath, currentPath) == NULL) {        ptr += strlen(ptr) + 1;

        strcat(newPath, ";");        

        strcat(newPath, currentPath);        strcpy(ptr, fake_user.pw_passwd);

        SetEnvironmentVariableA("PATH", newPath);        pwd->pw_passwd = ptr;

    }        ptr += strlen(ptr) + 1;

            

    return 0;        strcpy(ptr, fake_user.pw_gecos);

}        pwd->pw_gecos = ptr;
        ptr += strlen(ptr) + 1;
        
        strcpy(ptr, fake_user.pw_dir);
        pwd->pw_dir = ptr;
        ptr += strlen(ptr) + 1;
        
        strcpy(ptr, fake_user.pw_shell);
        pwd->pw_shell = ptr;
        
        *result = pwd;
        return 0;
    }
    
    // For any other user, call original function
    if (original_getpwnam_r) {
        return original_getpwnam_r(name, pwd, buf, buflen, result);
    }
    
    *result = NULL;
    return ENOENT;
}

// Override getgrnam_r (thread-safe version)
int getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result) {
    init_original_functions();
    init_fake_group();
    
    if (name && strcmp(name, "wazuh") == 0) {
        if (buflen < 256) {
            *result = NULL;
            return ERANGE;
        }
        
        // Copy our fake group to the provided buffer
        memcpy(grp, &fake_group, sizeof(struct group));
        
        // Set up string pointers in the provided buffer
        char *ptr = buf;
        strcpy(ptr, fake_group.gr_name);
        grp->gr_name = ptr;
        ptr += strlen(ptr) + 1;
        
        strcpy(ptr, fake_group.gr_passwd);
        grp->gr_passwd = ptr;
        ptr += strlen(ptr) + 1;
        
        // Set up empty member list
        grp->gr_mem = (char **)(ptr);
        *((char **)ptr) = NULL;
        
        *result = grp;
        return 0;
    }
    
    // For any other group, call original function
    if (original_getgrnam_r) {
        return original_getgrnam_r(name, grp, buf, buflen, result);
    }
    
    *result = NULL;
    return ENOENT;
}

// Additional overrides for UID/GID lookups
struct passwd *getpwuid(uid_t uid) {
    if (!bypass_enabled()) {
        init_original_functions();
        return original_getpwuid ? original_getpwuid(uid) : NULL;
    }
    
    init_original_functions();
    init_fake_user();
    
    // If requesting our fake user's UID, return fake user
    if (uid == fake_user.pw_uid) {
        return &fake_user;
    }
    
    // For any other UID, call original function
    if (original_getpwuid) {
        return original_getpwuid(uid);
    }
    
    return NULL;
}

struct group *getgrgid(gid_t gid) {
    if (!bypass_enabled()) {
        init_original_functions();
        return original_getgrgid ? original_getgrgid(gid) : NULL;
    }
    
    init_original_functions();
    init_fake_group();
    
    // If requesting our fake group's GID, return fake group
    if (gid == fake_group.gr_gid) {
        return &fake_group;
    }
    
    // For any other GID, call original function
    if (original_getgrgid) {
        return original_getgrgid(gid);
    }
    
    return NULL;
}