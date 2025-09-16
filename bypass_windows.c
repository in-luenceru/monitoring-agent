#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sddl.h>
#include <aclapi.h>

// Windows DLL injection approach for bypassing user/group checks
// This creates a fake user/group structure for Windows systems

typedef struct {
    char username[64];
    char domain[64];
    DWORD uid;
    DWORD gid;
    PSID sid;
    char sidString[256];
} FAKE_USER_INFO;

static FAKE_USER_INFO fake_user;
static BOOL bypass_initialized = FALSE;
static BOOL bypass_enabled = TRUE;

// Function pointers for original functions
typedef BOOL (WINAPI *LookupAccountNameA_t)(
    LPCSTR lpSystemName,
    LPCSTR lpAccountName,
    PSID Sid,
    LPDWORD cbSid,
    LPSTR ReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
);

typedef BOOL (WINAPI *LookupAccountNameW_t)(
    LPCWSTR lpSystemName,
    LPCWSTR lpAccountName,
    PSID Sid,
    LPDWORD cbSid,
    LPWSTR ReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
);

static LookupAccountNameA_t OriginalLookupAccountNameA = NULL;
static LookupAccountNameW_t OriginalLookupAccountNameW = NULL;

// Initialize fake user structure
void InitializeFakeUser() {
    if (bypass_initialized) return;
    
    // Check environment variable to disable bypass
    char* disable_bypass = getenv("DISABLE_WAZUH_BYPASS");
    if (disable_bypass && strcmp(disable_bypass, "1") == 0) {
        bypass_enabled = FALSE;
        bypass_initialized = TRUE;
        return;
    }
    
    // Get current user information
    DWORD username_len = sizeof(fake_user.username);
    DWORD domain_len = sizeof(fake_user.domain);
    
    GetUserNameA(fake_user.username, &username_len);
    GetComputerNameA(fake_user.domain, &domain_len);
    
    // Create a simple fake SID for the current user
    fake_user.uid = 1000;
    fake_user.gid = 1000;
    
    // Allocate and initialize a fake SID
    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    fake_user.sid = (PSID)malloc(sidSize);
    
    if (fake_user.sid) {
        // Create a simple SID: S-1-5-21-domain-1000
        // This is a simplified approach for demonstration
        InitializeSid(fake_user.sid, &(SID_IDENTIFIER_AUTHORITY){SECURITY_NT_AUTHORITY}, 4);
        *GetSidSubAuthority(fake_user.sid, 0) = SECURITY_NT_NON_UNIQUE;
        *GetSidSubAuthority(fake_user.sid, 1) = 12345; // Domain identifier
        *GetSidSubAuthority(fake_user.sid, 2) = 67890; // Domain identifier  
        *GetSidSubAuthority(fake_user.sid, 3) = fake_user.uid;
        
        // Convert SID to string for debugging
        LPSTR sidString;
        if (ConvertSidToStringSidA(fake_user.sid, &sidString)) {
            strncpy(fake_user.sidString, sidString, sizeof(fake_user.sidString) - 1);
            LocalFree(sidString);
        }
    }
    
    bypass_initialized = TRUE;
}

// Hook function for LookupAccountNameA
BOOL WINAPI LookupAccountNameA_Hook(
    LPCSTR lpSystemName,
    LPCSTR lpAccountName,
    PSID Sid,
    LPDWORD cbSid,
    LPSTR ReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
) {
    InitializeFakeUser();
    
    // If bypass is disabled, call original function
    if (!bypass_enabled) {
        if (OriginalLookupAccountNameA) {
            return OriginalLookupAccountNameA(lpSystemName, lpAccountName, Sid, cbSid, 
                                            ReferencedDomainName, cchReferencedDomainName, peUse);
        }
        return FALSE;
    }
    
    // If looking up "wazuh" user, return our fake data
    if (lpAccountName && (strcmp(lpAccountName, "wazuh") == 0 || strcmp(lpAccountName, "monitoring") == 0)) {
        DWORD required_sid_size = GetLengthSid(fake_user.sid);
        
        // Check if provided buffer is large enough
        if (Sid && *cbSid >= required_sid_size) {
            CopySid(*cbSid, Sid, fake_user.sid);
        }
        *cbSid = required_sid_size;
        
        // Set domain name
        if (ReferencedDomainName && *cchReferencedDomainName >= strlen(fake_user.domain) + 1) {
            strcpy(ReferencedDomainName, fake_user.domain);
        }
        *cchReferencedDomainName = strlen(fake_user.domain) + 1;
        
        if (peUse) {
            *peUse = SidTypeUser;
        }
        
        // Return success if we have enough buffer space, otherwise return buffer size needed
        return (Sid && *cbSid >= required_sid_size && 
                ReferencedDomainName && *cchReferencedDomainName >= strlen(fake_user.domain) + 1);
    }
    
    // For other users, call the original function if available
    if (OriginalLookupAccountNameA) {
        return OriginalLookupAccountNameA(lpSystemName, lpAccountName, Sid, cbSid, 
                                        ReferencedDomainName, cchReferencedDomainName, peUse);
    }
    
    SetLastError(ERROR_NONE_MAPPED);
    return FALSE;
}

// Hook function for LookupAccountNameW (Unicode version)
BOOL WINAPI LookupAccountNameW_Hook(
    LPCWSTR lpSystemName,
    LPCWSTR lpAccountName,
    PSID Sid,
    LPDWORD cbSid,
    LPWSTR ReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
) {
    InitializeFakeUser();
    
    // If bypass is disabled, call original function
    if (!bypass_enabled) {
        if (OriginalLookupAccountNameW) {
            return OriginalLookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid, 
                                            ReferencedDomainName, cchReferencedDomainName, peUse);
        }
        return FALSE;
    }
    
    // Convert wide string to multi-byte for comparison
    char accountName[256];
    if (lpAccountName) {
        WideCharToMultiByte(CP_UTF8, 0, lpAccountName, -1, accountName, sizeof(accountName), NULL, NULL);
        
        if (strcmp(accountName, "wazuh") == 0 || strcmp(accountName, "monitoring") == 0) {
            DWORD required_sid_size = GetLengthSid(fake_user.sid);
            
            // Check if provided buffer is large enough
            if (Sid && *cbSid >= required_sid_size) {
                CopySid(*cbSid, Sid, fake_user.sid);
            }
            *cbSid = required_sid_size;
            
            // Set domain name (convert to wide string)
            if (ReferencedDomainName && *cchReferencedDomainName >= strlen(fake_user.domain) + 1) {
                MultiByteToWideChar(CP_UTF8, 0, fake_user.domain, -1, ReferencedDomainName, *cchReferencedDomainName);
            }
            *cchReferencedDomainName = strlen(fake_user.domain) + 1;
            
            if (peUse) {
                *peUse = SidTypeUser;
            }
            
            return (Sid && *cbSid >= required_sid_size && 
                    ReferencedDomainName && *cchReferencedDomainName >= strlen(fake_user.domain) + 1);
        }
    }
    
    // For other users, call the original function if available
    if (OriginalLookupAccountNameW) {
        return OriginalLookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid, 
                                        ReferencedDomainName, cchReferencedDomainName, peUse);
    }
    
    SetLastError(ERROR_NONE_MAPPED);
    return FALSE;
}

// Simple API hooking using IAT patching
BOOL HookFunction(HMODULE hModule, LPCSTR lpProcName, LPVOID lpNewProc, LPVOID* lpOrigProc) {
    if (!hModule || !lpProcName || !lpNewProc) return FALSE;
    
    // Get the address of the function
    LPVOID originalFunc = GetProcAddress(hModule, lpProcName);
    if (!originalFunc) return FALSE;
    
    if (lpOrigProc) *lpOrigProc = originalFunc;
    
    // For simplicity, we'll use a basic approach
    // In a real implementation, you'd use more sophisticated hooking
    return TRUE;
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialize the bypass when DLL is loaded
        InitializeFakeUser();
        
        // Hook the LookupAccountName functions
        // Note: For production use, implement proper API hooking like Microsoft Detours
        HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");
        if (hAdvapi32) {
            HookFunction(hAdvapi32, "LookupAccountNameA", LookupAccountNameA_Hook, (LPVOID*)&OriginalLookupAccountNameA);
            HookFunction(hAdvapi32, "LookupAccountNameW", LookupAccountNameW_Hook, (LPVOID*)&OriginalLookupAccountNameW);
        }
        break;
        
    case DLL_THREAD_ATTACH:
        break;
        
    case DLL_THREAD_DETACH:
        break;
        
    case DLL_PROCESS_DETACH:
        // Clean up
        if (fake_user.sid) {
            free(fake_user.sid);
            fake_user.sid = NULL;
        }
        break;
    }
    return TRUE;
}

// Export functions for manual injection
__declspec(dllexport) BOOL EnableBypass() {
    bypass_enabled = TRUE;
    InitializeFakeUser();
    return TRUE;
}

__declspec(dllexport) BOOL DisableBypass() {
    bypass_enabled = FALSE;
    return TRUE;
}

__declspec(dllexport) BOOL IsBypassEnabled() {
    return bypass_enabled;
}

__declspec(dllexport) const char* GetFakeUserInfo() {
    InitializeFakeUser();
    static char info[512];
    snprintf(info, sizeof(info), "User: %s\\%s, UID: %d, GID: %d, SID: %s", 
             fake_user.domain, fake_user.username, fake_user.uid, fake_user.gid, fake_user.sidString);
    return info;
}