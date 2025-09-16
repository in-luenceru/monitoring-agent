#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <errno.h>

// Function pointers for original functions
static struct passwd *(*original_getpwnam)(const char *name) = NULL;
static struct group *(*original_getgrnam)(const char *name) = NULL;
static int (*original_getpwnam_r)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) = NULL;
static int (*original_getgrnam_r)(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result) = NULL;
static struct passwd *(*original_getpwuid)(uid_t uid) = NULL;
static struct group *(*original_getgrgid)(gid_t gid) = NULL;

// Static storage for fake user/group entries
static struct passwd fake_user;
static struct group fake_group;
static char user_name_buf[32] = "monitoring";
static char user_shell_buf[64] = "/bin/bash";
static char user_dir_buf[128] = "/workspaces/monitoring-agent";
static char group_name_buf[32] = "monitoring";
static char *group_members[] = {NULL};

// Environment check to enable/disable bypass
static int bypass_enabled() {
    static int checked = 0;
    static int enabled = 1;
    
    if (!checked) {
        char *disable_bypass = getenv("DISABLE_WAZUH_BYPASS");
        if (disable_bypass && strcmp(disable_bypass, "1") == 0) {
            enabled = 0;
        }
        checked = 1;
    }
    return enabled;
}

// Initialize function pointers
static void init_original_functions() {
    if (!original_getpwnam) {
        original_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
    }
    if (!original_getgrnam) {
        original_getgrnam = dlsym(RTLD_NEXT, "getgrnam");
    }
    if (!original_getpwnam_r) {
        original_getpwnam_r = dlsym(RTLD_NEXT, "getpwnam_r");
    }
    if (!original_getgrnam_r) {
        original_getgrnam_r = dlsym(RTLD_NEXT, "getgrnam_r");
    }
    if (!original_getpwuid) {
        original_getpwuid = dlsym(RTLD_NEXT, "getpwuid");
    }
    if (!original_getgrgid) {
        original_getgrgid = dlsym(RTLD_NEXT, "getgrgid");
    }
}

// Initialize fake user structure
static void init_fake_user() {
    static int initialized = 0;
    if (initialized) return;
    
    fake_user.pw_name = user_name_buf;
    fake_user.pw_passwd = "x";
    fake_user.pw_uid = getuid(); // Use current user's UID
    fake_user.pw_gid = getgid(); // Use current user's GID
    fake_user.pw_gecos = "Monitoring User";
    fake_user.pw_dir = user_dir_buf;
    fake_user.pw_shell = user_shell_buf;
    
    initialized = 1;
}

// Initialize fake group structure
static void init_fake_group() {
    static int initialized = 0;
    if (initialized) return;
    
    fake_group.gr_name = group_name_buf;
    fake_group.gr_passwd = "x";
    fake_group.gr_gid = getgid(); // Use current user's GID
    fake_group.gr_mem = group_members;
    
    initialized = 1;
}

// Override getpwnam
struct passwd *getpwnam(const char *name) {
    if (!bypass_enabled()) {
        init_original_functions();
        return original_getpwnam ? original_getpwnam(name) : NULL;
    }
    
    init_original_functions();
    init_fake_user();
    
    // If requesting "wazuh" user, return our fake user
    if (name && strcmp(name, "wazuh") == 0) {
        return &fake_user;
    }
    
    // For any other user, call original function
    if (original_getpwnam) {
        return original_getpwnam(name);
    }
    
    return NULL;
}

// Override getgrnam
struct group *getgrnam(const char *name) {
    if (!bypass_enabled()) {
        init_original_functions();
        return original_getgrnam ? original_getgrnam(name) : NULL;
    }
    
    init_original_functions();
    init_fake_group();
    
    // If requesting "wazuh" group, return our fake group
    if (name && strcmp(name, "wazuh") == 0) {
        return &fake_group;
    }
    
    // For any other group, call original function
    if (original_getgrnam) {
        return original_getgrnam(name);
    }
    
    return NULL;
}

// Override getpwnam_r (thread-safe version)
int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    init_original_functions();
    init_fake_user();
    
    if (name && strcmp(name, "wazuh") == 0) {
        if (buflen < 256) {
            *result = NULL;
            return ERANGE;
        }
        
        // Copy our fake user to the provided buffer
        memcpy(pwd, &fake_user, sizeof(struct passwd));
        
        // Set up string pointers in the provided buffer
        char *ptr = buf;
        strcpy(ptr, fake_user.pw_name);
        pwd->pw_name = ptr;
        ptr += strlen(ptr) + 1;
        
        strcpy(ptr, fake_user.pw_passwd);
        pwd->pw_passwd = ptr;
        ptr += strlen(ptr) + 1;
        
        strcpy(ptr, fake_user.pw_gecos);
        pwd->pw_gecos = ptr;
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