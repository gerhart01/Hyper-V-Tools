/*
 * Hyper-V Detector - Shared Utilities
 * Common functions used by both main detector and test projects
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <stdarg.h>

/*
 * Append formatted text to detection result details
 */
void AppendToDetails(PDETECTION_RESULT result, const char* format, ...)
{
    va_list args;
    int currentLen = 0;
    int remaining = 0;
    
    if (result == NULL || format == NULL) {
        return;
    }
    
    va_start(args, format);
    
    currentLen = (int)strlen(result->Details);
    remaining = (int)sizeof(result->Details) - currentLen - 1;
    
    if (remaining > 0) {
        vsnprintf(result->Details + currentLen, remaining, format, args);
    }
    
    va_end(args);
}

/*
 * Check if running as administrator
 */
BOOL IsRunningAsAdmin(void)
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, 
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin;
}
