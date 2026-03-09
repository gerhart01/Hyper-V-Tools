/**
 * system_guard_checks.c - System Guard Runtime Attestation Detection
 * 
 * Detects Windows Defender System Guard Runtime Attestation features.
 * 
 * Sources:
 * - Inside the Octagon: Analyzing System Guard Runtime Attestation (Alex Ionescu, David Weston):
 *   https://web.archive.org/web/20180808153201/http://alex-ionescu.com/Publications/OPCDE/octagon.pdf
 * - Redefining Security Boundaries (Connor McGarr):
 *   https://github.com/connormcgarr/Presentations/blob/master/McGarr_SANS_Hackfest_2024_Redefining_Security_Boundaries.pdf
 * - Microsoft System Guard: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-how-hardware-based-root-of-trust-helps-protect-windows
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_SYSTEM_GUARD 0x00000010

/* System Guard detection info */
typedef struct _SYSTEM_GUARD_INFO {
    BOOL sgRunning;
    BOOL srtmEnabled;         /* Static Root of Trust Measurement */
    BOOL drtmEnabled;         /* Dynamic Root of Trust Measurement */
    BOOL smmEnabled;          /* SMM protection */
    
    BOOL secureBootEnabled;
    BOOL tpmPresent;
    
    DWORD systemGuardState;
} SYSTEM_GUARD_INFO, *PSYSTEM_GUARD_INFO;

/*
 * Check System Guard registry settings
 */
static void CheckSystemGuardRegistry(PSYSTEM_GUARD_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check System Guard scenario */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->sgRunning = (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    /* Check Secure Launch (DRTM) */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SecureLaunch",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->drtmEnabled = (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    /* Check SMM protection */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SMMProtection",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->smmEnabled = (value != 0);
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check Secure Boot status
 */
static void CheckSecureBoot(PSYSTEM_GUARD_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->secureBootEnabled = (value != 0);
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check TPM presence
 */
static void CheckTpm(PSYSTEM_GUARD_INFO info)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    
    if (info == NULL) {
        return;
    }
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return;
    }
    
    /* Check TPM Base Services */
    hService = OpenServiceA(hSCManager, "tbs", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->tpmPresent = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
}

/*
 * Check firmware SRTM
 */
static BOOL CheckSrtm(void)
{
    /* SRTM is enabled via firmware - check UEFI variable */
    HKEY hKey;
    LONG result;
    
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\IntegrityServices",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main System Guard check function
 */
DWORD CheckSystemGuardHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    SYSTEM_GUARD_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckSystemGuardRegistry(&info);
    CheckSecureBoot(&info);
    CheckTpm(&info);
    info.srtmEnabled = CheckSrtm();
    
    /* Detection */
    if (info.sgRunning || info.drtmEnabled || info.srtmEnabled) {
        detected = HYPERV_DETECTED_SYSTEM_GUARD;
    }
    
    /* Build details */
    AppendToDetails(result, "System Guard Runtime Attestation Detection:\n");
    
    AppendToDetails(result, "\n  System Guard Status:\n");
    AppendToDetails(result, "    System Guard: %s\n", 
                   info.sgRunning ? "Running" : "Not running");
    
    AppendToDetails(result, "\n  Root of Trust:\n");
    AppendToDetails(result, "    SRTM (Static): %s\n", 
                   info.srtmEnabled ? "Enabled" : "Disabled");
    AppendToDetails(result, "    DRTM (Dynamic/Secure Launch): %s\n", 
                   info.drtmEnabled ? "Enabled" : "Disabled");
    AppendToDetails(result, "    SMM Protection: %s\n", 
                   info.smmEnabled ? "Enabled" : "Disabled");
    
    AppendToDetails(result, "\n  Hardware Security:\n");
    AppendToDetails(result, "    Secure Boot: %s\n", 
                   info.secureBootEnabled ? "Enabled" : "Disabled");
    AppendToDetails(result, "    TPM: %s\n", 
                   info.tpmPresent ? "Present" : "Not detected");
    
    if (info.drtmEnabled) {
        AppendToDetails(result, "\n  Note: DRTM (Secure Launch) is active\n");
        AppendToDetails(result, "        Hardware-based root of trust established\n");
    }
    
    return detected;
}

/*
 * Quick check for System Guard
 */
BOOL IsSystemGuardRunning(void)
{
    SYSTEM_GUARD_INFO info = {0};
    CheckSystemGuardRegistry(&info);
    return info.sgRunning;
}

/*
 * Check if DRTM is enabled
 */
BOOL IsDrtmEnabled(void)
{
    SYSTEM_GUARD_INFO info = {0};
    CheckSystemGuardRegistry(&info);
    return info.drtmEnabled;
}

/*
 * Check if Secure Boot is enabled
 */
BOOL IsSecureBootEnabled(void)
{
    SYSTEM_GUARD_INFO info = {0};
    CheckSecureBoot(&info);
    return info.secureBootEnabled;
}

/*
 * Check if TPM is present
 */
BOOL IsTpmPresent(void)
{
    SYSTEM_GUARD_INFO info = {0};
    CheckTpm(&info);
    return info.tpmPresent;
}
