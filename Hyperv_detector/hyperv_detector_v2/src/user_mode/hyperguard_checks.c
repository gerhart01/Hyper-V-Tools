/**
 * hyperguard_checks.c - HyperGuard / SKPG Detection
 * 
 * Detects HyperGuard (Secure Kernel Patch Guard) which protects
 * kernel integrity using the hypervisor.
 * 
 * Sources:
 * - HyperGuard – Secure Kernel Patch Guard (Yarden Shafir):
 *   Part 1: https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-1-skpg-initialization/
 *   Part 2: https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-2-skpg-extents/
 *   Part 3: https://windows-internals.com/hyperguard-part-3-more-skpg-extents/
 * - Secure Kernel Research with LiveCloudKd (Yarden Shafir):
 *   https://windows-internals.com/secure-kernel-research-with-livecloudkd/
 * - Breaking VSM by Attacking Secure Kernel (Saar Amar, Daniel King):
 *   https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2020_08_BlackHatUSA/Breaking_VSM_by_Attacking_SecureKernel.pdf
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_HYPERGUARD 0x00000008

/* HyperGuard detection info */
typedef struct _HYPERGUARD_INFO {
    BOOL skpgEnabled;
    BOOL secureKernelPresent;
    BOOL vbsRunning;
    
    BOOL skciPresent;       /* Secure Kernel Code Integrity */
    BOOL securePoolEnabled;
    
    DWORD hyperguardState;
} HYPERGUARD_INFO, *PHYPERGUARD_INFO;

/*
 * Check HyperGuard via registry
 */
static void CheckHyperGuardRegistry(PHYPERGUARD_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check Device Guard for VBS which enables HyperGuard */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->vbsRunning = (value != 0);
        }
        
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "HypervisorEnforcedCodeIntegrity",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            /* HVCI enables HyperGuard */
            if (value != 0) {
                info->skpgEnabled = TRUE;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    /* Check CI config for VBS status */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "VirtualizationBasedSecurityStatus",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->hyperguardState = value;
            /* Value 2 = Running */
            if (value == 2) {
                info->skpgEnabled = TRUE;
            }
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check for Secure Kernel files
 */
static void CheckSecureKernelFiles(PHYPERGUARD_INFO info)
{
    char systemPath[MAX_PATH];
    char filePath[MAX_PATH];
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    if (GetSystemDirectoryA(systemPath, MAX_PATH) == 0) {
        return;
    }
    
    /* Check securekernel.exe */
    snprintf(filePath, MAX_PATH, "%s\\securekernel.exe", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->secureKernelPresent = TRUE;
    }
    
    /* Check skci.dll (Secure Kernel Code Integrity) */
    snprintf(filePath, MAX_PATH, "%s\\skci.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->skciPresent = TRUE;
    }
}

/*
 * Check for Secure Pool (part of KDP)
 */
static void CheckSecurePool(PHYPERGUARD_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Secure Pool is enabled when VBS/HVCI is running */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Check for secure pool indicators */
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "FeatureSettingsOverride",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            /* Feature settings can indicate secure pool */
        }
        RegCloseKey(hKey);
    }
    
    /* If VBS is running, secure pool is likely enabled */
    if (info->vbsRunning && info->skpgEnabled) {
        info->securePoolEnabled = TRUE;
    }
}

/*
 * Check WMI for HyperGuard status
 */
static BOOL CheckHyperGuardWmi(void)
{
    /* Simplified - would use WMI in full implementation */
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Running",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

/*
 * Main HyperGuard check function
 */
DWORD CheckHyperGuardHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HYPERGUARD_INFO info = {0};
    BOOL wmiStatus;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckHyperGuardRegistry(&info);
    CheckSecureKernelFiles(&info);
    CheckSecurePool(&info);
    wmiStatus = CheckHyperGuardWmi();
    
    /* Detection */
    if (info.skpgEnabled || info.vbsRunning || wmiStatus) {
        detected = HYPERV_DETECTED_HYPERGUARD;
    }
    
    /* Build details */
    AppendToDetails(result, "HyperGuard / SKPG Detection:\n");
    
    AppendToDetails(result, "\n  HyperGuard Status:\n");
    AppendToDetails(result, "    SKPG Enabled: %s\n", 
                   info.skpgEnabled ? "YES" : "NO");
    AppendToDetails(result, "    VBS Running: %s\n", 
                   info.vbsRunning ? "YES" : "NO");
    AppendToDetails(result, "    HyperGuard State: 0x%08X\n", info.hyperguardState);
    
    AppendToDetails(result, "\n  Secure Kernel Components:\n");
    AppendToDetails(result, "    securekernel.exe: %s\n", 
                   info.secureKernelPresent ? "Present" : "Not found");
    AppendToDetails(result, "    skci.dll: %s\n", 
                   info.skciPresent ? "Present" : "Not found");
    
    AppendToDetails(result, "\n  Kernel Data Protection:\n");
    AppendToDetails(result, "    Secure Pool: %s\n", 
                   info.securePoolEnabled ? "Enabled" : "Disabled");
    
    if (info.skpgEnabled) {
        AppendToDetails(result, "\n  Note: HyperGuard (SKPG) is ACTIVE\n");
        AppendToDetails(result, "        Kernel integrity protected by hypervisor\n");
        AppendToDetails(result, "        Traditional kernel patching is blocked\n");
    }
    
    return detected;
}

/*
 * Quick check for HyperGuard
 */
BOOL IsHyperGuardEnabled(void)
{
    HYPERGUARD_INFO info = {0};
    CheckHyperGuardRegistry(&info);
    return info.skpgEnabled;
}

/*
 * Check if Secure Kernel is present
 */
BOOL HasSecureKernel(void)
{
    HYPERGUARD_INFO info = {0};
    CheckSecureKernelFiles(&info);
    return info.secureKernelPresent;
}

/*
 * Check if Secure Pool is enabled
 */
BOOL IsSecurePoolEnabled(void)
{
    HYPERGUARD_INFO info = {0};
    CheckHyperGuardRegistry(&info);
    CheckSecurePool(&info);
    return info.securePoolEnabled;
}

/*
 * Get HyperGuard state value
 */
DWORD GetHyperGuardState(void)
{
    HYPERGUARD_INFO info = {0};
    CheckHyperGuardRegistry(&info);
    return info.hyperguardState;
}
