/**
 * hvci_checks.c - Hypervisor-enforced Code Integrity (HVCI) Detection
 * 
 * Detects HVCI and related VBS code integrity features.
 * 
 * Sources:
 * - Living The Age of VBS, HVCI, and Kernel CFG (Connor McGarr): https://connormcgarr.github.io/hvci/
 * - CVE-2024-21305 HVCI Bypass (Satoshi Tanda): https://tandasat.github.io/blog/2024/01/15/CVE-2024-21305.html
 * - Code Execution against Windows HVCI (Worawit Wang): https://datafarm-cybersecurity.medium.com/code-execution-against-windows-hvci-f617570e9df0
 * - Introducing Kernel Data Protection (Andrea Allievi): Microsoft Blog
 * - KCFG and KCET (Connor McGarr): BlackHat 2025
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_HVCI 0x00000002

/* HVCI detection info */
typedef struct _HVCI_INFO {
    BOOL hvciEnabled;
    BOOL hvciRunning;
    BOOL kdpEnabled;
    BOOL kcfgEnabled;
    BOOL kcetEnabled;
    
    DWORD deviceGuardState;
    DWORD codeIntegrityPolicy;
    
    BOOL umciEnabled;
    BOOL kmciEnabled;
} HVCI_INFO, *PHVCI_INFO;

/*
 * Check HVCI via registry
 */
static void CheckHvciRegistry(PHVCI_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check Device Guard HVCI scenario */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->hvciEnabled = (value != 0);
        }
        
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "Running",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->hvciRunning = (value != 0);
        }
        
        RegCloseKey(hKey);
    }
    
    /* Check main Device Guard settings */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->deviceGuardState = value;
        }
        
        RegCloseKey(hKey);
    }
    
    /* Check CI policy */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "VirtualizationBasedSecurityStatus",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->codeIntegrityPolicy = value;
        }
        
        RegCloseKey(hKey);
    }
}

/*
 * Check for Kernel Data Protection (KDP)
 */
static void CheckKdp(PHVCI_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* KDP is enabled via HVCI + specific flags */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->kcetEnabled = (value != 0);  /* KCET - Kernel CET */
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check for KCFG (Kernel Control Flow Guard)
 */
static void CheckKcfg(PHVCI_INFO info)
{
    char systemPath[MAX_PATH];
    char filePath[MAX_PATH];
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    /* KCFG is enforced when HVCI is running */
    if (info->hvciRunning) {
        info->kcfgEnabled = TRUE;
    }
}

/*
 * Check WMI for VBS status
 */
static BOOL CheckVbsWmi(void)
{
    /* WMI query would go here, simplified to registry check */
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

/*
 * Main HVCI check function
 */
DWORD CheckHvciHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HVCI_INFO info = {0};
    BOOL vbsEnabled;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckHvciRegistry(&info);
    CheckKdp(&info);
    CheckKcfg(&info);
    vbsEnabled = CheckVbsWmi();
    
    /* Detection */
    if (info.hvciEnabled || info.hvciRunning) {
        detected = HYPERV_DETECTED_HVCI;
    }
    
    /* Build details */
    AppendToDetails(result, "HVCI (Hypervisor-enforced Code Integrity) Detection:\n");
    
    AppendToDetails(result, "\n  HVCI Status:\n");
    AppendToDetails(result, "    Enabled: %s\n", 
                   info.hvciEnabled ? "YES" : "NO");
    AppendToDetails(result, "    Running: %s\n", 
                   info.hvciRunning ? "YES" : "NO");
    
    AppendToDetails(result, "\n  Device Guard:\n");
    AppendToDetails(result, "    VBS State: 0x%08X\n", info.deviceGuardState);
    AppendToDetails(result, "    CI Policy: 0x%08X\n", info.codeIntegrityPolicy);
    AppendToDetails(result, "    VBS (Policy): %s\n", 
                   vbsEnabled ? "Enabled" : "Disabled");
    
    AppendToDetails(result, "\n  Code Integrity Features:\n");
    AppendToDetails(result, "    KCFG (Kernel CFG): %s\n", 
                   info.kcfgEnabled ? "Active" : "Not active");
    AppendToDetails(result, "    KCET (Kernel CET): %s\n", 
                   info.kcetEnabled ? "Active" : "Not active");
    
    if (info.hvciRunning) {
        AppendToDetails(result, "\n  Note: HVCI is ACTIVE\n");
        AppendToDetails(result, "        Kernel code integrity is hypervisor-enforced\n");
        AppendToDetails(result, "        Unsigned kernel code execution is blocked\n");
    } else if (info.hvciEnabled) {
        AppendToDetails(result, "\n  Note: HVCI is enabled but not running\n");
        AppendToDetails(result, "        Reboot may be required\n");
    }
    
    return detected;
}

/*
 * Quick check for HVCI
 */
BOOL IsHvciPolicyEnabled(void)
{
    HVCI_INFO info = {0};
    CheckHvciRegistry(&info);
    return info.hvciEnabled;
}

/*
 * Check if HVCI is running
 */
BOOL IsHvciRunning(void)
{
    HVCI_INFO info = {0};
    CheckHvciRegistry(&info);
    return info.hvciRunning;
}

/*
 * Check if KCFG is active
 */
BOOL IsKcfgActive(void)
{
    HVCI_INFO info = {0};
    CheckHvciRegistry(&info);
    CheckKcfg(&info);
    return info.kcfgEnabled;
}

/*
 * Check if KCET is active
 */
BOOL IsKcetActive(void)
{
    HVCI_INFO info = {0};
    CheckKdp(&info);
    return info.kcetEnabled;
}
