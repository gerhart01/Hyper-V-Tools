/**
 * vsm_checks.c - Virtual Secure Mode (VSM) and VTL Detection
 * 
 * Detects VSM features and Virtual Trust Levels through CPUID, MSRs,
 * and partition privilege flags.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
 * - https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html
 * - https://www.microsoftpressstore.com/articles/article.aspx?p=3145750
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

#define HYPERV_DETECTED_VSM 0x40000000

/* MSRs for VSM */
#define HV_X64_MSR_VSM_CAPABILITIES      0x4009001C
#define HV_X64_MSR_VSM_PARTITION_STATUS  0x4009001D
#define HV_X64_MSR_VSM_VP_STATUS         0x4009001E

/* Partition privilege flags from CPUID 0x40000003 */
#define HV_ACCESS_VSM                    (1ULL << 16)  /* AccessVsm privilege */
#define HV_ACCESS_VP_REGISTERS           (1ULL << 17)  /* AccessVpRegisters */
#define HV_ACCESS_SYNIC_REGS             (1ULL << 18)  /* AccessSynicRegs */

/* VSM Capabilities bits */
#define VSM_CAP_DR6_SHARED               (1 << 0)
#define VSM_CAP_MBEC_VTL_MASK            0xFF00        /* Bits 8-15 */
#define VSM_CAP_DENY_LOWER_VTL_STARTUP   (1 << 16)

/* VSM Partition Status bits */
#define VSM_PART_ENABLED_VTL_SET         0xFF          /* Bits 0-7: enabled VTLs */
#define VSM_PART_MAX_VTL                 0xFF00        /* Bits 8-15: max VTL */
#define VSM_PART_VSM_ENABLED             (1 << 16)

/* VSM detection info */
typedef struct _VSM_INFO {
    BOOL hasVsmPrivilege;
    BOOL hasVpRegPrivilege;
    BOOL hasSynicPrivilege;
    BOOL canUseVsm;
    
    BOOL vsmEnabled;
    DWORD enabledVtls;
    DWORD maxVtl;
    DWORD currentVtl;
    
    /* Capabilities */
    BOOL dr6Shared;
    DWORD mbecVtlMask;
    BOOL denyLowerVtlStartup;
    
    /* Security features */
    BOOL hasCredentialGuard;
    BOOL hasHvci;
    BOOL hasSecureBoot;
} VSM_INFO, *PVSM_INFO;

/*
 * Check VSM-related partition privileges from CPUID
 */
static void CheckVsmPrivileges(PVSM_INFO info)
{
    int cpuInfo[4] = {0};
    UINT64 privMask;
    
    if (info == NULL) {
        return;
    }
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 31))) {
        return;
    }
    
    /* Get privilege mask from CPUID 0x40000003 */
    __cpuid(cpuInfo, 0x40000003);
    
    /* EAX contains low 32 bits of privilege mask */
    /* EBX contains high 32 bits of privilege mask */
    privMask = ((UINT64)cpuInfo[1] << 32) | (UINT32)cpuInfo[0];
    
    info->hasVsmPrivilege = (privMask & HV_ACCESS_VSM) != 0;
    info->hasVpRegPrivilege = (privMask & HV_ACCESS_VP_REGISTERS) != 0;
    info->hasSynicPrivilege = (privMask & HV_ACCESS_SYNIC_REGS) != 0;
    
    /* VSM requires all three privileges */
    info->canUseVsm = info->hasVsmPrivilege && 
                      info->hasVpRegPrivilege && 
                      info->hasSynicPrivilege;
}

/*
 * Try to read VSM MSRs (may fail without proper privileges)
 */
static BOOL TryReadVsmMsrs(PVSM_INFO info)
{
    /* Note: Direct MSR access requires kernel mode
     * This is a placeholder for user-mode detection
     * In practice, use NtQuerySystemInformation or driver
     */
    return FALSE;
}

/*
 * Check VSM status through registry
 */
static void CheckVsmRegistry(PVSM_INFO info)
{
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    LONG result;
    
    if (info == NULL) {
        return;
    }
    
    /* Check Device Guard / HVCI status */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", 
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->vsmEnabled = (value != 0);
        }
        
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "HypervisorEnforcedCodeIntegrity",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->hasHvci = (value != 0);
        }
        
        RegCloseKey(hKey);
    }
    
    /* Check Credential Guard status */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Lsa",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "LsaCfgFlags",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->hasCredentialGuard = (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    /* Check Secure Boot */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->hasSecureBoot = (value != 0);
        }
        RegCloseKey(hKey);
    }
}

/*
 * Get current VTL via CPUID if available
 */
static DWORD GetCurrentVtl(void)
{
    /* Current VTL is typically obtained through:
     * 1. HvRegisterVsmVpStatus MSR (kernel mode)
     * 2. NtQuerySystemInformation with specific class
     * For user-mode, we assume VTL 0 unless in secure process
     */
    return 0;
}

/*
 * Gather VSM info
 */
static void GatherVsmInfo(PVSM_INFO info)
{
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(VSM_INFO));
    
    /* Check privileges from CPUID */
    CheckVsmPrivileges(info);
    
    /* Check registry for VSM status */
    CheckVsmRegistry(info);
    
    /* Try to read MSRs (usually fails in user mode) */
    TryReadVsmMsrs(info);
    
    /* Get current VTL */
    info->currentVtl = GetCurrentVtl();
    
    /* Estimate max VTL based on features */
    if (info->vsmEnabled) {
        info->maxVtl = 1;  /* VTL 0 and VTL 1 */
        info->enabledVtls = 0x03;  /* Both VTL 0 and 1 */
    }
}

/*
 * Main VSM check function
 */
DWORD CheckVsmHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    VSM_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    GatherVsmInfo(&info);
    
    /* Detection based on VSM being enabled or privileges present */
    if (info.vsmEnabled || info.canUseVsm) {
        detected = HYPERV_DETECTED_VSM;
    }
    
    /* Build details */
    AppendToDetails(result, "Virtual Secure Mode (VSM) Detection:\n");
    
    AppendToDetails(result, "  Partition Privileges (CPUID 0x40000003):\n");
    AppendToDetails(result, "    AccessVsm: %s\n", 
                   info.hasVsmPrivilege ? "YES" : "NO");
    AppendToDetails(result, "    AccessVpRegisters: %s\n", 
                   info.hasVpRegPrivilege ? "YES" : "NO");
    AppendToDetails(result, "    AccessSynicRegs: %s\n", 
                   info.hasSynicPrivilege ? "YES" : "NO");
    AppendToDetails(result, "    Can Use VSM: %s\n", 
                   info.canUseVsm ? "YES" : "NO");
    
    AppendToDetails(result, "  VSM Status (Registry):\n");
    AppendToDetails(result, "    VBS Enabled: %s\n", 
                   info.vsmEnabled ? "YES" : "NO");
    AppendToDetails(result, "    HVCI (Memory Integrity): %s\n", 
                   info.hasHvci ? "Enabled" : "Disabled");
    AppendToDetails(result, "    Credential Guard: %s\n", 
                   info.hasCredentialGuard ? "Enabled" : "Disabled");
    AppendToDetails(result, "    Secure Boot: %s\n", 
                   info.hasSecureBoot ? "Enabled" : "Disabled");
    
    if (info.vsmEnabled) {
        AppendToDetails(result, "  VTL Information:\n");
        AppendToDetails(result, "    Current VTL: %d\n", info.currentVtl);
        AppendToDetails(result, "    Max VTL: %d\n", info.maxVtl);
        AppendToDetails(result, "    Enabled VTLs Mask: 0x%02X\n", info.enabledVtls);
    }
    
    if (info.vsmEnabled) {
        AppendToDetails(result, "  Note: System running with Virtual Secure Mode\n");
        if (info.hasHvci) {
            AppendToDetails(result, "  Note: Hypervisor-enforced Code Integrity active\n");
        }
    }
    
    return detected;
}

/*
 * Quick check for VSM enabled
 */
BOOL IsVsmEnabled(void)
{
    VSM_INFO info = {0};
    GatherVsmInfo(&info);
    return info.vsmEnabled;
}

/*
 * Check if HVCI is enabled
 */
BOOL IsHvciEnabled(void)
{
    VSM_INFO info = {0};
    GatherVsmInfo(&info);
    return info.hasHvci;
}

/*
 * Check if Credential Guard is enabled
 */
BOOL IsCredentialGuardEnabled(void)
{
    VSM_INFO info = {0};
    GatherVsmInfo(&info);
    return info.hasCredentialGuard;
}

/*
 * Get current VTL level
 */
DWORD GetVtlLevel(void)
{
    VSM_INFO info = {0};
    GatherVsmInfo(&info);
    return info.currentVtl;
}
