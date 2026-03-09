/**
 * vmcs_ept_checks.c - VMCS and EPT Detection
 * 
 * Detects VMCS (Virtual Machine Control Structure) and EPT (Extended Page Tables)
 * indicators from user mode. These are key Intel VT-x structures used by Hyper-V
 * for hardware-assisted virtualization.
 * 
 * Sources:
 * - hvext - Hyper-V WinDbg extension for VMCS/EPT analysis (Satoshi Tanda):
 *   https://github.com/tandasat/hvext
 *   Provides commands for dumping EPT, VMCS, MSRs and other hypervisor structures
 * - Intel SDM: Volume 3, Chapter 24-28 (VMX)
 * - Hyper-V TLFS: VMCS enlightenments, nested virtualization
 * - Some notes on identifying exit and hypercall handlers (Bruce Dang):
 *   https://gracefulbits.wordpress.com/2019/03/25/some-notes-on-identifying-exit-and-hypercall-handlers-in-hyperv/
 * - Hyper-V Architecture and Vulnerabilities (Nicolas Joly, Joe Bialek): BlackHat 2018
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_VMCS_EPT 0x00000400

/* CPUID feature flags */
#define CPUID_FEATURE_VMX  (1 << 5)   /* ECX bit 5 - VMX support */
#define CPUID_FEATURE_EPT  (1 << 0)   /* Secondary proc-based controls */

/* VMCS/EPT detection info */
typedef struct _VMCS_EPT_INFO {
    BOOL vmxSupported;
    BOOL eptSupported;
    BOOL vpdidSupported;
    
    BOOL hypervisorPresent;
    BOOL nestedVmxAllowed;
    
    BOOL vmcsEnlightenments;
    BOOL eptViolationAssist;
    
    DWORD vmxRevision;
} VMCS_EPT_INFO, *PVMCS_EPT_INFO;

/*
 * Check VMX support via CPUID
 */
static void CheckVmxSupport(PVMCS_EPT_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    
    if (cpuInfo[2] & (1 << 31)) {
        info->hypervisorPresent = TRUE;
    }
    
    /* VMX support bit */
    if (cpuInfo[2] & CPUID_FEATURE_VMX) {
        info->vmxSupported = TRUE;
    }
}

/*
 * Check for EPT and VPID support indicators
 */
static void CheckEptVpid(PVMCS_EPT_INFO info)
{
    int cpuInfo[4] = {0};
    DWORD maxLeaf;
    
    if (info == NULL) {
        return;
    }
    
    /* If hypervisor is present, check its capabilities */
    if (!info->hypervisorPresent) {
        return;
    }
    
    /* Get max hypervisor leaf */
    __cpuid(cpuInfo, 0x40000000);
    maxLeaf = cpuInfo[0];
    
    if (maxLeaf < 0x40000004) {
        return;
    }
    
    /* Check hypervisor implementation recommendations */
    /* CPUID 0x40000004 contains nested virtualization info */
    __cpuid(cpuInfo, 0x40000004);
    
    /* EAX contains implementation recommendations */
    /* Bit 18 - Nested virtualization support */
    if (cpuInfo[0] & (1 << 18)) {
        info->nestedVmxAllowed = TRUE;
    }
    
    /* Check for enlightened VMCS */
    if (cpuInfo[0] & (1 << 20)) {
        info->vmcsEnlightenments = TRUE;
    }
    
    /* Check CPUID 0x40000006 for more features */
    if (maxLeaf >= 0x40000006) {
        __cpuid(cpuInfo, 0x40000006);
        
        /* EAX contains hardware features */
        /* These indicate EPT/VPID-like functionality */
        if (cpuInfo[0] != 0) {
            info->eptSupported = TRUE;
        }
    }
}

/*
 * Check for VMCS enlightenments via registry
 */
static void CheckVmcsEnlightenments(PVMCS_EPT_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check virtualization settings */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Check for enlightened VMCS setting */
        if (RegQueryValueExA(hKey, "EnlightenedVmcsEnabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value != 0) {
                info->vmcsEnlightenments = TRUE;
            }
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check for EPT violation assist
 */
static void CheckEptViolationAssist(PVMCS_EPT_INFO info)
{
    int cpuInfo[4] = {0};
    DWORD maxLeaf;
    
    if (info == NULL) {
        return;
    }
    
    if (!info->hypervisorPresent) {
        return;
    }
    
    /* Get max hypervisor leaf */
    __cpuid(cpuInfo, 0x40000000);
    maxLeaf = cpuInfo[0];
    
    /* Check CPUID 0x4000000A for nested enlightenments */
    if (maxLeaf >= 0x4000000A) {
        __cpuid(cpuInfo, 0x4000000A);
        
        /* EAX bit 3 - EPT shadow violation assist */
        if (cpuInfo[0] & (1 << 3)) {
            info->eptViolationAssist = TRUE;
        }
    }
}

/*
 * Main VMCS/EPT check function
 */
DWORD CheckVmcsEptHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    VMCS_EPT_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckVmxSupport(&info);
    CheckEptVpid(&info);
    CheckVmcsEnlightenments(&info);
    CheckEptViolationAssist(&info);
    
    /* Detection */
    if (info.hypervisorPresent && (info.vmcsEnlightenments || info.eptSupported)) {
        detected = HYPERV_DETECTED_VMCS_EPT;
    }
    
    /* Build details */
    AppendToDetails(result, "VMCS / EPT Detection:\n");
    
    AppendToDetails(result, "\n  CPU Virtualization Support:\n");
    AppendToDetails(result, "    VMX: %s\n", 
                   info.vmxSupported ? "Supported" : "Not supported");
    AppendToDetails(result, "    Hypervisor Present: %s\n", 
                   info.hypervisorPresent ? "YES" : "NO");
    
    AppendToDetails(result, "\n  Extended Page Tables:\n");
    AppendToDetails(result, "    EPT Indicators: %s\n", 
                   info.eptSupported ? "Present" : "Not detected");
    AppendToDetails(result, "    EPT Violation Assist: %s\n", 
                   info.eptViolationAssist ? "Enabled" : "Disabled");
    
    AppendToDetails(result, "\n  VMCS Enlightenments:\n");
    AppendToDetails(result, "    Enlightened VMCS: %s\n", 
                   info.vmcsEnlightenments ? "Enabled" : "Disabled");
    AppendToDetails(result, "    Nested VMX Allowed: %s\n", 
                   info.nestedVmxAllowed ? "YES" : "NO");
    
    if (info.vmcsEnlightenments) {
        AppendToDetails(result, "\n  Note: Enlightened VMCS is active\n");
        AppendToDetails(result, "        Optimized VM exits for nested virtualization\n");
    }
    
    return detected;
}

/*
 * Quick check for VMX support
 */
BOOL HasVmxSupport(void)
{
    VMCS_EPT_INFO info = {0};
    CheckVmxSupport(&info);
    return info.vmxSupported;
}

/*
 * Check if EPT is available
 */
BOOL HasEptSupport(void)
{
    VMCS_EPT_INFO info = {0};
    CheckVmxSupport(&info);
    CheckEptVpid(&info);
    return info.eptSupported;
}

/*
 * Check if enlightened VMCS is enabled
 */
BOOL IsEnlightenedVmcsEnabled(void)
{
    VMCS_EPT_INFO info = {0};
    CheckVmxSupport(&info);
    CheckVmcsEnlightenments(&info);
    return info.vmcsEnlightenments;
}

/*
 * Check if nested VMX is allowed
 */
BOOL IsNestedVmxAllowed(void)
{
    VMCS_EPT_INFO info = {0};
    CheckVmxSupport(&info);
    CheckEptVpid(&info);
    return info.nestedVmxAllowed;
}
