/**
 * hypercall_interface_checks.c - Hypercall Interface Detection
 * 
 * Detects Hyper-V hypercall interface availability from user mode.
 * 
 * Sources:
 * - Writing a Hyper-V Bridge for Fuzzing (Alex Ionescu): https://www.alex-ionescu.com/?p=471
 * - Fuzzing para-virtualized devices in Hyper-V (MSRC): https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/
 * - Ventures into Hyper-V - Fuzzing hypercalls (Amardeep Chana): https://labs.withsecure.com/publications/ventures-into-hyper-v-part-1-fuzzing-hypercalls
 * - Growing Hypervisor 0day with Hyperseed (Daniel King, Shawn Denbow): MSRC
 * - HyperDeceit (Aryan Xyrem): https://github.com/Xyrem/HyperDeceit
 * - Hvcalls GUI (Arthur Khudyaev): https://github.com/gerhart01/Hyper-V-Tools/tree/main/Extract.Hvcalls
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_HYPERCALL_IF 0x00008000

/* Hypercall page MSR */
#define HV_X64_MSR_HYPERCALL 0x40000001

/* Hypercall input codes (subset) */
#define HVCALL_POST_MESSAGE             0x005C
#define HVCALL_SIGNAL_EVENT             0x005D
#define HVCALL_GET_VP_REGISTERS         0x0050
#define HVCALL_SET_VP_REGISTERS         0x0051
#define HVCALL_TRANSLATE_VIRTUAL_ADDRESS 0x0052

/* Hypercall interface info */
typedef struct _HYPERCALL_IF_INFO {
    BOOL hypercallLeafAvailable;
    BOOL hypercallPageEnabled;
    
    /* CPUID 0x40000003 privileges */
    DWORD accessPartitionId;
    DWORD accessHypercallMsrs;
    DWORD accessVpIndex;
    DWORD accessResetMsr;
    DWORD accessStatsMsr;
    DWORD accessPartitionReferenceTsc;
    DWORD accessGuestIdleMsr;
    DWORD accessFrequencyMsrs;
    
    /* Hypercall capabilities */
    BOOL canPostMessage;
    BOOL canSignalEvent;
    BOOL canGetSetVpRegs;
    
    /* Guest OS ID */
    BOOL guestOsIdSet;
} HYPERCALL_IF_INFO, *PHYPERCALL_IF_INFO;

/*
 * Check hypercall privileges from CPUID
 */
static void CheckHypercallPrivileges(PHYPERCALL_IF_INFO info)
{
    int cpuInfo[4] = {0};
    DWORD maxLeaf;
    
    if (info == NULL) {
        return;
    }
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1 << 31)) == 0) {
        return;
    }
    
    /* Get max leaf */
    __cpuid(cpuInfo, 0x40000000);
    maxLeaf = cpuInfo[0];
    
    if (maxLeaf < 0x40000003) {
        return;
    }
    
    info->hypercallLeafAvailable = TRUE;
    
    /* Get partition privileges from 0x40000003 */
    __cpuid(cpuInfo, 0x40000003);
    
    /* EAX - Access partition reference counter, etc. */
    info->accessPartitionReferenceTsc = (cpuInfo[0] & (1 << 9)) != 0;
    info->accessGuestIdleMsr = (cpuInfo[0] & (1 << 10)) != 0;
    info->accessFrequencyMsrs = (cpuInfo[0] & (1 << 11)) != 0;
    
    /* EBX - Hypercall permissions */
    info->accessPartitionId = (cpuInfo[1] & (1 << 0)) != 0;  /* CreatePartitions */
    info->accessHypercallMsrs = (cpuInfo[1] & (1 << 2)) != 0; /* AccessHypercallMsrs */
    info->accessVpIndex = (cpuInfo[1] & (1 << 4)) != 0;       /* AccessVpIndex */
    
    /* Check if we can use basic hypercalls */
    info->canPostMessage = (cpuInfo[1] & (1 << 5)) != 0;      /* PostMessages */
    info->canSignalEvent = (cpuInfo[1] & (1 << 6)) != 0;      /* SignalEvents */
}

/*
 * Check if hypercall page is enabled (requires privilege)
 * This is informational only - actual MSR read needs kernel mode
 */
static void CheckHypercallPageInfo(PHYPERCALL_IF_INFO info)
{
    HKEY hKey;
    LONG result;
    
    if (info == NULL) {
        return;
    }
    
    /* Check registry for hypercall info */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Virtualization key exists - likely hypercall is available */
        info->hypercallPageEnabled = TRUE;
        RegCloseKey(hKey);
    }
}

/*
 * Check Guest OS ID (from CPUID 0x40000000-0x40000001)
 */
static void CheckGuestOsId(PHYPERCALL_IF_INFO info)
{
    int cpuInfo[4] = {0};
    char vendorId[13] = {0};
    
    if (info == NULL) {
        return;
    }
    
    /* Get vendor ID */
    __cpuid(cpuInfo, 0x40000000);
    
    memcpy(vendorId, &cpuInfo[1], 4);      /* EBX */
    memcpy(vendorId + 4, &cpuInfo[2], 4);  /* ECX */
    memcpy(vendorId + 8, &cpuInfo[3], 4);  /* EDX */
    
    if (strcmp(vendorId, "Microsoft Hv") == 0) {
        info->guestOsIdSet = TRUE;
    }
}

/*
 * Check for VID.sys (Virtualization Infrastructure Driver)
 */
static BOOL CheckVidDriver(void)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL result = FALSE;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return FALSE;
    }
    
    hService = OpenServiceA(hSCManager, "vid", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            result = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return result;
}

/*
 * Main hypercall interface check function
 */
DWORD CheckHypercallInterfaceHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HYPERCALL_IF_INFO info = {0};
    BOOL vidRunning;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckHypercallPrivileges(&info);
    CheckHypercallPageInfo(&info);
    CheckGuestOsId(&info);
    vidRunning = CheckVidDriver();
    
    /* Detection */
    if (info.hypercallLeafAvailable && info.guestOsIdSet) {
        detected = HYPERV_DETECTED_HYPERCALL_IF;
    }
    
    /* Build details */
    AppendToDetails(result, "Hypercall Interface Detection:\n");
    
    AppendToDetails(result, "\n  CPUID Availability:\n");
    AppendToDetails(result, "    Hypercall Leaf (0x40000003): %s\n", 
                   info.hypercallLeafAvailable ? "Available" : "Not available");
    AppendToDetails(result, "    Guest OS ID Set: %s\n", 
                   info.guestOsIdSet ? "YES" : "NO");
    
    if (info.hypercallLeafAvailable) {
        AppendToDetails(result, "\n  MSR Access Privileges:\n");
        AppendToDetails(result, "    Hypercall MSRs: %s\n", 
                       info.accessHypercallMsrs ? "Allowed" : "Denied");
        AppendToDetails(result, "    VP Index: %s\n", 
                       info.accessVpIndex ? "Allowed" : "Denied");
        AppendToDetails(result, "    Reference TSC: %s\n", 
                       info.accessPartitionReferenceTsc ? "Allowed" : "Denied");
        AppendToDetails(result, "    Guest Idle MSR: %s\n", 
                       info.accessGuestIdleMsr ? "Allowed" : "Denied");
        AppendToDetails(result, "    Frequency MSRs: %s\n", 
                       info.accessFrequencyMsrs ? "Allowed" : "Denied");
        
        AppendToDetails(result, "\n  Hypercall Capabilities:\n");
        AppendToDetails(result, "    PostMessage: %s\n", 
                       info.canPostMessage ? "Allowed" : "Denied");
        AppendToDetails(result, "    SignalEvent: %s\n", 
                       info.canSignalEvent ? "Allowed" : "Denied");
        AppendToDetails(result, "    CreatePartitions: %s\n", 
                       info.accessPartitionId ? "Allowed (ROOT)" : "Denied");
    }
    
    AppendToDetails(result, "\n  Driver Status:\n");
    AppendToDetails(result, "    VID.sys: %s\n", 
                   vidRunning ? "Running" : "Not running");
    
    if (info.accessPartitionId) {
        AppendToDetails(result, "\n  Note: CreatePartitions privilege = ROOT PARTITION\n");
    }
    
    return detected;
}

/*
 * Quick check for hypercall interface
 */
BOOL HasHypercallInterface(void)
{
    HYPERCALL_IF_INFO info = {0};
    CheckHypercallPrivileges(&info);
    CheckGuestOsId(&info);
    return info.hypercallLeafAvailable && info.guestOsIdSet;
}

/*
 * Check if PostMessage hypercall is available
 */
BOOL CanPostMessage(void)
{
    HYPERCALL_IF_INFO info = {0};
    CheckHypercallPrivileges(&info);
    return info.canPostMessage;
}

/*
 * Check if SignalEvent hypercall is available
 */
BOOL CanSignalEvent(void)
{
    HYPERCALL_IF_INFO info = {0};
    CheckHypercallPrivileges(&info);
    return info.canSignalEvent;
}

/*
 * Check if this is root partition by hypercall privileges
 */
BOOL IsRootByHypercallPrivileges(void)
{
    HYPERCALL_IF_INFO info = {0};
    CheckHypercallPrivileges(&info);
    return info.accessPartitionId;
}
