/**
 * partition_checks.c - Hyper-V Partition Properties Detection
 * 
 * Detects partition privilege mask, partition ID, and related properties
 * through CPUID leaves and MSRs.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/partition-properties
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

#define HYPERV_DETECTED_PARTITION 0x80000000

/* Partition privilege flags from CPUID 0x40000003 EAX (access to MSRs) */
#define HV_PRIV_ACCESS_VP_RUNTIME          (1ULL << 0)
#define HV_PRIV_ACCESS_PART_REF_COUNTER    (1ULL << 1)
#define HV_PRIV_ACCESS_SYNIC_REGS          (1ULL << 2)
#define HV_PRIV_ACCESS_SYNTH_TIMER_REGS    (1ULL << 3)
#define HV_PRIV_ACCESS_INTR_CTRL_REGS      (1ULL << 4)
#define HV_PRIV_ACCESS_HYPERCALL_MSRS      (1ULL << 5)
#define HV_PRIV_ACCESS_VP_INDEX            (1ULL << 6)
#define HV_PRIV_ACCESS_RESET_REG           (1ULL << 7)
#define HV_PRIV_ACCESS_STATS_REG           (1ULL << 8)
#define HV_PRIV_ACCESS_PART_REF_TSC        (1ULL << 9)
#define HV_PRIV_ACCESS_GUEST_IDLE_REG      (1ULL << 10)
#define HV_PRIV_ACCESS_FREQUENCY_REGS      (1ULL << 11)
#define HV_PRIV_ACCESS_REENLIGHTENMENT     (1ULL << 13)

/* Partition privilege flags from CPUID 0x40000003 EBX (access to hypercalls) */
#define HV_PRIV_CREATE_PARTITIONS          (1ULL << 32)
#define HV_PRIV_ACCESS_PARTITION_ID        (1ULL << 33)
#define HV_PRIV_ACCESS_MEMORY_POOL         (1ULL << 34)
#define HV_PRIV_POST_MESSAGES              (1ULL << 36)
#define HV_PRIV_SIGNAL_EVENTS              (1ULL << 37)
#define HV_PRIV_CREATE_PORT                (1ULL << 38)
#define HV_PRIV_CONNECT_PORT               (1ULL << 39)
#define HV_PRIV_ACCESS_STATS               (1ULL << 40)
#define HV_PRIV_DEBUGGING                  (1ULL << 43)
#define HV_PRIV_CPU_MANAGEMENT             (1ULL << 44)
#define HV_PRIV_ACCESS_VSM                 (1ULL << 48)
#define HV_PRIV_ACCESS_VP_REGS             (1ULL << 49)
#define HV_PRIV_ISOLATION                  (1ULL << 54)

/* Partition features from CPUID 0x40000003 ECX */
#define HV_FEAT_INVARIANT_MPERF            (1 << 0)
#define HV_FEAT_SUPERVISOR_SHADOW_STACK    (1 << 1)
#define HV_FEAT_ARCHITECTURAL_PMU          (1 << 2)
#define HV_FEAT_EXCEPTION_TRAP_INTERCEPT   (1 << 3)

/* Partition info structure */
typedef struct _PARTITION_INFO {
    BOOL isHypervisorPresent;
    BOOL isHv1Interface;
    
    /* Privilege mask */
    UINT64 privilegeMask;
    DWORD features;         /* ECX */
    DWORD miscFeatures;     /* EDX */
    
    /* MSR access privileges */
    BOOL canAccessVpRuntime;
    BOOL canAccessRefCounter;
    BOOL canAccessSynic;
    BOOL canAccessTimers;
    BOOL canAccessIntrCtrl;
    BOOL canAccessHypercall;
    BOOL canAccessVpIndex;
    BOOL canAccessReset;
    BOOL canAccessStats;
    BOOL canAccessRefTsc;
    BOOL canAccessGuestIdle;
    BOOL canAccessFrequency;
    BOOL canAccessReenlightenment;
    
    /* Hypercall privileges */
    BOOL canCreatePartitions;
    BOOL canAccessPartitionId;
    BOOL canAccessMemoryPool;
    BOOL canPostMessages;
    BOOL canSignalEvents;
    BOOL canCreatePort;
    BOOL canConnectPort;
    BOOL canDebug;
    BOOL canManageCpu;
    BOOL canAccessVsm;
    BOOL canAccessVpRegs;
    BOOL hasIsolation;
    
    /* Root partition indicator */
    BOOL isRootPartition;
} PARTITION_INFO, *PPARTITION_INFO;

/*
 * Check if Hv#1 interface is present
 */
static BOOL CheckHv1Interface(void)
{
    int cpuInfo[4] = {0};
    char interface[5] = {0};
    
    __cpuid(cpuInfo, 0x40000001);
    
    /* Interface signature in EAX */
    *(DWORD*)interface = cpuInfo[0];
    
    return (strcmp(interface, "Hv#1") == 0);
}

/*
 * Get partition privilege mask
 */
static void GetPartitionPrivileges(PPARTITION_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    /* Check hypervisor present first */
    __cpuid(cpuInfo, 1);
    info->isHypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!info->isHypervisorPresent) {
        return;
    }
    
    /* Check Hv#1 interface */
    info->isHv1Interface = CheckHv1Interface();
    
    if (!info->isHv1Interface) {
        return;
    }
    
    /* Get privilege mask from CPUID 0x40000003 */
    __cpuid(cpuInfo, 0x40000003);
    
    /* EAX: bits 0-31 of privilege mask (MSR access) */
    /* EBX: bits 32-63 of privilege mask (hypercall access) */
    info->privilegeMask = ((UINT64)cpuInfo[1] << 32) | (UINT32)cpuInfo[0];
    info->features = cpuInfo[2];
    info->miscFeatures = cpuInfo[3];
    
    /* Parse MSR access privileges (EAX) */
    info->canAccessVpRuntime = (info->privilegeMask & HV_PRIV_ACCESS_VP_RUNTIME) != 0;
    info->canAccessRefCounter = (info->privilegeMask & HV_PRIV_ACCESS_PART_REF_COUNTER) != 0;
    info->canAccessSynic = (info->privilegeMask & HV_PRIV_ACCESS_SYNIC_REGS) != 0;
    info->canAccessTimers = (info->privilegeMask & HV_PRIV_ACCESS_SYNTH_TIMER_REGS) != 0;
    info->canAccessIntrCtrl = (info->privilegeMask & HV_PRIV_ACCESS_INTR_CTRL_REGS) != 0;
    info->canAccessHypercall = (info->privilegeMask & HV_PRIV_ACCESS_HYPERCALL_MSRS) != 0;
    info->canAccessVpIndex = (info->privilegeMask & HV_PRIV_ACCESS_VP_INDEX) != 0;
    info->canAccessReset = (info->privilegeMask & HV_PRIV_ACCESS_RESET_REG) != 0;
    info->canAccessStats = (info->privilegeMask & HV_PRIV_ACCESS_STATS_REG) != 0;
    info->canAccessRefTsc = (info->privilegeMask & HV_PRIV_ACCESS_PART_REF_TSC) != 0;
    info->canAccessGuestIdle = (info->privilegeMask & HV_PRIV_ACCESS_GUEST_IDLE_REG) != 0;
    info->canAccessFrequency = (info->privilegeMask & HV_PRIV_ACCESS_FREQUENCY_REGS) != 0;
    info->canAccessReenlightenment = (info->privilegeMask & HV_PRIV_ACCESS_REENLIGHTENMENT) != 0;
    
    /* Parse hypercall privileges (EBX) */
    info->canCreatePartitions = (info->privilegeMask & HV_PRIV_CREATE_PARTITIONS) != 0;
    info->canAccessPartitionId = (info->privilegeMask & HV_PRIV_ACCESS_PARTITION_ID) != 0;
    info->canAccessMemoryPool = (info->privilegeMask & HV_PRIV_ACCESS_MEMORY_POOL) != 0;
    info->canPostMessages = (info->privilegeMask & HV_PRIV_POST_MESSAGES) != 0;
    info->canSignalEvents = (info->privilegeMask & HV_PRIV_SIGNAL_EVENTS) != 0;
    info->canCreatePort = (info->privilegeMask & HV_PRIV_CREATE_PORT) != 0;
    info->canConnectPort = (info->privilegeMask & HV_PRIV_CONNECT_PORT) != 0;
    info->canDebug = (info->privilegeMask & HV_PRIV_DEBUGGING) != 0;
    info->canManageCpu = (info->privilegeMask & HV_PRIV_CPU_MANAGEMENT) != 0;
    info->canAccessVsm = (info->privilegeMask & HV_PRIV_ACCESS_VSM) != 0;
    info->canAccessVpRegs = (info->privilegeMask & HV_PRIV_ACCESS_VP_REGS) != 0;
    info->hasIsolation = (info->privilegeMask & HV_PRIV_ISOLATION) != 0;
    
    /* Root partition has CreatePartitions and CpuManagement privileges */
    info->isRootPartition = info->canCreatePartitions && info->canManageCpu;
}

/*
 * Main partition check function
 */
DWORD CheckPartitionHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    PARTITION_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    GetPartitionPrivileges(&info);
    
    /* Detect if Hv#1 interface present */
    if (info.isHv1Interface) {
        detected = HYPERV_DETECTED_PARTITION;
    }
    
    /* Build details */
    AppendToDetails(result, "Partition Properties Detection:\n");
    AppendToDetails(result, "  Hypervisor Present: %s\n", 
                   info.isHypervisorPresent ? "YES" : "NO");
    AppendToDetails(result, "  Hv#1 Interface: %s\n", 
                   info.isHv1Interface ? "YES" : "NO");
    
    if (!info.isHv1Interface) {
        AppendToDetails(result, "  Note: Not a Hv#1 compatible hypervisor\n");
        return detected;
    }
    
    AppendToDetails(result, "  Privilege Mask: 0x%016llX\n", info.privilegeMask);
    AppendToDetails(result, "  Features (ECX): 0x%08X\n", info.features);
    AppendToDetails(result, "  Misc (EDX): 0x%08X\n", info.miscFeatures);
    
    AppendToDetails(result, "\n  MSR Access Privileges:\n");
    AppendToDetails(result, "    VP Runtime: %s\n", info.canAccessVpRuntime ? "YES" : "NO");
    AppendToDetails(result, "    Reference Counter: %s\n", info.canAccessRefCounter ? "YES" : "NO");
    AppendToDetails(result, "    SynIC Registers: %s\n", info.canAccessSynic ? "YES" : "NO");
    AppendToDetails(result, "    Synthetic Timers: %s\n", info.canAccessTimers ? "YES" : "NO");
    AppendToDetails(result, "    Hypercall MSRs: %s\n", info.canAccessHypercall ? "YES" : "NO");
    AppendToDetails(result, "    VP Index: %s\n", info.canAccessVpIndex ? "YES" : "NO");
    AppendToDetails(result, "    Reference TSC: %s\n", info.canAccessRefTsc ? "YES" : "NO");
    AppendToDetails(result, "    Frequency Regs: %s\n", info.canAccessFrequency ? "YES" : "NO");
    
    AppendToDetails(result, "\n  Hypercall Privileges:\n");
    AppendToDetails(result, "    Create Partitions: %s\n", info.canCreatePartitions ? "YES" : "NO");
    AppendToDetails(result, "    Access Partition ID: %s\n", info.canAccessPartitionId ? "YES" : "NO");
    AppendToDetails(result, "    Post Messages: %s\n", info.canPostMessages ? "YES" : "NO");
    AppendToDetails(result, "    Signal Events: %s\n", info.canSignalEvents ? "YES" : "NO");
    AppendToDetails(result, "    CPU Management: %s\n", info.canManageCpu ? "YES" : "NO");
    AppendToDetails(result, "    Access VSM: %s\n", info.canAccessVsm ? "YES" : "NO");
    AppendToDetails(result, "    Debugging: %s\n", info.canDebug ? "YES" : "NO");
    AppendToDetails(result, "    Isolation: %s\n", info.hasIsolation ? "YES" : "NO");
    
    AppendToDetails(result, "\n  Partition Type: %s\n", 
                   info.isRootPartition ? "ROOT (Host)" : "GUEST (VM)");
    
    if (info.features) {
        AppendToDetails(result, "\n  Additional Features:\n");
        if (info.features & HV_FEAT_INVARIANT_MPERF)
            AppendToDetails(result, "    + Invariant MPERF\n");
        if (info.features & HV_FEAT_SUPERVISOR_SHADOW_STACK)
            AppendToDetails(result, "    + Supervisor Shadow Stack (CET)\n");
        if (info.features & HV_FEAT_ARCHITECTURAL_PMU)
            AppendToDetails(result, "    + Architectural PMU\n");
        if (info.features & HV_FEAT_EXCEPTION_TRAP_INTERCEPT)
            AppendToDetails(result, "    + Exception Trap Intercept\n");
    }
    
    return detected;
}

/*
 * Quick check for Hv#1 interface
 */
BOOL HasHv1Interface(void)
{
    PARTITION_INFO info = {0};
    GetPartitionPrivileges(&info);
    return info.isHv1Interface;
}

/*
 * Check if current partition is root
 */
BOOL IsRootPartitionByPrivileges(void)
{
    PARTITION_INFO info = {0};
    GetPartitionPrivileges(&info);
    return info.isRootPartition;
}

/*
 * Get partition privilege mask
 */
UINT64 GetPartitionPrivilegeMask(void)
{
    PARTITION_INFO info = {0};
    GetPartitionPrivileges(&info);
    return info.privilegeMask;
}
