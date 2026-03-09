/**
 * enlightenments_checks.c - Hyper-V Enlightenments Detection
 * 
 * Detects Hyper-V paravirtualization enlightenments from CPUID.
 * Enlightenments are optimizations that improve VM performance.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 * - https://www.qemu.org/docs/master/system/i386/hyperv.html
 * - https://archive.fosdem.org/2019/schedule/event/vai_enlightening_kvm/
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

#define HYPERV_DETECTED_ENLIGHTENMENTS 0x00400000

/*
 * Enlightenment flags from CPUID 0x40000003
 */

/* EAX - Partition privilege flags (MSR access) */
#define HV_ACCESS_VP_RUNTIME_REG           (1 << 0)
#define HV_ACCESS_PARTITION_REF_COUNTER    (1 << 1)
#define HV_ACCESS_SYNIC_REGS               (1 << 2)
#define HV_ACCESS_SYNTHETIC_TIMER_REGS     (1 << 3)
#define HV_ACCESS_APIC_REGS                (1 << 4)
#define HV_ACCESS_HYPERCALL_MSRS           (1 << 5)
#define HV_ACCESS_VP_INDEX                 (1 << 6)
#define HV_ACCESS_RESET_REG                (1 << 7)
#define HV_ACCESS_STATS_REG                (1 << 8)
#define HV_ACCESS_PARTITION_REF_TSC        (1 << 9)
#define HV_ACCESS_GUEST_IDLE_REG           (1 << 10)
#define HV_ACCESS_FREQUENCY_REGS           (1 << 11)
#define HV_ACCESS_DEBUG_REGS               (1 << 12)
#define HV_ACCESS_REENLIGHTENMENT_CTRLS    (1 << 13)

/* ECX - Power management features */
#define HV_CPU_POWER_MANAGEMENT            (1 << 0)
#define HV_MWAIT_AVAILABLE                 (1 << 1)
#define HV_GUEST_DEBUGGING                 (1 << 2)

/* EDX - Miscellaneous features */
#define HV_MWAIT_DEPRECATED                (1 << 0)
#define HV_GUEST_CRASH_MSR                 (1 << 10)
#define HV_DEBUG_MSR                       (1 << 11)
#define HV_NPIEP                           (1 << 12)
#define HV_DISABLE_HYPERVISOR              (1 << 13)
#define HV_EXTENDED_CPUID                  (1 << 14)
#define HV_EXTENDED_CPUID_NESTED           (1 << 15)
#define HV_ENABLE_EXTENDED_HYPERCALL       (1 << 20)
#define HV_ISOLATED_VM                     (1 << 22)
#define HV_START_VP                        (1 << 24)

/*
 * Enlightenment flags from CPUID 0x40000004 (Implementation Recommendations)
 */
#define HV_RECOMMEND_USE_HYPERCALL_FOR_ADDRESS_SWITCH (1 << 0)
#define HV_RECOMMEND_USE_HYPERCALL_FOR_LOCAL_TLB_FLUSH (1 << 1)
#define HV_RECOMMEND_USE_HYPERCALL_FOR_REMOTE_TLB_FLUSH (1 << 2)
#define HV_RECOMMEND_USE_MSR_FOR_APIC_ACCESS          (1 << 3)
#define HV_RECOMMEND_USE_MSR_FOR_SYS_RESET            (1 << 4)
#define HV_RECOMMEND_RELAXED_TIMING                   (1 << 5)
#define HV_RECOMMEND_DMA_REMAPPING                    (1 << 6)
#define HV_RECOMMEND_INTERRUPT_REMAPPING              (1 << 7)
#define HV_RECOMMEND_X2APIC_MSR                       (1 << 8)
#define HV_RECOMMEND_DEPRECATE_AUTO_EOI               (1 << 9)
#define HV_RECOMMEND_SYNTHETIC_CLUSTER_IPI_HYPERCALL  (1 << 10)
#define HV_RECOMMEND_EXPROCESSORMASKS                 (1 << 11)
#define HV_RECOMMEND_NESTED_HYPERV                    (1 << 12)
#define HV_RECOMMEND_INT_MBEC                         (1 << 13)
#define HV_RECOMMEND_NESTED_EVMCS                     (1 << 14)
#define HV_RECOMMEND_SYNCED_TIMELINE                  (1 << 17)
#define HV_RECOMMEND_DIRECT_LOCAL_FLUSH               (1 << 18)
#define HV_RECOMMEND_NO_NONARCH_CORESHARING           (1 << 19)

/*
 * Enlightenment info structure
 */
typedef struct _ENLIGHTENMENT_INFO {
    /* CPUID 0x40000003 */
    DWORD privilegeFlags;      /* EAX */
    DWORD hypercallFlags;      /* EBX */
    DWORD powerFlags;          /* ECX */
    DWORD miscFlags;           /* EDX */
    
    /* CPUID 0x40000004 */
    DWORD recommendations;     /* EAX */
    DWORD spinlockRetries;     /* EBX */
    
    /* CPUID 0x40000006 */
    DWORD hardwareFeatures;    /* EAX */
    
    /* Counts */
    int privilegeCount;
    int recommendationCount;
} ENLIGHTENMENT_INFO, *PENLIGHTENMENT_INFO;

/*
 * Count set bits in a DWORD
 */
static int CountBits(DWORD value)
{
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

/*
 * Get all enlightenment information
 */
static void GetEnlightenmentInfo(PENLIGHTENMENT_INFO info)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(ENLIGHTENMENT_INFO));
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return;
    }
    
    /* CPUID 0x40000003 - Partition privileges */
    __cpuid(cpuInfo, 0x40000003);
    info->privilegeFlags = (DWORD)cpuInfo[0];
    info->hypercallFlags = (DWORD)cpuInfo[1];
    info->powerFlags = (DWORD)cpuInfo[2];
    info->miscFlags = (DWORD)cpuInfo[3];
    
    /* CPUID 0x40000004 - Implementation recommendations */
    __cpuid(cpuInfo, 0x40000004);
    info->recommendations = (DWORD)cpuInfo[0];
    info->spinlockRetries = (DWORD)cpuInfo[1];
    
    /* CPUID 0x40000006 - Hardware features */
    __cpuid(cpuInfo, 0x40000006);
    info->hardwareFeatures = (DWORD)cpuInfo[0];
    
    /* Calculate counts */
    info->privilegeCount = CountBits(info->privilegeFlags);
    info->recommendationCount = CountBits(info->recommendations);
}

/*
 * Main enlightenments check function
 */
DWORD CheckEnlightenmentsHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    ENLIGHTENMENT_INFO info = {0};
    int cpuInfo[4] = {0, 0, 0, 0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        AppendToDetails(result, "Enlightenments: No hypervisor present\n");
        return 0;
    }
    
    /* Get enlightenment info */
    GetEnlightenmentInfo(&info);
    
    if (info.privilegeCount > 0 || info.recommendationCount > 0) {
        detected = HYPERV_DETECTED_ENLIGHTENMENTS;
    }
    
    /* Build details */
    AppendToDetails(result, "Hyper-V Enlightenments:\n");
    AppendToDetails(result, "  Privilege flags: 0x%08X (%d enabled)\n", 
                   info.privilegeFlags, info.privilegeCount);
    AppendToDetails(result, "  Hypercall flags: 0x%08X\n", info.hypercallFlags);
    AppendToDetails(result, "  Recommendations: 0x%08X (%d enabled)\n",
                   info.recommendations, info.recommendationCount);
    AppendToDetails(result, "  Spinlock retries: %u\n", info.spinlockRetries);
    AppendToDetails(result, "  Hardware features: 0x%08X\n", info.hardwareFeatures);
    
    /* List key enlightenments */
    if (info.privilegeFlags & HV_ACCESS_PARTITION_REF_TSC) {
        AppendToDetails(result, "  + Reference TSC (hv-time)\n");
    }
    if (info.privilegeFlags & HV_ACCESS_SYNIC_REGS) {
        AppendToDetails(result, "  + SynIC (hv-synic)\n");
    }
    if (info.privilegeFlags & HV_ACCESS_SYNTHETIC_TIMER_REGS) {
        AppendToDetails(result, "  + Synthetic Timers (hv-stimer)\n");
    }
    if (info.privilegeFlags & HV_ACCESS_VP_INDEX) {
        AppendToDetails(result, "  + VP Index (hv-vpindex)\n");
    }
    if (info.privilegeFlags & HV_ACCESS_VP_RUNTIME_REG) {
        AppendToDetails(result, "  + VP Runtime (hv-runtime)\n");
    }
    if (info.recommendations & HV_RECOMMEND_USE_HYPERCALL_FOR_REMOTE_TLB_FLUSH) {
        AppendToDetails(result, "  + TLB Flush Hypercall (hv-tlbflush)\n");
    }
    if (info.recommendations & HV_RECOMMEND_SYNTHETIC_CLUSTER_IPI_HYPERCALL) {
        AppendToDetails(result, "  + Cluster IPI Hypercall (hv-ipi)\n");
    }
    if (info.recommendations & HV_RECOMMEND_RELAXED_TIMING) {
        AppendToDetails(result, "  + Relaxed Timing (hv-relaxed)\n");
    }
    if (info.miscFlags & HV_GUEST_CRASH_MSR) {
        AppendToDetails(result, "  + Crash MSRs (hv-crash)\n");
    }
    if (info.miscFlags & HV_ISOLATED_VM) {
        AppendToDetails(result, "  + Isolated VM (CoCo/VBS)\n");
    }
    
    return detected;
}

/*
 * Check if specific enlightenment is enabled
 */
BOOL HasEnlightenment(DWORD enlightenmentBit, int cpuidLeaf)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    DWORD value = 0;
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return FALSE;
    }
    
    __cpuid(cpuInfo, cpuidLeaf);
    value = (DWORD)cpuInfo[0];  /* EAX */
    
    return (value & enlightenmentBit) != 0;
}

/*
 * Get spinlock retry count recommendation
 */
DWORD GetSpinlockRetryCount(void)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return 0;
    }
    
    __cpuid(cpuInfo, 0x40000004);
    return (DWORD)cpuInfo[1];  /* EBX */
}

/*
 * Check if running in isolated/confidential VM
 */
BOOL IsIsolatedVM(void)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return FALSE;
    }
    
    __cpuid(cpuInfo, 0x40000003);
    return (cpuInfo[3] & HV_ISOLATED_VM) != 0;
}
