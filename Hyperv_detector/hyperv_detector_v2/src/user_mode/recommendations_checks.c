/**
 * recommendations_checks.c - Hyper-V Recommendations Detection
 * 
 * Detects hypervisor recommendations from CPUID leaf 0x40000004
 * which guides the guest OS for optimal performance.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 * - https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e
 * - QEMU Hyper-V Enlightenments documentation
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_RECOMMENDATIONS 0x00020000

/* CPUID 0x40000004 EAX - Recommendations */
#define HV_HINT_HYPERCALL_FOR_SWITCH      (1 << 0)   /* Use hypercall for address space switch */
#define HV_HINT_HYPERCALL_FOR_LOCAL_TLB   (1 << 1)   /* Use hypercall for local TLB flush */
#define HV_HINT_HYPERCALL_FOR_REMOTE_TLB  (1 << 2)   /* Use hypercall for remote TLB flush */
#define HV_HINT_MSR_FOR_APIC_ACCESS       (1 << 3)   /* Use MSRs for APIC access */
#define HV_HINT_MSR_FOR_RESET             (1 << 4)   /* Use MSR for system reset */
#define HV_HINT_RELAXED_TIMING            (1 << 5)   /* Use relaxed timing */
#define HV_HINT_DMA_REMAPPING             (1 << 6)   /* Use DMA remapping */
#define HV_HINT_INTERRUPT_REMAPPING       (1 << 7)   /* Use interrupt remapping */
#define HV_HINT_X2APIC_MSRS               (1 << 8)   /* Use x2APIC MSRs */
#define HV_HINT_DEPRECATE_AUTO_EOI        (1 << 9)   /* Deprecate AutoEOI */
#define HV_HINT_HYPERCALL_FOR_IPI         (1 << 10)  /* Use hypercall for IPI */
#define HV_HINT_CLUSTER_IPI_RECOMMENDED   (1 << 11)  /* Use HvCallSendSyntheticClusterIpi */
#define HV_HINT_EX_PROC_MASKS_RECOMMENDED (1 << 12)  /* Use extended processor masks */
#define HV_HINT_NESTED                    (1 << 13)  /* Nested hypervisor is running */
#define HV_HINT_INT_MBEC_SYSCALLS         (1 << 14)  /* INT for MBEC syscalls */
#define HV_HINT_ENLIGHTENED_VMCS          (1 << 15)  /* Use enlightened VMCS */
#define HV_HINT_SYNCED_TIMELINE           (1 << 16)  /* Use synced timeline */
#define HV_HINT_DIRECT_LOCAL_FLUSH        (1 << 17)  /* Use direct local flush */
#define HV_HINT_NO_NONARCH_CORESHARING    (1 << 18)  /* No non-arch core sharing */

/* CPUID 0x40000004 ECX - Physical address width, etc */
#define HV_PHYSICAL_ADDRESS_WIDTH_MASK    0x7F       /* Bits 0-6 */

/* Recommendations detection info */
typedef struct _RECOMMENDATIONS_INFO {
    BOOL isHypervisorPresent;
    BOOL hasRecommendationsLeaf;
    
    /* Raw CPUID values */
    DWORD recommendations;  /* EAX */
    DWORD spinlockRetries;  /* EBX */
    DWORD physAddrInfo;     /* ECX */
    DWORD reserved;         /* EDX */
    
    /* Parsed recommendations */
    BOOL useHypercallForSwitch;
    BOOL useHypercallForLocalTlb;
    BOOL useHypercallForRemoteTlb;
    BOOL useMsrForApic;
    BOOL useMsrForReset;
    BOOL useRelaxedTiming;
    BOOL useDmaRemapping;
    BOOL useInterruptRemapping;
    BOOL useX2ApicMsrs;
    BOOL deprecateAutoEoi;
    BOOL useHypercallForIpi;
    BOOL useClusterIpi;
    BOOL useExProcMasks;
    BOOL isNested;
    BOOL useEnlightenedVmcs;
    BOOL useSyncedTimeline;
    BOOL useDirectLocalFlush;
    BOOL noNonArchCoreSharing;
    
    /* Physical address info */
    int physicalAddressWidth;
    
    /* Count */
    int recommendationCount;
} RECOMMENDATIONS_INFO, *PRECOMMENDATIONS_INFO;

/*
 * Check recommendations from CPUID
 */
static void CheckRecommendations(PRECOMMENDATIONS_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(RECOMMENDATIONS_INFO));
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    info->isHypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!info->isHypervisorPresent) {
        return;
    }
    
    /* Check max leaf */
    __cpuid(cpuInfo, 0x40000000);
    info->hasRecommendationsLeaf = (cpuInfo[0] >= 0x40000004);
    
    if (!info->hasRecommendationsLeaf) {
        return;
    }
    
    /* Get recommendations from CPUID 0x40000004 */
    __cpuid(cpuInfo, 0x40000004);
    
    info->recommendations = (DWORD)cpuInfo[0];
    info->spinlockRetries = (DWORD)cpuInfo[1];
    info->physAddrInfo = (DWORD)cpuInfo[2];
    info->reserved = (DWORD)cpuInfo[3];
    
    /* Parse recommendations */
    info->useHypercallForSwitch = (info->recommendations & HV_HINT_HYPERCALL_FOR_SWITCH) != 0;
    info->useHypercallForLocalTlb = (info->recommendations & HV_HINT_HYPERCALL_FOR_LOCAL_TLB) != 0;
    info->useHypercallForRemoteTlb = (info->recommendations & HV_HINT_HYPERCALL_FOR_REMOTE_TLB) != 0;
    info->useMsrForApic = (info->recommendations & HV_HINT_MSR_FOR_APIC_ACCESS) != 0;
    info->useMsrForReset = (info->recommendations & HV_HINT_MSR_FOR_RESET) != 0;
    info->useRelaxedTiming = (info->recommendations & HV_HINT_RELAXED_TIMING) != 0;
    info->useDmaRemapping = (info->recommendations & HV_HINT_DMA_REMAPPING) != 0;
    info->useInterruptRemapping = (info->recommendations & HV_HINT_INTERRUPT_REMAPPING) != 0;
    info->useX2ApicMsrs = (info->recommendations & HV_HINT_X2APIC_MSRS) != 0;
    info->deprecateAutoEoi = (info->recommendations & HV_HINT_DEPRECATE_AUTO_EOI) != 0;
    info->useHypercallForIpi = (info->recommendations & HV_HINT_HYPERCALL_FOR_IPI) != 0;
    info->useClusterIpi = (info->recommendations & HV_HINT_CLUSTER_IPI_RECOMMENDED) != 0;
    info->useExProcMasks = (info->recommendations & HV_HINT_EX_PROC_MASKS_RECOMMENDED) != 0;
    info->isNested = (info->recommendations & HV_HINT_NESTED) != 0;
    info->useEnlightenedVmcs = (info->recommendations & HV_HINT_ENLIGHTENED_VMCS) != 0;
    info->useSyncedTimeline = (info->recommendations & HV_HINT_SYNCED_TIMELINE) != 0;
    info->useDirectLocalFlush = (info->recommendations & HV_HINT_DIRECT_LOCAL_FLUSH) != 0;
    info->noNonArchCoreSharing = (info->recommendations & HV_HINT_NO_NONARCH_CORESHARING) != 0;
    
    /* Physical address width */
    info->physicalAddressWidth = info->physAddrInfo & HV_PHYSICAL_ADDRESS_WIDTH_MASK;
    
    /* Count recommendations */
    info->recommendationCount = 0;
    if (info->useHypercallForSwitch) info->recommendationCount++;
    if (info->useHypercallForLocalTlb) info->recommendationCount++;
    if (info->useHypercallForRemoteTlb) info->recommendationCount++;
    if (info->useMsrForApic) info->recommendationCount++;
    if (info->useMsrForReset) info->recommendationCount++;
    if (info->useRelaxedTiming) info->recommendationCount++;
    if (info->useHypercallForIpi) info->recommendationCount++;
    if (info->useEnlightenedVmcs) info->recommendationCount++;
}

/*
 * Main recommendations check function
 */
DWORD CheckRecommendationsHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    RECOMMENDATIONS_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckRecommendations(&info);
    
    /* Detection based on having recommendations leaf */
    if (info.hasRecommendationsLeaf) {
        detected = HYPERV_DETECTED_RECOMMENDATIONS;
    }
    
    /* Build details */
    AppendToDetails(result, "Hypervisor Recommendations Detection:\n");
    AppendToDetails(result, "  Hypervisor Present: %s\n", 
                   info.isHypervisorPresent ? "YES" : "NO");
    AppendToDetails(result, "  Recommendations Leaf (0x40000004): %s\n", 
                   info.hasRecommendationsLeaf ? "Available" : "Not available");
    
    if (!info.hasRecommendationsLeaf) {
        return detected;
    }
    
    AppendToDetails(result, "\n  Raw Values:\n");
    AppendToDetails(result, "    EAX (Recommendations): 0x%08X\n", info.recommendations);
    AppendToDetails(result, "    EBX (Spinlock Retries): 0x%08X (%s)\n", 
                   info.spinlockRetries,
                   info.spinlockRetries == 0xFFFFFFFF ? "Never notify" : "Retry count");
    AppendToDetails(result, "    ECX (Phys Addr Info): 0x%08X\n", info.physAddrInfo);
    
    AppendToDetails(result, "\n  Active Recommendations (%d):\n", info.recommendationCount);
    
    if (info.useHypercallForSwitch)
        AppendToDetails(result, "    + Use hypercall for address space switch\n");
    if (info.useHypercallForLocalTlb)
        AppendToDetails(result, "    + Use hypercall for local TLB flush\n");
    if (info.useHypercallForRemoteTlb)
        AppendToDetails(result, "    + Use hypercall for remote TLB flush\n");
    if (info.useMsrForApic)
        AppendToDetails(result, "    + Use MSRs for APIC access\n");
    if (info.useMsrForReset)
        AppendToDetails(result, "    + Use MSR for system reset\n");
    if (info.useRelaxedTiming)
        AppendToDetails(result, "    + Use relaxed timing\n");
    if (info.useDmaRemapping)
        AppendToDetails(result, "    + Use DMA remapping\n");
    if (info.useInterruptRemapping)
        AppendToDetails(result, "    + Use interrupt remapping\n");
    if (info.useX2ApicMsrs)
        AppendToDetails(result, "    + Use x2APIC MSRs\n");
    if (info.deprecateAutoEoi)
        AppendToDetails(result, "    + Deprecate AutoEOI\n");
    if (info.useHypercallForIpi)
        AppendToDetails(result, "    + Use hypercall for IPI\n");
    if (info.useClusterIpi)
        AppendToDetails(result, "    + Use synthetic cluster IPI\n");
    if (info.useEnlightenedVmcs)
        AppendToDetails(result, "    + Use enlightened VMCS (nested)\n");
    if (info.useSyncedTimeline)
        AppendToDetails(result, "    + Use synced timeline\n");
    if (info.useDirectLocalFlush)
        AppendToDetails(result, "    + Use direct local flush\n");
    
    if (info.isNested) {
        AppendToDetails(result, "\n  NESTED HYPERVISOR DETECTED\n");
    }
    
    if (info.physicalAddressWidth > 0) {
        AppendToDetails(result, "\n  Physical Address Width: %d bits\n", 
                       info.physicalAddressWidth);
    }
    
    return detected;
}

/*
 * Quick check for recommendations
 */
BOOL HasHypervisorRecommendations(void)
{
    RECOMMENDATIONS_INFO info = {0};
    CheckRecommendations(&info);
    return info.hasRecommendationsLeaf;
}

/*
 * Check if nested hypervisor hint is set
 */
BOOL IsNestedByRecommendation(void)
{
    RECOMMENDATIONS_INFO info = {0};
    CheckRecommendations(&info);
    return info.isNested;
}

/*
 * Check if enlightened VMCS is recommended
 */
BOOL IsEnlightenedVmcsRecommended(void)
{
    RECOMMENDATIONS_INFO info = {0};
    CheckRecommendations(&info);
    return info.useEnlightenedVmcs;
}

/*
 * Get spinlock retry count
 */
DWORD GetRecommendedSpinlockRetries(void)
{
    RECOMMENDATIONS_INFO info = {0};
    CheckRecommendations(&info);
    return info.spinlockRetries;
}
