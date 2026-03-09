/**
 * hw_features_checks.c - Hyper-V Hardware Features Detection
 * 
 * Detects hardware-specific features from CPUID leaf 0x40000006
 * that the hypervisor has detected and is using.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 * - https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e
 * - Alex Ionescu's Hyper-V Development Kit (hdv)
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_HW_FEATURES 0x00080000

/* Hardware features flags from CPUID 0x40000006 EAX */
#define HV_HW_APIC_OVERLAY                 (1 << 0)   /* APIC overlay assist */
#define HV_HW_MSR_BITMAPS                  (1 << 1)   /* MSR bitmaps */
#define HV_HW_ARCHITECTURAL_PERF_COUNTERS  (1 << 2)   /* Architectural perf counters */
#define HV_HW_SLAT                         (1 << 3)   /* Second Level Address Translation */
#define HV_HW_DMA_REMAPPING                (1 << 4)   /* DMA remapping (IOMMU) */
#define HV_HW_INTERRUPT_REMAPPING          (1 << 5)   /* Interrupt remapping */
#define HV_HW_MEMORY_PATROL_SCRUBBER       (1 << 6)   /* Memory patrol scrubber */
#define HV_HW_DMA_PROTECTION               (1 << 7)   /* DMA protection in use */
#define HV_HW_HPET_REQUESTED               (1 << 8)   /* HPET requested */
#define HV_HW_SYNTHETIC_TIMERS_VOLATILE    (1 << 9)   /* Synthetic timers are volatile */

/* Hardware features info */
typedef struct _HW_FEATURES_INFO {
    BOOL isHypervisorPresent;
    BOOL hasHwFeaturesLeaf;
    
    /* Raw CPUID values from 0x40000006 */
    DWORD hwFeatures;           /* EAX */
    DWORD reservedEbx;          /* EBX - reserved */
    DWORD reservedEcx;          /* ECX - reserved */
    DWORD reservedEdx;          /* EDX - reserved */
    
    /* Parsed features */
    BOOL hasApicOverlay;
    BOOL hasMsrBitmaps;
    BOOL hasArchPerfCounters;
    BOOL hasSlat;               /* EPT/NPT - very common */
    BOOL hasDmaRemapping;
    BOOL hasInterruptRemapping;
    BOOL hasMemoryPatrolScrubber;
    BOOL hasDmaProtection;
    BOOL hasHpetRequested;
    BOOL hasSyntheticTimersVolatile;
    
    /* Feature count */
    int featureCount;
} HW_FEATURES_INFO, *PHW_FEATURES_INFO;

/*
 * Check hardware features from CPUID
 */
static void CheckHardwareFeatures(PHW_FEATURES_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(HW_FEATURES_INFO));
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    info->isHypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!info->isHypervisorPresent) {
        return;
    }
    
    /* Check max leaf */
    __cpuid(cpuInfo, 0x40000000);
    info->hasHwFeaturesLeaf = (cpuInfo[0] >= 0x40000006);
    
    if (!info->hasHwFeaturesLeaf) {
        return;
    }
    
    /* Get hardware features from CPUID 0x40000006 */
    __cpuid(cpuInfo, 0x40000006);
    
    info->hwFeatures = (DWORD)cpuInfo[0];  /* EAX */
    info->reservedEbx = (DWORD)cpuInfo[1]; /* EBX - reserved */
    info->reservedEcx = (DWORD)cpuInfo[2]; /* ECX - reserved */
    info->reservedEdx = (DWORD)cpuInfo[3]; /* EDX - reserved */
    
    /* Parse individual features */
    info->hasApicOverlay = (info->hwFeatures & HV_HW_APIC_OVERLAY) != 0;
    info->hasMsrBitmaps = (info->hwFeatures & HV_HW_MSR_BITMAPS) != 0;
    info->hasArchPerfCounters = (info->hwFeatures & HV_HW_ARCHITECTURAL_PERF_COUNTERS) != 0;
    info->hasSlat = (info->hwFeatures & HV_HW_SLAT) != 0;
    info->hasDmaRemapping = (info->hwFeatures & HV_HW_DMA_REMAPPING) != 0;
    info->hasInterruptRemapping = (info->hwFeatures & HV_HW_INTERRUPT_REMAPPING) != 0;
    info->hasMemoryPatrolScrubber = (info->hwFeatures & HV_HW_MEMORY_PATROL_SCRUBBER) != 0;
    info->hasDmaProtection = (info->hwFeatures & HV_HW_DMA_PROTECTION) != 0;
    info->hasHpetRequested = (info->hwFeatures & HV_HW_HPET_REQUESTED) != 0;
    info->hasSyntheticTimersVolatile = (info->hwFeatures & HV_HW_SYNTHETIC_TIMERS_VOLATILE) != 0;
    
    /* Count features */
    info->featureCount = 0;
    if (info->hasApicOverlay) info->featureCount++;
    if (info->hasMsrBitmaps) info->featureCount++;
    if (info->hasArchPerfCounters) info->featureCount++;
    if (info->hasSlat) info->featureCount++;
    if (info->hasDmaRemapping) info->featureCount++;
    if (info->hasInterruptRemapping) info->featureCount++;
    if (info->hasMemoryPatrolScrubber) info->featureCount++;
    if (info->hasDmaProtection) info->featureCount++;
    if (info->hasHpetRequested) info->featureCount++;
    if (info->hasSyntheticTimersVolatile) info->featureCount++;
}

/*
 * Main hardware features check function
 */
DWORD CheckHwFeaturesHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HW_FEATURES_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckHardwareFeatures(&info);
    
    /* Detection based on having hardware features leaf */
    if (info.hasHwFeaturesLeaf) {
        detected = HYPERV_DETECTED_HW_FEATURES;
    }
    
    /* Build details */
    AppendToDetails(result, "Hardware Features Detection:\n");
    AppendToDetails(result, "  Hypervisor Present: %s\n", 
                   info.isHypervisorPresent ? "YES" : "NO");
    AppendToDetails(result, "  HW Features Leaf (0x40000006): %s\n", 
                   info.hasHwFeaturesLeaf ? "Available" : "Not available");
    
    if (!info.hasHwFeaturesLeaf) {
        return detected;
    }
    
    AppendToDetails(result, "\n  Raw Value (EAX): 0x%08X\n", info.hwFeatures);
    AppendToDetails(result, "  Active Features: %d\n", info.featureCount);
    
    AppendToDetails(result, "\n  Hardware Features in Use:\n");
    
    if (info.hwFeatures == 0) {
        AppendToDetails(result, "    (No hardware features reported)\n");
    } else {
        if (info.hasApicOverlay)
            AppendToDetails(result, "    + APIC Overlay Assist\n");
        if (info.hasMsrBitmaps)
            AppendToDetails(result, "    + MSR Bitmaps\n");
        if (info.hasArchPerfCounters)
            AppendToDetails(result, "    + Architectural Performance Counters\n");
        if (info.hasSlat)
            AppendToDetails(result, "    + SLAT (EPT/NPT) - Second Level Address Translation\n");
        if (info.hasDmaRemapping)
            AppendToDetails(result, "    + DMA Remapping (VT-d/AMD-Vi)\n");
        if (info.hasInterruptRemapping)
            AppendToDetails(result, "    + Interrupt Remapping\n");
        if (info.hasMemoryPatrolScrubber)
            AppendToDetails(result, "    + Memory Patrol Scrubber\n");
        if (info.hasDmaProtection)
            AppendToDetails(result, "    + DMA Protection\n");
        if (info.hasHpetRequested)
            AppendToDetails(result, "    + HPET Requested\n");
        if (info.hasSyntheticTimersVolatile)
            AppendToDetails(result, "    + Synthetic Timers Volatile\n");
    }
    
    /* Note about SLAT */
    if (info.hasSlat) {
        AppendToDetails(result, "\n  Note: SLAT (bit 3) is expected to be set on virtually\n");
        AppendToDetails(result, "        every modern hypervisor (Intel EPT / AMD NPT)\n");
    }
    
    return detected;
}

/*
 * Quick check for hardware features
 */
BOOL HasHardwareFeatures(void)
{
    HW_FEATURES_INFO info = {0};
    CheckHardwareFeatures(&info);
    return info.hasHwFeaturesLeaf;
}

/*
 * Check if SLAT is enabled
 */
BOOL HasSlatEnabled(void)
{
    HW_FEATURES_INFO info = {0};
    CheckHardwareFeatures(&info);
    return info.hasSlat;
}

/*
 * Check if DMA remapping is enabled
 */
BOOL HasDmaRemapping(void)
{
    HW_FEATURES_INFO info = {0};
    CheckHardwareFeatures(&info);
    return info.hasDmaRemapping;
}

/*
 * Get hardware features bitmask
 */
DWORD GetHardwareFeaturesBitmask(void)
{
    HW_FEATURES_INFO info = {0};
    CheckHardwareFeatures(&info);
    return info.hwFeatures;
}
