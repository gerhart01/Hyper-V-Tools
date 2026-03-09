/**
 * limits_checks.c - Hyper-V Implementation Limits Detection
 * 
 * Detects hypervisor implementation limits from CPUID leaf 0x40000005
 * including maximum virtual processors and interrupt vectors.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 * - https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e
 * - Windows Driver documentation (MSDN)
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_LIMITS 0x00040000

/* Implementation limits info */
typedef struct _LIMITS_INFO {
    BOOL isHypervisorPresent;
    BOOL hasLimitsLeaf;
    
    /* Raw CPUID values from 0x40000005 */
    DWORD maxVirtualProcessors;         /* EAX */
    DWORD maxLogicalProcessors;         /* EBX */
    DWORD maxInterruptVectors;          /* ECX */
    DWORD reserved;                     /* EDX */
    
    /* Derived values */
    BOOL hasProcessorLimits;
    BOOL hasInterruptLimits;
} LIMITS_INFO, *PLIMITS_INFO;

/*
 * Check implementation limits from CPUID
 */
static void CheckImplementationLimits(PLIMITS_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(LIMITS_INFO));
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    info->isHypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!info->isHypervisorPresent) {
        return;
    }
    
    /* Check max leaf */
    __cpuid(cpuInfo, 0x40000000);
    info->hasLimitsLeaf = (cpuInfo[0] >= 0x40000005);
    
    if (!info->hasLimitsLeaf) {
        return;
    }
    
    /* Get limits from CPUID 0x40000005 */
    __cpuid(cpuInfo, 0x40000005);
    
    info->maxVirtualProcessors = (DWORD)cpuInfo[0];  /* EAX */
    info->maxLogicalProcessors = (DWORD)cpuInfo[1];  /* EBX */
    info->maxInterruptVectors = (DWORD)cpuInfo[2];   /* ECX */
    info->reserved = (DWORD)cpuInfo[3];              /* EDX */
    
    /* Check if values are non-zero (hypervisor exposes info) */
    info->hasProcessorLimits = (info->maxVirtualProcessors > 0);
    info->hasInterruptLimits = (info->maxInterruptVectors > 0);
}

/*
 * Main limits check function
 */
DWORD CheckLimitsHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    LIMITS_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckImplementationLimits(&info);
    
    /* Detection based on having limits leaf */
    if (info.hasLimitsLeaf && info.hasProcessorLimits) {
        detected = HYPERV_DETECTED_LIMITS;
    }
    
    /* Build details */
    AppendToDetails(result, "Implementation Limits Detection:\n");
    AppendToDetails(result, "  Hypervisor Present: %s\n", 
                   info.isHypervisorPresent ? "YES" : "NO");
    AppendToDetails(result, "  Limits Leaf (0x40000005): %s\n", 
                   info.hasLimitsLeaf ? "Available" : "Not available");
    
    if (!info.hasLimitsLeaf) {
        return detected;
    }
    
    AppendToDetails(result, "\n  Implementation Limits:\n");
    
    if (info.hasProcessorLimits) {
        AppendToDetails(result, "    Max Virtual Processors: %u\n", 
                       info.maxVirtualProcessors);
        AppendToDetails(result, "    Max Logical Processors: %u\n", 
                       info.maxLogicalProcessors);
    } else {
        AppendToDetails(result, "    Processor limits: Not exposed\n");
    }
    
    if (info.hasInterruptLimits) {
        AppendToDetails(result, "    Max Interrupt Vectors: %u\n", 
                       info.maxInterruptVectors);
    } else {
        AppendToDetails(result, "    Interrupt limits: Not exposed\n");
    }
    
    if (info.reserved != 0) {
        AppendToDetails(result, "    Reserved (EDX): 0x%08X\n", info.reserved);
    }
    
    /* Interpretation */
    if (info.hasProcessorLimits) {
        AppendToDetails(result, "\n  Interpretation:\n");
        AppendToDetails(result, "    This partition can have up to %u vCPUs\n", 
                       info.maxVirtualProcessors);
        if (info.maxLogicalProcessors > 0) {
            AppendToDetails(result, "    Hypervisor supports up to %u LPs total\n", 
                           info.maxLogicalProcessors);
        }
    }
    
    return detected;
}

/*
 * Quick check for limits leaf
 */
BOOL HasImplementationLimits(void)
{
    LIMITS_INFO info = {0};
    CheckImplementationLimits(&info);
    return info.hasLimitsLeaf && info.hasProcessorLimits;
}

/*
 * Get max virtual processors
 */
DWORD GetMaxVirtualProcessors(void)
{
    LIMITS_INFO info = {0};
    CheckImplementationLimits(&info);
    return info.maxVirtualProcessors;
}

/*
 * Get max logical processors
 */
DWORD GetMaxLogicalProcessors(void)
{
    LIMITS_INFO info = {0};
    CheckImplementationLimits(&info);
    return info.maxLogicalProcessors;
}

/*
 * Get max interrupt vectors
 */
DWORD GetMaxInterruptVectors(void)
{
    LIMITS_INFO info = {0};
    CheckImplementationLimits(&info);
    return info.maxInterruptVectors;
}
