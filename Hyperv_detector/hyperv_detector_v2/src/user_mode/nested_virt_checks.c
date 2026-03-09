/**
 * nested_virt_checks.c - Nested Virtualization Detection
 * 
 * Detects nested virtualization features through CPUID leaves 0x4000000A
 * and related enlightenments for running hypervisors inside VMs.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/nested-virtualization
 * - https://www.qemu.org/docs/master/system/i386/hyperv.html
 * - https://docs.kernel.org/virt/hyperv/coco.html
 * - Linux kernel: arch/x86/include/asm/hyperv-tlfs.h
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

#define HYPERV_DETECTED_NESTED 0x20000000

/* CPUID leaves for nested virtualization */
#define HYPERV_CPUID_NESTED_FEATURES    0x4000000A
#define HYPERV_CPUID_ISOLATION_CONFIG   0x4000000C

/* Nested features flags from CPUID 0x4000000A EAX */
#define HV_X64_NESTED_DIRECT_FLUSH              (1 << 17)
#define HV_X64_NESTED_GUEST_MAPPING_FLUSH       (1 << 18)
#define HV_X64_NESTED_MSR_BITMAP                (1 << 19)
#define HV_X64_NESTED_EVMCS                     (1 << 20)  /* Enlightened VMCS */
#define HV_X64_NESTED_ENLIGHTENED_TLB           (1 << 22)
#define HV_X64_NESTED_EXCEPTION_COMBINING       (1 << 23)

/* Isolation config flags from CPUID 0x4000000C EAX */
#define HV_PARAVISOR_PRESENT                    (1 << 0)
#define HV_ISOLATION_TYPE_MASK                  0x1E       /* Bits 1-4 */
#define HV_ISOLATION_TYPE_NONE                  0x00
#define HV_ISOLATION_TYPE_VBS                   0x02
#define HV_ISOLATION_TYPE_SNP                   0x04       /* AMD SEV-SNP */
#define HV_ISOLATION_TYPE_TDX                   0x06       /* Intel TDX */

/* Nested virtualization detection info */
typedef struct _NESTED_VIRT_INFO {
    BOOL isNested;
    BOOL hasNestedFeatures;
    BOOL hasIsolationConfig;
    DWORD maxLeaf;
    DWORD nestedFeatures;
    DWORD isolationConfigA;
    DWORD isolationConfigB;
    
    /* Specific features */
    BOOL hasDirectFlush;
    BOOL hasGuestMappingFlush;
    BOOL hasMsrBitmap;
    BOOL hasEvmcs;
    BOOL hasEnlightenedTlb;
    BOOL hasExceptionCombining;
    
    /* Isolation */
    BOOL hasParavisor;
    int isolationType;
    const char* isolationTypeName;
} NESTED_VIRT_INFO, *PNESTED_VIRT_INFO;

/*
 * Check if CPU supports nested virtualization leaves
 */
static BOOL CheckNestedSupport(PDWORD maxLeaf)
{
    int cpuInfo[4] = {0};
    
    /* Check max hypervisor leaf */
    __cpuid(cpuInfo, 0x40000000);
    
    if (maxLeaf) {
        *maxLeaf = (DWORD)cpuInfo[0];
    }
    
    /* Need at least 0x4000000A for nested features */
    return (cpuInfo[0] >= 0x4000000A);
}

/*
 * Get nested virtualization features
 */
static DWORD GetNestedFeatures(void)
{
    int cpuInfo[4] = {0};
    
    __cpuid(cpuInfo, HYPERV_CPUID_NESTED_FEATURES);
    
    return (DWORD)cpuInfo[0];  /* EAX contains nested features */
}

/*
 * Get isolation configuration
 */
static void GetIsolationConfig(PDWORD configA, PDWORD configB)
{
    int cpuInfo[4] = {0};
    
    __cpuid(cpuInfo, HYPERV_CPUID_ISOLATION_CONFIG);
    
    if (configA) {
        *configA = (DWORD)cpuInfo[0];
    }
    if (configB) {
        *configB = (DWORD)cpuInfo[1];
    }
}

/*
 * Get isolation type name
 */
static const char* GetIsolationTypeName(DWORD configA)
{
    int isoType = (configA & HV_ISOLATION_TYPE_MASK) >> 1;
    
    switch (isoType) {
        case 0: return "None";
        case 1: return "VBS (Virtualization-Based Security)";
        case 2: return "AMD SEV-SNP";
        case 3: return "Intel TDX";
        default: return "Unknown";
    }
}

/*
 * Gather nested virtualization info
 */
static void GatherNestedVirtInfo(PNESTED_VIRT_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(NESTED_VIRT_INFO));
    
    /* Check hypervisor present first */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 31))) {
        return;  /* No hypervisor */
    }
    
    /* Get max leaf */
    if (!CheckNestedSupport(&info->maxLeaf)) {
        return;
    }
    
    info->hasNestedFeatures = TRUE;
    
    /* Get nested features from 0x4000000A */
    info->nestedFeatures = GetNestedFeatures();
    
    /* Parse individual features */
    info->hasDirectFlush = (info->nestedFeatures & HV_X64_NESTED_DIRECT_FLUSH) != 0;
    info->hasGuestMappingFlush = (info->nestedFeatures & HV_X64_NESTED_GUEST_MAPPING_FLUSH) != 0;
    info->hasMsrBitmap = (info->nestedFeatures & HV_X64_NESTED_MSR_BITMAP) != 0;
    info->hasEvmcs = (info->nestedFeatures & HV_X64_NESTED_EVMCS) != 0;
    info->hasEnlightenedTlb = (info->nestedFeatures & HV_X64_NESTED_ENLIGHTENED_TLB) != 0;
    info->hasExceptionCombining = (info->nestedFeatures & HV_X64_NESTED_EXCEPTION_COMBINING) != 0;
    
    /* Check if any nested feature is enabled - indicates nested VM */
    if (info->nestedFeatures != 0) {
        info->isNested = TRUE;
    }
    
    /* Check isolation config (0x4000000C) if available */
    if (info->maxLeaf >= HYPERV_CPUID_ISOLATION_CONFIG) {
        info->hasIsolationConfig = TRUE;
        GetIsolationConfig(&info->isolationConfigA, &info->isolationConfigB);
        
        info->hasParavisor = (info->isolationConfigA & HV_PARAVISOR_PRESENT) != 0;
        info->isolationType = (info->isolationConfigA & HV_ISOLATION_TYPE_MASK) >> 1;
        info->isolationTypeName = GetIsolationTypeName(info->isolationConfigA);
    }
}

/*
 * Main nested virtualization check function
 */
DWORD CheckNestedVirtHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    NESTED_VIRT_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    GatherNestedVirtInfo(&info);
    
    /* Determine detection */
    if (info.hasNestedFeatures && info.nestedFeatures != 0) {
        detected = HYPERV_DETECTED_NESTED;
    }
    
    /* Build details */
    AppendToDetails(result, "Nested Virtualization Detection:\n");
    AppendToDetails(result, "  Max Hypervisor Leaf: 0x%08X\n", info.maxLeaf);
    AppendToDetails(result, "  Nested Features Available: %s\n", 
                   info.hasNestedFeatures ? "YES" : "NO");
    
    if (info.hasNestedFeatures) {
        AppendToDetails(result, "  Nested Features (0x4000000A EAX): 0x%08X\n", 
                       info.nestedFeatures);
        
        if (info.nestedFeatures != 0) {
            AppendToDetails(result, "  Nested Enlightenments:\n");
            if (info.hasDirectFlush)
                AppendToDetails(result, "    + Direct Virtual Flush\n");
            if (info.hasGuestMappingFlush)
                AppendToDetails(result, "    + Guest Mapping Flush\n");
            if (info.hasMsrBitmap)
                AppendToDetails(result, "    + Enlightened MSR Bitmap\n");
            if (info.hasEvmcs)
                AppendToDetails(result, "    + Enlightened VMCS (Intel)\n");
            if (info.hasEnlightenedTlb)
                AppendToDetails(result, "    + Enlightened TLB (AMD)\n");
            if (info.hasExceptionCombining)
                AppendToDetails(result, "    + Exception Combining\n");
        }
    }
    
    if (info.hasIsolationConfig) {
        AppendToDetails(result, "  Isolation Config (0x4000000C):\n");
        AppendToDetails(result, "    Config A: 0x%08X\n", info.isolationConfigA);
        AppendToDetails(result, "    Config B: 0x%08X\n", info.isolationConfigB);
        AppendToDetails(result, "    Paravisor: %s\n", 
                       info.hasParavisor ? "Present" : "Not present");
        AppendToDetails(result, "    Isolation Type: %s\n", info.isolationTypeName);
        
        if (info.isolationType == 2) {
            AppendToDetails(result, "    Note: Running in AMD SEV-SNP CoCo VM\n");
        } else if (info.isolationType == 3) {
            AppendToDetails(result, "    Note: Running in Intel TDX CoCo VM\n");
        }
    }
    
    if (info.isNested) {
        AppendToDetails(result, "  CONCLUSION: Nested virtualization ENABLED\n");
    }
    
    return detected;
}

/*
 * Quick check for nested virtualization
 */
BOOL IsNestedVirtualization(void)
{
    NESTED_VIRT_INFO info = {0};
    GatherNestedVirtInfo(&info);
    return info.isNested;
}

/*
 * Check if running in confidential VM
 */
BOOL IsConfidentialVM(void)
{
    NESTED_VIRT_INFO info = {0};
    GatherNestedVirtInfo(&info);
    return (info.hasIsolationConfig && info.isolationType > 1);
}

/*
 * Get isolation type (0=none, 1=VBS, 2=SEV-SNP, 3=TDX)
 */
int GetIsolationType(void)
{
    NESTED_VIRT_INFO info = {0};
    GatherNestedVirtInfo(&info);
    return info.isolationType;
}
