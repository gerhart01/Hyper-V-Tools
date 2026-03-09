/**
 * ntquery_checks.c - NtQuerySystemInformation Hypervisor Detection
 * 
 * Uses undocumented SystemHypervisorDetailInformation (0x9F) to get
 * hypervisor details directly from Windows kernel.
 * 
 * Sources:
 * - https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e
 * - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_hypervisor_detail_information.htm
 * - Microsoft TLFS
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

#define HYPERV_DETECTED_NTQUERY 0x08000000

/* System information class for hypervisor details */
#define SystemHypervisorDetailInformation 0x9F

/* NT status codes */
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/* HV_DETAILS structure - contains CPUID results for one leaf */
typedef struct _HV_DETAILS {
    DWORD Data[4];  /* EAX, EBX, ECX, EDX */
} HV_DETAILS, *PHV_DETAILS;

/* 
 * SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure (0x70 bytes)
 * Returned by NtQuerySystemInformation with class 0x9F
 */
typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION {
    HV_DETAILS HvVendorAndMaxFunction;  /* CPUID 0x40000000 */
    HV_DETAILS HvInterface;             /* CPUID 0x40000001 */
    HV_DETAILS HvVersion;               /* CPUID 0x40000002 */
    HV_DETAILS HvFeatures;              /* CPUID 0x40000003 */
    HV_DETAILS HvEnlightenments;        /* CPUID 0x40000004 - Implementation recommendations */
    HV_DETAILS HvImplementationLimits;  /* CPUID 0x40000005 */
    HV_DETAILS HvHardwareFeatures;      /* CPUID 0x40000006 */
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, *PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

/* NtQuerySystemInformation function pointer type */
typedef NTSTATUS (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

/* Parsed hypervisor info */
typedef struct _HYPERVISOR_DETAIL_INFO {
    BOOL querySucceeded;
    char vendorId[13];
    DWORD maxLeaf;
    char interfaceId[5];
    DWORD buildNumber;
    DWORD majorVersion;
    DWORD minorVersion;
    DWORD serviceVersion;
    DWORD privilegeFlags;       /* EAX from 0x40000003 */
    DWORD hypercallFlags;       /* EBX from 0x40000003 */
    DWORD recommendations;      /* EAX from 0x40000004 */
    DWORD spinlockRetries;      /* EBX from 0x40000004 */
    DWORD maxVirtualProcessors; /* EAX from 0x40000005 */
    DWORD maxLogicalProcessors; /* EBX from 0x40000005 */
    DWORD hardwareFeatures;     /* EAX from 0x40000006 */
    BOOL isHyperV;
    BOOL isRootPartition;
} HYPERVISOR_DETAIL_INFO, *PHYPERVISOR_DETAIL_INFO;

/*
 * Call NtQuerySystemInformation with SystemHypervisorDetailInformation
 */
static BOOL QueryHypervisorDetails(PSYSTEM_HYPERVISOR_DETAIL_INFORMATION info)
{
    HMODULE hNtdll = NULL;
    PFN_NtQuerySystemInformation pfnNtQuerySystemInformation = NULL;
    NTSTATUS status = 0;
    ULONG returnLength = 0;
    
    if (info == NULL) {
        return FALSE;
    }
    
    memset(info, 0, sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION));
    
    /* Load ntdll and get function pointer */
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return FALSE;
    }
    
    pfnNtQuerySystemInformation = (PFN_NtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    
    if (pfnNtQuerySystemInformation == NULL) {
        return FALSE;
    }
    
    /* Query hypervisor details */
    status = pfnNtQuerySystemInformation(
        SystemHypervisorDetailInformation,
        info,
        sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION),
        &returnLength
    );
    
    return (status == STATUS_SUCCESS);
}

/*
 * Parse hypervisor details into readable structure
 */
static void ParseHypervisorDetails(
    PSYSTEM_HYPERVISOR_DETAIL_INFORMATION raw,
    PHYPERVISOR_DETAIL_INFO parsed)
{
    if (raw == NULL || parsed == NULL) {
        return;
    }
    
    memset(parsed, 0, sizeof(HYPERVISOR_DETAIL_INFO));
    
    /* Parse vendor ID from 0x40000000 */
    memcpy(parsed->vendorId, &raw->HvVendorAndMaxFunction.Data[1], 4);     /* EBX */
    memcpy(parsed->vendorId + 4, &raw->HvVendorAndMaxFunction.Data[2], 4); /* ECX */
    memcpy(parsed->vendorId + 8, &raw->HvVendorAndMaxFunction.Data[3], 4); /* EDX */
    parsed->vendorId[12] = '\0';
    
    parsed->maxLeaf = raw->HvVendorAndMaxFunction.Data[0];  /* EAX */
    
    /* Parse interface ID from 0x40000001 */
    memcpy(parsed->interfaceId, &raw->HvInterface.Data[0], 4);  /* EAX */
    parsed->interfaceId[4] = '\0';
    
    /* Parse version from 0x40000002 */
    parsed->buildNumber = raw->HvVersion.Data[0];    /* EAX */
    parsed->majorVersion = (raw->HvVersion.Data[1] >> 16) & 0xFFFF;  /* EBX high */
    parsed->minorVersion = raw->HvVersion.Data[1] & 0xFFFF;          /* EBX low */
    parsed->serviceVersion = raw->HvVersion.Data[2]; /* ECX */
    
    /* Parse features from 0x40000003 */
    parsed->privilegeFlags = raw->HvFeatures.Data[0];   /* EAX */
    parsed->hypercallFlags = raw->HvFeatures.Data[1];   /* EBX */
    
    /* Parse enlightenments from 0x40000004 */
    parsed->recommendations = raw->HvEnlightenments.Data[0];    /* EAX */
    parsed->spinlockRetries = raw->HvEnlightenments.Data[1];    /* EBX */
    
    /* Parse limits from 0x40000005 */
    parsed->maxVirtualProcessors = raw->HvImplementationLimits.Data[0];  /* EAX */
    parsed->maxLogicalProcessors = raw->HvImplementationLimits.Data[1];  /* EBX */
    
    /* Parse hardware features from 0x40000006 */
    parsed->hardwareFeatures = raw->HvHardwareFeatures.Data[0];  /* EAX */
    
    /* Check if Hyper-V */
    parsed->isHyperV = (strcmp(parsed->vendorId, "Microsoft Hv") == 0);
    
    /* Check if root partition (CreatePartitions privilege) */
    parsed->isRootPartition = (parsed->hypercallFlags & 0x01) != 0;
    
    parsed->querySucceeded = TRUE;
}

/*
 * Main NtQuery check function
 */
DWORD CheckNtQueryHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    SYSTEM_HYPERVISOR_DETAIL_INFORMATION rawInfo = {0};
    HYPERVISOR_DETAIL_INFO parsedInfo = {0};
    BOOL queryResult = FALSE;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Query hypervisor details */
    queryResult = QueryHypervisorDetails(&rawInfo);
    
    if (!queryResult) {
        AppendToDetails(result, "NtQuery Hypervisor: Query failed (no hypervisor or access denied)\n");
        return 0;
    }
    
    /* Parse results */
    ParseHypervisorDetails(&rawInfo, &parsedInfo);
    
    if (parsedInfo.isHyperV) {
        detected = HYPERV_DETECTED_NTQUERY;
    }
    
    /* Build details */
    AppendToDetails(result, "NtQuerySystemInformation Hypervisor Details:\n");
    AppendToDetails(result, "  Vendor: '%s'\n", parsedInfo.vendorId);
    AppendToDetails(result, "  Interface: '%s'\n", parsedInfo.interfaceId);
    AppendToDetails(result, "  Max Leaf: 0x%08X\n", parsedInfo.maxLeaf);
    AppendToDetails(result, "  Version: %u.%u.%u (Build %u)\n",
                   parsedInfo.majorVersion, parsedInfo.minorVersion,
                   parsedInfo.serviceVersion, parsedInfo.buildNumber);
    AppendToDetails(result, "  Privilege Flags: 0x%08X\n", parsedInfo.privilegeFlags);
    AppendToDetails(result, "  Hypercall Flags: 0x%08X\n", parsedInfo.hypercallFlags);
    AppendToDetails(result, "  Recommendations: 0x%08X\n", parsedInfo.recommendations);
    AppendToDetails(result, "  Spinlock Retries: %u\n", parsedInfo.spinlockRetries);
    AppendToDetails(result, "  Max Virtual CPUs: %u\n", parsedInfo.maxVirtualProcessors);
    AppendToDetails(result, "  Max Logical CPUs: %u\n", parsedInfo.maxLogicalProcessors);
    AppendToDetails(result, "  Hardware Features: 0x%08X\n", parsedInfo.hardwareFeatures);
    
    if (parsedInfo.isHyperV) {
        AppendToDetails(result, "  Is Hyper-V: YES\n");
        AppendToDetails(result, "  Partition: %s\n", 
                       parsedInfo.isRootPartition ? "ROOT" : "GUEST");
    }
    
    /* Check specific hardware features */
    if (parsedInfo.hardwareFeatures & 0x01) {
        AppendToDetails(result, "  + APIC Overlay Assist\n");
    }
    if (parsedInfo.hardwareFeatures & 0x02) {
        AppendToDetails(result, "  + MSR Bitmaps\n");
    }
    if (parsedInfo.hardwareFeatures & 0x04) {
        AppendToDetails(result, "  + Architectural Perf Counters\n");
    }
    if (parsedInfo.hardwareFeatures & 0x08) {
        AppendToDetails(result, "  + SLAT (Second Level Address Translation)\n");
    }
    if (parsedInfo.hardwareFeatures & 0x10) {
        AppendToDetails(result, "  + DMA Remapping\n");
    }
    if (parsedInfo.hardwareFeatures & 0x20) {
        AppendToDetails(result, "  + Interrupt Remapping\n");
    }
    
    return detected;
}

/*
 * Get hypervisor details directly
 */
BOOL GetHypervisorDetailsNt(PHYPERVISOR_DETAIL_INFO info)
{
    SYSTEM_HYPERVISOR_DETAIL_INFORMATION rawInfo = {0};
    
    if (info == NULL) {
        return FALSE;
    }
    
    if (!QueryHypervisorDetails(&rawInfo)) {
        return FALSE;
    }
    
    ParseHypervisorDetails(&rawInfo, info);
    return TRUE;
}

/*
 * Quick check if hypervisor is present using NtQuery
 */
BOOL HasHypervisorNtQuery(void)
{
    SYSTEM_HYPERVISOR_DETAIL_INFORMATION info = {0};
    return QueryHypervisorDetails(&info);
}
