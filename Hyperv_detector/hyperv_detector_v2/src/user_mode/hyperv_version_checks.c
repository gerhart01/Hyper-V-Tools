/**
 * hyperv_version_checks.c - Hyper-V Version Detection
 * 
 * Detects Hyper-V version information from CPUID leaf 0x40000002.
 * 
 * Sources:
 * - https://gist.github.com/BehroozAbbassi/8e07bae41b0b037a55259c19d00aa458
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 * - https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e
 * - https://github.com/ionescu007/hdk (Hyper-V Development Kit)
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_VERSION 0x00000100

/* Known Hyper-V build versions */
typedef struct _HYPERV_BUILD_INFO {
    DWORD buildNumber;
    const char* windowsVersion;
    const char* description;
} HYPERV_BUILD_INFO;

static const HYPERV_BUILD_INFO g_knownBuilds[] = {
    /* Windows Server 2008 R2 / Windows 7 */
    {6001, "Windows Server 2008 / Vista SP1", "Hyper-V 1.0"},
    {6002, "Windows Server 2008 SP2", "Hyper-V 1.0"},
    {7600, "Windows Server 2008 R2 / Windows 7", "Hyper-V 2.0"},
    {7601, "Windows Server 2008 R2 SP1 / Windows 7 SP1", "Hyper-V 2.0"},
    
    /* Windows Server 2012 / Windows 8 */
    {9200, "Windows Server 2012 / Windows 8", "Hyper-V 3.0"},
    {9600, "Windows Server 2012 R2 / Windows 8.1", "Hyper-V 3.0 R2"},
    
    /* Windows Server 2016 / Windows 10 */
    {10240, "Windows 10 1507", "Hyper-V (Windows 10)"},
    {10586, "Windows 10 1511", "Hyper-V (Windows 10)"},
    {14393, "Windows Server 2016 / Windows 10 1607", "Hyper-V 2016"},
    {15063, "Windows 10 1703", "Hyper-V (Windows 10)"},
    {16299, "Windows 10 1709", "Hyper-V (Windows 10)"},
    {17134, "Windows 10 1803", "Hyper-V + WHPX"},
    {17763, "Windows Server 2019 / Windows 10 1809", "Hyper-V 2019"},
    {18362, "Windows 10 1903", "Hyper-V (Windows 10)"},
    {18363, "Windows 10 1909", "Hyper-V (Windows 10)"},
    {19041, "Windows 10 2004", "Hyper-V (Windows 10)"},
    {19042, "Windows 10 20H2", "Hyper-V (Windows 10)"},
    {19043, "Windows 10 21H1", "Hyper-V (Windows 10)"},
    {19044, "Windows 10 21H2", "Hyper-V (Windows 10)"},
    {19045, "Windows 10 22H2", "Hyper-V (Windows 10)"},
    
    /* Windows Server 2022 / Windows 11 */
    {20348, "Windows Server 2022", "Hyper-V 2022"},
    {22000, "Windows 11 21H2", "Hyper-V (Windows 11)"},
    {22621, "Windows 11 22H2", "Hyper-V (Windows 11)"},
    {22631, "Windows 11 23H2", "Hyper-V (Windows 11)"},
    {26100, "Windows 11 24H2 / Server 2025", "Hyper-V 2025"},
    
    {0, NULL, NULL}
};

/* Version info structure */
typedef struct _VERSION_INFO {
    BOOL isHypervisorPresent;
    BOOL hasVersionLeaf;
    
    /* Raw CPUID values from 0x40000002 */
    DWORD buildNumber;          /* EAX */
    WORD majorVersion;          /* EBX high word */
    WORD minorVersion;          /* EBX low word */
    DWORD servicePackInfo;      /* ECX */
    DWORD serviceBranch;        /* EDX bits 0-23 */
    DWORD serviceNumber;        /* EDX bits 24-31 */
    
    /* Lookup results */
    const char* windowsVersion;
    const char* hypervDescription;
} VERSION_INFO, *PVERSION_INFO;

/*
 * Lookup build number in known versions
 */
static void LookupBuildNumber(PVERSION_INFO info)
{
    const HYPERV_BUILD_INFO* entry;
    
    if (info == NULL) {
        return;
    }
    
    info->windowsVersion = "Unknown";
    info->hypervDescription = "Unknown";
    
    for (entry = g_knownBuilds; entry->windowsVersion != NULL; entry++) {
        if (entry->buildNumber == info->buildNumber) {
            info->windowsVersion = entry->windowsVersion;
            info->hypervDescription = entry->description;
            return;
        }
    }
    
    /* Try to guess based on build range */
    if (info->buildNumber > 26100) {
        info->windowsVersion = "Windows 11 24H2+ / Server 2025+";
        info->hypervDescription = "Hyper-V (latest)";
    } else if (info->buildNumber > 22631) {
        info->windowsVersion = "Windows 11 (unknown build)";
        info->hypervDescription = "Hyper-V (Windows 11)";
    } else if (info->buildNumber > 20000) {
        info->windowsVersion = "Windows Server 2022 / Windows 11";
        info->hypervDescription = "Hyper-V 2022+";
    } else if (info->buildNumber > 17763) {
        info->windowsVersion = "Windows 10 (unknown build)";
        info->hypervDescription = "Hyper-V 2019+";
    }
}

/*
 * Check version from CPUID
 */
static void CheckHypervisorVersion(PVERSION_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(VERSION_INFO));
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    info->isHypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!info->isHypervisorPresent) {
        return;
    }
    
    /* Check max leaf */
    __cpuid(cpuInfo, 0x40000000);
    info->hasVersionLeaf = (cpuInfo[0] >= 0x40000002);
    
    if (!info->hasVersionLeaf) {
        return;
    }
    
    /* Get version from CPUID 0x40000002 */
    __cpuid(cpuInfo, 0x40000002);
    
    info->buildNumber = (DWORD)cpuInfo[0];
    info->majorVersion = (WORD)((cpuInfo[1] >> 16) & 0xFFFF);
    info->minorVersion = (WORD)(cpuInfo[1] & 0xFFFF);
    info->servicePackInfo = (DWORD)cpuInfo[2];
    info->serviceBranch = (DWORD)(cpuInfo[3] & 0x00FFFFFF);
    info->serviceNumber = (DWORD)((cpuInfo[3] >> 24) & 0xFF);
    
    /* Lookup build info */
    LookupBuildNumber(info);
}

/*
 * Main version check function
 */
DWORD CheckVersionHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    VERSION_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckHypervisorVersion(&info);
    
    /* Detection based on having version leaf */
    if (info.hasVersionLeaf && info.buildNumber > 0) {
        detected = HYPERV_DETECTED_VERSION;
    }
    
    /* Build details */
    AppendToDetails(result, "Hypervisor Version Detection:\n");
    AppendToDetails(result, "  Hypervisor Present: %s\n", 
                   info.isHypervisorPresent ? "YES" : "NO");
    AppendToDetails(result, "  Version Leaf (0x40000002): %s\n", 
                   info.hasVersionLeaf ? "Available" : "Not available");
    
    if (!info.hasVersionLeaf) {
        return detected;
    }
    
    AppendToDetails(result, "\n  Version Information:\n");
    AppendToDetails(result, "    Build Number: %u\n", info.buildNumber);
    AppendToDetails(result, "    Version: %u.%u\n", info.majorVersion, info.minorVersion);
    
    if (info.servicePackInfo != 0) {
        AppendToDetails(result, "    Service Pack: %u\n", info.servicePackInfo);
    }
    
    if (info.serviceBranch != 0 || info.serviceNumber != 0) {
        AppendToDetails(result, "    Service Branch: %u\n", info.serviceBranch);
        AppendToDetails(result, "    Service Number: %u\n", info.serviceNumber);
    }
    
    AppendToDetails(result, "\n  Identified As:\n");
    AppendToDetails(result, "    Windows Version: %s\n", info.windowsVersion);
    AppendToDetails(result, "    Hyper-V: %s\n", info.hypervDescription);
    
    return detected;
}

/*
 * Quick check for version info
 */
BOOL HasHypervisorVersion(void)
{
    VERSION_INFO info = {0};
    CheckHypervisorVersion(&info);
    return info.hasVersionLeaf && info.buildNumber > 0;
}

/*
 * Get hypervisor build number
 */
DWORD GetHypervisorBuildNumber(void)
{
    VERSION_INFO info = {0};
    CheckHypervisorVersion(&info);
    return info.buildNumber;
}

/*
 * Get hypervisor major version
 */
WORD GetHypervisorMajorVersion(void)
{
    VERSION_INFO info = {0};
    CheckHypervisorVersion(&info);
    return info.majorVersion;
}

/*
 * Get hypervisor minor version
 */
WORD GetHypervisorMinorVersion(void)
{
    VERSION_INFO info = {0};
    CheckHypervisorVersion(&info);
    return info.minorVersion;
}
