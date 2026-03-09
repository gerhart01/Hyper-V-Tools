/**
 * whp_checks.c - Windows Hypervisor Platform (WHP) API Detection
 * 
 * Detects Windows Hypervisor Platform API availability.
 * WHP allows third-party virtualization software to use Hyper-V's
 * hypervisor capabilities (introduced in Windows 10 1803).
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform
 * - https://github.com/ionescu007/Simpleator
 * - https://github.com/0vercl0k/pywinhv
 * - https://crates.io/crates/libwhp
 * - https://github.com/epakskape/whpexp
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_WHP 0x00000400

/* WHP capability IDs */
#define WHvCapabilityCodeHypervisorPresent      0x00000000
#define WHvCapabilityCodeFeatures               0x00000001
#define WHvCapabilityCodeExtendedVmExits        0x00000002
#define WHvCapabilityCodeProcessorVendor        0x00001000
#define WHvCapabilityCodeProcessorFeatures      0x00001001
#define WHvCapabilityCodeProcessorClFlushSize   0x00001002
#define WHvCapabilityCodeProcessorXsaveFeatures 0x00001003

/* Processor vendor enum */
typedef enum _WHV_PROCESSOR_VENDOR {
    WHvProcessorVendorAmd   = 0,
    WHvProcessorVendorIntel = 1,
    WHvProcessorVendorHygon = 2
} WHV_PROCESSOR_VENDOR;

/* WHP feature flags */
#define WHV_FEATURE_PARTIAL_UNMAP           (1 << 0)
#define WHV_FEATURE_LOCAL_APIC_EMULATION    (1 << 1)
#define WHV_FEATURE_XSAVE_CPU_STATE         (1 << 2)
#define WHV_FEATURE_DEVICE_INTERRUPT        (1 << 3)

/* WHP function types */
typedef HRESULT (WINAPI *PFN_WHvGetCapability)(
    UINT32 CapabilityCode,
    VOID* CapabilityBuffer,
    UINT32 CapabilityBufferSizeInBytes,
    UINT32* WrittenSizeInBytes
);

/* WHP detection info */
typedef struct _WHP_INFO {
    BOOL dllLoaded;
    BOOL apiAvailable;
    BOOL hypervisorPresent;
    
    /* Capabilities */
    UINT64 features;
    WHV_PROCESSOR_VENDOR processorVendor;
    UINT64 processorFeatures;
    UINT32 clFlushSize;
    
    /* Feature flags */
    BOOL hasPartialUnmap;
    BOOL hasLocalApicEmulation;
    BOOL hasXsaveCpuState;
    BOOL hasDeviceInterrupt;
    
    /* Error info */
    DWORD lastError;
    HRESULT lastHResult;
} WHP_INFO, *PWHP_INFO;

/*
 * Check WHP API availability
 */
static void CheckWhpApi(PWHP_INFO info)
{
    HMODULE hWHvPlatform = NULL;
    PFN_WHvGetCapability pfnGetCapability = NULL;
    BOOL hypervisorPresent = FALSE;
    UINT32 writtenSize = 0;
    HRESULT hr;
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(WHP_INFO));
    
    /* Try to load WinHvPlatform.dll */
    hWHvPlatform = LoadLibraryA("WinHvPlatform.dll");
    if (hWHvPlatform == NULL) {
        info->lastError = GetLastError();
        return;
    }
    
    info->dllLoaded = TRUE;
    
    /* Get WHvGetCapability function */
    pfnGetCapability = (PFN_WHvGetCapability)GetProcAddress(
        hWHvPlatform, "WHvGetCapability");
    
    if (pfnGetCapability == NULL) {
        info->lastError = GetLastError();
        FreeLibrary(hWHvPlatform);
        return;
    }
    
    info->apiAvailable = TRUE;
    
    /* Check hypervisor presence */
    hr = pfnGetCapability(
        WHvCapabilityCodeHypervisorPresent,
        &hypervisorPresent,
        sizeof(hypervisorPresent),
        &writtenSize);
    
    if (SUCCEEDED(hr)) {
        info->hypervisorPresent = hypervisorPresent;
    } else {
        info->lastHResult = hr;
    }
    
    if (!info->hypervisorPresent) {
        FreeLibrary(hWHvPlatform);
        return;
    }
    
    /* Get features */
    hr = pfnGetCapability(
        WHvCapabilityCodeFeatures,
        &info->features,
        sizeof(info->features),
        &writtenSize);
    
    if (SUCCEEDED(hr)) {
        info->hasPartialUnmap = (info->features & WHV_FEATURE_PARTIAL_UNMAP) != 0;
        info->hasLocalApicEmulation = (info->features & WHV_FEATURE_LOCAL_APIC_EMULATION) != 0;
        info->hasXsaveCpuState = (info->features & WHV_FEATURE_XSAVE_CPU_STATE) != 0;
        info->hasDeviceInterrupt = (info->features & WHV_FEATURE_DEVICE_INTERRUPT) != 0;
    }
    
    /* Get processor vendor */
    hr = pfnGetCapability(
        WHvCapabilityCodeProcessorVendor,
        &info->processorVendor,
        sizeof(info->processorVendor),
        &writtenSize);
    
    /* Get processor features */
    hr = pfnGetCapability(
        WHvCapabilityCodeProcessorFeatures,
        &info->processorFeatures,
        sizeof(info->processorFeatures),
        &writtenSize);
    
    /* Get CL flush size */
    hr = pfnGetCapability(
        WHvCapabilityCodeProcessorClFlushSize,
        &info->clFlushSize,
        sizeof(info->clFlushSize),
        &writtenSize);
    
    FreeLibrary(hWHvPlatform);
}

/*
 * Check for WHP feature in Windows features
 */
static BOOL CheckWhpWindowsFeature(void)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    /* Check if Windows Hypervisor Platform feature is enabled */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "HypervisorPlatformEnabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

/*
 * Main WHP check function
 */
DWORD CheckWhpHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    WHP_INFO info = {0};
    BOOL featureEnabled;
    const char* vendorName;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Check WHP API */
    CheckWhpApi(&info);
    
    /* Check Windows feature */
    featureEnabled = CheckWhpWindowsFeature();
    
    /* Detection */
    if (info.hypervisorPresent || featureEnabled) {
        detected = HYPERV_DETECTED_WHP;
    }
    
    /* Build details */
    AppendToDetails(result, "Windows Hypervisor Platform (WHP) Detection:\n");
    
    AppendToDetails(result, "\n  API Availability:\n");
    AppendToDetails(result, "    WinHvPlatform.dll: %s\n", 
                   info.dllLoaded ? "Loaded" : "Not found");
    AppendToDetails(result, "    WHvGetCapability: %s\n", 
                   info.apiAvailable ? "Available" : "Not available");
    AppendToDetails(result, "    Hypervisor Present: %s\n", 
                   info.hypervisorPresent ? "YES" : "NO");
    
    if (!info.dllLoaded && info.lastError != 0) {
        AppendToDetails(result, "    Load Error: %u\n", info.lastError);
    }
    
    AppendToDetails(result, "\n  Windows Feature:\n");
    AppendToDetails(result, "    Hypervisor Platform: %s\n", 
                   featureEnabled ? "Enabled" : "Disabled");
    
    if (info.hypervisorPresent) {
        /* Vendor name */
        switch (info.processorVendor) {
            case WHvProcessorVendorIntel: vendorName = "Intel"; break;
            case WHvProcessorVendorAmd: vendorName = "AMD"; break;
            case WHvProcessorVendorHygon: vendorName = "Hygon"; break;
            default: vendorName = "Unknown"; break;
        }
        
        AppendToDetails(result, "\n  WHP Capabilities:\n");
        AppendToDetails(result, "    Features: 0x%016llX\n", info.features);
        AppendToDetails(result, "    Processor Vendor: %s\n", vendorName);
        AppendToDetails(result, "    Processor Features: 0x%016llX\n", info.processorFeatures);
        AppendToDetails(result, "    CL Flush Size: %u\n", info.clFlushSize);
        
        AppendToDetails(result, "\n  Feature Flags:\n");
        AppendToDetails(result, "    Partial Unmap: %s\n", 
                       info.hasPartialUnmap ? "YES" : "NO");
        AppendToDetails(result, "    Local APIC Emulation: %s\n", 
                       info.hasLocalApicEmulation ? "YES" : "NO");
        AppendToDetails(result, "    XSAVE CPU State: %s\n", 
                       info.hasXsaveCpuState ? "YES" : "NO");
        AppendToDetails(result, "    Device Interrupt: %s\n", 
                       info.hasDeviceInterrupt ? "YES" : "NO");
    }
    
    return detected;
}

/*
 * Quick check for WHP
 */
BOOL HasWhpSupport(void)
{
    WHP_INFO info = {0};
    CheckWhpApi(&info);
    return info.hypervisorPresent;
}

/*
 * Check if WHP API is available
 */
BOOL IsWhpApiAvailable(void)
{
    WHP_INFO info = {0};
    CheckWhpApi(&info);
    return info.apiAvailable;
}

/*
 * Get WHP features
 */
UINT64 GetWhpFeatures(void)
{
    WHP_INFO info = {0};
    CheckWhpApi(&info);
    return info.features;
}
