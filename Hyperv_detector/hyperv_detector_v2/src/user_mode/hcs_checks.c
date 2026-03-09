/**
 * hcs_checks.c - Host Compute System (HCS) API Detection
 * 
 * Detects Host Compute System API availability.
 * HCS is used for Windows containers, Windows Sandbox, and other
 * lightweight VMs.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/api/hcs/overview
 * - https://github.com/MouriNaruto/MouriDocs/tree/main/docs/4
 * - https://github.com/M2Team/NanaBox
 * - https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Windows-Sandbox/ba-p/301849
 * - Benjamin Armstrong - Hyper-V API Overview
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_HCS 0x00000800

/* HCS function types */
typedef HRESULT (WINAPI *PFN_HcsGetServiceProperties)(
    const wchar_t* propertyQuery,
    wchar_t** result
);

typedef HRESULT (WINAPI *PFN_HcsEnumerateComputeSystems)(
    const wchar_t* query,
    void* operation
);

/* HCS detection info */
typedef struct _HCS_INFO {
    BOOL computeDllLoaded;
    BOOL computeCoreDllLoaded;
    BOOL vmcomputeDllLoaded;
    
    BOOL hcsApiAvailable;
    BOOL hcsEnumerateAvailable;
    
    BOOL computeServiceRunning;
    BOOL vmmsServiceRunning;
    
    DWORD lastError;
} HCS_INFO, *PHCS_INFO;

/*
 * Check for compute DLLs
 */
static void CheckHcsDlls(PHCS_INFO info)
{
    HMODULE hCompute = NULL;
    HMODULE hComputeCore = NULL;
    HMODULE hVmcompute = NULL;
    
    if (info == NULL) {
        return;
    }
    
    /* Try computecore.dll (newer) */
    hComputeCore = LoadLibraryA("computecore.dll");
    if (hComputeCore != NULL) {
        info->computeCoreDllLoaded = TRUE;
        
        /* Check for HCS functions */
        if (GetProcAddress(hComputeCore, "HcsGetServiceProperties") != NULL) {
            info->hcsApiAvailable = TRUE;
        }
        if (GetProcAddress(hComputeCore, "HcsEnumerateComputeSystems") != NULL) {
            info->hcsEnumerateAvailable = TRUE;
        }
        
        FreeLibrary(hComputeCore);
    }
    
    /* Try vmcompute.dll (alternative) */
    hVmcompute = LoadLibraryA("vmcompute.dll");
    if (hVmcompute != NULL) {
        info->vmcomputeDllLoaded = TRUE;
        FreeLibrary(hVmcompute);
    }
    
    /* Try compute.dll (legacy) */
    hCompute = LoadLibraryA("compute.dll");
    if (hCompute != NULL) {
        info->computeDllLoaded = TRUE;
        FreeLibrary(hCompute);
    }
}

/*
 * Check compute services
 */
static void CheckComputeServices(PHCS_INFO info)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    
    if (info == NULL) {
        return;
    }
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        info->lastError = GetLastError();
        return;
    }
    
    /* Check Host Compute Service (vmcompute) */
    hService = OpenServiceA(hSCManager, "vmcompute", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->computeServiceRunning = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    /* Check VMMS service */
    hService = OpenServiceA(hSCManager, "vmms", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->vmmsServiceRunning = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
}

/*
 * Check Windows Sandbox feature
 */
static BOOL CheckWindowsSandbox(void)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    /* Check if Windows Sandbox is enabled */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    
    /* Check for sandbox feature via optional features */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackageDetect\\Microsoft-Windows-Containers-Compressed-Package~31bf3856ad364e35~amd64~~0.0.0.0",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check Containers feature
 */
static BOOL CheckContainersFeature(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check for Containers package */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Would need to enumerate subkeys to find container packages */
        RegCloseKey(hKey);
    }
    
    /* Alternative: check for container base images */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Containers\\BaseImages",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main HCS check function
 */
DWORD CheckHcsHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HCS_INFO info = {0};
    BOOL sandboxEnabled;
    BOOL containersEnabled;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Check DLLs */
    CheckHcsDlls(&info);
    
    /* Check services */
    CheckComputeServices(&info);
    
    /* Check features */
    sandboxEnabled = CheckWindowsSandbox();
    containersEnabled = CheckContainersFeature();
    
    /* Detection */
    if (info.hcsApiAvailable || info.computeServiceRunning || 
        sandboxEnabled || containersEnabled) {
        detected = HYPERV_DETECTED_HCS;
    }
    
    /* Build details */
    AppendToDetails(result, "Host Compute System (HCS) API Detection:\n");
    
    AppendToDetails(result, "\n  DLL Availability:\n");
    AppendToDetails(result, "    computecore.dll: %s\n", 
                   info.computeCoreDllLoaded ? "Loaded" : "Not found");
    AppendToDetails(result, "    vmcompute.dll: %s\n", 
                   info.vmcomputeDllLoaded ? "Loaded" : "Not found");
    AppendToDetails(result, "    compute.dll (legacy): %s\n", 
                   info.computeDllLoaded ? "Loaded" : "Not found");
    
    AppendToDetails(result, "\n  HCS API:\n");
    AppendToDetails(result, "    HcsGetServiceProperties: %s\n", 
                   info.hcsApiAvailable ? "Available" : "Not available");
    AppendToDetails(result, "    HcsEnumerateComputeSystems: %s\n", 
                   info.hcsEnumerateAvailable ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Services:\n");
    AppendToDetails(result, "    Host Compute Service (vmcompute): %s\n", 
                   info.computeServiceRunning ? "Running" : "Not running");
    AppendToDetails(result, "    Virtual Machine Management (vmms): %s\n", 
                   info.vmmsServiceRunning ? "Running" : "Not running");
    
    AppendToDetails(result, "\n  Features:\n");
    AppendToDetails(result, "    Windows Sandbox: %s\n", 
                   sandboxEnabled ? "Detected" : "Not detected");
    AppendToDetails(result, "    Containers: %s\n", 
                   containersEnabled ? "Detected" : "Not detected");
    
    if (info.computeServiceRunning) {
        AppendToDetails(result, "\n  Note: HCS is active - indicates Hyper-V HOST\n");
        AppendToDetails(result, "        or container/sandbox environment\n");
    }
    
    return detected;
}

/*
 * Quick check for HCS
 */
BOOL HasHcsSupport(void)
{
    HCS_INFO info = {0};
    CheckHcsDlls(&info);
    return info.hcsApiAvailable;
}

/*
 * Check if compute service is running
 */
BOOL IsComputeServiceRunning(void)
{
    HCS_INFO info = {0};
    CheckComputeServices(&info);
    return info.computeServiceRunning;
}

/*
 * Check if this is likely a host
 */
BOOL IsHyperVHostByHcs(void)
{
    HCS_INFO info = {0};
    CheckHcsDlls(&info);
    CheckComputeServices(&info);
    return info.computeServiceRunning && info.hcsApiAvailable;
}
