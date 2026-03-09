/**
 * saved_state_checks.c - VM Saved State Detection
 * 
 * Detects VM saved state files and APIs for memory forensics.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/windows/win32/api/vmsavedstatedump/
 * - LiveCloudKd (Matthieu Suiche, Arthur Khudyaev): https://github.com/gerhart01/LiveCloudKd
 * - MemProcFS integration: https://github.com/ufrisk/MemProcFS
 * - Windows SDK headers: vmsavedstatedump.h, vmsavedstatedumpdefs.h
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_SAVEDSTATE 0x00000001 /* Low bit, reuse space */

/* Saved state API function types */
typedef HRESULT (WINAPI *PFN_GetVmSavedStateSummaryInfo)(
    LPCWSTR vmrsFilePath,
    void* info
);

typedef HRESULT (WINAPI *PFN_ApplyPendingSavedStateFileReplayLog)(
    LPCWSTR vmrsFilePath
);

/* Saved state detection info */
typedef struct _SAVEDSTATE_INFO {
    BOOL dllLoaded;
    BOOL apiAvailable;
    
    BOOL vmrsFilesExist;
    BOOL binFilesExist;
    BOOL vsavFilesExist;
    
    char vmDirectory[MAX_PATH];
} SAVEDSTATE_INFO, *PSAVEDSTATE_INFO;

/*
 * Check for saved state DLL
 */
static void CheckSavedStateDll(PSAVEDSTATE_INFO info)
{
    HMODULE hVmSavedState = NULL;
    
    if (info == NULL) {
        return;
    }
    
    /* Try to load vmsavedstatedumpprovider.dll */
    hVmSavedState = LoadLibraryA("vmsavedstatedumpprovider.dll");
    if (hVmSavedState != NULL) {
        info->dllLoaded = TRUE;
        
        /* Check for key functions */
        if (GetProcAddress(hVmSavedState, "GetVmSavedStateSummaryInformation") != NULL ||
            GetProcAddress(hVmSavedState, "ApplyPendingSavedStateFileReplayLog") != NULL) {
            info->apiAvailable = TRUE;
        }
        
        FreeLibrary(hVmSavedState);
    }
}

/*
 * Check for default VM location
 */
static void CheckDefaultVmLocation(PSAVEDSTATE_INFO info)
{
    char programData[MAX_PATH];
    char vmPath[MAX_PATH];
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    /* Get ProgramData path */
    if (GetEnvironmentVariableA("ProgramData", programData, MAX_PATH) == 0) {
        return;
    }
    
    /* Default Hyper-V VM location */
    snprintf(vmPath, MAX_PATH, "%s\\Microsoft\\Windows\\Hyper-V\\Virtual Machines", programData);
    
    attrs = GetFileAttributesA(vmPath);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        strncpy(info->vmDirectory, vmPath, MAX_PATH - 1);
    }
}

/*
 * Check for saved state files in common locations
 */
static void CheckSavedStateFiles(PSAVEDSTATE_INFO info)
{
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];
    char programData[MAX_PATH];
    
    if (info == NULL) {
        return;
    }
    
    if (GetEnvironmentVariableA("ProgramData", programData, MAX_PATH) == 0) {
        return;
    }
    
    /* Search for .vmrs files (runtime saved state) */
    snprintf(searchPath, MAX_PATH, "%s\\Microsoft\\Windows\\Hyper-V\\*.vmrs", programData);
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        info->vmrsFilesExist = TRUE;
        FindClose(hFind);
    }
    
    /* Search for .bin files (memory snapshot) */
    snprintf(searchPath, MAX_PATH, "%s\\Microsoft\\Windows\\Hyper-V\\*.bin", programData);
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        info->binFilesExist = TRUE;
        FindClose(hFind);
    }
    
    /* Search for .vsav files (legacy saved state) */
    snprintf(searchPath, MAX_PATH, "%s\\Microsoft\\Windows\\Hyper-V\\*.vsav", programData);
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        info->vsavFilesExist = TRUE;
        FindClose(hFind);
    }
}

/*
 * Check registry for VM configurations
 */
static BOOL CheckVmConfigRegistry(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check for VM configurations */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\GuestInstallerInfo",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main saved state check function
 */
DWORD CheckSavedStateHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    SAVEDSTATE_INFO info = {0};
    BOOL registryFound;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckSavedStateDll(&info);
    CheckDefaultVmLocation(&info);
    CheckSavedStateFiles(&info);
    registryFound = CheckVmConfigRegistry();
    
    /* Detection - host indicators */
    if (info.dllLoaded || info.vmrsFilesExist || 
        info.vmDirectory[0] != '\0') {
        detected = HYPERV_DETECTED_SAVEDSTATE;
    }
    
    /* Build details */
    AppendToDetails(result, "VM Saved State Detection:\n");
    
    AppendToDetails(result, "\n  Saved State API:\n");
    AppendToDetails(result, "    vmsavedstatedumpprovider.dll: %s\n", 
                   info.dllLoaded ? "Loaded" : "Not found");
    AppendToDetails(result, "    API Functions: %s\n", 
                   info.apiAvailable ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  VM Directory:\n");
    if (info.vmDirectory[0] != '\0') {
        AppendToDetails(result, "    Location: %s\n", info.vmDirectory);
    } else {
        AppendToDetails(result, "    Location: Not found\n");
    }
    
    AppendToDetails(result, "\n  Saved State Files:\n");
    AppendToDetails(result, "    .vmrs (Runtime): %s\n", 
                   info.vmrsFilesExist ? "Found" : "Not found");
    AppendToDetails(result, "    .bin (Memory): %s\n", 
                   info.binFilesExist ? "Found" : "Not found");
    AppendToDetails(result, "    .vsav (Legacy): %s\n", 
                   info.vsavFilesExist ? "Found" : "Not found");
    
    AppendToDetails(result, "\n  Registry:\n");
    AppendToDetails(result, "    VM Config: %s\n", 
                   registryFound ? "Found" : "Not found");
    
    if (info.dllLoaded) {
        AppendToDetails(result, "\n  Note: Saved State API available - Hyper-V HOST\n");
    }
    
    return detected;
}

/*
 * Quick check for saved state API
 */
BOOL HasSavedStateApi(void)
{
    SAVEDSTATE_INFO info = {0};
    CheckSavedStateDll(&info);
    return info.apiAvailable;
}

/*
 * Check if VM directory exists
 */
BOOL HasVmDirectory(void)
{
    SAVEDSTATE_INFO info = {0};
    CheckDefaultVmLocation(&info);
    return info.vmDirectory[0] != '\0';
}

/*
 * Check if saved state files exist
 */
BOOL HasSavedStateFiles(void)
{
    SAVEDSTATE_INFO info = {0};
    CheckSavedStateFiles(&info);
    return info.vmrsFilesExist || info.binFilesExist || info.vsavFilesExist;
}
