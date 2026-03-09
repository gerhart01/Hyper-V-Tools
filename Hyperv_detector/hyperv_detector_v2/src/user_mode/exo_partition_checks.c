/**
 * exo_partition_checks.c - EXO Partition Detection
 * 
 * Detects EXO (external) partition memory access features.
 * EXO partitions are special partitions for memory forensics.
 * 
 * Sources:
 * - Hyper-V memory internals. EXO partition memory access (Arthur Khudyaev):
 *   https://hvinternals.blogspot.com/2020/06/hyper-v-memory-internals-exo-partition.html
 * - Hyper-V memory internals. Guest OS memory access (Arthur Khudyaev):
 *   https://hvinternals.blogspot.com/2019/09/hyper-v-memory-internals-guest-os-memory-access.html
 * - LiveCloudKd (Arthur Khudyaev): https://github.com/gerhart01/LiveCloudKd
 * - MemProcFS Hyper-V plugin: https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd
 * - hvlib SDK: https://gitlab.com/hvlib/sdk
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_EXO_PARTITION 0x00000100

/* EXO partition detection info */
typedef struct _EXO_PARTITION_INFO {
    BOOL vidSysLoaded;
    BOOL vidDllPresent;
    BOOL hvmmSysPresent;
    
    BOOL exoPartitionApiAvailable;
    BOOL guestMemoryAccessApi;
    
    BOOL liveCloudKdPresent;
    BOOL memProcFsPresent;
    
    DWORD vidApiVersion;
} EXO_PARTITION_INFO, *PEXO_PARTITION_INFO;

/*
 * Check for VID (Virtualization Infrastructure Driver)
 */
static void CheckVidDriver(PEXO_PARTITION_INFO info)
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
        return;
    }
    
    /* Check vid.sys driver */
    hService = OpenServiceA(hSCManager, "vid", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->vidSysLoaded = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
}

/*
 * Check for VID DLL and API
 */
static void CheckVidApi(PEXO_PARTITION_INFO info)
{
    HMODULE hVid = NULL;
    char systemPath[MAX_PATH];
    char filePath[MAX_PATH];
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    if (GetSystemDirectoryA(systemPath, MAX_PATH) == 0) {
        return;
    }
    
    /* Check vid.dll presence */
    snprintf(filePath, MAX_PATH, "%s\\vid.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->vidDllPresent = TRUE;
    }
    
    /* Try to load vid.dll and check for EXO APIs */
    hVid = LoadLibraryA("vid.dll");
    if (hVid != NULL) {
        /* Check for partition memory access APIs */
        if (GetProcAddress(hVid, "VidGetPartitionProperty") != NULL) {
            info->guestMemoryAccessApi = TRUE;
        }
        
        /* Check for EXO partition related functions */
        if (GetProcAddress(hVid, "VidCreatePartition") != NULL &&
            GetProcAddress(hVid, "VidMapGpaPages") != NULL) {
            info->exoPartitionApiAvailable = TRUE;
        }
        
        FreeLibrary(hVid);
    }
}

/*
 * Check for HVMM driver (Hyper-V Memory Manager)
 */
static void CheckHvmmDriver(PEXO_PARTITION_INFO info)
{
    char systemPath[MAX_PATH];
    char filePath[MAX_PATH];
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    /* HVMM is typically not in system32, check common locations */
    if (GetSystemDirectoryA(systemPath, MAX_PATH) == 0) {
        return;
    }
    
    /* Check for hvmm.sys (custom driver from LiveCloudKd) */
    snprintf(filePath, MAX_PATH, "%s\\drivers\\hvmm.sys", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->hvmmSysPresent = TRUE;
    }
}

/*
 * Check for memory forensics tools
 */
static void CheckForensicsTools(PEXO_PARTITION_INFO info)
{
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    /* Check for LiveCloudKd */
    attrs = GetFileAttributesA("C:\\Program Files\\LiveCloudKd\\LiveCloudKd.exe");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->liveCloudKdPresent = TRUE;
    }
    
    /* Alternative path */
    attrs = GetFileAttributesA("C:\\LiveCloudKd\\LiveCloudKd.exe");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->liveCloudKdPresent = TRUE;
    }
    
    /* Check for MemProcFS */
    attrs = GetFileAttributesA("C:\\Program Files\\MemProcFS\\MemProcFS.exe");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->memProcFsPresent = TRUE;
    }
    
    /* Alternative path */
    attrs = GetFileAttributesA("C:\\MemProcFS\\MemProcFS.exe");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->memProcFsPresent = TRUE;
    }
}

/*
 * Check registry for EXO partition settings
 */
static BOOL CheckExoRegistry(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check for VID parameters */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vid\\Parameters",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main EXO partition check function
 */
DWORD CheckExoPartitionHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    EXO_PARTITION_INFO info = {0};
    BOOL registryFound;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckVidDriver(&info);
    CheckVidApi(&info);
    CheckHvmmDriver(&info);
    CheckForensicsTools(&info);
    registryFound = CheckExoRegistry();
    
    /* Detection */
    if (info.vidSysLoaded && info.exoPartitionApiAvailable) {
        detected = HYPERV_DETECTED_EXO_PARTITION;
    }
    
    /* Build details */
    AppendToDetails(result, "EXO Partition / Memory Access Detection:\n");
    
    AppendToDetails(result, "\n  VID Infrastructure:\n");
    AppendToDetails(result, "    vid.sys Driver: %s\n", 
                   info.vidSysLoaded ? "Loaded" : "Not loaded");
    AppendToDetails(result, "    vid.dll: %s\n", 
                   info.vidDllPresent ? "Present" : "Not found");
    AppendToDetails(result, "    hvmm.sys: %s\n", 
                   info.hvmmSysPresent ? "Present" : "Not found");
    
    AppendToDetails(result, "\n  Memory Access APIs:\n");
    AppendToDetails(result, "    EXO Partition API: %s\n", 
                   info.exoPartitionApiAvailable ? "Available" : "Not available");
    AppendToDetails(result, "    Guest Memory Access: %s\n", 
                   info.guestMemoryAccessApi ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Forensics Tools:\n");
    AppendToDetails(result, "    LiveCloudKd: %s\n", 
                   info.liveCloudKdPresent ? "Found" : "Not found");
    AppendToDetails(result, "    MemProcFS: %s\n", 
                   info.memProcFsPresent ? "Found" : "Not found");
    
    AppendToDetails(result, "\n  Registry:\n");
    AppendToDetails(result, "    VID Parameters: %s\n", 
                   registryFound ? "Found" : "Not found");
    
    if (info.exoPartitionApiAvailable) {
        AppendToDetails(result, "\n  Note: EXO Partition API available\n");
        AppendToDetails(result, "        Can access guest VM memory from host\n");
    }
    
    return detected;
}

/*
 * Quick check for EXO partition API
 */
BOOL HasExoPartitionApi(void)
{
    EXO_PARTITION_INFO info = {0};
    CheckVidApi(&info);
    return info.exoPartitionApiAvailable;
}

/*
 * Check if VID driver is loaded
 */
BOOL IsVidDriverLoaded(void)
{
    EXO_PARTITION_INFO info = {0};
    CheckVidDriver(&info);
    return info.vidSysLoaded;
}

/*
 * Check if guest memory access is available
 */
BOOL HasGuestMemoryAccess(void)
{
    EXO_PARTITION_INFO info = {0};
    CheckVidApi(&info);
    return info.guestMemoryAccessApi;
}

/*
 * Check if forensics tools are installed
 */
BOOL HasForensicsTools(void)
{
    EXO_PARTITION_INFO info = {0};
    CheckForensicsTools(&info);
    return info.liveCloudKdPresent || info.memProcFsPresent;
}
