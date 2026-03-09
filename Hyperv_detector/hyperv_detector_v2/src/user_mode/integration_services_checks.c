/**
 * integration_services_checks.c - Hyper-V Integration Services Detection
 * 
 * Detects Hyper-V Integration Services (IC) which are present in guest VMs.
 * These services provide communication between host and guest.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services
 * - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/integration-services
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

#define HYPERV_DETECTED_INTEGRATION_SERVICES 0x00100000

/* Integration Services list */
typedef struct _IC_SERVICE_INFO {
    const char* serviceName;
    const char* displayName;
    const char* description;
    BOOL guestOnly;  /* TRUE = only in guest VM, FALSE = can be on host too */
} IC_SERVICE_INFO, *PIC_SERVICE_INFO;

static const IC_SERVICE_INFO g_IntegrationServices[] = {
    {"vmicheartbeat",      "Hyper-V Heartbeat Service",              "Monitors VM state via heartbeat",        TRUE},
    {"vmicshutdown",       "Hyper-V Guest Shutdown Service",         "Allows graceful VM shutdown",            TRUE},
    {"vmictimesync",       "Hyper-V Time Synchronization Service",   "Syncs VM clock with host",               TRUE},
    {"vmickvpexchange",    "Hyper-V Data Exchange Service",          "Exchanges metadata with host",           TRUE},
    {"vmicguestinterface", "Hyper-V Guest Service Interface",        "Host-to-guest file copy",                TRUE},
    {"vmicrdv",            "Hyper-V Remote Desktop Virtualization",  "Enhanced RDP session",                   TRUE},
    {"vmicvss",            "Hyper-V Volume Shadow Copy Requestor",   "Backup coordination",                    TRUE},
    {"vmicvmsession",      "Hyper-V PowerShell Direct Service",      "PowerShell Direct support",              TRUE},
    {NULL, NULL, NULL, FALSE}
};

/* Integration Components drivers */
static const char* g_ICDrivers[] = {
    "vmicheartbeat.sys",
    "vmicshutdown.sys",
    "vmictimesync.sys",
    "vmickvpexchange.sys",
    "vmicguestinterface.sys",
    "vmicrdv.sys",
    "vmicvss.sys",
    "vmbushid.sys",
    "vmbusr.sys",
    "vmbus.sys",
    "storflt.sys",      /* Storage filter */
    "vhdmp.sys",        /* VHD miniport */
    "winhv.sys",        /* Windows Hypervisor Interface */
    "hvax64.sys",       /* Hyper-V Accelerator */
    "hvboot.sys",       /* Hyper-V Boot */
    NULL
};

/* Integration Components registry keys */
static const char* g_ICRegistryKeys[] = {
    "SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
    "SYSTEM\\CurrentControlSet\\Services\\vmicshutdown",
    "SYSTEM\\CurrentControlSet\\Services\\vmictimesync",
    "SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange",
    "SYSTEM\\CurrentControlSet\\Services\\vmicguestinterface",
    "SYSTEM\\CurrentControlSet\\Services\\vmicrdv",
    "SYSTEM\\CurrentControlSet\\Services\\vmicvss",
    "SYSTEM\\CurrentControlSet\\Services\\vmicvmsession",
    NULL
};

/*
 * Check if Integration Service is running
 */
static BOOL IsServiceRunning(const char* serviceName)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status = {0};
    DWORD bytesNeeded = 0;
    BOOL isRunning = FALSE;
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return FALSE;
    }
    
    hService = OpenServiceA(hSCManager, serviceName, SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            isRunning = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return isRunning;
}

/*
 * Check if Integration Service exists (installed)
 */
static BOOL IsServiceInstalled(const char* serviceName)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL exists = FALSE;
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return FALSE;
    }
    
    hService = OpenServiceA(hSCManager, serviceName, SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        exists = TRUE;
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return exists;
}

/*
 * Count running Integration Services
 */
static int CountRunningICServices(void)
{
    int count = 0;
    int i = 0;
    
    for (i = 0; g_IntegrationServices[i].serviceName != NULL; i++) {
        if (IsServiceRunning(g_IntegrationServices[i].serviceName)) {
            count++;
        }
    }
    return count;
}

/*
 * Count installed Integration Services
 */
static int CountInstalledICServices(void)
{
    int count = 0;
    int i = 0;
    
    for (i = 0; g_IntegrationServices[i].serviceName != NULL; i++) {
        if (IsServiceInstalled(g_IntegrationServices[i].serviceName)) {
            count++;
        }
    }
    return count;
}

/*
 * Check IC driver files
 */
static int CountICDriverFiles(void)
{
    char path[MAX_PATH] = {0};
    char sysDir[MAX_PATH] = {0};
    int count = 0;
    int i = 0;
    DWORD attr = 0;
    
    GetSystemDirectoryA(sysDir, sizeof(sysDir));
    
    for (i = 0; g_ICDrivers[i] != NULL; i++) {
        snprintf(path, sizeof(path), "%s\\drivers\\%s", sysDir, g_ICDrivers[i]);
        attr = GetFileAttributesA(path);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            count++;
        }
    }
    return count;
}

/*
 * Check IC registry keys
 */
static int CountICRegistryKeys(void)
{
    HKEY hKey = NULL;
    int count = 0;
    int i = 0;
    LONG res = 0;
    
    for (i = 0; g_ICRegistryKeys[i] != NULL; i++) {
        res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_ICRegistryKeys[i], 
                           0, KEY_READ, &hKey);
        if (res == ERROR_SUCCESS) {
            count++;
            RegCloseKey(hKey);
        }
    }
    return count;
}

/*
 * Get IC version from registry
 */
static BOOL GetICVersion(char* versionBuffer, size_t bufferSize)
{
    HKEY hKey = NULL;
    DWORD dataSize = 0;
    LONG res = 0;
    BOOL found = FALSE;
    
    /* Try to get version from heartbeat service */
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Virtual Machine\\Auto",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        dataSize = (DWORD)bufferSize;
        res = RegQueryValueExA(hKey, "IntegrationServicesVersion", NULL, NULL,
                              (LPBYTE)versionBuffer, &dataSize);
        if (res == ERROR_SUCCESS) {
            found = TRUE;
        }
        RegCloseKey(hKey);
    }
    
    if (!found) {
        versionBuffer[0] = '\0';
    }
    
    return found;
}

/*
 * Main Integration Services check function
 */
DWORD CheckIntegrationServicesHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    int runningCount = 0;
    int installedCount = 0;
    int driverCount = 0;
    int registryCount = 0;
    char icVersion[64] = {0};
    int i = 0;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Count services */
    runningCount = CountRunningICServices();
    installedCount = CountInstalledICServices();
    driverCount = CountICDriverFiles();
    registryCount = CountICRegistryKeys();
    
    /* Get IC version */
    GetICVersion(icVersion, sizeof(icVersion));
    
    /* Determine detection */
    if (runningCount > 0 || installedCount >= 3 || driverCount >= 5) {
        detected = HYPERV_DETECTED_INTEGRATION_SERVICES;
    }
    
    /* Build details */
    AppendToDetails(result, "Integration Services:\n");
    AppendToDetails(result, "  Running services: %d\n", runningCount);
    AppendToDetails(result, "  Installed services: %d\n", installedCount);
    AppendToDetails(result, "  Driver files: %d\n", driverCount);
    AppendToDetails(result, "  Registry keys: %d\n", registryCount);
    
    if (icVersion[0] != '\0') {
        AppendToDetails(result, "  IC Version: %s\n", icVersion);
    }
    
    /* List running services */
    if (runningCount > 0) {
        AppendToDetails(result, "  Running:\n");
        for (i = 0; g_IntegrationServices[i].serviceName != NULL; i++) {
            if (IsServiceRunning(g_IntegrationServices[i].serviceName)) {
                AppendToDetails(result, "    - %s\n", g_IntegrationServices[i].displayName);
            }
        }
    }
    
    return detected;
}

/*
 * Quick check - just verify heartbeat service
 */
BOOL HasIntegrationServicesQuick(void)
{
    return IsServiceInstalled("vmicheartbeat") || 
           IsServiceInstalled("vmicshutdown") ||
           IsServiceInstalled("vmictimesync");
}

/*
 * Get detailed IC info structure
 */
typedef struct _IC_DETECTION_INFO {
    int runningServices;
    int installedServices;
    int driverFiles;
    int registryKeys;
    char version[64];
    BOOL hasHeartbeat;
    BOOL hasShutdown;
    BOOL hasTimesync;
    BOOL hasKVP;
    BOOL hasGuestInterface;
    BOOL hasRDV;
    BOOL hasVSS;
    BOOL hasPSSession;
} IC_DETECTION_INFO, *PIC_DETECTION_INFO;

void GetIntegrationServicesInfo(PIC_DETECTION_INFO info)
{
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(IC_DETECTION_INFO));
    
    info->runningServices = CountRunningICServices();
    info->installedServices = CountInstalledICServices();
    info->driverFiles = CountICDriverFiles();
    info->registryKeys = CountICRegistryKeys();
    
    GetICVersion(info->version, sizeof(info->version));
    
    info->hasHeartbeat = IsServiceInstalled("vmicheartbeat");
    info->hasShutdown = IsServiceInstalled("vmicshutdown");
    info->hasTimesync = IsServiceInstalled("vmictimesync");
    info->hasKVP = IsServiceInstalled("vmickvpexchange");
    info->hasGuestInterface = IsServiceInstalled("vmicguestinterface");
    info->hasRDV = IsServiceInstalled("vmicrdv");
    info->hasVSS = IsServiceInstalled("vmicvss");
    info->hasPSSession = IsServiceInstalled("vmicvmsession");
}
