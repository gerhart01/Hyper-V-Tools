/**
 * container_checks.c - Windows Container Detection
 * 
 * Detects Windows containers and isolation features.
 * 
 * Sources:
 * - Windows SDK: wmcontainer.h, Wmcontainer.idl
 * - Host Compute Network (HCN): https://github.com/microsoft/hcsshim
 * - Windows Sandbox (Hari Pulapaka): https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Windows-Sandbox/ba-p/301849
 * - Windows Defender Application Guard (Yunhai Zhang): https://www.powerofcommunity.net/poc2018/yunhai.pdf
 * - Isolated App Launcher SDK header: isolatedapplauncher.h
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_CONTAINER 0x00000020

/* Container detection info */
typedef struct _CONTAINER_INFO {
    BOOL containersEnabled;
    BOOL sandboxEnabled;
    BOOL wdagEnabled;           /* Windows Defender Application Guard */
    BOOL hyperVIsolation;
    BOOL processIsolation;
    
    BOOL hcnServiceRunning;
    BOOL cexecServiceRunning;
    
    DWORD containerCount;
} CONTAINER_INFO, *PCONTAINER_INFO;

/*
 * Check container features via registry
 */
static void CheckContainerRegistry(PCONTAINER_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check Containers feature */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Would enumerate for container packages */
        RegCloseKey(hKey);
    }
    
    /* Check Windows Sandbox */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Sandbox",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        info->sandboxEnabled = TRUE;
        RegCloseKey(hKey);
    }
    
    /* Alternative sandbox check */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\WindowsSandbox",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        info->sandboxEnabled = TRUE;
        RegCloseKey(hKey);
    }
    
    /* Check WDAG */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Hvsi",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        info->wdagEnabled = TRUE;
        RegCloseKey(hKey);
    }
    
    /* Check Hyper-V isolation */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\Containers",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        info->hyperVIsolation = TRUE;
        RegCloseKey(hKey);
    }
}

/*
 * Check container services
 */
static void CheckContainerServices(PCONTAINER_INFO info)
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
    
    /* Check Host Compute Network service */
    hService = OpenServiceA(hSCManager, "hns", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->hcnServiceRunning = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    /* Check Container Execution Agent */
    hService = OpenServiceA(hSCManager, "cexecsvc", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->cexecServiceRunning = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
}

/*
 * Check for container files
 */
static void CheckContainerFiles(PCONTAINER_INFO info)
{
    char systemPath[MAX_PATH];
    char filePath[MAX_PATH];
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    if (GetSystemDirectoryA(systemPath, MAX_PATH) == 0) {
        return;
    }
    
    /* Check for container DLLs */
    snprintf(filePath, MAX_PATH, "%s\\container.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->containersEnabled = TRUE;
    }
    
    /* Check for computecore.dll (already checked in hcs_checks) */
    snprintf(filePath, MAX_PATH, "%s\\computecore.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->containersEnabled = TRUE;
    }
}

/*
 * Check if running inside container
 */
static BOOL CheckInsideContainer(void)
{
    /* Check for container-specific environment */
    char buffer[256];
    DWORD size;
    
    /* Check for container hostname pattern */
    size = GetEnvironmentVariableA("CONTAINER_NAME", buffer, sizeof(buffer));
    if (size > 0) {
        return TRUE;
    }
    
    /* Check for sandbox-specific file */
    DWORD attrs = GetFileAttributesA("C:\\Windows\\System32\\CompatTelRunner.exe");
    /* In sandbox, certain files may be missing */
    
    return FALSE;
}

/*
 * Main container check function
 */
DWORD CheckContainerHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    CONTAINER_INFO info = {0};
    BOOL insideContainer;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckContainerRegistry(&info);
    CheckContainerServices(&info);
    CheckContainerFiles(&info);
    insideContainer = CheckInsideContainer();
    
    /* Detection */
    if (info.containersEnabled || info.sandboxEnabled || 
        info.wdagEnabled || info.hcnServiceRunning) {
        detected = HYPERV_DETECTED_CONTAINER;
    }
    
    /* Build details */
    AppendToDetails(result, "Windows Container Detection:\n");
    
    AppendToDetails(result, "\n  Container Features:\n");
    AppendToDetails(result, "    Containers: %s\n", 
                   info.containersEnabled ? "Enabled" : "Disabled");
    AppendToDetails(result, "    Windows Sandbox: %s\n", 
                   info.sandboxEnabled ? "Enabled" : "Disabled");
    AppendToDetails(result, "    WDAG: %s\n", 
                   info.wdagEnabled ? "Enabled" : "Disabled");
    
    AppendToDetails(result, "\n  Isolation Types:\n");
    AppendToDetails(result, "    Hyper-V Isolation: %s\n", 
                   info.hyperVIsolation ? "Available" : "Not available");
    AppendToDetails(result, "    Process Isolation: %s\n", 
                   info.processIsolation ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Services:\n");
    AppendToDetails(result, "    HCN (Host Compute Network): %s\n", 
                   info.hcnServiceRunning ? "Running" : "Not running");
    AppendToDetails(result, "    Container Exec Agent: %s\n", 
                   info.cexecServiceRunning ? "Running" : "Not running");
    
    AppendToDetails(result, "\n  Current Environment:\n");
    AppendToDetails(result, "    Inside Container: %s\n", 
                   insideContainer ? "YES" : "NO");
    
    if (info.sandboxEnabled) {
        AppendToDetails(result, "\n  Note: Windows Sandbox available\n");
    }
    if (info.wdagEnabled) {
        AppendToDetails(result, "        WDAG (Application Guard) enabled\n");
    }
    
    return detected;
}

/*
 * Quick check for containers
 */
BOOL HasContainerSupport(void)
{
    CONTAINER_INFO info = {0};
    CheckContainerRegistry(&info);
    CheckContainerFiles(&info);
    return info.containersEnabled;
}

/*
 * Check if Windows Sandbox is enabled
 */
BOOL IsSandboxEnabled(void)
{
    CONTAINER_INFO info = {0};
    CheckContainerRegistry(&info);
    return info.sandboxEnabled;
}

/*
 * Check if WDAG is enabled
 */
BOOL IsWdagEnabled(void)
{
    CONTAINER_INFO info = {0};
    CheckContainerRegistry(&info);
    return info.wdagEnabled;
}

/*
 * Check if running inside a container
 */
BOOL IsInsideContainer(void)
{
    return CheckInsideContainer();
}
