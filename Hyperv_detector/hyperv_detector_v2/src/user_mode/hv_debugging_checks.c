/**
 * hv_debugging_checks.c - Hyper-V Debugging Interface Detection
 * 
 * Detects Hyper-V debugging interfaces and tools.
 * 
 * Sources:
 * - Hyper-V debugging for beginners (Arthur Khudyaev): 
 *   https://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html
 * - Hyper-V debugging for beginners. Part 2 (Arthur Khudyaev):
 *   https://hvinternals.blogspot.com/2017/10/hyper-v-debugging-for-beginners-part-2.html
 * - LiveCloudKd EXDi plugin: https://github.com/gerhart01/LiveCloudKd/tree/master/ExdiKdSample
 * - hvext (Satoshi Tanda): https://github.com/tandasat/hvext
 * - SecurekernelIUMDebug (cbwang505): https://github.com/cbwang505/SecurekernelIUMDebug
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_HV_DEBUGGING 0x00000200

/* Debugging detection info */
typedef struct _HV_DEBUGGING_INFO {
    BOOL debugModeEnabled;
    BOOL kernelDebuggerPresent;
    BOOL vmDebuggingEnabled;
    
    BOOL exdiPluginPresent;
    BOOL kdcomPresent;
    BOOL hvextPresent;
    
    BOOL bcdeditDebugOn;
    BOOL hypervisorDebugOn;
    
    DWORD debugType;
} HV_DEBUGGING_INFO, *PHV_DEBUGGING_INFO;

/*
 * Check if kernel debugger is present
 */
static void CheckKernelDebugger(PHV_DEBUGGING_INFO info)
{
    BOOL debuggerPresent = FALSE;
    
    if (info == NULL) {
        return;
    }
    
    /* Use IsDebuggerPresent for user-mode */
    if (IsDebuggerPresent()) {
        info->debugModeEnabled = TRUE;
    }
    
    /* Check for kernel debugger via system call */
    /* This is a simplified check */
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemStartOptions",
            NULL, NULL, NULL, &size) == ERROR_SUCCESS) {
            char* startOptions = (char*)malloc(size);
            if (startOptions) {
                if (RegQueryValueExA(hKey, "SystemStartOptions",
                    NULL, NULL, (LPBYTE)startOptions, &size) == ERROR_SUCCESS) {
                    if (strstr(startOptions, "DEBUG") != NULL) {
                        info->kernelDebuggerPresent = TRUE;
                        info->debugModeEnabled = TRUE;
                    }
                }
                free(startOptions);
            }
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check BCD for debug settings
 */
static void CheckBcdDebugSettings(PHV_DEBUGGING_INFO info)
{
    HKEY hKey;
    LONG result;
    
    if (info == NULL) {
        return;
    }
    
    /* Check BCD store for debug settings */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "BCD00000000\\Objects\\{default}\\Elements\\16000010",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Debug element exists */
        info->bcdeditDebugOn = TRUE;
        RegCloseKey(hKey);
    }
    
    /* Check for hypervisor debug */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "BCD00000000\\Objects\\{default}\\Elements\\250000f4",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Hypervisor debug element exists */
        info->hypervisorDebugOn = TRUE;
        RegCloseKey(hKey);
    }
}

/*
 * Check for debugging tools
 */
static void CheckDebuggingTools(PHV_DEBUGGING_INFO info)
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
    
    /* Check for kdcom.dll */
    snprintf(filePath, MAX_PATH, "%s\\kdcom.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->kdcomPresent = TRUE;
    }
    
    /* Check for EXDi plugin */
    attrs = GetFileAttributesA("C:\\Program Files\\LiveCloudKd\\ExdiKdSample.dll");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->exdiPluginPresent = TRUE;
    }
    
    /* Check for hvext (WinDbg extension) */
    attrs = GetFileAttributesA("C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\winext\\hvext.dll");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->hvextPresent = TRUE;
    }
}

/*
 * Check for VM debugging configuration
 */
static void CheckVmDebugging(PHV_DEBUGGING_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check vmms debug settings */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        /* Check for debug-related values */
        if (RegQueryValueExA(hKey, "GuestDebuggingEnabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->vmDebuggingEnabled = (value != 0);
        }
        RegCloseKey(hKey);
    }
}

/*
 * Main debugging check function
 */
DWORD CheckHvDebuggingHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HV_DEBUGGING_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckKernelDebugger(&info);
    CheckBcdDebugSettings(&info);
    CheckDebuggingTools(&info);
    CheckVmDebugging(&info);
    
    /* Detection */
    if (info.debugModeEnabled || info.bcdeditDebugOn || 
        info.hypervisorDebugOn || info.exdiPluginPresent) {
        detected = HYPERV_DETECTED_HV_DEBUGGING;
    }
    
    /* Build details */
    AppendToDetails(result, "Hyper-V Debugging Interface Detection:\n");
    
    AppendToDetails(result, "\n  Debug Status:\n");
    AppendToDetails(result, "    Debug Mode: %s\n", 
                   info.debugModeEnabled ? "Enabled" : "Disabled");
    AppendToDetails(result, "    Kernel Debugger: %s\n", 
                   info.kernelDebuggerPresent ? "Present" : "Not detected");
    AppendToDetails(result, "    VM Debugging: %s\n", 
                   info.vmDebuggingEnabled ? "Enabled" : "Disabled");
    
    AppendToDetails(result, "\n  BCD Settings:\n");
    AppendToDetails(result, "    bcdedit /debug: %s\n", 
                   info.bcdeditDebugOn ? "ON" : "OFF");
    AppendToDetails(result, "    Hypervisor Debug: %s\n", 
                   info.hypervisorDebugOn ? "ON" : "OFF");
    
    AppendToDetails(result, "\n  Debugging Tools:\n");
    AppendToDetails(result, "    kdcom.dll: %s\n", 
                   info.kdcomPresent ? "Present" : "Not found");
    AppendToDetails(result, "    EXDi Plugin: %s\n", 
                   info.exdiPluginPresent ? "Found" : "Not found");
    AppendToDetails(result, "    hvext: %s\n", 
                   info.hvextPresent ? "Found" : "Not found");
    
    if (info.hypervisorDebugOn) {
        AppendToDetails(result, "\n  Warning: Hypervisor debugging is ENABLED\n");
        AppendToDetails(result, "           Security features may be reduced\n");
    }
    
    return detected;
}

/*
 * Quick check for debugging mode
 */
BOOL IsDebugModeEnabled(void)
{
    HV_DEBUGGING_INFO info = {0};
    CheckKernelDebugger(&info);
    return info.debugModeEnabled;
}

/*
 * Check if hypervisor debugging is enabled
 */
BOOL IsHypervisorDebugEnabled(void)
{
    HV_DEBUGGING_INFO info = {0};
    CheckBcdDebugSettings(&info);
    return info.hypervisorDebugOn;
}

/*
 * Check if VM debugging is enabled
 */
BOOL IsVmDebuggingEnabled(void)
{
    HV_DEBUGGING_INFO info = {0};
    CheckVmDebugging(&info);
    return info.vmDebuggingEnabled;
}

/*
 * Check if debugging tools are present
 */
BOOL HasDebuggingTools(void)
{
    HV_DEBUGGING_INFO info = {0};
    CheckDebuggingTools(&info);
    return info.exdiPluginPresent || info.hvextPresent;
}
