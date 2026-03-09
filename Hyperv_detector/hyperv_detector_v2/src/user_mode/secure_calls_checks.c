/**
 * secure_calls_checks.c - Secure Calls / SkBridge Detection
 * 
 * Detects Secure Calls interface between NT Kernel and Secure Kernel.
 * 
 * Sources:
 * - Windows Internals: Secure Calls - The Bridge Between NT and SK (Connor McGarr):
 *   https://connormcgarr.github.io/secure-calls-and-skbridge
 * - SkBridge (Connor McGarr): https://github.com/connormcgarr/SkBridge
 * - Vtl1Mon (Connor McGarr): https://github.com/connormcgarr/Vtl1Mon
 * - Breaking VSM by Attacking SecureKernel (Saar Amar, Daniel King): MSRC 2020
 * - VBS Internals (Saar Amar): BlueHat IL 2018
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_SECURE_CALLS 0x00000080

/* Secure Calls detection info */
typedef struct _SECURE_CALLS_INFO {
    BOOL secureKernelPresent;
    BOOL ciDllPresent;
    BOOL skciPresent;
    
    BOOL vtl1Available;
    BOOL vbsEnabled;
    
    BOOL secureSystemCallsAvailable;
    BOOL ikmCallsAvailable;
    
    DWORD secureCallCount;
} SECURE_CALLS_INFO, *PSECURE_CALLS_INFO;

/*
 * Check for Secure Kernel binaries
 */
static void CheckSecureKernelBinaries(PSECURE_CALLS_INFO info)
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
    
    /* Check securekernel.exe */
    snprintf(filePath, MAX_PATH, "%s\\securekernel.exe", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->secureKernelPresent = TRUE;
    }
    
    /* Check CI.dll (Code Integrity) */
    snprintf(filePath, MAX_PATH, "%s\\CI.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->ciDllPresent = TRUE;
    }
    
    /* Check SKCI.dll (Secure Kernel Code Integrity) */
    snprintf(filePath, MAX_PATH, "%s\\skci.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->skciPresent = TRUE;
    }
}

/*
 * Check VBS/VTL status via registry
 */
static void CheckVbsVtlRegistry(PSECURE_CALLS_INFO info)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    if (info == NULL) {
        return;
    }
    
    /* Check VBS enabled */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            info->vbsEnabled = (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    /* Check CI config for VBS status - indicates VTL1 active */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "VirtualizationBasedSecurityStatus",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            /* Value 2 = Running means VTL1 is active */
            if (value == 2) {
                info->vtl1Available = TRUE;
            }
        }
        RegCloseKey(hKey);
    }
}

/*
 * Check for Secure System calls availability
 * Secure calls are made from VTL0 to VTL1
 */
static void CheckSecureSystemCalls(PSECURE_CALLS_INFO info)
{
    HMODULE hNtdll = NULL;
    
    if (info == NULL) {
        return;
    }
    
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return;
    }
    
    /* Check for secure call related exports */
    /* These are indirect indicators of secure call infrastructure */
    if (GetProcAddress(hNtdll, "RtlGetSystemGlobalData") != NULL) {
        /* System global data includes VBS info */
        info->secureSystemCallsAvailable = TRUE;
    }
}

/*
 * Check for IUM (Isolated User Mode) process
 * LsaIso.exe indicates secure calls are being used
 */
static void CheckIumProcesses(PSECURE_CALLS_INFO info)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    
    if (info == NULL) {
        return;
    }
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            /* LsaIso.exe - Credential Guard IUM process */
            if (_stricmp(pe32.szExeFile, "LsaIso.exe") == 0) {
                info->ikmCallsAvailable = TRUE;
            }
            
            /* bioiso.exe - Windows Hello IUM process */
            if (_stricmp(pe32.szExeFile, "bioiso.exe") == 0) {
                info->ikmCallsAvailable = TRUE;
            }
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

/*
 * Main secure calls check function
 */
DWORD CheckSecureCallsHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    SECURE_CALLS_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckSecureKernelBinaries(&info);
    CheckVbsVtlRegistry(&info);
    CheckSecureSystemCalls(&info);
    CheckIumProcesses(&info);
    
    /* Detection */
    if (info.vtl1Available || info.secureKernelPresent) {
        detected = HYPERV_DETECTED_SECURE_CALLS;
    }
    
    /* Build details */
    AppendToDetails(result, "Secure Calls / SkBridge Detection:\n");
    
    AppendToDetails(result, "\n  Secure Kernel Components:\n");
    AppendToDetails(result, "    securekernel.exe: %s\n", 
                   info.secureKernelPresent ? "Present" : "Not found");
    AppendToDetails(result, "    CI.dll: %s\n", 
                   info.ciDllPresent ? "Present" : "Not found");
    AppendToDetails(result, "    SKCI.dll: %s\n", 
                   info.skciPresent ? "Present" : "Not found");
    
    AppendToDetails(result, "\n  VTL Status:\n");
    AppendToDetails(result, "    VBS Enabled: %s\n", 
                   info.vbsEnabled ? "YES" : "NO");
    AppendToDetails(result, "    VTL1 Active: %s\n", 
                   info.vtl1Available ? "YES" : "NO");
    
    AppendToDetails(result, "\n  Secure Call Infrastructure:\n");
    AppendToDetails(result, "    Secure System Calls: %s\n", 
                   info.secureSystemCallsAvailable ? "Available" : "Not available");
    AppendToDetails(result, "    IUM Calls Active: %s\n", 
                   info.ikmCallsAvailable ? "YES (IUM processes found)" : "NO");
    
    if (info.vtl1Available && info.secureKernelPresent) {
        AppendToDetails(result, "\n  Note: Secure Calls infrastructure is ACTIVE\n");
        AppendToDetails(result, "        NT Kernel <-> Secure Kernel bridge operational\n");
    }
    
    return detected;
}

/*
 * Quick check for secure calls
 */
BOOL HasSecureCallsSupport(void)
{
    SECURE_CALLS_INFO info = {0};
    CheckVbsVtlRegistry(&info);
    return info.vtl1Available;
}

/*
 * Check if VTL1 is active
 */
BOOL IsVtl1Active(void)
{
    SECURE_CALLS_INFO info = {0};
    CheckVbsVtlRegistry(&info);
    return info.vtl1Available;
}

/*
 * Check if IUM processes are running
 */
BOOL HasIumProcesses(void)
{
    SECURE_CALLS_INFO info = {0};
    CheckIumProcesses(&info);
    return info.ikmCallsAvailable;
}

/*
 * Get VBS enabled status
 */
BOOL IsVbsEnabledSecureCalls(void)
{
    SECURE_CALLS_INFO info = {0};
    CheckVbsVtlRegistry(&info);
    return info.vbsEnabled;
}
