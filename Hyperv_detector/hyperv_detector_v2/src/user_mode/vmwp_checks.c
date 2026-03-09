/**
 * vmwp_checks.c - VM Worker Process Detection
 * 
 * Detects VM Worker Process (vmwp.exe) and related components.
 * Each Hyper-V VM has its own vmwp.exe process in the host.
 * 
 * Sources:
 * - Attacking the VM Worker Process (Saar Amar): https://msrc.microsoft.com/blog/2019/09/attacking-the-vm-worker-process/
 * - VmwpMonitor (Behrooz Abbassi): https://github.com/BehroozAbbassi/VmwpMonitor
 * - First Steps in Hyper-V Research (Saar Amar): https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/
 * - A Dive in to Hyper-V Architecture (Joly, Bialek): BlackHat 2018
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <tlhelp32.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_VMWP 0x00004000

/* VMWP detection info */
typedef struct _VMWP_INFO {
    BOOL vmwpFound;
    BOOL vmmsFound;
    BOOL vmcompFound;
    BOOL vmsvcFound;
    
    DWORD vmwpCount;
    DWORD vmwpPid;
    
    BOOL vmwpDllsFound;
    BOOL vidDllFound;
    BOOL winhvDllFound;
} VMWP_INFO, *PVMWP_INFO;

/*
 * Check for VM-related processes
 */
static void CheckVmProcesses(PVMWP_INFO info)
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
            /* VM Worker Process */
            if (_stricmp(pe32.szExeFile, "vmwp.exe") == 0) {
                info->vmwpFound = TRUE;
                info->vmwpCount++;
                if (info->vmwpPid == 0) {
                    info->vmwpPid = pe32.th32ProcessID;
                }
            }
            
            /* Virtual Machine Management Service */
            if (_stricmp(pe32.szExeFile, "vmms.exe") == 0) {
                info->vmmsFound = TRUE;
            }
            
            /* VM Compute Process */
            if (_stricmp(pe32.szExeFile, "vmcompute.exe") == 0) {
                info->vmcompFound = TRUE;
            }
            
            /* VM Service */
            if (_stricmp(pe32.szExeFile, "vmsvc.exe") == 0) {
                info->vmsvcFound = TRUE;
            }
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

/*
 * Check for VMWP-related DLLs in system
 */
static void CheckVmwpDlls(PVMWP_INFO info)
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
    
    /* Check vid.dll (Virtualization Infrastructure Driver) */
    snprintf(filePath, MAX_PATH, "%s\\vid.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->vidDllFound = TRUE;
        info->vmwpDllsFound = TRUE;
    }
    
    /* Check winhvplatform.dll */
    snprintf(filePath, MAX_PATH, "%s\\winhvplatform.dll", systemPath);
    attrs = GetFileAttributesA(filePath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        info->winhvDllFound = TRUE;
    }
}

/*
 * Check VMWP registry settings
 */
static BOOL CheckVmwpRegistry(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check for VMWP configuration */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\WorkerProcesses",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check if current process is inside a VM (guest perspective)
 */
static BOOL CheckGuestVmwp(void)
{
    /* From guest perspective, vmwp.exe runs on host */
    /* Check for VMBus presence which indicates guest */
    HKEY hKey;
    LONG result;
    
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vmbus",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        DWORD startType = 0;
        DWORD size = sizeof(DWORD);
        
        if (RegQueryValueExA(hKey, "Start",
            NULL, NULL, (LPBYTE)&startType, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            /* Start = 0 means boot start (active in guest) */
            return (startType == 0);
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

/*
 * Main VMWP check function
 */
DWORD CheckVmwpHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    VMWP_INFO info = {0};
    BOOL registryFound;
    BOOL isGuest;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckVmProcesses(&info);
    CheckVmwpDlls(&info);
    registryFound = CheckVmwpRegistry();
    isGuest = CheckGuestVmwp();
    
    /* Detection - host indicators */
    if (info.vmwpFound || info.vmmsFound || registryFound) {
        detected = HYPERV_DETECTED_VMWP;
    }
    
    /* Build details */
    AppendToDetails(result, "VM Worker Process (VMWP) Detection:\n");
    
    AppendToDetails(result, "\n  Host Processes:\n");
    AppendToDetails(result, "    vmwp.exe: %s", 
                   info.vmwpFound ? "Found" : "Not found");
    if (info.vmwpFound) {
        AppendToDetails(result, " (%u instance(s), PID: %u)", 
                       info.vmwpCount, info.vmwpPid);
    }
    AppendToDetails(result, "\n");
    
    AppendToDetails(result, "    vmms.exe: %s\n", 
                   info.vmmsFound ? "Found" : "Not found");
    AppendToDetails(result, "    vmcompute.exe: %s\n", 
                   info.vmcompFound ? "Found" : "Not found");
    AppendToDetails(result, "    vmsvc.exe: %s\n", 
                   info.vmsvcFound ? "Found" : "Not found");
    
    AppendToDetails(result, "\n  System DLLs:\n");
    AppendToDetails(result, "    vid.dll: %s\n", 
                   info.vidDllFound ? "Found" : "Not found");
    AppendToDetails(result, "    winhvplatform.dll: %s\n", 
                   info.winhvDllFound ? "Found" : "Not found");
    
    AppendToDetails(result, "\n  Configuration:\n");
    AppendToDetails(result, "    VMWP Registry: %s\n", 
                   registryFound ? "Found" : "Not found");
    AppendToDetails(result, "    Guest VMBus: %s\n", 
                   isGuest ? "Active (GUEST)" : "Not active");
    
    if (info.vmwpFound) {
        AppendToDetails(result, "\n  Note: vmwp.exe found - this is Hyper-V HOST\n");
        AppendToDetails(result, "        Running %u VM(s)\n", info.vmwpCount);
    } else if (isGuest) {
        AppendToDetails(result, "\n  Note: VMBus active - this is Hyper-V GUEST\n");
    }
    
    return detected;
}

/*
 * Quick check for VMWP (host indicator)
 */
BOOL HasVmwpProcess(void)
{
    VMWP_INFO info = {0};
    CheckVmProcesses(&info);
    return info.vmwpFound;
}

/*
 * Get count of running VMs
 */
DWORD GetRunningVmCount(void)
{
    VMWP_INFO info = {0};
    CheckVmProcesses(&info);
    return info.vmwpCount;
}

/*
 * Check if VMMS is running
 */
BOOL IsVmmsRunning(void)
{
    VMWP_INFO info = {0};
    CheckVmProcesses(&info);
    return info.vmmsFound;
}

/*
 * Check if this is definitely a host
 */
BOOL IsHyperVHostByVmwp(void)
{
    VMWP_INFO info = {0};
    CheckVmProcesses(&info);
    return info.vmwpFound || info.vmmsFound;
}
