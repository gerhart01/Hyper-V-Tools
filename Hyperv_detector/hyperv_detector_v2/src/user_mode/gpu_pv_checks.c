/**
 * gpu_pv_checks.c - GPU Paravirtualization Detection
 * 
 * Detects GPU-PV (GPU Paravirtualization) used by Hyper-V for
 * hardware-accelerated graphics in VMs.
 * 
 * Sources:
 * - DirectX: The New Hyper-V Attack Surface (Zhenhao Hon, Ziming Zhang)
 *   https://i.blackhat.com/USA-22/Thursday/US-22-Hong-DirectX-The-New-Hyper-V-Attack-Surface.pdf
 * - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/gpu-partitioning
 * - https://github.com/gerhart01/Hyper-V-Internals
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <setupapi.h>

#pragma comment(lib, "setupapi.lib")

/* Detection flag for this module */
#define HYPERV_DETECTED_GPU_PV 0x00001000

/* GPU-PV device class GUID */
/* Microsoft Hyper-V Video: 5B45201D-F2F2-4F3B-85BB-30FF1F953599 */
static const GUID GUID_DEVCLASS_DISPLAY = 
    {0x4d36e968, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};

/* GPU-PV detection info */
typedef struct _GPU_PV_INFO {
    BOOL hyperVVideoFound;
    BOOL basicDisplayFound;
    BOOL gpuPvEnabled;
    
    char adapterName[256];
    char driverVersion[64];
    
    BOOL isDxGkrnlPresent;
    BOOL isVmRdrPresent;
    
    DWORD vmbusDxDeviceCount;
} GPU_PV_INFO, *PGPU_PV_INFO;

/*
 * Check for Hyper-V video adapter
 */
static void CheckHyperVVideoAdapter(PGPU_PV_INFO info)
{
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfoData;
    DWORD i;
    char buffer[256];
    DWORD bufferSize;
    
    if (info == NULL) {
        return;
    }
    
    hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_DISPLAY, NULL, NULL, 
                                    DIGCF_PRESENT);
    
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return;
    }
    
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        bufferSize = sizeof(buffer);
        
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, bufferSize, NULL)) {
            
            /* Check for Hyper-V Video */
            if (strstr(buffer, "Hyper-V") != NULL ||
                strstr(buffer, "Microsoft Hyper-V Video") != NULL) {
                info->hyperVVideoFound = TRUE;
                strncpy(info->adapterName, buffer, sizeof(info->adapterName) - 1);
            }
            
            /* Check for Basic Display (no GPU-PV) */
            if (strstr(buffer, "Microsoft Basic Display") != NULL ||
                strstr(buffer, "Basic Display Adapter") != NULL) {
                info->basicDisplayFound = TRUE;
            }
            
            /* Check for GPU-PV indicators */
            if (strstr(buffer, "GPU-PV") != NULL ||
                strstr(buffer, "GPU Partitioning") != NULL ||
                strstr(buffer, "RemoteFX") != NULL) {
                info->gpuPvEnabled = TRUE;
            }
        }
        
        /* Get hardware ID */
        bufferSize = sizeof(buffer);
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
            SPDRP_HARDWAREID, NULL, (PBYTE)buffer, bufferSize, NULL)) {
            
            /* Check for VMBus GPU device */
            if (strstr(buffer, "VMBUS") != NULL ||
                strstr(buffer, "{da0a7802-e377-4aac-8e77-0558eb1073f8}") != NULL) {
                info->vmbusDxDeviceCount++;
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

/*
 * Check for GPU-PV related drivers
 */
static void CheckGpuPvDrivers(PGPU_PV_INFO info)
{
    HMODULE hDxGkrnl = NULL;
    HMODULE hVmRdr = NULL;
    
    if (info == NULL) {
        return;
    }
    
    /* Check for dxgkrnl (DirectX Graphics Kernel) */
    /* Note: This is a kernel driver, so we check service status instead */
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager != NULL) {
        SC_HANDLE hService;
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        
        /* Check dxgkrnl */
        hService = OpenServiceA(hSCManager, "dxgkrnl", SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
                info->isDxGkrnlPresent = (status.dwCurrentState == SERVICE_RUNNING);
            }
            CloseServiceHandle(hService);
        }
        
        /* Check vmrdvcore / vmrdr (VM Remote Desktop) */
        hService = OpenServiceA(hSCManager, "vmrdvcore", SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
                info->isVmRdrPresent = (status.dwCurrentState == SERVICE_RUNNING);
            }
            CloseServiceHandle(hService);
        }
        
        CloseServiceHandle(hSCManager);
    }
}

/*
 * Check registry for GPU-PV settings
 */
static BOOL CheckGpuPvRegistry(void)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    /* Check for GPU-PV assignment */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\GuestEnabledVirtualDevices",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    /* Alternative: Check for RemoteFX 3D Video Adapter */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vmrdvcore",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main GPU-PV check function
 */
DWORD CheckGpuPvHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    GPU_PV_INFO info = {0};
    BOOL registryFound;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckHyperVVideoAdapter(&info);
    CheckGpuPvDrivers(&info);
    registryFound = CheckGpuPvRegistry();
    
    /* Detection */
    if (info.hyperVVideoFound || info.gpuPvEnabled || 
        info.vmbusDxDeviceCount > 0) {
        detected = HYPERV_DETECTED_GPU_PV;
    }
    
    /* Build details */
    AppendToDetails(result, "GPU Paravirtualization (GPU-PV) Detection:\n");
    
    AppendToDetails(result, "\n  Video Adapters:\n");
    AppendToDetails(result, "    Hyper-V Video: %s\n", 
                   info.hyperVVideoFound ? "Found" : "Not found");
    AppendToDetails(result, "    Basic Display: %s\n", 
                   info.basicDisplayFound ? "Found" : "Not found");
    AppendToDetails(result, "    GPU-PV Enabled: %s\n", 
                   info.gpuPvEnabled ? "YES" : "NO");
    
    if (info.adapterName[0] != '\0') {
        AppendToDetails(result, "    Adapter Name: %s\n", info.adapterName);
    }
    
    if (info.vmbusDxDeviceCount > 0) {
        AppendToDetails(result, "    VMBus DX Devices: %u\n", info.vmbusDxDeviceCount);
    }
    
    AppendToDetails(result, "\n  Drivers:\n");
    AppendToDetails(result, "    dxgkrnl: %s\n", 
                   info.isDxGkrnlPresent ? "Running" : "Not running");
    AppendToDetails(result, "    vmrdvcore: %s\n", 
                   info.isVmRdrPresent ? "Running" : "Not running");
    
    AppendToDetails(result, "\n  Registry:\n");
    AppendToDetails(result, "    GPU-PV Settings: %s\n", 
                   registryFound ? "Found" : "Not found");
    
    if (info.hyperVVideoFound && !info.gpuPvEnabled) {
        AppendToDetails(result, "\n  Note: Running with Hyper-V basic video\n");
        AppendToDetails(result, "        (no GPU passthrough/GPU-PV)\n");
    } else if (info.gpuPvEnabled) {
        AppendToDetails(result, "\n  Note: GPU-PV is active - hardware-accelerated graphics\n");
    }
    
    return detected;
}

/*
 * Quick check for GPU-PV
 */
BOOL HasGpuPv(void)
{
    GPU_PV_INFO info = {0};
    CheckHyperVVideoAdapter(&info);
    return info.gpuPvEnabled || info.hyperVVideoFound;
}

/*
 * Check if Hyper-V video adapter is present
 */
BOOL HasHyperVVideo(void)
{
    GPU_PV_INFO info = {0};
    CheckHyperVVideoAdapter(&info);
    return info.hyperVVideoFound;
}

/*
 * Check if basic display only (no GPU-PV)
 */
BOOL IsBasicDisplayOnly(void)
{
    GPU_PV_INFO info = {0};
    CheckHyperVVideoAdapter(&info);
    return info.basicDisplayFound && !info.gpuPvEnabled;
}
