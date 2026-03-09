/**
 * vmbus_channel_checks.c - VMBus Channel Detection
 * 
 * Detects VMBus channels and communication interfaces.
 * 
 * Sources:
 * - Linux Integration Services: https://github.com/LIS
 * - Hyper-V LIS description (Alisa Shevchenko): https://re.alisa.sh/notes/Hyper-V-LIS.html
 * - VMBusPipe (Marc-André Moreau): https://github.com/awakecoding/VMBusPipe
 * - hcsshim (Microsoft): https://github.com/microsoft/hcsshim
 * - Linux kernel hyperv: hv_vmbus.h, vmbus_drv.c
 * - CHIPSEC VMBus fuzzing (Yuriy Bulygin): https://github.com/chipsec/chipsec/tree/master/chipsec/modules/tools/vmm/hv
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <setupapi.h>

#pragma comment(lib, "setupapi.lib")

/* Detection flag for this module */
#define HYPERV_DETECTED_VMBUS_CHANNEL 0x00000004

/* VMBus device interface GUID */
/* {8684f561-f900-42a3-b0c4-1a59cf26f93d} - VMBus */
static const GUID GUID_VMBUS = 
    {0x8684f561, 0xf900, 0x42a3, {0xb0, 0xc4, 0x1a, 0x59, 0xcf, 0x26, 0xf9, 0x3d}};

/* VMBus channel info */
typedef struct _VMBUS_CHANNEL_INFO {
    BOOL vmbusDriverLoaded;
    BOOL vmbusrDriverLoaded;
    BOOL vmbusDeviceFound;
    
    DWORD channelCount;
    
    BOOL kvpChannelFound;      /* Key-Value Pair */
    BOOL shutdownChannelFound; /* Shutdown IC */
    BOOL heartbeatChannelFound;/* Heartbeat IC */
    BOOL vssChannelFound;      /* VSS IC */
    BOOL rdvChannelFound;      /* Remote Desktop */
} VMBUS_CHANNEL_INFO, *PVMBUS_CHANNEL_INFO;

/*
 * Check VMBus driver status
 */
static void CheckVmbusDrivers(PVMBUS_CHANNEL_INFO info)
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
    
    /* Check vmbus (guest driver) */
    hService = OpenServiceA(hSCManager, "vmbus", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->vmbusDriverLoaded = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    /* Check vmbusr (root partition driver) */
    hService = OpenServiceA(hSCManager, "vmbusr", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            info->vmbusrDriverLoaded = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
}

/*
 * Check for VMBus devices
 */
static void CheckVmbusDevices(PVMBUS_CHANNEL_INFO info)
{
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfoData;
    DWORD i;
    char buffer[512];
    DWORD bufferSize;
    
    if (info == NULL) {
        return;
    }
    
    /* Get all present devices */
    hDevInfo = SetupDiGetClassDevsA(NULL, "VMBUS", NULL, 
                                    DIGCF_ALLCLASSES | DIGCF_PRESENT);
    
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return;
    }
    
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        info->vmbusDeviceFound = TRUE;
        info->channelCount++;
        
        bufferSize = sizeof(buffer);
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, bufferSize, NULL)) {
            
            /* Check for specific channels */
            if (strstr(buffer, "Data Exchange") != NULL ||
                strstr(buffer, "KVP") != NULL) {
                info->kvpChannelFound = TRUE;
            }
            
            if (strstr(buffer, "Shutdown") != NULL) {
                info->shutdownChannelFound = TRUE;
            }
            
            if (strstr(buffer, "Heartbeat") != NULL) {
                info->heartbeatChannelFound = TRUE;
            }
            
            if (strstr(buffer, "VSS") != NULL ||
                strstr(buffer, "Volume Shadow Copy") != NULL) {
                info->vssChannelFound = TRUE;
            }
            
            if (strstr(buffer, "Remote Desktop") != NULL ||
                strstr(buffer, "Video") != NULL) {
                info->rdvChannelFound = TRUE;
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

/*
 * Check VMBus registry entries
 */
static BOOL CheckVmbusRegistry(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check VMBus parameters */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vmbus\\Parameters",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main VMBus channel check function
 */
DWORD CheckVmbusChannelHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    VMBUS_CHANNEL_INFO info = {0};
    BOOL registryFound;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckVmbusDrivers(&info);
    CheckVmbusDevices(&info);
    registryFound = CheckVmbusRegistry();
    
    /* Detection */
    if (info.vmbusDriverLoaded || info.vmbusDeviceFound) {
        detected = HYPERV_DETECTED_VMBUS_CHANNEL;
    }
    
    /* Build details */
    AppendToDetails(result, "VMBus Channel Detection:\n");
    
    AppendToDetails(result, "\n  Driver Status:\n");
    AppendToDetails(result, "    vmbus (Guest): %s\n", 
                   info.vmbusDriverLoaded ? "Running" : "Not running");
    AppendToDetails(result, "    vmbusr (Root): %s\n", 
                   info.vmbusrDriverLoaded ? "Running" : "Not running");
    
    AppendToDetails(result, "\n  VMBus Devices:\n");
    AppendToDetails(result, "    Devices Found: %s\n", 
                   info.vmbusDeviceFound ? "YES" : "NO");
    AppendToDetails(result, "    Channel Count: %u\n", info.channelCount);
    
    AppendToDetails(result, "\n  Integration Channels:\n");
    AppendToDetails(result, "    KVP (Data Exchange): %s\n", 
                   info.kvpChannelFound ? "Found" : "Not found");
    AppendToDetails(result, "    Shutdown: %s\n", 
                   info.shutdownChannelFound ? "Found" : "Not found");
    AppendToDetails(result, "    Heartbeat: %s\n", 
                   info.heartbeatChannelFound ? "Found" : "Not found");
    AppendToDetails(result, "    VSS: %s\n", 
                   info.vssChannelFound ? "Found" : "Not found");
    AppendToDetails(result, "    Remote Desktop: %s\n", 
                   info.rdvChannelFound ? "Found" : "Not found");
    
    AppendToDetails(result, "\n  Registry:\n");
    AppendToDetails(result, "    VMBus Parameters: %s\n", 
                   registryFound ? "Found" : "Not found");
    
    if (info.vmbusDriverLoaded && !info.vmbusrDriverLoaded) {
        AppendToDetails(result, "\n  Note: vmbus only = GUEST VM\n");
    } else if (info.vmbusrDriverLoaded) {
        AppendToDetails(result, "\n  Note: vmbusr present = ROOT PARTITION\n");
    }
    
    return detected;
}

/*
 * Quick check for VMBus
 */
BOOL HasVmbusChannel(void)
{
    VMBUS_CHANNEL_INFO info = {0};
    CheckVmbusDrivers(&info);
    return info.vmbusDriverLoaded;
}

/*
 * Get VMBus channel count
 */
DWORD GetVmbusChannelCount(void)
{
    VMBUS_CHANNEL_INFO info = {0};
    CheckVmbusDevices(&info);
    return info.channelCount;
}

/*
 * Check if this is guest (vmbus only, not vmbusr)
 */
BOOL IsGuestByVmbus(void)
{
    VMBUS_CHANNEL_INFO info = {0};
    CheckVmbusDrivers(&info);
    return info.vmbusDriverLoaded && !info.vmbusrDriverLoaded;
}

/*
 * Check if this is root partition (vmbusr)
 */
BOOL IsRootByVmbusr(void)
{
    VMBUS_CHANNEL_INFO info = {0};
    CheckVmbusDrivers(&info);
    return info.vmbusrDriverLoaded;
}
