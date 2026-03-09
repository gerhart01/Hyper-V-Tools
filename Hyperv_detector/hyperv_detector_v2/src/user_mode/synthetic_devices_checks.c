/**
 * synthetic_devices_checks.c - Hyper-V Synthetic Devices Detection
 * 
 * Detects Hyper-V synthetic devices that use VMBus for communication.
 * Synthetic devices provide better performance than emulated devices.
 * 
 * Sources:
 * - https://docs.kernel.org/virt/hyperv/vmbus.html
 * - https://learn.microsoft.com/en-us/archive/blogs/tvoellm/hyper-v-integration-components-and-enlightenments
 * - https://github.com/torvalds/linux/blob/master/Documentation/virt/hyperv/vmbus.rst
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <setupapi.h>
#include <devguid.h>
#include <initguid.h>

#pragma comment(lib, "setupapi.lib")

#define HYPERV_DETECTED_SYNTHETIC 0x04000000

/* VMBus Device GUIDs (from Linux kernel and Windows headers) */
/* These GUIDs identify specific Hyper-V synthetic devices */

/* {f8615163-df3e-46c5-913f-f2d2f965ed0e} - Synthetic Network */
DEFINE_GUID(GUID_NETVSC, 
    0xf8615163, 0xdf3e, 0x46c5, 0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e);

/* {ba6163d9-04a1-4d29-b605-72e2ffb1dc7f} - Synthetic SCSI Controller */
DEFINE_GUID(GUID_STORVSC,
    0xba6163d9, 0x04a1, 0x4d29, 0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f);

/* {0e0b6031-5213-4934-818b-38d90ced39db} - Shutdown */
DEFINE_GUID(GUID_SHUTDOWN,
    0x0e0b6031, 0x5213, 0x4934, 0x81, 0x8b, 0x38, 0xd9, 0x0c, 0xed, 0x39, 0xdb);

/* {9527e630-d0ae-497b-adce-e80ab0175caf} - Time Sync */
DEFINE_GUID(GUID_TIMESYNC,
    0x9527e630, 0xd0ae, 0x497b, 0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf);

/* {57164f39-9115-4e78-ab55-382f3bd5422d} - Heartbeat */
DEFINE_GUID(GUID_HEARTBEAT,
    0x57164f39, 0x9115, 0x4e78, 0xab, 0x55, 0x38, 0x2f, 0x3b, 0xd5, 0x42, 0x2d);

/* {a9a0f4e7-5a45-4d96-b827-8a841e8c03e6} - KVP (Key-Value Pair) Exchange */
DEFINE_GUID(GUID_KVP,
    0xa9a0f4e7, 0x5a45, 0x4d96, 0xb8, 0x27, 0x8a, 0x84, 0x1e, 0x8c, 0x03, 0xe6);

/* {35fa2e29-ea23-4236-96ae-3a6ebacba440} - Dynamic Memory */
DEFINE_GUID(GUID_DM,
    0x35fa2e29, 0xea23, 0x4236, 0x96, 0xae, 0x3a, 0x6e, 0xba, 0xcb, 0xa4, 0x40);

/* {34d14be3-dee4-41c8-9ae7-6b174977c192} - VSS (Volume Shadow Copy) */
DEFINE_GUID(GUID_VSS,
    0x34d14be3, 0xdee4, 0x41c8, 0x9a, 0xe7, 0x6b, 0x17, 0x49, 0x77, 0xc1, 0x92);

/* {da0a7802-e377-4aac-8e77-0558eb1073f8} - Guest Services */
DEFINE_GUID(GUID_FCOPY,
    0xda0a7802, 0xe377, 0x4aac, 0x8e, 0x77, 0x05, 0x58, 0xeb, 0x10, 0x73, 0xf8);

/* {276aacf4-ac15-426c-98dd-7521ad3f01fe} - RDV (Remote Desktop) */
DEFINE_GUID(GUID_RDV,
    0x276aacf4, 0xac15, 0x426c, 0x98, 0xdd, 0x75, 0x21, 0xad, 0x3f, 0x01, 0xfe);

/* {cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a} - Synthetic Mouse */
DEFINE_GUID(GUID_MOUSE,
    0xcfa8b69e, 0x5b4a, 0x4cc0, 0xb9, 0x8b, 0x8b, 0xa1, 0xa1, 0xf3, 0xf9, 0x5a);

/* {f912ad6d-2b17-48ea-bd65-f927a61c7684} - Synthetic Keyboard */
DEFINE_GUID(GUID_KEYBOARD,
    0xf912ad6d, 0x2b17, 0x48ea, 0xbd, 0x65, 0xf9, 0x27, 0xa6, 0x1c, 0x76, 0x84);

/* {d34b2567-b9b6-42b9-8778-0a4ec0b955bf} - Synthetic Video */
DEFINE_GUID(GUID_VIDEO,
    0xd34b2567, 0xb9b6, 0x42b9, 0x87, 0x78, 0x0a, 0x4e, 0xc0, 0xb9, 0x55, 0xbf);

/* VMBus Class GUID */
DEFINE_GUID(GUID_VMBUS,
    0xc376c1c3, 0xd276, 0x48d2, 0x90, 0xa9, 0xc0, 0x47, 0x48, 0x07, 0x2c, 0x60);

/* Synthetic device info */
typedef struct _SYNTHETIC_DEVICE_INFO {
    const char* name;
    const char* description;
    BOOL detected;
} SYNTHETIC_DEVICE_INFO, *PSYNTHETIC_DEVICE_INFO;

/* Detection results */
typedef struct _SYNTHETIC_DETECTION_INFO {
    BOOL hasVmBus;
    BOOL hasNetVsc;
    BOOL hasStorVsc;
    BOOL hasShutdown;
    BOOL hasTimesync;
    BOOL hasHeartbeat;
    BOOL hasKvp;
    BOOL hasDynamicMemory;
    BOOL hasVss;
    BOOL hasGuestServices;
    BOOL hasRdv;
    BOOL hasMouse;
    BOOL hasKeyboard;
    BOOL hasVideo;
    int syntheticDeviceCount;
    int vmBusChildCount;
} SYNTHETIC_DETECTION_INFO, *PSYNTHETIC_DETECTION_INFO;

/* Device names to look for in Device Manager */
static const char* g_SyntheticDeviceNames[] = {
    "Microsoft Hyper-V Network Adapter",
    "Microsoft Hyper-V Video",
    "Microsoft Hyper-V Virtual Keyboard",
    "Microsoft Hyper-V Virtual Mouse",
    "Microsoft Hyper-V S3 Cap",
    "Microsoft Hyper-V SCSI Controller",
    "Hyper-V Virtual Machine Bus",
    "Hyper-V Data Exchange",
    "Hyper-V Guest Service Interface",
    "Hyper-V Heartbeat",
    "Hyper-V Remote Desktop Control",
    "Hyper-V Shutdown",
    "Hyper-V Time Synchronization",
    "Hyper-V Volume Shadow Copy",
    "Hyper-V PowerShell Direct",
    NULL
};

/* Hardware IDs for VMBus devices */
static const char* g_VmBusHardwareIds[] = {
    "VMBUS\\",
    "ROOT\\VMBUS",
    "ACPI\\VMBUS",
    "ACPI\\VMBus",
    NULL
};

/*
 * Check if a device with given name exists
 */
static BOOL CheckDeviceByName(const char* deviceName)
{
    HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA deviceInfoData = {0};
    DWORD i = 0;
    char buffer[256] = {0};
    DWORD bufferSize = 0;
    BOOL found = FALSE;
    
    deviceInfoSet = SetupDiGetClassDevsA(NULL, NULL, NULL, 
                                         DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
        bufferSize = sizeof(buffer);
        if (SetupDiGetDeviceRegistryPropertyA(deviceInfoSet, &deviceInfoData,
                SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, bufferSize, NULL)) {
            if (strstr(buffer, deviceName) != NULL) {
                found = TRUE;
                break;
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return found;
}

/*
 * Count VMBus child devices
 */
static int CountVmBusDevices(void)
{
    HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA deviceInfoData = {0};
    DWORD i = 0;
    char buffer[512] = {0};
    int count = 0;
    
    /* Get devices on VMBus */
    deviceInfoSet = SetupDiGetClassDevsA(NULL, "VMBUS", NULL, 
                                         DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
        count++;
    }
    
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return count;
}

/*
 * Check for VMBus root device
 */
static BOOL CheckVmBusRoot(void)
{
    HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA deviceInfoData = {0};
    DWORD i = 0;
    char hardwareId[512] = {0};
    BOOL found = FALSE;
    int j = 0;
    
    deviceInfoSet = SetupDiGetClassDevsA(NULL, NULL, NULL, 
                                         DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
        if (SetupDiGetDeviceRegistryPropertyA(deviceInfoSet, &deviceInfoData,
                SPDRP_HARDWAREID, NULL, (PBYTE)hardwareId, sizeof(hardwareId), NULL)) {
            
            for (j = 0; g_VmBusHardwareIds[j] != NULL; j++) {
                if (strstr(hardwareId, g_VmBusHardwareIds[j]) != NULL) {
                    found = TRUE;
                    break;
                }
            }
            
            if (found) break;
        }
    }
    
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return found;
}

/*
 * Count synthetic devices by searching device names
 */
static int CountSyntheticDevicesByName(void)
{
    int count = 0;
    int i = 0;
    
    for (i = 0; g_SyntheticDeviceNames[i] != NULL; i++) {
        if (CheckDeviceByName(g_SyntheticDeviceNames[i])) {
            count++;
        }
    }
    
    return count;
}

/*
 * Gather synthetic device detection info
 */
static void GatherSyntheticDeviceInfo(PSYNTHETIC_DETECTION_INFO info)
{
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(SYNTHETIC_DETECTION_INFO));
    
    /* Check VMBus root */
    info->hasVmBus = CheckVmBusRoot();
    
    /* Count VMBus children */
    info->vmBusChildCount = CountVmBusDevices();
    
    /* Check specific synthetic devices */
    info->hasNetVsc = CheckDeviceByName("Hyper-V Network Adapter") ||
                      CheckDeviceByName("Microsoft Hyper-V Network");
    info->hasStorVsc = CheckDeviceByName("Hyper-V SCSI Controller") ||
                       CheckDeviceByName("Microsoft Hyper-V Virtual") ||
                       CheckDeviceByName("storvsc");
    info->hasVideo = CheckDeviceByName("Hyper-V Video") ||
                     CheckDeviceByName("Microsoft Hyper-V Video");
    info->hasMouse = CheckDeviceByName("Hyper-V Mouse") ||
                     CheckDeviceByName("Microsoft Hyper-V Virtual Mouse");
    info->hasKeyboard = CheckDeviceByName("Hyper-V Keyboard") ||
                        CheckDeviceByName("Microsoft Hyper-V Virtual Keyboard");
    info->hasHeartbeat = CheckDeviceByName("Heartbeat");
    info->hasShutdown = CheckDeviceByName("Shutdown");
    info->hasTimesync = CheckDeviceByName("Time Synchronization");
    info->hasKvp = CheckDeviceByName("Data Exchange");
    info->hasVss = CheckDeviceByName("Volume Shadow Copy");
    info->hasGuestServices = CheckDeviceByName("Guest Service");
    info->hasRdv = CheckDeviceByName("Remote Desktop");
    info->hasDynamicMemory = CheckDeviceByName("Dynamic Memory");
    
    /* Total count */
    info->syntheticDeviceCount = CountSyntheticDevicesByName();
}

/*
 * Main synthetic devices check function
 */
DWORD CheckSyntheticDevicesHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    SYNTHETIC_DETECTION_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    GatherSyntheticDeviceInfo(&info);
    
    /* Determine detection */
    if (info.hasVmBus || info.vmBusChildCount > 0 || info.syntheticDeviceCount >= 2) {
        detected = HYPERV_DETECTED_SYNTHETIC;
    }
    
    /* Build details */
    AppendToDetails(result, "Synthetic Devices Detection:\n");
    AppendToDetails(result, "  VMBus root: %s\n", info.hasVmBus ? "Present" : "Not found");
    AppendToDetails(result, "  VMBus children: %d\n", info.vmBusChildCount);
    AppendToDetails(result, "  Synthetic devices found: %d\n", info.syntheticDeviceCount);
    
    /* List detected devices */
    if (info.hasNetVsc) AppendToDetails(result, "  + Network (netvsc)\n");
    if (info.hasStorVsc) AppendToDetails(result, "  + Storage (storvsc)\n");
    if (info.hasVideo) AppendToDetails(result, "  + Video\n");
    if (info.hasMouse) AppendToDetails(result, "  + Mouse\n");
    if (info.hasKeyboard) AppendToDetails(result, "  + Keyboard\n");
    if (info.hasHeartbeat) AppendToDetails(result, "  + Heartbeat\n");
    if (info.hasShutdown) AppendToDetails(result, "  + Shutdown\n");
    if (info.hasTimesync) AppendToDetails(result, "  + Time Sync\n");
    if (info.hasKvp) AppendToDetails(result, "  + KVP Exchange\n");
    if (info.hasVss) AppendToDetails(result, "  + VSS\n");
    if (info.hasGuestServices) AppendToDetails(result, "  + Guest Services\n");
    if (info.hasRdv) AppendToDetails(result, "  + Remote Desktop\n");
    if (info.hasDynamicMemory) AppendToDetails(result, "  + Dynamic Memory\n");
    
    return detected;
}

/*
 * Quick VMBus check
 */
BOOL HasVmBus(void)
{
    return CheckVmBusRoot() || (CountVmBusDevices() > 0);
}

/*
 * Get synthetic device count
 */
int GetSyntheticDeviceCount(void)
{
    return CountSyntheticDevicesByName();
}
