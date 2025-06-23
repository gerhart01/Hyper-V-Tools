#include "hyperv_detector.h"
#include <setupapi.h>
#include <devguid.h>

static const char* HYPERV_DEVICE_IDS[] = {
    "ROOT\\VMBUS",
    "VMBUS\\{da0a7802-e377-4aac-8e77-0558eb1073f8}",  // Synthetic keyboard
    "VMBUS\\{cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a}",  // Synthetic mouse
    "VMBUS\\{f8615163-df3e-46c5-913f-f2d2f965ed0e}",  // Synthetic network adapter
    "VMBUS\\{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}",  // Synthetic SCSI controller
    "VMBUS\\{2f9bcc4a-0069-4af3-b76b-6fd0be528cda}",  // Synthetic fiber channel
    "VMBUS\\{2497f4de-e9fa-4204-80e4-4b75c46419c0}",  // Synthetic RDMA adapter
    "VMBUS\\{44c4f61d-4444-4400-9d52-802e27ede19f}",  // PCI Express pass-through
    "VMBUS\\{276aacf4-ac15-426c-98dd-7521ad3f01fe}",  // Synthetic video
    "VMBUS\\{fd149e91-82e0-4a7d-afa6-2a4166cbd7c0}",  // Synthetic DVD
    "VMBUS\\{58f75a6d-d949-4320-99e1-a2a2576d581c}",  // Synthetic fiber channel HBA
    "ROOT\\COMPOSITEBUS",
    "ROOT\\RDPBUS",
    "ROOT\\TERMINPT",
    NULL
};

static const char* HYPERV_DEVICE_NAMES[] = {
    "Microsoft Hyper-V",
    "Hyper-V",
    "Virtual Machine Bus",
    "VMBus",
    "Microsoft Virtual",
    "Synthetic",
    "VirtIO",
    NULL
};

DWORD CheckDevicesHyperV(PDETECTION_RESULT result) {
    HDEVINFO deviceInfoSet;
    SP_DEVINFO_DATA deviceInfoData;
    DWORD detected = 0;
    char deviceId[MAX_PATH];
    char deviceDesc[MAX_PATH];
    DWORD requiredSize;
    
    // Enumerate all devices
    deviceInfoSet = SetupDiGetClassDevsA(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        AppendToDetails(result, "Device: Failed to enumerate devices\n");
        return 0;
    }
    
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
        // Get device ID
        if (SetupDiGetDeviceInstanceIdA(deviceInfoSet, &deviceInfoData, deviceId, sizeof(deviceId), &requiredSize)) {
            // Check against known Hyper-V device IDs
            for (int j = 0; HYPERV_DEVICE_IDS[j] != NULL; j++) {
                if (strstr(deviceId, HYPERV_DEVICE_IDS[j])) {
                    detected |= HYPERV_DETECTED_DEVICES;
                    AppendToDetails(result, "Device: Found Hyper-V device ID: %s\n", deviceId);
                    break;
                }
            }
            
            // Get device description
            if (SetupDiGetDeviceRegistryPropertyA(deviceInfoSet, &deviceInfoData, SPDRP_DEVICEDESC, 
                                                 NULL, (PBYTE)deviceDesc, sizeof(deviceDesc), &requiredSize)) {
                // Check against known Hyper-V device names
                for (int j = 0; HYPERV_DEVICE_NAMES[j] != NULL; j++) {
                    if (strstr(deviceDesc, HYPERV_DEVICE_NAMES[j])) {
                        detected |= HYPERV_DETECTED_DEVICES;
                        AppendToDetails(result, "Device: Found Hyper-V device: %s (%s)\n", deviceDesc, deviceId);
                        break;
                    }
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    
    // Check for VMBus root device specifically
    HANDLE hDevice = CreateFileA("\\\\.\\vmbus", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        detected |= HYPERV_DETECTED_DEVICES;
        AppendToDetails(result, "Device: VMBus root device accessible\n");
        CloseHandle(hDevice);
    }
    
    return detected;
}