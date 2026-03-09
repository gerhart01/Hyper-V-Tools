/**
 * storage_checks.c - Storage and Disk based Hyper-V detection
 * 
 * Detects Hyper-V through virtual disk characteristics, SCSI identifiers,
 * and storage controller properties.
 */

#define _CRT_SECURE_NO_WARNINGS

#include "hyperv_detector.h"
#include <setupapi.h>
#include <devguid.h>
#include <winioctl.h>
#include <ntddscsi.h>

#pragma comment(lib, "setupapi.lib")

// Detection flag for storage
#define HYPERV_DETECTED_STORAGE 0x00400000

// Custom SCSI inquiry data structure (renamed to avoid ntddscsi.h conflict)
#pragma pack(push, 1)
typedef struct _MY_SCSI_INQUIRY_DATA {
    UCHAR DeviceType : 5;
    UCHAR DeviceTypeQualifier : 3;
    UCHAR DeviceTypeModifier : 7;
    UCHAR RemovableMedia : 1;
    UCHAR ANSIVersion : 3;
    UCHAR ECMAVersion : 3;
    UCHAR ISOVersion : 2;
    UCHAR ResponseDataFormat : 4;
    UCHAR Reserved1 : 2;
    UCHAR TrmIOP : 1;
    UCHAR AENC : 1;
    UCHAR AdditionalLength;
    UCHAR Reserved2[2];
    UCHAR SoftReset : 1;
    UCHAR CommandQueue : 1;
    UCHAR Reserved3 : 1;
    UCHAR LinkedCommands : 1;
    UCHAR Synchronous : 1;
    UCHAR Wide16Bit : 1;
    UCHAR Wide32Bit : 1;
    UCHAR RelativeAddressing : 1;
    UCHAR VendorId[8];
    UCHAR ProductId[16];
    UCHAR ProductRevision[4];
} MY_SCSI_INQUIRY_DATA, *PMY_SCSI_INQUIRY_DATA;
#pragma pack(pop)

// Known Hyper-V disk identifiers
static const char* HYPERV_DISK_VENDORS[] = {
    "Msft",
    "MSFT",
    "Microsoft",
    "Virtual",
    "VRTUAL",
    "Hyper-V",
    NULL
};

static const char* HYPERV_DISK_PRODUCTS[] = {
    "Virtual HD",
    "Virtual Disk",
    "Virtual CD",
    "Virtual DVD",
    "Virtual Machine",
    NULL
};

static BOOL ContainsHyperVDiskString(const char* str) {
    if (str == NULL || strlen(str) == 0) return FALSE;
    
    for (int i = 0; HYPERV_DISK_VENDORS[i] != NULL; i++) {
        if (strstr(str, HYPERV_DISK_VENDORS[i])) {
            return TRUE;
        }
    }
    
    for (int i = 0; HYPERV_DISK_PRODUCTS[i] != NULL; i++) {
        if (strstr(str, HYPERV_DISK_PRODUCTS[i])) {
            return TRUE;
        }
    }
    
    return FALSE;
}

static DWORD CheckPhysicalDrives(PDETECTION_RESULT result) {
    DWORD detected = 0;
    char drivePath[64];
    HANDLE hDrive;
    
    // Check physical drives 0-15
    for (int i = 0; i < 16; i++) {
        snprintf(drivePath, sizeof(drivePath), "\\\\.\\PhysicalDrive%d", i);
        
        hDrive = CreateFileA(drivePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);
        
        if (hDrive != INVALID_HANDLE_VALUE) {
            // Get storage device descriptor
            STORAGE_PROPERTY_QUERY query = {0};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;
            
            BYTE buffer[1024] = {0};
            DWORD bytesReturned = 0;
            
            if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                               &query, sizeof(query), buffer, sizeof(buffer),
                               &bytesReturned, NULL)) {
                
                STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
                
                // Extract vendor and product strings
                char vendorId[64] = {0};
                char productId[64] = {0};
                char serialNumber[64] = {0};
                
                if (desc->VendorIdOffset > 0 && desc->VendorIdOffset < bytesReturned) {
                    strncpy(vendorId, (char*)(buffer + desc->VendorIdOffset), sizeof(vendorId) - 1);
                }
                
                if (desc->ProductIdOffset > 0 && desc->ProductIdOffset < bytesReturned) {
                    strncpy(productId, (char*)(buffer + desc->ProductIdOffset), sizeof(productId) - 1);
                }
                
                if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < bytesReturned) {
                    strncpy(serialNumber, (char*)(buffer + desc->SerialNumberOffset), sizeof(serialNumber) - 1);
                }
                
                // Trim whitespace
                char* p;
                p = vendorId + strlen(vendorId) - 1;
                while (p > vendorId && (*p == ' ' || *p == '\0')) *p-- = '\0';
                p = productId + strlen(productId) - 1;
                while (p > productId && (*p == ' ' || *p == '\0')) *p-- = '\0';
                
                AppendToDetails(result, "Storage: PhysicalDrive%d - Vendor: '%s', Product: '%s'\n",
                               i, vendorId, productId);
                
                // Check for Hyper-V signatures
                if (ContainsHyperVDiskString(vendorId) || ContainsHyperVDiskString(productId)) {
                    detected |= HYPERV_DETECTED_STORAGE;
                    AppendToDetails(result, "Storage: Hyper-V virtual disk detected on PhysicalDrive%d\n", i);
                }
                
                // Check bus type
                const char* busTypeStr = "Unknown";
                switch (desc->BusType) {
                    case BusTypeScsi: busTypeStr = "SCSI"; break;
                    case BusTypeAtapi: busTypeStr = "ATAPI"; break;
                    case BusTypeAta: busTypeStr = "ATA"; break;
                    case BusType1394: busTypeStr = "1394"; break;
                    case BusTypeSsa: busTypeStr = "SSA"; break;
                    case BusTypeFibre: busTypeStr = "Fibre"; break;
                    case BusTypeUsb: busTypeStr = "USB"; break;
                    case BusTypeRAID: busTypeStr = "RAID"; break;
                    case BusTypeiScsi: busTypeStr = "iSCSI"; break;
                    case BusTypeSas: busTypeStr = "SAS"; break;
                    case BusTypeSata: busTypeStr = "SATA"; break;
                    case BusTypeSd: busTypeStr = "SD"; break;
                    case BusTypeMmc: busTypeStr = "MMC"; break;
                    case BusTypeVirtual: busTypeStr = "Virtual"; 
                        detected |= HYPERV_DETECTED_STORAGE;
                        AppendToDetails(result, "Storage: Virtual bus type detected\n");
                        break;
                    case BusTypeFileBackedVirtual: busTypeStr = "FileBackedVirtual";
                        detected |= HYPERV_DETECTED_STORAGE;
                        AppendToDetails(result, "Storage: File-backed virtual bus detected\n");
                        break;
                    case BusTypeSpaces: busTypeStr = "Spaces"; break;
                    case BusTypeNvme: busTypeStr = "NVMe"; break;
                    case BusTypeSCM: busTypeStr = "SCM"; break;
                    case BusTypeUfs: busTypeStr = "UFS"; break;
                }
                
                AppendToDetails(result, "Storage: PhysicalDrive%d - Bus Type: %s\n", i, busTypeStr);
            }
            
            // Get SCSI address
            SCSI_ADDRESS scsiAddress = {0};
            scsiAddress.Length = sizeof(SCSI_ADDRESS);
            
            if (DeviceIoControl(hDrive, IOCTL_SCSI_GET_ADDRESS,
                               NULL, 0, &scsiAddress, sizeof(scsiAddress),
                               &bytesReturned, NULL)) {
                AppendToDetails(result, "Storage: PhysicalDrive%d - SCSI Port:%d Path:%d Target:%d Lun:%d\n",
                               i, scsiAddress.PortNumber, scsiAddress.PathId,
                               scsiAddress.TargetId, scsiAddress.Lun);
            }
            
            CloseHandle(hDrive);
        }
    }
    
    return detected;
}

static DWORD CheckSCSIControllers(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfoData;
    char deviceId[MAX_PATH];
    char deviceDesc[MAX_PATH];
    DWORD requiredSize;
    
    // Enumerate SCSI controllers
    hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_SCSIADAPTER, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        // Get device instance ID
        if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, deviceId, sizeof(deviceId), &requiredSize)) {
            // Get device description
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_DEVICEDESC,
                                                 NULL, (PBYTE)deviceDesc, sizeof(deviceDesc), &requiredSize)) {
                
                AppendToDetails(result, "Storage: SCSI Controller: %s\n", deviceDesc);
                
                // Check for Hyper-V SCSI controller
                if (strstr(deviceId, "VMBUS") || strstr(deviceDesc, "Hyper-V") ||
                    strstr(deviceDesc, "Virtual") || strstr(deviceDesc, "Synthetic")) {
                    detected |= HYPERV_DETECTED_STORAGE;
                    AppendToDetails(result, "Storage: Hyper-V SCSI controller detected: %s\n", deviceDesc);
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return detected;
}

static DWORD CheckStorageControllers(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfoData;
    char deviceId[MAX_PATH];
    char deviceDesc[MAX_PATH];
    char hardwareIds[1024];
    DWORD requiredSize;
    
    // Enumerate all storage controllers
    static const GUID GUID_DEVCLASS_HIDSTORAGE = 
        {0x6bdd1fc5, 0x810f, 0x11d0, {0xbe, 0xc7, 0x08, 0x00, 0x2b, 0xe2, 0x09, 0x2f}};
    
    hDevInfo = SetupDiGetClassDevsA(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, deviceId, sizeof(deviceId), &requiredSize)) {
            // Only check storage-related devices
            if (strstr(deviceId, "STORAGE") || strstr(deviceId, "DISK") || 
                strstr(deviceId, "SCSI") || strstr(deviceId, "VMBUS")) {
                
                // Get hardware IDs
                if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_HARDWAREID,
                                                     NULL, (PBYTE)hardwareIds, sizeof(hardwareIds), &requiredSize)) {
                    
                    // Check each hardware ID in the multi-string
                    char* hwId = hardwareIds;
                    while (*hwId) {
                        if (strstr(hwId, "Hyper") || strstr(hwId, "VRTUAL") ||
                            strstr(hwId, "Msft") || strstr(hwId, "Virtual")) {
                            detected |= HYPERV_DETECTED_STORAGE;
                            
                            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_DEVICEDESC,
                                                                 NULL, (PBYTE)deviceDesc, sizeof(deviceDesc), &requiredSize)) {
                                AppendToDetails(result, "Storage: Found Hyper-V storage device: %s (HwID: %s)\n",
                                               deviceDesc, hwId);
                            }
                        }
                        hwId += strlen(hwId) + 1;
                    }
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return detected;
}

static DWORD CheckVHDFiles(PDETECTION_RESULT result) {
    DWORD detected = 0;
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    
    // Common VHD/VHDX locations
    const char* vhdPaths[] = {
        "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual hard disks\\*.vhdx",
        "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual hard disks\\*.vhd",
        "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\*.vhdx",
        "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\*.vhd",
        NULL
    };
    
    for (int i = 0; vhdPaths[i] != NULL; i++) {
        hFind = FindFirstFileA(vhdPaths[i], &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                detected |= HYPERV_DETECTED_STORAGE;
                AppendToDetails(result, "Storage: Found VHD file: %s (Size: %llu bytes)\n",
                               findData.cFileName,
                               ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow);
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    return detected;
}

DWORD CheckStorageHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "Storage: Checking storage devices...\n");
    
    detected |= CheckPhysicalDrives(result);
    detected |= CheckSCSIControllers(result);
    detected |= CheckStorageControllers(result);
    detected |= CheckVHDFiles(result);
    
    return detected;
}
