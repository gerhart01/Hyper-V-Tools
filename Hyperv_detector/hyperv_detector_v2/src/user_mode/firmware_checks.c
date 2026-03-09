/**
 * firmware_checks.c - Firmware and SMBIOS table based Hyper-V detection
 * 
 * Uses GetSystemFirmwareTable() to directly read SMBIOS and ACPI tables
 * for Hyper-V detection signatures.
 */

#include "hyperv_detector.h"

#pragma comment(lib, "kernel32.lib")

// Detection flag for firmware
#define HYPERV_DETECTED_FIRMWARE 0x00008000

// SMBIOS table signatures
#define RSMB_SIGNATURE 'BMSR'  // "RSMB" reversed
#define ACPI_SIGNATURE 'IPCA'  // "ACPI" reversed
#define FIRM_SIGNATURE 'MRIF'  // "FIRM" reversed

// SMBIOS structure types
#define SMBIOS_TYPE_BIOS        0
#define SMBIOS_TYPE_SYSTEM      1
#define SMBIOS_TYPE_BASEBOARD   2
#define SMBIOS_TYPE_CHASSIS     3
#define SMBIOS_TYPE_PROCESSOR   4
#define SMBIOS_TYPE_OEM         11
#define SMBIOS_TYPE_END         127

#pragma pack(push, 1)
typedef struct _RAW_SMBIOS_DATA {
    BYTE Used20CallingMethod;
    BYTE SMBIOSMajorVersion;
    BYTE SMBIOSMinorVersion;
    BYTE DmiRevision;
    DWORD Length;
    BYTE SMBIOSTableData[];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;

typedef struct _SMBIOS_HEADER {
    BYTE Type;
    BYTE Length;
    WORD Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOS_BIOS_INFO {
    SMBIOS_HEADER Header;
    BYTE Vendor;
    BYTE Version;
    WORD StartingAddressSegment;
    BYTE ReleaseDate;
    BYTE RomSize;
    ULONGLONG Characteristics;
    // Extended fields follow
} SMBIOS_BIOS_INFO, *PSMBIOS_BIOS_INFO;

typedef struct _SMBIOS_SYSTEM_INFO {
    SMBIOS_HEADER Header;
    BYTE Manufacturer;
    BYTE ProductName;
    BYTE Version;
    BYTE SerialNumber;
    BYTE UUID[16];
    BYTE WakeUpType;
    BYTE SKUNumber;
    BYTE Family;
} SMBIOS_SYSTEM_INFO, *PSMBIOS_SYSTEM_INFO;

typedef struct _SMBIOS_BASEBOARD_INFO {
    SMBIOS_HEADER Header;
    BYTE Manufacturer;
    BYTE Product;
    BYTE Version;
    BYTE SerialNumber;
    BYTE AssetTag;
    BYTE FeatureFlags;
    BYTE LocationInChassis;
    WORD ChassisHandle;
    BYTE BoardType;
} SMBIOS_BASEBOARD_INFO, *PSMBIOS_BASEBOARD_INFO;
#pragma pack(pop)

static const char* HYPERV_FIRMWARE_STRINGS[] = {
    "Microsoft Corporation",
    "Hyper-V",
    "Virtual Machine",
    "VRTUAL",
    "Msft Virtual",
    "Virtual HD",
    NULL
};

static const char* GetSMBIOSString(const BYTE* data, BYTE stringIndex) {
    if (stringIndex == 0) return "";
    
    const char* str = (const char*)data;
    for (BYTE i = 1; i < stringIndex; i++) {
        str += strlen(str) + 1;
    }
    return str;
}

static BOOL ContainsHyperVString(const char* str) {
    if (str == NULL || strlen(str) == 0) return FALSE;
    
    for (int i = 0; HYPERV_FIRMWARE_STRINGS[i] != NULL; i++) {
        if (strstr(str, HYPERV_FIRMWARE_STRINGS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static PSMBIOS_HEADER GetNextSMBIOSStructure(PSMBIOS_HEADER current) {
    const BYTE* data = (const BYTE*)current + current->Length;
    
    // Skip strings section (terminated by double NULL)
    while (!(data[0] == 0 && data[1] == 0)) {
        data++;
    }
    data += 2;  // Skip the double NULL
    
    return (PSMBIOS_HEADER)data;
}

DWORD CheckFirmwareHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    DWORD bufferSize;
    PRAW_SMBIOS_DATA smbiosData = NULL;
    PSMBIOS_HEADER header;
    DWORD offset;
    
    // Get SMBIOS table size
    bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (bufferSize == 0) {
        AppendToDetails(result, "Firmware: Failed to get SMBIOS table size\n");
        return 0;
    }
    
    smbiosData = (PRAW_SMBIOS_DATA)malloc(bufferSize);
    if (smbiosData == NULL) {
        AppendToDetails(result, "Firmware: Memory allocation failed\n");
        return 0;
    }
    
    // Get SMBIOS table
    if (GetSystemFirmwareTable('RSMB', 0, smbiosData, bufferSize) == 0) {
        AppendToDetails(result, "Firmware: Failed to get SMBIOS table\n");
        free(smbiosData);
        return 0;
    }
    
    AppendToDetails(result, "Firmware: SMBIOS Version %d.%d, Table Length: %d bytes\n",
                   smbiosData->SMBIOSMajorVersion, smbiosData->SMBIOSMinorVersion,
                   smbiosData->Length);
    
    // Parse SMBIOS structures
    header = (PSMBIOS_HEADER)smbiosData->SMBIOSTableData;
    offset = 0;
    
    while (offset < smbiosData->Length && header->Type != SMBIOS_TYPE_END) {
        const BYTE* stringBase = (const BYTE*)header + header->Length;
        
        switch (header->Type) {
            case SMBIOS_TYPE_BIOS: {
                PSMBIOS_BIOS_INFO biosInfo = (PSMBIOS_BIOS_INFO)header;
                const char* vendor = GetSMBIOSString(stringBase, biosInfo->Vendor);
                const char* version = GetSMBIOSString(stringBase, biosInfo->Version);
                
                AppendToDetails(result, "Firmware: BIOS Vendor: %s\n", vendor);
                AppendToDetails(result, "Firmware: BIOS Version: %s\n", version);
                
                if (ContainsHyperVString(vendor) || ContainsHyperVString(version)) {
                    detected |= HYPERV_DETECTED_FIRMWARE;
                    AppendToDetails(result, "Firmware: Hyper-V BIOS signature detected\n");
                }
                
                // Check for American Megatrends + Hyper-V (common combination)
                if (strstr(vendor, "American Megatrends") && strstr(version, "090008")) {
                    detected |= HYPERV_DETECTED_FIRMWARE;
                    AppendToDetails(result, "Firmware: Hyper-V AMI BIOS detected\n");
                }
                break;
            }
            
            case SMBIOS_TYPE_SYSTEM: {
                PSMBIOS_SYSTEM_INFO sysInfo = (PSMBIOS_SYSTEM_INFO)header;
                const char* manufacturer = GetSMBIOSString(stringBase, sysInfo->Manufacturer);
                const char* productName = GetSMBIOSString(stringBase, sysInfo->ProductName);
                const char* version = GetSMBIOSString(stringBase, sysInfo->Version);
                const char* serialNumber = GetSMBIOSString(stringBase, sysInfo->SerialNumber);
                
                AppendToDetails(result, "Firmware: System Manufacturer: %s\n", manufacturer);
                AppendToDetails(result, "Firmware: System Product: %s\n", productName);
                AppendToDetails(result, "Firmware: System Version: %s\n", version);
                
                if (ContainsHyperVString(manufacturer) || 
                    ContainsHyperVString(productName) ||
                    ContainsHyperVString(version)) {
                    detected |= HYPERV_DETECTED_FIRMWARE;
                    AppendToDetails(result, "Firmware: Hyper-V system info detected\n");
                }
                
                // Check UUID for Hyper-V pattern
                if (sysInfo->UUID[0] != 0 || sysInfo->UUID[1] != 0) {
                    AppendToDetails(result, "Firmware: System UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-"
                                   "%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                                   sysInfo->UUID[0], sysInfo->UUID[1], sysInfo->UUID[2], sysInfo->UUID[3],
                                   sysInfo->UUID[4], sysInfo->UUID[5], sysInfo->UUID[6], sysInfo->UUID[7],
                                   sysInfo->UUID[8], sysInfo->UUID[9], sysInfo->UUID[10], sysInfo->UUID[11],
                                   sysInfo->UUID[12], sysInfo->UUID[13], sysInfo->UUID[14], sysInfo->UUID[15]);
                }
                break;
            }
            
            case SMBIOS_TYPE_BASEBOARD: {
                PSMBIOS_BASEBOARD_INFO bbInfo = (PSMBIOS_BASEBOARD_INFO)header;
                const char* manufacturer = GetSMBIOSString(stringBase, bbInfo->Manufacturer);
                const char* product = GetSMBIOSString(stringBase, bbInfo->Product);
                
                AppendToDetails(result, "Firmware: Baseboard Manufacturer: %s\n", manufacturer);
                AppendToDetails(result, "Firmware: Baseboard Product: %s\n", product);
                
                if (ContainsHyperVString(manufacturer) || ContainsHyperVString(product)) {
                    detected |= HYPERV_DETECTED_FIRMWARE;
                    AppendToDetails(result, "Firmware: Hyper-V baseboard detected\n");
                }
                break;
            }
            
            case SMBIOS_TYPE_OEM: {
                // OEM strings can contain virtualization info
                const char* oemStr = (const char*)stringBase;
                int strIdx = 1;
                while (*oemStr) {
                    if (ContainsHyperVString(oemStr)) {
                        detected |= HYPERV_DETECTED_FIRMWARE;
                        AppendToDetails(result, "Firmware: Hyper-V OEM string detected: %s\n", oemStr);
                    }
                    oemStr += strlen(oemStr) + 1;
                    strIdx++;
                }
                break;
            }
        }
        
        // Move to next structure
        header = GetNextSMBIOSStructure(header);
        offset = (DWORD)((BYTE*)header - smbiosData->SMBIOSTableData);
    }
    
    free(smbiosData);
    
    // Check ACPI tables
    DWORD acpiSize = GetSystemFirmwareTable('ACPI', 0, NULL, 0);
    if (acpiSize > 0) {
        // Enumerate ACPI table signatures
        DWORD tableCount = acpiSize / sizeof(DWORD);
        DWORD* tableSignatures = (DWORD*)malloc(acpiSize);
        
        if (tableSignatures && GetSystemFirmwareTable('ACPI', 0, tableSignatures, acpiSize)) {
            AppendToDetails(result, "Firmware: Found %d ACPI table signatures\n", tableCount);
            
            for (DWORD i = 0; i < tableCount; i++) {
                char sig[5] = {0};
                memcpy(sig, &tableSignatures[i], 4);
                
                // Check for Hyper-V specific ACPI tables
                if (strcmp(sig, "WAET") == 0 ||  // Windows ACPI Emulated Table
                    strcmp(sig, "VRTL") == 0 ||  // Virtual
                    strcmp(sig, "MSFT") == 0) {  // Microsoft
                    detected |= HYPERV_DETECTED_FIRMWARE;
                    AppendToDetails(result, "Firmware: Found Hyper-V ACPI table: %s\n", sig);
                }
            }
        }
        free(tableSignatures);
    }
    
    return detected;
}

// Additional check for firmware variables (UEFI only)
DWORD CheckUEFIVariablesHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Check if running in UEFI mode
    FIRMWARE_TYPE firmwareType;
    if (GetFirmwareType(&firmwareType)) {
        const char* fwTypeName = "Unknown";
        switch (firmwareType) {
            case FirmwareTypeBios: fwTypeName = "BIOS"; break;
            case FirmwareTypeUefi: fwTypeName = "UEFI"; break;
            case FirmwareTypeMax: fwTypeName = "Max"; break;
        }
        AppendToDetails(result, "Firmware: Running in %s mode\n", fwTypeName);
        
        if (firmwareType == FirmwareTypeUefi) {
            // In UEFI mode, check for Hyper-V specific variables
            // Note: Requires SeSystemEnvironmentPrivilege
            HANDLE hToken;
            
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                TOKEN_PRIVILEGES tp;
                LUID luid;
                
                if (LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &luid)) {
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    
                    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
                }
                CloseHandle(hToken);
            }
            
            // Try to enumerate firmware variables
            // This may fail without admin privileges
            AppendToDetails(result, "Firmware: UEFI variable enumeration requires elevation\n");
        }
    }
    
    return detected;
}
