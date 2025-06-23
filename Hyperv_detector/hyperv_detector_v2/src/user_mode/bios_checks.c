#include "hyperv_detector.h"

typedef struct _SMBIOS_HEADER {
    BYTE Type;
    BYTE Length;
    WORD Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

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

static const char* HYPERV_BIOS_STRINGS[] = {
    "Microsoft Corporation",
    "Hyper-V",
    "Virtual Machine",
    "VRTUAL",
    "A M I",
    "American Megatrends",
    NULL
};

DWORD CheckBiosHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    char buffer[1024];
    DWORD bufferSize;
    DWORD type;
    
    // Check BIOS information from registry
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Check BIOS Vendor
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "BIOSVendor", NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            AppendToDetails(result, "BIOS: Vendor: %s\n", buffer);
            for (int i = 0; HYPERV_BIOS_STRINGS[i] != NULL; i++) {
                if (strstr(buffer, HYPERV_BIOS_STRINGS[i])) {
                    detected |= HYPERV_DETECTED_BIOS;
                    AppendToDetails(result, "BIOS: Hyper-V BIOS vendor detected\n");
                    break;
                }
            }
        }
        
        // Check BIOS Version
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "BIOSVersion", NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            AppendToDetails(result, "BIOS: Version: %s\n", buffer);
            for (int i = 0; HYPERV_BIOS_STRINGS[i] != NULL; i++) {
                if (strstr(buffer, HYPERV_BIOS_STRINGS[i])) {
                    detected |= HYPERV_DETECTED_BIOS;
                    AppendToDetails(result, "BIOS: Hyper-V BIOS version detected\n");
                    break;
                }
            }
        }
        
        // Check System Manufacturer
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            AppendToDetails(result, "BIOS: System Manufacturer: %s\n", buffer);
            if (strstr(buffer, "Microsoft Corporation")) {
                detected |= HYPERV_DETECTED_BIOS;
                AppendToDetails(result, "BIOS: Microsoft system manufacturer detected\n");
            }
        }
        
        // Check System Product Name
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemProductName", NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            AppendToDetails(result, "BIOS: System Product: %s\n", buffer);
            if (strstr(buffer, "Virtual Machine")) {
                detected |= HYPERV_DETECTED_BIOS;
                AppendToDetails(result, "BIOS: Virtual Machine product detected\n");
            }
        }
        
        RegCloseKey(hKey);
    }
    
    // Check ACPI tables for Hyper-V signatures
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        char keyName[256];
        while (RegEnumKeyA(hKey, index++, keyName, sizeof(keyName)) == ERROR_SUCCESS) {
            if (strstr(keyName, "VRTUAL") || strstr(keyName, "MSFT")) {
                detected |= HYPERV_DETECTED_BIOS;
                AppendToDetails(result, "ACPI: Found Hyper-V ACPI table: %s\n", keyName);
            }
        }
        RegCloseKey(hKey);
    }
    
    // Check for UEFI variables
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD secureBootEnabled = 0;
        bufferSize = sizeof(secureBootEnabled);
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, &type, (LPBYTE)&secureBootEnabled, &bufferSize) == ERROR_SUCCESS) {
            AppendToDetails(result, "UEFI: Secure Boot %s\n", secureBootEnabled ? "Enabled" : "Disabled");
        }
        RegCloseKey(hKey);
    }
    
    return detected;
}