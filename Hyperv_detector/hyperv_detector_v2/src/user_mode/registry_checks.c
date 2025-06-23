#include "hyperv_detector.h"

static const char* HYPERV_REGISTRY_KEYS[] = {
    "SYSTEM\\CurrentControlSet\\Services\\vmbus",
    "SYSTEM\\CurrentControlSet\\Services\\VMBusHID",
    "SYSTEM\\CurrentControlSet\\Services\\hyperkbd",
    "SYSTEM\\CurrentControlSet\\Services\\hypermouse",
    "SYSTEM\\CurrentControlSet\\Services\\hvsocket",
    "SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange",
    "SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
    "SYSTEM\\CurrentControlSet\\Services\\vmicshutdown",
    "SYSTEM\\CurrentControlSet\\Services\\vmictimesync",
    "SYSTEM\\CurrentControlSet\\Services\\vmicvss",
    "SYSTEM\\CurrentControlSet\\Services\\vmicrdv",
    "SYSTEM\\CurrentControlSet\\Services\\vmicguestinterface",
    "SYSTEM\\CurrentControlSet\\Services\\vmicvmsession",
    "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
    "SOFTWARE\\Microsoft\\VirtualMachine\\Guest\\Parameters",
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e97d-e325-11ce-bfc1-08002be10318}\\0000\\DriverDesc",
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e97d-e325-11ce-bfc1-08002be10318}\\0001\\DriverDesc",
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e97d-e325-11ce-bfc1-08002be10318}\\0002\\DriverDesc",
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e97d-e325-11ce-bfc1-08002be10318}\\0003\\DriverDesc",
    "SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
    NULL
};

static const char* HYPERV_REGISTRY_VALUES[] = {
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemBiosVersion",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemBiosDate",
    "HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion",
    "HARDWARE\\DESCRIPTION\\System\\SystemBiosDate",
    "HARDWARE\\DESCRIPTION\\System\\VideoBiosVersion",
    "SYSTEM\\CurrentControlSet\\Control\\SystemInformation\\SystemProductName",
    "SYSTEM\\CurrentControlSet\\Control\\SystemInformation\\SystemManufacturer",
    NULL
};

DWORD CheckRegistryHyperV(PDETECTION_RESULT result) {
    HKEY hKey;
    DWORD detected = 0;
    char buffer[1024];
    DWORD bufferSize;
    DWORD type;
    
    // Check for Hyper-V specific registry keys
    for (int i = 0; HYPERV_REGISTRY_KEYS[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HYPERV_REGISTRY_KEYS[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            detected |= HYPERV_DETECTED_REGISTRY;
            AppendToDetails(result, "Registry: Found key: HKLM\\%s\n", HYPERV_REGISTRY_KEYS[i]);
            RegCloseKey(hKey);
        }
    }
    
    // Check for Hyper-V specific registry values
    for (int i = 0; HYPERV_REGISTRY_VALUES[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HYPERV_REGISTRY_VALUES[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, NULL, NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                if (strstr(buffer, "Hyper-V") || strstr(buffer, "Microsoft Corporation") || 
                    strstr(buffer, "Virtual") || strstr(buffer, "VRTUAL")) {
                    detected |= HYPERV_DETECTED_REGISTRY;
                    AppendToDetails(result, "Registry: Found Hyper-V value in %s: %s\n", 
                                   HYPERV_REGISTRY_VALUES[i], buffer);
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    // Check for Windows Sandbox registry keys
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Vmmem", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        detected |= HYPERV_DETECTED_REGISTRY;
        AppendToDetails(result, "Registry: Found Windows Sandbox/WSL2 Vmmem service\n");
        RegCloseKey(hKey);
    }
    
    // Check for Docker Desktop registry keys
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Docker Inc.\\Docker Desktop", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        detected |= HYPERV_DETECTED_REGISTRY;
        AppendToDetails(result, "Registry: Found Docker Desktop\n");
        RegCloseKey(hKey);
    }
    
    return detected;
}