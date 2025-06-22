#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <winternl.h>
#include <tlhelp32.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

// Hyper-V specific constants
#define HYPERV_CPUID_VENDOR_SIGNATURE_EAX   0x31235356  // "1#SV"
#define HYPERV_CPUID_VENDOR_SIGNATURE_EBX   0x4D566548  // "MveH"
#define HYPERV_CPUID_VENDOR_SIGNATURE_ECX   0x65746E49  // "etnI"
#define HYPERV_CPUID_VENDOR_SIGNATURE_EDX   0x00000000

#define HYPERV_CPUID_INTERFACE              0x40000001
#define HYPERV_CPUID_VERSION                0x40000002
#define HYPERV_CPUID_FEATURES               0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO       0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS       0x40000005

// Hyper-V hypercall MSRs
#define HV_X64_MSR_GUEST_OS_ID              0x40000000
#define HV_X64_MSR_HYPERCALL                0x40000001
#define HV_X64_MSR_VP_INDEX                 0x40000002
#define HV_X64_MSR_RESET                    0x40000003
#define HV_X64_MSR_VP_RUNTIME               0x40000010

// Function prototypes
BOOL DetectFiles(void);
BOOL DetectRegistryKeys(void);
BOOL DetectServices(void);
BOOL DetectDrivers(void);
BOOL DetectCPUInstructions(void);
BOOL DetectProcesses(void);
BOOL DetectVMBusDevices(void);
BOOL DetectBIOSUEFI(void);
BOOL DetectACPI(void);
BOOL DetectHypervisorVendor(void);
BOOL DetectMutexes(void);
BOOL DetectHypercalls(void);
BOOL DetectEnlightenments(void);
BOOL DetectRingBuffers(void);
BOOL DetectHyperVFeatures(void);

// Utility functions
BOOL CheckFileExists(const char* filepath);
BOOL CheckRegistryKey(HKEY hKey, const char* subKey);
BOOL CheckService(const char* serviceName);
BOOL CheckProcess(const char* processName);
BOOL IsElevated(void);

int main() {
    printf("=== Hyper-V Virtual Machine Detector ===\n\n");
    
    if (!IsElevated()) {
        printf("Warning: Running without administrator privileges. Some checks may fail.\n\n");
    }
    
    int detectionCount = 0;
    
    printf("[1] Checking specific files...\n");
    if (DetectFiles()) {
        printf("    [+] Hyper-V files detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V files found\n");
    }
    
    printf("[2] Checking registry keys...\n");
    if (DetectRegistryKeys()) {
        printf("    [+] Hyper-V registry keys detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V registry keys found\n");
    }
    
    printf("[3] Checking services...\n");
    if (DetectServices()) {
        printf("    [+] Hyper-V services detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V services found\n");
    }
    
    printf("[4] Checking drivers...\n");
    if (DetectDrivers()) {
        printf("    [+] Hyper-V drivers detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V drivers found\n");
    }
    
    printf("[5] Checking CPU instructions (CPUID)...\n");
    if (DetectCPUInstructions()) {
        printf("    [+] Hyper-V CPUID signature detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V CPUID signature found\n");
    }
    
    printf("[6] Checking processes...\n");
    if (DetectProcesses()) {
        printf("    [+] Hyper-V processes detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V processes found\n");
    }
    
    printf("[7] Checking VMBus devices...\n");
    if (DetectVMBusDevices()) {
        printf("    [+] VMBus devices detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No VMBus devices found\n");
    }
    
    printf("[8] Checking BIOS/UEFI information...\n");
    if (DetectBIOSUEFI()) {
        printf("    [+] Hyper-V BIOS/UEFI signatures detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V BIOS/UEFI signatures found\n");
    }
    
    printf("[9] Checking ACPI tables...\n");
    if (DetectACPI()) {
        printf("    [+] Hyper-V ACPI signatures detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V ACPI signatures found\n");
    }
    
    printf("[10] Checking hypervisor vendor...\n");
    if (DetectHypervisorVendor()) {
        printf("    [+] Microsoft hypervisor vendor detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Microsoft hypervisor vendor found\n");
    }
    
    printf("[11] Checking Windows internal mutexes...\n");
    if (DetectMutexes()) {
        printf("    [+] Hyper-V mutexes detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V mutexes found\n");
    }
    
    printf("[12] Checking hypercalls...\n");
    if (DetectHypercalls()) {
        printf("    [+] Hyper-V hypercalls detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V hypercalls found\n");
    }
    
    printf("[13] Checking enlightenments...\n");
    if (DetectEnlightenments()) {
        printf("    [+] Hyper-V enlightenments detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V enlightenments found\n");
    }
    
    printf("[14] Checking ring buffers...\n");
    if (DetectRingBuffers()) {
        printf("    [+] Hyper-V ring buffers detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V ring buffers found\n");
    }
    
    printf("[15] Checking Hyper-V specific features...\n");
    if (DetectHyperVFeatures()) {
        printf("    [+] Hyper-V specific features detected!\n");
        detectionCount++;
    } else {
        printf("    [-] No Hyper-V specific features found\n");
    }
    
    printf("\n=== Detection Summary ===\n");
    printf("Detection methods triggered: %d/15\n", detectionCount);
    
    if (detectionCount > 0) {
        printf("RESULT: Running inside Hyper-V virtual machine\n");
        printf("Confidence level: %s\n", 
               detectionCount >= 10 ? "Very High" :
               detectionCount >= 5 ? "High" :
               detectionCount >= 3 ? "Medium" : "Low");
    } else {
        printf("RESULT: Not running inside Hyper-V virtual machine\n");
    }
    
    return 0;
}

BOOL CheckFileExists(const char* filepath) {
    DWORD attributes = GetFileAttributesA(filepath);
    return (attributes != INVALID_FILE_ATTRIBUTES);
}

BOOL DetectFiles() {
    const char* hypervFiles[] = {
        "C:\\Windows\\System32\\vmicheartbeat.dll",
        "C:\\Windows\\System32\\vmickvpexchange.dll",
        "C:\\Windows\\System32\\vmicshutdown.dll",
        "C:\\Windows\\System32\\vmicsvc.exe",
        "C:\\Windows\\System32\\vmictimesync.dll",
        "C:\\Windows\\System32\\vmicvss.dll",
        "C:\\Windows\\System32\\drivers\\vmbus.sys",
        "C:\\Windows\\System32\\drivers\\storvsc.sys",
        "C:\\Windows\\System32\\drivers\\netvsc.sys",
        "C:\\Windows\\System32\\drivers\\vmstorfl.sys",
        "C:\\Windows\\System32\\drivers\\hypervideo.sys",
        "C:\\Windows\\System32\\drivers\\hyperv.sys",
        NULL
    };
    
    for (int i = 0; hypervFiles[i] != NULL; i++) {
        if (CheckFileExists(hypervFiles[i])) {
            printf("    Found: %s\n", hypervFiles[i]);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL CheckRegistryKey(HKEY hKey, const char* subKey) {
    HKEY hResult;
    LONG result = RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &hResult);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hResult);
        return TRUE;
    }
    return FALSE;
}

BOOL DetectRegistryKeys() {
    const char* hypervKeys[] = {
        "SYSTEM\\CurrentControlSet\\Services\\vmbus",
        "SYSTEM\\CurrentControlSet\\Services\\VMBusHID",
        "SYSTEM\\CurrentControlSet\\Services\\hypervideo",
        "SYSTEM\\CurrentControlSet\\Services\\hyperv",
        "SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
        "SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange",
        "SYSTEM\\CurrentControlSet\\Services\\vmicshutdown",
        "SYSTEM\\CurrentControlSet\\Services\\vmictimesync",
        "SYSTEM\\CurrentControlSet\\Services\\vmicvss",
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e97d-e325-11ce-bfc1-08002be10318}\\0000",
        NULL
    };
    
    for (int i = 0; hypervKeys[i] != NULL; i++) {
        if (CheckRegistryKey(HKEY_LOCAL_MACHINE, hypervKeys[i])) {
            printf("    Found: HKLM\\%s\n", hypervKeys[i]);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL CheckService(const char* serviceName) {
    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager == NULL) return FALSE;
    
    SC_HANDLE service = OpenServiceA(scManager, serviceName, SERVICE_QUERY_STATUS);
    BOOL found = (service != NULL);
    
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    
    return found;
}

BOOL DetectServices() {
    const char* hypervServices[] = {
        "vmbus",
        "VMBusHID",
        "vmicheartbeat",
        "vmickvpexchange",
        "vmicshutdown",
        "vmictimesync",
        "vmicvss",
        "hypervideo",
        "storvsc",
        "netvsc",
        NULL
    };
    
    for (int i = 0; hypervServices[i] != NULL; i++) {
        if (CheckService(hypervServices[i])) {
            printf("    Found service: %s\n", hypervServices[i]);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL DetectDrivers() {
    HDEVINFO deviceInfoSet;
    SP_DEVINFO_DATA deviceInfoData;
    DWORD i;
    char deviceID[256];
    
    deviceInfoSet = SetupDiGetClassDevsA(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
        if (SetupDiGetDeviceInstanceIdA(deviceInfoSet, &deviceInfoData, deviceID, sizeof(deviceID), NULL)) {
            if (strstr(deviceID, "VMBUS") || 
                strstr(deviceID, "VEN_1414") ||  // Microsoft vendor ID
                strstr(deviceID, "SCSI\\DISK&VEN_MSFT") ||
                strstr(deviceID, "ROOT\\VMBUS")) {
                printf("    Found device: %s\n", deviceID);
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
                return TRUE;
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return FALSE;
}

BOOL DetectCPUInstructions() {
    int cpuid_info[4];
    
    // Check for hypervisor presence bit
    __cpuid(cpuid_info, 1);
    if (!(cpuid_info[2] & (1 << 31))) {
        return FALSE; // No hypervisor present
    }
    
    // Check hypervisor vendor signature
    __cpuid(cpuid_info, 0x40000000);
    
    // Check if it's Microsoft Hyper-V
    if (cpuid_info[1] == 0x7263694D && // "Micr"
        cpuid_info[2] == 0x666F736F && // "osof"
        cpuid_info[3] == 0x76482074) { // "t Hv"
        printf("    Detected Microsoft Hyper-V hypervisor signature\n");
        
        // Get Hyper-V interface signature
        __cpuid(cpuid_info, 0x40000001);
        printf("    Hyper-V interface signature: 0x%08x\n", cpuid_info[0]);
        
        // Get Hyper-V version info
        __cpuid(cpuid_info, 0x40000002);
        printf("    Hyper-V version: %d.%d Build %d\n", 
               (cpuid_info[1] >> 16) & 0xFFFF,
               cpuid_info[1] & 0xFFFF,
               cpuid_info[0]);
        
        return TRUE;
    }
    
    return FALSE;
}

BOOL CheckProcess(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    BOOL found = FALSE;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                found = TRUE;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

BOOL DetectProcesses() {
    const char* hypervProcesses[] = {
        "vmms.exe",
        "vmwp.exe",
        "vmcompute.exe",
        "vmconnect.exe",
        "vmicsvc.exe",
        NULL
    };
    
    for (int i = 0; hypervProcesses[i] != NULL; i++) {
        if (CheckProcess(hypervProcesses[i])) {
            printf("    Found process: %s\n", hypervProcesses[i]);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL DetectVMBusDevices() {
    GUID vmbus_guid = {0xc376c1c3, 0xd073, 0x4c04, {0x9f, 0xf5, 0xbd, 0x65, 0xd7, 0x85, 0x44, 0x47}};
    
    HDEVINFO deviceInfoSet = SetupDiGetClassDevsA(&vmbus_guid, NULL, NULL, DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    BOOL found = SetupDiEnumDeviceInfo(deviceInfoSet, 0, &deviceInfoData);
    if (found) {
        printf("    VMBus device class found\n");
    }
    
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return found;
}

BOOL DetectBIOSUEFI() {
    HKEY hKey;
    char data[256];
    DWORD dataSize = sizeof(data);
    
    // Check BIOS version
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        if (RegQueryValueExA(hKey, "BIOSVersion", NULL, NULL, (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
            if (strstr(data, "Hyper-V") || strstr(data, "Microsoft") || strstr(data, "VRTUAL")) {
                printf("    BIOS Version: %s\n", data);
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        
        dataSize = sizeof(data);
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
            if (strstr(data, "Microsoft")) {
                printf("    System Manufacturer: %s\n", data);
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

BOOL DetectACPI() {
    // Check for Hyper-V specific ACPI tables via registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      "HARDWARE\\ACPI\\DSDT\\VRTUAL__", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("    Found Hyper-V ACPI DSDT table\n");
        RegCloseKey(hKey);
        return TRUE;
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      "HARDWARE\\ACPI\\FADT\\VRTUAL__", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("    Found Hyper-V ACPI FADT table\n");
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

BOOL DetectHypervisorVendor() {
    int cpuid_info[4];
    char vendor[13] = {0};
    
    __cpuid(cpuid_info, 0x40000000);
    
    // Extract vendor string
    memcpy(vendor, &cpuid_info[1], 4);
    memcpy(vendor + 4, &cpuid_info[2], 4);
    memcpy(vendor + 8, &cpuid_info[3], 4);
    
    printf("    Hypervisor vendor: %s\n", vendor);
    
    return (strcmp(vendor, "Microsoft Hv") == 0);
}

BOOL DetectMutexes() {
    const char* hypervMutexes[] = {
        "Global\\HyperVServiceMutex",
        "Global\\VMBusMutex",
        "Global\\HyperVVmMutex",
        NULL
    };
    
    for (int i = 0; hypervMutexes[i] != NULL; i++) {
        HANDLE hMutex = OpenMutexA(SYNCHRONIZE, FALSE, hypervMutexes[i]);
        if (hMutex != NULL) {
            printf("    Found mutex: %s\n", hypervMutexes[i]);
            CloseHandle(hMutex);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL DetectHypercalls() {
    // Check if hypercall MSRs are accessible (requires ring 0)
    // This is a simplified check - real implementation would need kernel driver
    
    int cpuid_info[4];
    __cpuid(cpuid_info, 0x40000003); // Hyper-V features
    
    if (cpuid_info[0] & 0x01) { // VP Runtime MSR available
        printf("    Hyper-V hypercall interface available\n");
        return TRUE;
    }
    
    return FALSE;
}

BOOL DetectEnlightenments() {
    int cpuid_info[4];
    __cpuid(cpuid_info, 0x40000004); // Hyper-V enlightenment info
    
    BOOL found = FALSE;
    
    if (cpuid_info[0] & 0x01) {
        printf("    APIC access enlightenment available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x02) {
        printf("    System reset enlightenment available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x04) {
        printf("    Relaxed timing enlightenment available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x08) {
        printf("    DMA remapping enlightenment available\n");
        found = TRUE;
    }
    
    return found;
}

BOOL DetectRingBuffers() {
    // Check for VMBus channel ring buffer structures
    // This would typically require analyzing VMBus channel structures
    
    // Simplified check: look for VMBus registry entries that indicate ring buffers
    if (CheckRegistryKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmbus\\Parameters")) {
        printf("    VMBus parameters found (ring buffers likely present)\n");
        return TRUE;
    }
    
    return FALSE;
}

BOOL DetectHyperVFeatures() {
    int cpuid_info[4];
    BOOL found = FALSE;
    
    // Check Hyper-V specific features
    __cpuid(cpuid_info, 0x40000003);
    
    if (cpuid_info[0] & 0x01) {
        printf("    VP Runtime MSR available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x02) {
        printf("    Partition Reference Counter available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x04) {
        printf("    Basic SynIC MSRs available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x08) {
        printf("    Synthetic Timer MSRs available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x10) {
        printf("    APIC access MSRs available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x20) {
        printf("    Hypercall MSRs available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x40) {
        printf("    VP Index MSR available\n");
        found = TRUE;
    }
    
    if (cpuid_info[0] & 0x80) {
        printf("    Virtual System Reset MSR available\n");
        found = TRUE;
    }
    
    return found;
}

BOOL IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    return isElevated;
}