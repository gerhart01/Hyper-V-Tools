/**
 * env_checks.c - Environment Variable Detection for Hyper-V
 * 
 * Checks environment variables and system information that may indicate
 * Hyper-V virtualization:
 * - Processor identification strings
 * - Computer name patterns
 * - User profile paths
 * - System drive characteristics
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HYPERV_DETECTED_ENV
#define HYPERV_DETECTED_ENV 0x00800000
#endif

typedef struct _DETECTION_RESULT {
    DWORD DetectionFlags;
    char Details[4096];
    DWORD ProcessId;
    char ProcessName[256];
} DETECTION_RESULT, *PDETECTION_RESULT;

extern void AppendToDetails(PDETECTION_RESULT result, const char* format, ...);

// Hyper-V related environment variable patterns
static const char* HYPERV_ENV_PATTERNS[] = {
    "HYPERV",
    "VIRTUAL",
    "VMBUS",
    "VMSVC",
    "SANDBOX",
    "CONTAINER",
    NULL
};

// Suspicious computer name patterns
static const char* VM_COMPUTERNAME_PATTERNS[] = {
    "DESKTOP-",      // Default Windows 10/11 pattern
    "WIN-",          // Default Windows Server pattern
    "SANDBOX",
    "CONTAINER",
    "HYPERV",
    "VM-",
    "VIRTUAL",
    NULL
};

/**
 * Check environment variables for virtualization indicators
 */
static DWORD CheckEnvironmentVariables(PDETECTION_RESULT result) {
    DWORD detected = 0;
    LPWCH envStringsW = GetEnvironmentStringsW();
    
    if (envStringsW == NULL) {
        return 0;
    }
    
    LPWCH currentW = envStringsW;
    while (*currentW) {
        // Convert to ANSI for pattern matching
        char envVarA[1024] = {0};
        WideCharToMultiByte(CP_ACP, 0, currentW, -1, envVarA, sizeof(envVarA) - 1, NULL, NULL);
        
        // Check for Hyper-V related patterns in env vars
        for (int i = 0; HYPERV_ENV_PATTERNS[i] != NULL; i++) {
            if (strstr(envVarA, HYPERV_ENV_PATTERNS[i])) {
                detected |= HYPERV_DETECTED_ENV;
                AppendToDetails(result, "ENV: Found suspicious env var: %.100s...\n", envVarA);
                break;
            }
        }
        
        // Move to next env string
        currentW += wcslen(currentW) + 1;
    }
    
    FreeEnvironmentStringsW(envStringsW);
    return detected;
}

/**
 * Check specific environment variables
 */
static DWORD CheckSpecificEnvVars(PDETECTION_RESULT result) {
    DWORD detected = 0;
    char buffer[4096];
    
    // Check PROCESSOR_IDENTIFIER
    if (GetEnvironmentVariableA("PROCESSOR_IDENTIFIER", buffer, sizeof(buffer))) {
        AppendToDetails(result, "ENV: PROCESSOR_IDENTIFIER: %s\n", buffer);
        
        // Hyper-V VMs often show "Virtual" in processor info
        if (strstr(buffer, "Virtual") || strstr(buffer, "QEMU") || 
            strstr(buffer, "AMD EPYC") || strstr(buffer, "Intel Xeon")) {
            // Note: Xeon/EPYC alone don't indicate VM, but combined with other factors
            detected |= HYPERV_DETECTED_ENV;
            AppendToDetails(result, "ENV: Processor identifier suggests virtualization\n");
        }
    }
    
    // Check NUMBER_OF_PROCESSORS
    if (GetEnvironmentVariableA("NUMBER_OF_PROCESSORS", buffer, sizeof(buffer))) {
        int numProcs = atoi(buffer);
        AppendToDetails(result, "ENV: NUMBER_OF_PROCESSORS: %d\n", numProcs);
        
        // VMs often have unusual processor counts (1, 2, 4, 8 are common)
        // Not a strong indicator, but useful as supporting evidence
    }
    
    // Check COMPUTERNAME
    if (GetEnvironmentVariableA("COMPUTERNAME", buffer, sizeof(buffer))) {
        AppendToDetails(result, "ENV: COMPUTERNAME: %s\n", buffer);
        
        for (int i = 0; VM_COMPUTERNAME_PATTERNS[i] != NULL; i++) {
            if (strstr(buffer, VM_COMPUTERNAME_PATTERNS[i])) {
                // Not a strong indicator but worth noting
                AppendToDetails(result, "ENV: Computer name matches VM pattern: %s\n", 
                               VM_COMPUTERNAME_PATTERNS[i]);
                break;
            }
        }
    }
    
    // Check USERNAME - VMs often use default usernames
    if (GetEnvironmentVariableA("USERNAME", buffer, sizeof(buffer))) {
        AppendToDetails(result, "ENV: USERNAME: %s\n", buffer);
        
        if (_stricmp(buffer, "WDAGUtilityAccount") == 0) {
            detected |= HYPERV_DETECTED_ENV;
            AppendToDetails(result, "ENV: Windows Sandbox utility account detected\n");
        }
        if (_stricmp(buffer, "ContainerUser") == 0 || 
            _stricmp(buffer, "ContainerAdministrator") == 0) {
            detected |= HYPERV_DETECTED_ENV;
            AppendToDetails(result, "ENV: Container user account detected\n");
        }
    }
    
    // Check for Windows Sandbox specific env vars
    if (GetEnvironmentVariableA("LOCALAPPDATA", buffer, sizeof(buffer))) {
        if (strstr(buffer, "Sandbox") || strstr(buffer, "Container")) {
            detected |= HYPERV_DETECTED_ENV;
            AppendToDetails(result, "ENV: Sandbox/Container path detected in LOCALAPPDATA\n");
        }
    }
    
    return detected;
}

/**
 * Check system information via GetSystemInfo
 */
static DWORD CheckSystemInfo(PDETECTION_RESULT result) {
    DWORD detected = 0;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    AppendToDetails(result, "ENV: Processor architecture: %d\n", sysInfo.wProcessorArchitecture);
    AppendToDetails(result, "ENV: Number of processors: %d\n", sysInfo.dwNumberOfProcessors);
    AppendToDetails(result, "ENV: Page size: %d\n", sysInfo.dwPageSize);
    AppendToDetails(result, "ENV: Processor type: %d\n", sysInfo.dwProcessorType);
    AppendToDetails(result, "ENV: Processor revision: %04X\n", sysInfo.wProcessorRevision);
    
    // Hyper-V VMs typically have specific characteristics
    // Unusual page sizes or processor configurations could indicate VM
    if (sysInfo.dwPageSize != 4096) {
        AppendToDetails(result, "ENV: Non-standard page size (possible VM indicator)\n");
    }
    
    return detected;
}

/**
 * Check native system info for more details
 */
static DWORD CheckNativeSystemInfo(PDETECTION_RESULT result) {
    DWORD detected = 0;
    SYSTEM_INFO sysInfo;
    
    // Get native system info (for WOW64 processes)
    typedef void (WINAPI *GetNativeSystemInfo_t)(LPSYSTEM_INFO);
    GetNativeSystemInfo_t pGetNativeSystemInfo = 
        (GetNativeSystemInfo_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");
    
    if (pGetNativeSystemInfo) {
        pGetNativeSystemInfo(&sysInfo);
        AppendToDetails(result, "ENV: Native processor architecture: %d\n", 
                       sysInfo.wProcessorArchitecture);
    }
    
    return detected;
}

/**
 * Check global memory status
 */
static DWORD CheckMemoryStatus(PDETECTION_RESULT result) {
    DWORD detected = 0;
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    
    if (GlobalMemoryStatusEx(&memStatus)) {
        ULONGLONG totalMB = memStatus.ullTotalPhys / (1024 * 1024);
        ULONGLONG availMB = memStatus.ullAvailPhys / (1024 * 1024);
        
        AppendToDetails(result, "ENV: Total physical memory: %llu MB\n", totalMB);
        AppendToDetails(result, "ENV: Available physical memory: %llu MB\n", availMB);
        AppendToDetails(result, "ENV: Memory load: %d%%\n", memStatus.dwMemoryLoad);
        
        // VMs often have "round" memory sizes
        if (totalMB == 1024 || totalMB == 2048 || totalMB == 4096 || 
            totalMB == 8192 || totalMB == 16384 || totalMB == 32768) {
            AppendToDetails(result, "ENV: Memory size is exact power of 2 (common in VMs)\n");
        }
        
        // Check for suspiciously small memory (sandbox/container)
        if (totalMB < 2048) {
            AppendToDetails(result, "ENV: Low memory configuration (possible sandbox)\n");
        }
    }
    
    return detected;
}

/**
 * Check logical drive information
 */
static DWORD CheckDriveInfo(PDETECTION_RESULT result) {
    DWORD detected = 0;
    DWORD drives = GetLogicalDrives();
    char rootPath[4] = "C:\\";
    
    AppendToDetails(result, "ENV: Logical drives bitmask: 0x%08X\n", drives);
    
    int driveCount = 0;
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            driveCount++;
            rootPath[0] = 'A' + i;
            
            UINT driveType = GetDriveTypeA(rootPath);
            char volumeName[256] = {0};
            char fsName[256] = {0};
            DWORD serialNumber = 0;
            DWORD maxComponentLen = 0;
            DWORD fsFlags = 0;
            
            if (GetVolumeInformationA(rootPath, volumeName, sizeof(volumeName),
                                      &serialNumber, &maxComponentLen, &fsFlags,
                                      fsName, sizeof(fsName))) {
                
                // Check for Hyper-V related volume names
                if (strstr(volumeName, "Virtual") || strstr(volumeName, "Sandbox") ||
                    strstr(volumeName, "Container")) {
                    detected |= HYPERV_DETECTED_ENV;
                    AppendToDetails(result, "ENV: Suspicious volume name: %s on %s\n", 
                                   volumeName, rootPath);
                }
                
                // Check for specific serial numbers (some VMs use predictable serials)
                if (serialNumber == 0 || serialNumber == 0x12345678) {
                    AppendToDetails(result, "ENV: Suspicious volume serial on %s: 0x%08X\n", 
                                   rootPath, serialNumber);
                }
            }
        }
    }
    
    // VMs often have minimal drive configurations
    if (driveCount <= 2) {
        AppendToDetails(result, "ENV: Minimal drive configuration (%d drives)\n", driveCount);
    }
    
    return detected;
}

/**
 * Check GetVersionEx for OS information
 */
static DWORD CheckOSVersion(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    RtlGetVersion_t pRtlGetVersion = 
        (RtlGetVersion_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    
    if (pRtlGetVersion) {
        RTL_OSVERSIONINFOW osInfo = {0};
        osInfo.dwOSVersionInfoSize = sizeof(osInfo);
        
        if (pRtlGetVersion(&osInfo) == 0) {
            AppendToDetails(result, "ENV: OS Version: %d.%d.%d\n", 
                           osInfo.dwMajorVersion, 
                           osInfo.dwMinorVersion, 
                           osInfo.dwBuildNumber);
        }
    }
    
    return detected;
}

/**
 * Check for firmware environment variables (UEFI)
 */
static DWORD CheckFirmwareEnvironment(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    typedef DWORD (WINAPI *GetFirmwareEnvironmentVariableA_t)(
        LPCSTR lpName, LPCSTR lpGuid, PVOID pBuffer, DWORD nSize);
    
    GetFirmwareEnvironmentVariableA_t pGetFirmwareEnv = 
        (GetFirmwareEnvironmentVariableA_t)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "GetFirmwareEnvironmentVariableA");
    
    if (pGetFirmwareEnv) {
        char buffer[256];
        
        // Try to read SecureBoot variable
        // GUID: {8BE4DF61-93CA-11d2-AA0D-00E098032B8C} - EFI Global Variable
        DWORD size = pGetFirmwareEnv("SecureBoot", 
                                     "{8BE4DF61-93CA-11d2-AA0D-00E098032B8C}",
                                     buffer, sizeof(buffer));
        
        if (size > 0) {
            AppendToDetails(result, "ENV: UEFI SecureBoot variable accessible\n");
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_INVALID_FUNCTION) {
                AppendToDetails(result, "ENV: Legacy BIOS mode (no UEFI)\n");
            } else if (error == ERROR_NOACCESS) {
                AppendToDetails(result, "ENV: UEFI present but requires elevation\n");
            }
        }
    }
    
    return detected;
}

/**
 * Check for IsProcessorFeaturePresent
 */
static DWORD CheckProcessorFeatures(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    struct {
        DWORD feature;
        const char* name;
    } features[] = {
        {PF_FLOATING_POINT_PRECISION_ERRATA, "FP Precision Errata"},
        {PF_FLOATING_POINT_EMULATED, "FP Emulated"},
        {PF_COMPARE_EXCHANGE_DOUBLE, "CMPXCHG8B"},
        {PF_MMX_INSTRUCTIONS_AVAILABLE, "MMX"},
        {PF_XMMI_INSTRUCTIONS_AVAILABLE, "SSE"},
        {PF_3DNOW_INSTRUCTIONS_AVAILABLE, "3DNow"},
        {PF_RDTSC_INSTRUCTION_AVAILABLE, "RDTSC"},
        {PF_XMMI64_INSTRUCTIONS_AVAILABLE, "SSE2"},
        {PF_SSE3_INSTRUCTIONS_AVAILABLE, "SSE3"},
        {PF_NX_ENABLED, "NX/DEP"},
        {PF_COMPARE_EXCHANGE128, "CMPXCHG16B"},
        {PF_VIRT_FIRMWARE_ENABLED, "Virtualization Firmware"},
        {PF_SECOND_LEVEL_ADDRESS_TRANSLATION, "SLAT"},
        {0, NULL}
    };
    
    AppendToDetails(result, "ENV: Processor features:\n");
    
    for (int i = 0; features[i].name != NULL; i++) {
        if (IsProcessorFeaturePresent(features[i].feature)) {
            AppendToDetails(result, "ENV:   - %s: Present\n", features[i].name);
            
            // Virtualization firmware bit is interesting
            if (features[i].feature == PF_VIRT_FIRMWARE_ENABLED) {
                AppendToDetails(result, "ENV: Virtualization firmware enabled (hypervisor may be present)\n");
            }
        }
    }
    
    return detected;
}

/**
 * Main environment check function
 */
DWORD CheckEnvHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "\n=== Environment Variable Checks ===\n");
    
    detected |= CheckEnvironmentVariables(result);
    detected |= CheckSpecificEnvVars(result);
    detected |= CheckSystemInfo(result);
    detected |= CheckNativeSystemInfo(result);
    detected |= CheckMemoryStatus(result);
    detected |= CheckDriveInfo(result);
    detected |= CheckOSVersion(result);
    detected |= CheckFirmwareEnvironment(result);
    detected |= CheckProcessorFeatures(result);
    
    return detected;
}
