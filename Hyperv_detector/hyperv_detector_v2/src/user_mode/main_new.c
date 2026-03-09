/**
 * main.c - Comprehensive Hyper-V Detection Tool
 * 
 * Extended version with additional detection methods:
 * - WMI checks
 * - MAC address analysis
 * - Firmware/SMBIOS inspection
 * - Timing-based detection
 * - Performance counters
 * - Event logs
 * - Security features (VBS, HVCI)
 * - Descriptor tables (IDT/GDT)
 * - Windows features
 * - Storage analysis
 */

#include "hyperv_detector.h"
#include <stdio.h>
#include <time.h>

// Version info
#define VERSION_MAJOR 2
#define VERSION_MINOR 0
#define VERSION_PATCH 0

void AppendToDetails(PDETECTION_RESULT result, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    int currentLen = (int)strlen(result->Details);
    int remaining = (int)(sizeof(result->Details) - currentLen - 1);
    
    if (remaining > 0) {
        vsnprintf(result->Details + currentLen, remaining, format, args);
    }
    
    va_end(args);
}

BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin;
}

const char* GetDetectionFlagName(DWORD flag) {
    switch (flag) {
        case HYPERV_DETECTED_CPUID:       return "CPUID";
        case HYPERV_DETECTED_REGISTRY:    return "Registry";
        case HYPERV_DETECTED_FILES:       return "Files";
        case HYPERV_DETECTED_SERVICES:    return "Services";
        case HYPERV_DETECTED_DEVICES:     return "Devices";
        case HYPERV_DETECTED_BIOS:        return "BIOS";
        case HYPERV_DETECTED_PROCESSES:   return "Processes";
        case HYPERV_DETECTED_HYPERCALLS:  return "Hypercalls";
        case HYPERV_DETECTED_OBJECTS:     return "Windows Objects";
        case HYPERV_DETECTED_NESTED:      return "Nested Virtualization";
        case HYPERV_DETECTED_SANDBOX:     return "Windows Sandbox";
        case HYPERV_DETECTED_DOCKER:      return "Docker";
        case HYPERV_DETECTED_REMOVED:     return "Removed Hyper-V";
        case HYPERV_DETECTED_WMI:         return "WMI";
        case HYPERV_DETECTED_MAC:         return "MAC Address";
        case HYPERV_DETECTED_FIRMWARE:    return "Firmware/SMBIOS";
        case HYPERV_DETECTED_TIMING:      return "Timing Analysis";
        case HYPERV_DETECTED_PERFCOUNTER: return "Performance Counters";
        case HYPERV_DETECTED_EVENTLOG:    return "Event Logs";
        case HYPERV_DETECTED_SECURITY:    return "Security Features";
        case HYPERV_DETECTED_DESCRIPTOR:  return "Descriptor Tables";
        case HYPERV_DETECTED_FEATURES:    return "Windows Features";
        case HYPERV_DETECTED_STORAGE:     return "Storage";
        default:                          return "Unknown";
    }
}

void PrintDetectionSummary(PDETECTION_RESULT result) {
    printf("\n");
    printf("================================================================================\n");
    printf("                         HYPER-V DETECTION SUMMARY                              \n");
    printf("================================================================================\n");
    
    if (result->DetectionFlags == HYPERV_DETECTED_NONE) {
        printf("\n  [OK] No Hyper-V virtualization detected.\n");
    } else {
        printf("\n  [!] Hyper-V virtualization DETECTED!\n");
        printf("\n  Detection Flags: 0x%08X\n", result->DetectionFlags);
        printf("\n  Triggered Detection Methods:\n");
        printf("  ---------------------------\n");
        
        DWORD flags[] = {
            HYPERV_DETECTED_CPUID,
            HYPERV_DETECTED_REGISTRY,
            HYPERV_DETECTED_FILES,
            HYPERV_DETECTED_SERVICES,
            HYPERV_DETECTED_DEVICES,
            HYPERV_DETECTED_BIOS,
            HYPERV_DETECTED_PROCESSES,
            HYPERV_DETECTED_HYPERCALLS,
            HYPERV_DETECTED_OBJECTS,
            HYPERV_DETECTED_NESTED,
            HYPERV_DETECTED_SANDBOX,
            HYPERV_DETECTED_DOCKER,
            HYPERV_DETECTED_REMOVED,
            HYPERV_DETECTED_WMI,
            HYPERV_DETECTED_MAC,
            HYPERV_DETECTED_FIRMWARE,
            HYPERV_DETECTED_TIMING,
            HYPERV_DETECTED_PERFCOUNTER,
            HYPERV_DETECTED_EVENTLOG,
            HYPERV_DETECTED_SECURITY,
            HYPERV_DETECTED_DESCRIPTOR,
            HYPERV_DETECTED_FEATURES,
            HYPERV_DETECTED_STORAGE
        };
        
        int detectedCount = 0;
        for (int i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
            if (result->DetectionFlags & flags[i]) {
                printf("    [X] %s\n", GetDetectionFlagName(flags[i]));
                detectedCount++;
            }
        }
        
        printf("\n  Total detection methods triggered: %d\n", detectedCount);
    }
    
    printf("\n================================================================================\n");
}

// Implementation of original checks (stubs if implemented in separate files)
DWORD CheckWindowsObjectsHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HANDLE hObject;
    
    // Check for Hyper-V specific mutexes
    const char* hypervMutexes[] = {
        "Global\\HyperVMutex",
        "Global\\VmmsApiMutex",
        "Global\\VmComputeMutex",
        "Global\\WindowsSandboxMutex",
        NULL
    };
    
    for (int i = 0; hypervMutexes[i] != NULL; i++) {
        hObject = OpenMutexA(SYNCHRONIZE, FALSE, hypervMutexes[i]);
        if (hObject != NULL) {
            detected |= HYPERV_DETECTED_OBJECTS;
            AppendToDetails(result, "Object: Found mutex: %s\n", hypervMutexes[i]);
            CloseHandle(hObject);
        }
    }
    
    // Check for Hyper-V specific events
    const char* hypervEvents[] = {
        "Global\\HyperVEvent",
        "Global\\VmmsEvent",
        "Global\\VmComputeEvent",
        NULL
    };
    
    for (int i = 0; hypervEvents[i] != NULL; i++) {
        hObject = OpenEventA(SYNCHRONIZE, FALSE, hypervEvents[i]);
        if (hObject != NULL) {
            detected |= HYPERV_DETECTED_OBJECTS;
            AppendToDetails(result, "Object: Found event: %s\n", hypervEvents[i]);
            CloseHandle(hObject);
        }
    }
    
    // Check for Hyper-V named pipes
    const char* hypervPipes[] = {
        "\\\\.\\pipe\\vmms",
        "\\\\.\\pipe\\vmcompute",
        "\\\\.\\pipe\\WindowsSandbox",
        NULL
    };
    
    for (int i = 0; hypervPipes[i] != NULL; i++) {
        hObject = CreateFileA(hypervPipes[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hObject != INVALID_HANDLE_VALUE) {
            detected |= HYPERV_DETECTED_OBJECTS;
            AppendToDetails(result, "Object: Found named pipe: %s\n", hypervPipes[i]);
            CloseHandle(hObject);
        }
    }
    
    return detected;
}

DWORD CheckNestedHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    DWORD value;
    DWORD size = sizeof(value);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value) {
                detected |= HYPERV_DETECTED_NESTED;
                AppendToDetails(result, "Nested: Virtualization-based security enabled\n");
            }
        }
        RegCloseKey(hKey);
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "NestedVirtualization", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value) {
                detected |= HYPERV_DETECTED_NESTED;
                AppendToDetails(result, "Nested: Nested virtualization support detected\n");
            }
        }
        RegCloseKey(hKey);
    }
    
    return detected;
}

DWORD CheckWindowsSandbox(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    DWORD attributes = GetFileAttributesA("C:\\Windows\\System32\\WindowsSandbox.exe");
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        detected |= HYPERV_DETECTED_SANDBOX;
        AppendToDetails(result, "Sandbox: Windows Sandbox executable found\n");
    }
    
    return detected;
}

DWORD CheckDockerHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    char buffer[1024];
    DWORD bufferSize;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Docker Inc.\\Docker Desktop", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "Backend", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            if (strstr(buffer, "hyper-v") || strstr(buffer, "hyperv")) {
                detected |= HYPERV_DETECTED_DOCKER;
                AppendToDetails(result, "Docker: Docker Desktop using Hyper-V backend\n");
            }
        }
        RegCloseKey(hKey);
    }
    
    return detected;
}

DWORD CheckRemovedHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    const char* remnantKeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft-Hyper-V",
        "SYSTEM\\CurrentControlSet\\Services\\vmms_removed",
        NULL
    };
    
    for (int i = 0; remnantKeys[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, remnantKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            detected |= HYPERV_DETECTED_REMOVED;
            AppendToDetails(result, "Removed: Found Hyper-V remnant key: %s\n", remnantKeys[i]);
            RegCloseKey(hKey);
        }
    }
    
    return detected;
}

DWORD RunDetection(PDETECTION_RESULT result, DETECTION_LEVEL level) {
    DWORD totalFlags = 0;
    
    // Fast checks (always run)
    printf("[*] Running CPUID checks...\n");
    totalFlags |= CheckCpuidHyperV(result);
    
    printf("[*] Running registry checks...\n");
    totalFlags |= CheckRegistryHyperV(result);
    
    printf("[*] Running file system checks...\n");
    totalFlags |= CheckFilesHyperV(result);
    
    if (level >= DETECTION_LEVEL_NORMAL) {
        printf("[*] Running service checks...\n");
        totalFlags |= CheckServicesHyperV(result);
        
        printf("[*] Running device checks...\n");
        totalFlags |= CheckDevicesHyperV(result);
        
        printf("[*] Running BIOS checks...\n");
        totalFlags |= CheckBiosHyperV(result);
        
        printf("[*] Running process checks...\n");
        totalFlags |= CheckProcessesHyperV(result);
        
        printf("[*] Running Windows object checks...\n");
        totalFlags |= CheckWindowsObjectsHyperV(result);
    }
    
    if (level >= DETECTION_LEVEL_THOROUGH) {
        printf("[*] Running nested virtualization checks...\n");
        totalFlags |= CheckNestedHyperV(result);
        
        printf("[*] Running Windows Sandbox checks...\n");
        totalFlags |= CheckWindowsSandbox(result);
        
        printf("[*] Running Docker checks...\n");
        totalFlags |= CheckDockerHyperV(result);
        
        printf("[*] Running removed Hyper-V checks...\n");
        totalFlags |= CheckRemovedHyperV(result);
        
        // New detection methods
        printf("[*] Running WMI checks...\n");
        totalFlags |= CheckWMIHyperV(result);
        
        printf("[*] Running MAC address checks...\n");
        totalFlags |= CheckMACAddressHyperV(result);
        
        printf("[*] Running firmware/SMBIOS checks...\n");
        totalFlags |= CheckFirmwareHyperV(result);
        
        printf("[*] Running performance counter checks...\n");
        totalFlags |= CheckPerfCountersHyperV(result);
        totalFlags |= CheckETWProvidersHyperV(result);
        
        printf("[*] Running event log checks...\n");
        totalFlags |= CheckEventLogsHyperV(result);
        
        printf("[*] Running security features checks...\n");
        totalFlags |= CheckSecurityFeaturesHyperV(result);
        
        printf("[*] Running Windows features checks...\n");
        totalFlags |= CheckWindowsFeaturesHyperV(result);
        
        printf("[*] Running storage checks...\n");
        totalFlags |= CheckStorageHyperV(result);
    }
    
    if (level >= DETECTION_LEVEL_FULL) {
        printf("[*] Running timing analysis...\n");
        totalFlags |= CheckTimingHyperV(result);
        
        printf("[*] Running descriptor table checks...\n");
        totalFlags |= CheckDescriptorTablesHyperV(result);
    }
    
    result->DetectionFlags = totalFlags;
    return totalFlags;
}

void PrintUsage(const char* programName) {
    printf("\nUsage: %s [options]\n\n", programName);
    printf("Options:\n");
    printf("  --fast       Run only fast detection methods (CPUID, registry, files)\n");
    printf("  --normal     Run standard detection methods (default)\n");
    printf("  --thorough   Run all non-invasive detection methods\n");
    printf("  --full       Run all detection methods including timing analysis\n");
    printf("  --json       Output results in JSON format\n");
    printf("  --quiet      Suppress progress output\n");
    printf("  --details    Show detailed detection output\n");
    printf("  --help       Show this help message\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    DETECTION_RESULT result = {0};
    DETECTION_LEVEL level = DETECTION_LEVEL_NORMAL;
    BOOL jsonOutput = FALSE;
    BOOL quietMode = FALSE;
    BOOL showDetails = FALSE;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fast") == 0) {
            level = DETECTION_LEVEL_FAST;
        } else if (strcmp(argv[i], "--normal") == 0) {
            level = DETECTION_LEVEL_NORMAL;
        } else if (strcmp(argv[i], "--thorough") == 0) {
            level = DETECTION_LEVEL_THOROUGH;
        } else if (strcmp(argv[i], "--full") == 0) {
            level = DETECTION_LEVEL_FULL;
        } else if (strcmp(argv[i], "--json") == 0) {
            jsonOutput = TRUE;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quietMode = TRUE;
        } else if (strcmp(argv[i], "--details") == 0) {
            showDetails = TRUE;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    if (!quietMode && !jsonOutput) {
        printf("\n");
        printf("================================================================================\n");
        printf("        Hyper-V Virtual Machine Detector v%d.%d.%d (Extended Edition)          \n",
               VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
        printf("================================================================================\n\n");
        
        // Get current time
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timeStr[64];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tm_info);
        printf("Scan started: %s\n\n", timeStr);
        
        if (!IsRunningAsAdmin()) {
            printf("[!] Warning: Not running as administrator. Some checks may fail.\n\n");
        }
        
        const char* levelStr = "Normal";
        switch (level) {
            case DETECTION_LEVEL_FAST: levelStr = "Fast"; break;
            case DETECTION_LEVEL_NORMAL: levelStr = "Normal"; break;
            case DETECTION_LEVEL_THOROUGH: levelStr = "Thorough"; break;
            case DETECTION_LEVEL_FULL: levelStr = "Full"; break;
        }
        printf("Detection level: %s\n\n", levelStr);
    }
    
    result.ProcessId = GetCurrentProcessId();
    GetModuleFileNameA(NULL, result.ProcessName, sizeof(result.ProcessName));
    
    // Run detection
    DWORD totalFlags = RunDetection(&result, level);
    
    // Output results
    if (jsonOutput) {
        // JSON output
        printf("{\n");
        printf("  \"version\": \"%d.%d.%d\",\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
        printf("  \"detected\": %s,\n", (totalFlags != 0) ? "true" : "false");
        printf("  \"flags\": \"0x%08X\",\n", totalFlags);
        printf("  \"flags_decimal\": %u,\n", totalFlags);
        printf("  \"process_id\": %d,\n", result.ProcessId);
        printf("  \"process_name\": \"%s\",\n", result.ProcessName);
        printf("  \"detection_methods\": [\n");
        
        DWORD flags[] = {
            HYPERV_DETECTED_CPUID, HYPERV_DETECTED_REGISTRY, HYPERV_DETECTED_FILES,
            HYPERV_DETECTED_SERVICES, HYPERV_DETECTED_DEVICES, HYPERV_DETECTED_BIOS,
            HYPERV_DETECTED_PROCESSES, HYPERV_DETECTED_HYPERCALLS, HYPERV_DETECTED_OBJECTS,
            HYPERV_DETECTED_NESTED, HYPERV_DETECTED_SANDBOX, HYPERV_DETECTED_DOCKER,
            HYPERV_DETECTED_REMOVED, HYPERV_DETECTED_WMI, HYPERV_DETECTED_MAC,
            HYPERV_DETECTED_FIRMWARE, HYPERV_DETECTED_TIMING, HYPERV_DETECTED_PERFCOUNTER,
            HYPERV_DETECTED_EVENTLOG, HYPERV_DETECTED_SECURITY, HYPERV_DETECTED_DESCRIPTOR,
            HYPERV_DETECTED_FEATURES, HYPERV_DETECTED_STORAGE
        };
        
        BOOL first = TRUE;
        for (int i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
            if (totalFlags & flags[i]) {
                if (!first) printf(",\n");
                printf("    \"%s\"", GetDetectionFlagName(flags[i]));
                first = FALSE;
            }
        }
        printf("\n  ]\n");
        printf("}\n");
    } else {
        PrintDetectionSummary(&result);
        
        if (showDetails && strlen(result.Details) > 0) {
            printf("\n=== DETAILED OUTPUT ===\n\n");
            printf("%s\n", result.Details);
        }
        
        // Try kernel driver
        HANDLE hDriver = CreateFileA("\\\\.\\HyperVDetector", GENERIC_READ | GENERIC_WRITE, 
                                    0, NULL, OPEN_EXISTING, 0, NULL);
        if (hDriver != INVALID_HANDLE_VALUE) {
            printf("\n[*] Kernel driver available - running kernel mode checks...\n");
            
            HYPERCALL_INPUT hypercallInput = {0};
            HYPERCALL_OUTPUT hypercallOutput = {0};
            DWORD bytesReturned;
            
            hypercallInput.HypercallCode = HVCALL_GET_PARTITION_ID;
            if (DeviceIoControl(hDriver, IOCTL_HYPERV_CHECK_HYPERCALL, 
                               &hypercallInput, sizeof(hypercallInput),
                               &hypercallOutput, sizeof(hypercallOutput), 
                               &bytesReturned, NULL)) {
                if (hypercallOutput.Result == 0) {
                    printf("[+] Kernel: Hypercall successful - Partition ID: %d\n", 
                           hypercallOutput.OutputValue);
                    totalFlags |= HYPERV_DETECTED_HYPERCALLS;
                }
            }
            
            CloseHandle(hDriver);
        }
    }
    
    return (totalFlags != 0) ? 1 : 0;
}
