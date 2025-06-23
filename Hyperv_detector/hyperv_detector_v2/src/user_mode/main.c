#include "hyperv_detector.h"
#include <stdio.h>

void AppendToDetails(PDETECTION_RESULT result, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    int currentLen = strlen(result->Details);
    int remaining = sizeof(result->Details) - currentLen - 1;
    
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
    
    // Check for nested virtualization capability
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value) {
                detected |= HYPERV_DETECTED_NESTED;
                AppendToDetails(result, "Nested: Virtualization-based security enabled\n");
            }
        }
        RegCloseKey(hKey);
    }
    
    // Check for Hyper-V running with nested support
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
    
    // Check for Windows Sandbox capability
    DWORD attributes = GetFileAttributesA("C:\\Windows\\System32\\WindowsSandbox.exe");
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        detected |= HYPERV_DETECTED_SANDBOX;
        AppendToDetails(result, "Sandbox: Windows Sandbox executable found\n");
    }
    
    // Check for Windows Sandbox container
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (hProcess != NULL) {
        BOOL isInContainer = FALSE;
        typedef BOOL (WINAPI *IsProcessInJob_t)(HANDLE, HANDLE, PBOOL);
        IsProcessInJob_t pIsProcessInJob = (IsProcessInJob_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsProcessInJob");
        
        if (pIsProcessInJob && pIsProcessInJob(hProcess, NULL, &isInContainer) && isInContainer) {
            detected |= HYPERV_DETECTED_SANDBOX;
            AppendToDetails(result, "Sandbox: Process running in container/sandbox\n");
        }
        CloseHandle(hProcess);
    }
    
    return detected;
}

DWORD CheckDockerHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    char buffer[1024];
    DWORD bufferSize;
    
    // Check for Docker Desktop with Hyper-V backend
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
    
    // Check for Docker processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (strstr(pe32.szExeFile, "docker") || strstr(pe32.szExeFile, "containerR")) {
                    detected |= HYPERV_DETECTED_DOCKER;
                    AppendToDetails(result, "Docker: Found Docker process: %s\n", pe32.szExeFile);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    return detected;
}

DWORD CheckRemovedHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check for remnants of uninstalled Hyper-V
    const char* remnantKeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft-Hyper-V",
        "SYSTEM\\CurrentControlSet\\Services\\vmms_removed",
        "SOFTWARE\\Classes\\Installer\\Products\\Microsoft-Hyper-V",
        NULL
    };
    
    for (int i = 0; remnantKeys[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, remnantKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            detected |= HYPERV_DETECTED_REMOVED;
            AppendToDetails(result, "Removed: Found Hyper-V remnant key: %s\n", remnantKeys[i]);
            RegCloseKey(hKey);
        }
    }
    
    // Check for orphaned Hyper-V files
    const char* orphanedFiles[] = {
        "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\InitialStore.xml",
        "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual hard disks",
        NULL
    };
    
    for (int i = 0; orphanedFiles[i] != NULL; i++) {
        DWORD attributes = GetFileAttributesA(orphanedFiles[i]);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            detected |= HYPERV_DETECTED_REMOVED;
            AppendToDetails(result, "Removed: Found orphaned Hyper-V file/directory: %s\n", orphanedFiles[i]);
        }
    }
    
    return detected;
}

int main(int argc, char* argv[]) {
    DETECTION_RESULT result = {0};
    DWORD totalFlags = 0;
    
    printf("Hyper-V Virtual Machine Detector v1.0\n");
    printf("=====================================\n\n");
    
    if (!IsRunningAsAdmin()) {
        printf("Warning: Not running as administrator. Some checks may fail.\n\n");
    }
    
    result.ProcessId = GetCurrentProcessId();
    GetModuleFileNameA(NULL, result.ProcessName, sizeof(result.ProcessName));
    
    // Perform all detection checks
    printf("Performing CPUID checks...\n");
    totalFlags |= CheckCpuidHyperV(&result);
    
    printf("Performing registry checks...\n");
    totalFlags |= CheckRegistryHyperV(&result);
    
    printf("Performing file system checks...\n");
    totalFlags |= CheckFilesHyperV(&result);
    
    printf("Performing service checks...\n");
    totalFlags |= CheckServicesHyperV(&result);
    
    printf("Performing device checks...\n");
    totalFlags |= CheckDevicesHyperV(&result);
    
    printf("Performing BIOS/UEFI checks...\n");
    totalFlags |= CheckBiosHyperV(&result);
    
    printf("Performing process checks...\n");
    totalFlags |= CheckProcessesHyperV(&result);
    
    printf("Performing Windows object checks...\n");
    totalFlags |= CheckWindowsObjectsHyperV(&result);
    
    printf("Performing nested virtualization checks...\n");
    totalFlags |= CheckNestedHyperV(&result);
    
    printf("Performing Windows Sandbox checks...\n");
    totalFlags |= CheckWindowsSandbox(&result);
    
    printf("Performing Docker checks...\n");
    totalFlags |= CheckDockerHyperV(&result);
    
    printf("Performing removed Hyper-V checks...\n");
    totalFlags |= CheckRemovedHyperV(&result);
    
    result.DetectionFlags = totalFlags;
    
    // Display results
    printf("\n=== DETECTION RESULTS ===\n");
    if (totalFlags == HYPERV_DETECTED_NONE) {
        printf("No Hyper-V virtualization detected.\n");
    } else {
        printf("Hyper-V virtualization detected! Flags: 0x%08X\n", totalFlags);
        
        if (totalFlags & HYPERV_DETECTED_CPUID) printf("- CPUID detection\n");
        if (totalFlags & HYPERV_DETECTED_REGISTRY) printf("- Registry detection\n");
        if (totalFlags & HYPERV_DETECTED_FILES) printf("- File system detection\n");
        if (totalFlags & HYPERV_DETECTED_SERVICES) printf("- Service detection\n");
        if (totalFlags & HYPERV_DETECTED_DEVICES) printf("- Device detection\n");
        if (totalFlags & HYPERV_DETECTED_BIOS) printf("- BIOS/UEFI detection\n");
        if (totalFlags & HYPERV_DETECTED_PROCESSES) printf("- Process detection\n");
        if (totalFlags & HYPERV_DETECTED_OBJECTS) printf("- Windows object detection\n");
        if (totalFlags & HYPERV_DETECTED_NESTED) printf("- Nested virtualization detection\n");
        if (totalFlags & HYPERV_DETECTED_SANDBOX) printf("- Windows Sandbox detection\n");
        if (totalFlags & HYPERV_DETECTED_DOCKER) printf("- Docker Hyper-V detection\n");
        if (totalFlags & HYPERV_DETECTED_REMOVED) printf("- Removed Hyper-V detection\n");
    }
    
    printf("\n=== DETAILED OUTPUT ===\n");
    printf("%s\n", result.Details);
    
    // Try to communicate with kernel driver for additional checks
    HANDLE hDriver = CreateFileA("\\\\.\\HyperVDetector", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver != INVALID_HANDLE_VALUE) {
        printf("\n=== KERNEL MODE CHECKS ===\n");
        
        // Perform hypercall checks through driver
        HYPERCALL_INPUT hypercallInput = {0};
        HYPERCALL_OUTPUT hypercallOutput = {0};
        DWORD bytesReturned;
        
        hypercallInput.HypercallCode = HVCALL_GET_PARTITION_ID;
        if (DeviceIoControl(hDriver, IOCTL_HYPERV_CHECK_HYPERCALL, &hypercallInput, sizeof(hypercallInput),
                           &hypercallOutput, sizeof(hypercallOutput), &bytesReturned, NULL)) {
            if (hypercallOutput.Result == 0) {
                printf("Kernel: Hypercall successful - Partition ID: %d\n", hypercallOutput.OutputValue);
                totalFlags |= HYPERV_DETECTED_HYPERCALLS;
            }
        }
        
        CloseHandle(hDriver);
    } else {
        printf("\nKernel driver not loaded. Skipping kernel mode checks.\n");
        printf("To enable kernel mode checks, run: sc create HyperVDetector binPath= hyperv_driver.sys type= kernel\n");
    }
    
    if (argc > 1 && strcmp(argv[1], "--json") == 0) {
        // Output JSON format for automated processing
        printf("\n=== JSON OUTPUT ===\n");
        printf("{\n");
        printf("  \"detected\": %s,\n", (totalFlags != 0) ? "true" : "false");
        printf("  \"flags\": \"0x%08X\",\n", totalFlags);
        printf("  \"process_id\": %d,\n", result.ProcessId);
        printf("  \"process_name\": \"%s\",\n", result.ProcessName);
        printf("  \"details\": \"%s\"\n", result.Details);
        printf("}\n");
    }
    
    return (totalFlags != 0) ? 1 : 0;
}