#include "hyperv_detector.h"
#include <tlhelp32.h>
#include <psapi.h>

static const char* HYPERV_PROCESSES[] = {
    "vmms.exe",           // Hyper-V Virtual Machine Management Service
    "vmwp.exe",           // Hyper-V Worker Process
    "vmcompute.exe",      // Hyper-V Host Compute Service
    "vmcomputeagent.exe", // Hyper-V Compute Agent
    "vmmem",              // WSL2/Windows Sandbox Memory Process
    "WindowsSandbox.exe", // Windows Sandbox
    "WindowsSandboxClient.exe", // Windows Sandbox Client
    "docker.exe",         // Docker
    "dockerd.exe",        // Docker Daemon
    "com.docker.service.exe", // Docker Desktop Service
    "wslservice.exe",     // WSL Service
    "lxssmanager.exe",    // Linux Subsystem Manager
    NULL
};

DWORD CheckProcessesHyperV(PDETECTION_RESULT result) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD detected = 0;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        AppendToDetails(result, "Process: Failed to create process snapshot\n");
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Check against known Hyper-V processes
            for (int i = 0; HYPERV_PROCESSES[i] != NULL; i++) {
                if (_stricmp(pe32.szExeFile, HYPERV_PROCESSES[i]) == 0) {
                    detected |= HYPERV_DETECTED_PROCESSES;
                    AppendToDetails(result, "Process: Found %s (PID: %d, PPID: %d)\n", 
                                   pe32.szExeFile, pe32.th32ProcessID, pe32.th32ParentProcessID);
                    
                    // Get additional process information
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                                FALSE, pe32.th32ProcessID);
                    if (hProcess != NULL) {
                        char modulePath[MAX_PATH];
                        if (GetModuleFileNameExA(hProcess, NULL, modulePath, sizeof(modulePath))) {
                            AppendToDetails(result, "Process: %s path: %s\n", pe32.szExeFile, modulePath);
                        }
                        
                        PROCESS_MEMORY_COUNTERS_EX memCounters;
                        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&memCounters, sizeof(memCounters))) {
                            AppendToDetails(result, "Process: %s memory usage: %lu KB\n", 
                                           pe32.szExeFile, memCounters.WorkingSetSize / 1024);
                        }
                        
                        CloseHandle(hProcess);
                    }
                    break;
                }
            }
            
            // Check for processes with Hyper-V related strings in their name
            if (strstr(pe32.szExeFile, "hyper") || strstr(pe32.szExeFile, "vm") || 
                strstr(pe32.szExeFile, "virtual") || strstr(pe32.szExeFile, "sandbox")) {
                detected |= HYPERV_DETECTED_PROCESSES;
                AppendToDetails(result, "Process: Found virtualization-related process: %s (PID: %d)\n", 
                               pe32.szExeFile, pe32.th32ProcessID);
            }
            
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return detected;
}