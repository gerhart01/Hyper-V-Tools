/**
 * dll_checks.c - DLL and Export Detection for Hyper-V
 * 
 * Analyzes loaded DLLs and their exports for Hyper-V indicators:
 * - Hyper-V specific DLLs
 * - VM-related exports
 * - Module characteristics
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dbghelp.h>

#ifndef HYPERV_DETECTED_DLL
#define HYPERV_DETECTED_DLL 0x01000000
#endif

typedef struct _DETECTION_RESULT {
    DWORD DetectionFlags;
    char Details[4096];
    DWORD ProcessId;
    char ProcessName[256];
} DETECTION_RESULT, *PDETECTION_RESULT;

extern void AppendToDetails(PDETECTION_RESULT result, const char* format, ...);

// Hyper-V related DLLs
static const char* HYPERV_DLLS[] = {
    "vmbus.sys",
    "vmbushid.sys",
    "vmbusr.dll",
    "vmchipset.dll",
    "vmcompute.dll",
    "vmcomputeagent.dll",
    "vmdevicehost.dll",
    "vmeventhub.dll",
    "vmfirmware.dll",
    "vmguestdelegation.dll",
    "vmguestlib.dll",
    "vmhgfs.dll",
    "vmhvevents.dll",
    "vmictimeprovider.dll",
    "vmmsproxy.dll",
    "vmnetextension.dll",
    "vmpipe.dll",
    "vmprox.dll",
    "vmrdvcore.dll",
    "vmsif.dll",
    "vmsmb.dll",
    "vmsp.dll",
    "vmswitch.dll",
    "vmuidevices.dll",
    "vmvirtualization.dll",
    "vmvpci.dll",
    "vmwp.exe",
    "virtdisk.dll",
    "vhdparser.dll",
    "hvloader.dll",
    "hvix64.exe",
    "hvax64.exe",
    "hvboot.sys",
    "winhv.sys",
    "winhvr.sys",
    "winhvemulation.dll",
    "vid.sys",
    "vid.dll",
    "vpcivsp.sys",
    "vmgencounter.sys",
    "vmgid.sys",
    "vmicguestinterface.sys",
    "vmicheartbeat.sys",
    "vmickvpexchange.sys",
    "vmicrdv.sys",
    "vmicshutdown.sys",
    "vmictimesync.sys",
    "vmicvmsession.sys",
    "vmicvss.sys",
    NULL
};

// Exports that indicate VM environment
static const char* VM_EXPORTS[] = {
    "VmSavedStateDumpOpen",
    "VmSavedStateDumpClose",
    "VmSavedStateDumpGetVpCount",
    "VmSavedStateDumpGetVpState",
    "VmSavedStateDumpGetGuestPhysicalMemoryChunks",
    "VmSavedStateDumpReadGuestPhysicalAddress",
    "WHvCreatePartition",
    "WHvDeletePartition",
    "WHvSetPartitionProperty",
    "WHvGetPartitionProperty",
    "WHvSetupPartition",
    "WHvCreateVirtualProcessor",
    "WHvDeleteVirtualProcessor",
    "WHvRunVirtualProcessor",
    "WHvCancelRunVirtualProcessor",
    "WHvGetVirtualProcessorRegisters",
    "WHvSetVirtualProcessorRegisters",
    "WHvMapGpaRange",
    "WHvUnmapGpaRange",
    "HcsEnumerateComputeSystems",
    "HcsCreateComputeSystem",
    "HcsOpenComputeSystem",
    "HcsCloseComputeSystem",
    "HcsStartComputeSystem",
    "HcsShutDownComputeSystem",
    "HcsTerminateComputeSystem",
    "HcsPauseComputeSystem",
    "HcsResumeComputeSystem",
    "HcsGetComputeSystemProperties",
    "HcsModifyComputeSystem",
    NULL
};

/**
 * Check for loaded Hyper-V DLLs in current process
 */
static DWORD CheckLoadedModules(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE modules[1024];
    DWORD needed;
    
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        DWORD moduleCount = needed / sizeof(HMODULE);
        
        for (DWORD i = 0; i < moduleCount; i++) {
            char moduleName[MAX_PATH];
            if (GetModuleFileNameExA(GetCurrentProcess(), modules[i], 
                                     moduleName, sizeof(moduleName))) {
                
                char* baseName = strrchr(moduleName, '\\');
                baseName = baseName ? baseName + 1 : moduleName;
                
                // Check against known Hyper-V DLLs
                for (int j = 0; HYPERV_DLLS[j] != NULL; j++) {
                    if (_stricmp(baseName, HYPERV_DLLS[j]) == 0) {
                        detected |= HYPERV_DETECTED_DLL;
                        AppendToDetails(result, "DLL: Hyper-V module loaded: %s\n", moduleName);
                        break;
                    }
                }
                
                // Check for VM-related patterns in module name
                if (strstr(baseName, "vm") || strstr(baseName, "hv") || 
                    strstr(baseName, "hyper") || strstr(baseName, "virt")) {
                    AppendToDetails(result, "DLL: Suspicious module name: %s\n", baseName);
                }
            }
        }
    }
    
    return detected;
}

/**
 * Check for Hyper-V DLL existence in system
 */
static DWORD CheckSystemDLLs(PDETECTION_RESULT result) {
    DWORD detected = 0;
    char systemPath[MAX_PATH];
    char dllPath[MAX_PATH];
    
    GetSystemDirectoryA(systemPath, sizeof(systemPath));
    
    for (int i = 0; HYPERV_DLLS[i] != NULL; i++) {
        snprintf(dllPath, sizeof(dllPath), "%s\\%s", systemPath, HYPERV_DLLS[i]);
        
        if (GetFileAttributesA(dllPath) != INVALID_FILE_ATTRIBUTES) {
            detected |= HYPERV_DETECTED_DLL;
            AppendToDetails(result, "DLL: Found system DLL: %s\n", dllPath);
        }
        
        // Also check drivers directory
        snprintf(dllPath, sizeof(dllPath), "%s\\drivers\\%s", systemPath, HYPERV_DLLS[i]);
        
        if (GetFileAttributesA(dllPath) != INVALID_FILE_ATTRIBUTES) {
            detected |= HYPERV_DETECTED_DLL;
            AppendToDetails(result, "DLL: Found driver: %s\n", dllPath);
        }
    }
    
    return detected;
}

/**
 * Check for VM-related exports in WinHvPlatform.dll
 */
static DWORD CheckWinHvPlatformExports(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hModule = LoadLibraryExA("WinHvPlatform.dll", NULL, 
                                      LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        detected |= HYPERV_DETECTED_DLL;
        AppendToDetails(result, "DLL: WinHvPlatform.dll found (Windows Hypervisor Platform)\n");
        
        // Check for specific exports
        for (int i = 0; VM_EXPORTS[i] != NULL; i++) {
            if (strncmp(VM_EXPORTS[i], "WHv", 3) == 0) {
                FARPROC proc = GetProcAddress(hModule, VM_EXPORTS[i]);
                if (proc) {
                    AppendToDetails(result, "DLL: Found export: %s\n", VM_EXPORTS[i]);
                }
            }
        }
        
        FreeLibrary(hModule);
    }
    
    return detected;
}

/**
 * Check for VM-related exports in vmcompute.dll
 */
static DWORD CheckVmComputeExports(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hModule = LoadLibraryExA("vmcompute.dll", NULL, 
                                      LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        detected |= HYPERV_DETECTED_DLL;
        AppendToDetails(result, "DLL: vmcompute.dll found (Hyper-V Compute)\n");
        
        FreeLibrary(hModule);
    }
    
    // Try computecore.dll (newer name)
    hModule = LoadLibraryExA("computecore.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hModule) {
        detected |= HYPERV_DETECTED_DLL;
        AppendToDetails(result, "DLL: computecore.dll found (Host Compute Service)\n");
        
        for (int i = 0; VM_EXPORTS[i] != NULL; i++) {
            if (strncmp(VM_EXPORTS[i], "Hcs", 3) == 0) {
                FARPROC proc = GetProcAddress(hModule, VM_EXPORTS[i]);
                if (proc) {
                    AppendToDetails(result, "DLL: Found HCS export: %s\n", VM_EXPORTS[i]);
                }
            }
        }
        
        FreeLibrary(hModule);
    }
    
    return detected;
}

/**
 * Check for virtdisk.dll (Virtual Disk API)
 */
static DWORD CheckVirtDiskAPI(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hModule = LoadLibraryExA("virtdisk.dll", NULL, 
                                      LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        AppendToDetails(result, "DLL: virtdisk.dll found (Virtual Disk API)\n");
        
        // Check for VHD-related exports
        const char* vhdExports[] = {
            "OpenVirtualDisk",
            "CreateVirtualDisk",
            "AttachVirtualDisk",
            "DetachVirtualDisk",
            "GetVirtualDiskInformation",
            "SetVirtualDiskInformation",
            "CompactVirtualDisk",
            "MergeVirtualDisk",
            "ExpandVirtualDisk",
            "MirrorVirtualDisk",
            NULL
        };
        
        int exportCount = 0;
        for (int i = 0; vhdExports[i] != NULL; i++) {
            if (GetProcAddress(hModule, vhdExports[i])) {
                exportCount++;
            }
        }
        
        AppendToDetails(result, "DLL: Found %d VHD exports\n", exportCount);
        FreeLibrary(hModule);
    }
    
    return detected;
}

/**
 * Check for VID.dll (Virtual Infrastructure Driver)
 */
static DWORD CheckVIDExports(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hModule = LoadLibraryExA("vid.dll", NULL, 
                                      LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        detected |= HYPERV_DETECTED_DLL;
        AppendToDetails(result, "DLL: vid.dll found (Virtual Infrastructure Driver)\n");
        
        // VID exports indicate Hyper-V is installed
        const char* vidExports[] = {
            "VidCreatePartition",
            "VidDeletePartition",
            "VidMapGpaPages",
            "VidUnmapGpaPages",
            "VidCreateVirtualProcessor",
            "VidDeleteVirtualProcessor",
            "VidStartVirtualProcessor",
            "VidStopVirtualProcessor",
            "VidGetVirtualProcessorState",
            "VidSetVirtualProcessorState",
            NULL
        };
        
        int exportCount = 0;
        for (int i = 0; vidExports[i] != NULL; i++) {
            if (GetProcAddress(hModule, vidExports[i])) {
                exportCount++;
            }
        }
        
        AppendToDetails(result, "DLL: Found %d VID exports\n", exportCount);
        FreeLibrary(hModule);
    }
    
    return detected;
}

/**
 * Check ntdll.dll for VM-related exports
 */
static DWORD CheckNtdllVMExports(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    if (hNtdll) {
        // Check for hypervisor-related NT functions
        const char* ntExports[] = {
            "NtQuerySystemInformation",      // Can query hypervisor info
            "NtQueryVirtualMemory",          // Memory layout analysis
            "NtSetSystemInformation",        // System configuration
            "RtlIsMultiSessionSku",          // Multi-session/VDI check
            "RtlIsStateSeparationEnabled",   // State separation (containers)
            "RtlIsCloudFilesPlaceholder",    // Cloud files (OneDrive in VMs)
            "RtlIsEnclaveFeaturePresent",    // VBS enclaves
            NULL
        };
        
        for (int i = 0; ntExports[i] != NULL; i++) {
            if (GetProcAddress(hNtdll, ntExports[i])) {
                AppendToDetails(result, "DLL: ntdll export available: %s\n", ntExports[i]);
            }
        }
        
        // Check for NtQuerySystemInformation class for hypervisor
        typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength);
        
        NtQuerySystemInformation_t pNtQuerySystemInformation = 
            (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        
        if (pNtQuerySystemInformation) {
            // SystemHypervisorInformation = 0x66 (102)
            ULONG hypervisorInfo[16] = {0};
            ULONG returnLength = 0;
            
            NTSTATUS status = pNtQuerySystemInformation(102, hypervisorInfo, 
                                                        sizeof(hypervisorInfo), 
                                                        &returnLength);
            
            if (status == 0) {  // STATUS_SUCCESS
                detected |= HYPERV_DETECTED_DLL;
                AppendToDetails(result, "DLL: SystemHypervisorInformation query succeeded\n");
                AppendToDetails(result, "DLL: Hypervisor info returned %d bytes\n", returnLength);
            } else if (status == 0xC0000004) {  // STATUS_INFO_LENGTH_MISMATCH
                detected |= HYPERV_DETECTED_DLL;
                AppendToDetails(result, "DLL: Hypervisor info exists (buffer too small)\n");
            }
        }
    }
    
    return detected;
}

/**
 * Check for winhvemulation.dll (Emulator for WHPX)
 */
static DWORD CheckWinHvEmulation(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hModule = LoadLibraryExA("winhvemulation.dll", NULL, 
                                      LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        detected |= HYPERV_DETECTED_DLL;
        AppendToDetails(result, "DLL: winhvemulation.dll found (Hyper-V Emulator)\n");
        FreeLibrary(hModule);
    }
    
    return detected;
}

/**
 * Check module digital signatures
 */
static DWORD CheckModuleSignatures(PDETECTION_RESULT result) {
    DWORD detected = 0;
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, sizeof(systemPath));
    
    // Key Hyper-V modules to verify
    const char* keyModules[] = {
        "vmcompute.dll",
        "vmbus.sys",
        "hvloader.dll",
        NULL
    };
    
    for (int i = 0; keyModules[i] != NULL; i++) {
        char modulePath[MAX_PATH];
        snprintf(modulePath, sizeof(modulePath), "%s\\%s", systemPath, keyModules[i]);
        
        if (GetFileAttributesA(modulePath) != INVALID_FILE_ATTRIBUTES) {
            // Get file version info
            DWORD versionInfoSize = GetFileVersionInfoSizeA(modulePath, NULL);
            if (versionInfoSize > 0) {
                LPVOID versionInfo = malloc(versionInfoSize);
                if (versionInfo && GetFileVersionInfoA(modulePath, 0, 
                                                       versionInfoSize, versionInfo)) {
                    
                    VS_FIXEDFILEINFO* fileInfo;
                    UINT fileInfoSize;
                    if (VerQueryValueA(versionInfo, "\\", 
                                      (LPVOID*)&fileInfo, &fileInfoSize)) {
                        
                        detected |= HYPERV_DETECTED_DLL;
                        AppendToDetails(result, "DLL: %s version %d.%d.%d.%d\n",
                                       keyModules[i],
                                       HIWORD(fileInfo->dwFileVersionMS),
                                       LOWORD(fileInfo->dwFileVersionMS),
                                       HIWORD(fileInfo->dwFileVersionLS),
                                       LOWORD(fileInfo->dwFileVersionLS));
                    }
                    
                    // Get company name
                    struct LANGANDCODEPAGE {
                        WORD wLanguage;
                        WORD wCodePage;
                    } *lpTranslate;
                    UINT cbTranslate;
                    
                    if (VerQueryValueA(versionInfo, "\\VarFileInfo\\Translation",
                                      (LPVOID*)&lpTranslate, &cbTranslate)) {
                        char subBlock[256];
                        char* companyName = NULL;
                        UINT len;
                        
                        snprintf(subBlock, sizeof(subBlock),
                                "\\StringFileInfo\\%04x%04x\\CompanyName",
                                lpTranslate[0].wLanguage,
                                lpTranslate[0].wCodePage);
                        
                        if (VerQueryValueA(versionInfo, subBlock,
                                          (LPVOID*)&companyName, &len)) {
                            AppendToDetails(result, "DLL: %s signed by: %s\n",
                                           keyModules[i], companyName);
                        }
                    }
                }
                free(versionInfo);
            }
        }
    }
    
    return detected;
}

/**
 * Main DLL check function
 */
DWORD CheckDLLHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "\n=== DLL and Export Checks ===\n");
    
    detected |= CheckLoadedModules(result);
    detected |= CheckSystemDLLs(result);
    detected |= CheckWinHvPlatformExports(result);
    detected |= CheckVmComputeExports(result);
    detected |= CheckVirtDiskAPI(result);
    detected |= CheckVIDExports(result);
    detected |= CheckNtdllVMExports(result);
    detected |= CheckWinHvEmulation(result);
    detected |= CheckModuleSignatures(result);
    
    return detected;
}

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")
