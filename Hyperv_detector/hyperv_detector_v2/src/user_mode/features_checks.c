/**
 * features_checks.c - Windows Optional Features based Hyper-V detection
 * 
 * Checks installed Windows features for Hyper-V components using
 * DISM APIs and registry.
 */

#include "hyperv_detector.h"

// Detection flag for Windows features
#define HYPERV_DETECTED_FEATURES 0x00200000

// Hyper-V related Windows feature names
static const char* HYPERV_FEATURE_NAMES[] = {
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-All",
    "Microsoft-Hyper-V-Tools-All",
    "Microsoft-Hyper-V-Management-Clients",
    "Microsoft-Hyper-V-Management-PowerShell",
    "Microsoft-Hyper-V-Hypervisor",
    "Microsoft-Hyper-V-Services",
    "Microsoft-Hyper-V-Online",
    "Containers",
    "Containers-DisposableClientVM",
    "HostGuardian",
    "VirtualMachinePlatform",
    "HypervisorPlatform",
    "Microsoft-Windows-Subsystem-Linux",
    NULL
};

// Registry paths for feature state
static const char* FEATURE_REGISTRY_PATHS[] = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State",
    NULL
};

static BOOL CheckFeatureInstalled(const char* featureName, PDETECTION_RESULT result) {
    HKEY hKey;
    char keyPath[512];
    BOOL found = FALSE;
    
    // Check CBS packages
    snprintf(keyPath, sizeof(keyPath), 
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages\\%s~*",
             featureName);
    
    // Enumerate packages looking for the feature
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hKey) == ERROR_SUCCESS) {
        
        char subKeyName[512];
        DWORD subKeyNameLen;
        DWORD index = 0;
        
        while (TRUE) {
            subKeyNameLen = sizeof(subKeyName);
            if (RegEnumKeyExA(hKey, index++, subKeyName, &subKeyNameLen, 
                             NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }
            
            // Check if this package matches the feature
            if (strstr(subKeyName, featureName) != NULL) {
                found = TRUE;
                
                // Check package state
                HKEY hSubKey;
                snprintf(keyPath, sizeof(keyPath), 
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages\\%s",
                        subKeyName);
                
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    DWORD currentState = 0;
                    DWORD size = sizeof(currentState);
                    
                    if (RegQueryValueExA(hSubKey, "CurrentState", NULL, NULL, 
                                        (LPBYTE)&currentState, &size) == ERROR_SUCCESS) {
                        const char* stateStr = "Unknown";
                        switch (currentState) {
                            case 0: stateStr = "Absent"; break;
                            case 5: stateStr = "Uninstall Pending"; break;
                            case 10: stateStr = "Resolving"; break;
                            case 20: stateStr = "Resolved"; break;
                            case 30: stateStr = "Staging"; break;
                            case 40: stateStr = "Staged"; break;
                            case 50: stateStr = "Superseded"; break;
                            case 60: stateStr = "Install Pending"; break;
                            case 65: stateStr = "Partially Installed"; break;
                            case 70: stateStr = "Installed"; break;
                            case 80: stateStr = "Permanent"; break;
                        }
                        
                        if (currentState >= 70) {
                            AppendToDetails(result, "Feature: %s - %s (State: %d)\n", 
                                           featureName, stateStr, currentState);
                        }
                    }
                    
                    RegCloseKey(hSubKey);
                }
                break;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return found;
}

static DWORD CheckOptionalFeatures(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check Windows optional features via registry
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\State\\Microsoft-Hyper-V",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        detected |= HYPERV_DETECTED_FEATURES;
        AppendToDetails(result, "Feature: Microsoft-Hyper-V feature state found\n");
        
        DWORD installState = 0;
        DWORD size = sizeof(installState);
        if (RegQueryValueExA(hKey, "InstallState", NULL, NULL, 
                            (LPBYTE)&installState, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Feature: InstallState = %d\n", installState);
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

static DWORD CheckHyperVCapability(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Use SystemInfo to check for virtualization support
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    
    // Check processor architecture
    const char* archStr = "Unknown";
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: archStr = "x64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: archStr = "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM: archStr = "ARM"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: archStr = "ARM64"; break;
    }
    AppendToDetails(result, "Feature: Processor architecture: %s\n", archStr);
    AppendToDetails(result, "Feature: Number of processors: %d\n", sysInfo.dwNumberOfProcessors);
    
    // Check for hardware virtualization support via CPUID
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    
    BOOL vmxSupport = (cpuInfo[2] & (1 << 5)) != 0;  // VMX (Intel)
    BOOL svmSupport = FALSE;
    
    // Check AMD SVM support
    __cpuid(cpuInfo, 0x80000001);
    svmSupport = (cpuInfo[2] & (1 << 2)) != 0;  // SVM (AMD)
    
    if (vmxSupport) {
        AppendToDetails(result, "Feature: Intel VT-x (VMX) supported\n");
    }
    if (svmSupport) {
        AppendToDetails(result, "Feature: AMD-V (SVM) supported\n");
    }
    
    // Check if virtualization is enabled in BIOS
    // This is indicated by the hypervisor present bit when Hyper-V is running
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        detected |= HYPERV_DETECTED_FEATURES;
        AppendToDetails(result, "Feature: Hypervisor is present (virtualization enabled)\n");
    }
    
    return detected;
}

static DWORD CheckServerRoleFeatures(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check for Server Roles (Windows Server)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\ServerManager\\ServicingStorage\\ServerComponentCache",
        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hKey) == ERROR_SUCCESS) {
        
        char subKeyName[256];
        DWORD subKeyNameLen;
        DWORD index = 0;
        
        while (TRUE) {
            subKeyNameLen = sizeof(subKeyName);
            if (RegEnumKeyExA(hKey, index++, subKeyName, &subKeyNameLen, 
                             NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }
            
            // Check for Hyper-V related roles
            if (strstr(subKeyName, "Hyper-V") != NULL ||
                strstr(subKeyName, "Microsoft-Hyper-V") != NULL) {
                detected |= HYPERV_DETECTED_FEATURES;
                AppendToDetails(result, "Feature: Server role found: %s\n", subKeyName);
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

static DWORD CheckContainerFeatures(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check Containers feature
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\State\\Containers",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        detected |= HYPERV_DETECTED_FEATURES;
        AppendToDetails(result, "Feature: Windows Containers feature found\n");
        RegCloseKey(hKey);
    }
    
    // Check Virtual Machine Platform (required for WSL2)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\State\\VirtualMachinePlatform",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        detected |= HYPERV_DETECTED_FEATURES;
        AppendToDetails(result, "Feature: Virtual Machine Platform feature found\n");
        RegCloseKey(hKey);
    }
    
    // Check Windows Sandbox
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\State\\Containers-DisposableClientVM",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        detected |= HYPERV_DETECTED_FEATURES;
        AppendToDetails(result, "Feature: Windows Sandbox feature found\n");
        RegCloseKey(hKey);
    }
    
    // Check WSL
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD defaultVersion = 0;
        DWORD size = sizeof(defaultVersion);
        
        if (RegQueryValueExA(hKey, "DefaultVersion", NULL, NULL, 
                            (LPBYTE)&defaultVersion, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Feature: WSL Default Version = %d\n", defaultVersion);
            if (defaultVersion == 2) {
                detected |= HYPERV_DETECTED_FEATURES;
                AppendToDetails(result, "Feature: WSL2 is default (uses Hyper-V)\n");
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

DWORD CheckWindowsFeaturesHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "Feature: Checking Windows features...\n");
    
    // Check all known Hyper-V features
    for (int i = 0; HYPERV_FEATURE_NAMES[i] != NULL; i++) {
        if (CheckFeatureInstalled(HYPERV_FEATURE_NAMES[i], result)) {
            detected |= HYPERV_DETECTED_FEATURES;
        }
    }
    
    detected |= CheckOptionalFeatures(result);
    detected |= CheckHyperVCapability(result);
    detected |= CheckServerRoleFeatures(result);
    detected |= CheckContainerFeatures(result);
    
    return detected;
}
