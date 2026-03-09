/**
 * security_checks.c - Security Features based Hyper-V detection
 * 
 * Detects Hyper-V through Windows security features that depend on it:
 * - Virtualization-Based Security (VBS)
 * - Hypervisor-protected Code Integrity (HVCI)
 * - Credential Guard
 * - Device Guard
 * - Windows Defender Application Guard
 */

#include "hyperv_detector.h"

// Detection flag for security features
#define HYPERV_DETECTED_SECURITY 0x00080000

// VBS System Information Class
#define SystemVirtualizationBasedSecurityInformation 196

typedef struct _SYSTEM_VBS_INFORMATION {
    DWORD VbsState;
    DWORD VbsBootPhase;
    DWORD VbsProperties;
} SYSTEM_VBS_INFORMATION, *PSYSTEM_VBS_INFORMATION;

// VBS state flags
#define VBS_STATE_ENABLED           0x01
#define VBS_STATE_SECURE_MEMORY     0x02
#define VBS_STATE_CREDENTIAL_GUARD  0x04
#define VBS_STATE_HVCI              0x08

typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Device Guard policy structure
typedef struct _DEVICE_GUARD_STATE {
    DWORD VirtualizationBasedSecurityStatus;
    DWORD VirtualizationBasedSecurityPoliciesRequired;
    DWORD VirtualizationBasedSecurityPoliciesEnforced;
    DWORD VirtualizationBasedSecurityAvailableSecurityProperties;
} DEVICE_GUARD_STATE, *PDEVICE_GUARD_STATE;

static DWORD CheckVBSStatus(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    DWORD value;
    DWORD size = sizeof(value);
    
    // Check Device Guard registry settings
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        // EnableVirtualizationBasedSecurity
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: EnableVirtualizationBasedSecurity = %d\n", value);
            if (value == 1) {
                detected |= HYPERV_DETECTED_SECURITY;
                AppendToDetails(result, "Security: VBS is enabled via registry\n");
            }
        }
        
        // RequirePlatformSecurityFeatures
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "RequirePlatformSecurityFeatures", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: RequirePlatformSecurityFeatures = %d\n", value);
            if (value >= 1) {
                detected |= HYPERV_DETECTED_SECURITY;
            }
        }
        
        // Configured
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "Configured", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: DeviceGuard Configured = %d\n", value);
        }
        
        RegCloseKey(hKey);
    }
    
    // Check Device Guard Scenarios
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            detected |= HYPERV_DETECTED_SECURITY;
            AppendToDetails(result, "Security: HVCI is enabled\n");
        }
        
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "Locked", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            AppendToDetails(result, "Security: HVCI is locked (UEFI lock)\n");
        }
        
        RegCloseKey(hKey);
    }
    
    // Check Credential Guard
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            detected |= HYPERV_DETECTED_SECURITY;
            AppendToDetails(result, "Security: Credential Guard is enabled\n");
        }
        
        RegCloseKey(hKey);
    }
    
    // Check LSA protection
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "LsaCfgFlags", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: LsaCfgFlags = %d\n", value);
            if (value & 0x01) {
                detected |= HYPERV_DETECTED_SECURITY;
                AppendToDetails(result, "Security: LSA Credential Guard protection enabled\n");
            }
        }
        
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "RunAsPPL", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            AppendToDetails(result, "Security: LSA running as Protected Process\n");
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

static DWORD CheckHVCIStatus(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HMODULE hNtdll;
    NtQuerySystemInformation_t pNtQuerySystemInformation;
    
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    pNtQuerySystemInformation = (NtQuerySystemInformation_t)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) return 0;
    
    // Try to query CodeIntegrity information
    DWORD codeIntegrityInfo[2] = {0};
    ULONG returnLength = 0;
    
    NTSTATUS status = pNtQuerySystemInformation(
        103,  // SystemCodeIntegrityInformation
        codeIntegrityInfo,
        sizeof(codeIntegrityInfo),
        &returnLength
    );
    
    if (NT_SUCCESS(status)) {
        DWORD ciOptions = codeIntegrityInfo[1];
        AppendToDetails(result, "Security: CodeIntegrity Options = 0x%08X\n", ciOptions);
        
        // CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x4
        if (ciOptions & 0x4) {
            detected |= HYPERV_DETECTED_SECURITY;
            AppendToDetails(result, "Security: HVCI (Kernel Mode CI) is active\n");
        }
        
        // CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED = 0x400
        if (ciOptions & 0x400) {
            detected |= HYPERV_DETECTED_SECURITY;
            AppendToDetails(result, "Security: Isolated User Mode is active\n");
        }
    }
    
    return detected;
}

static DWORD CheckSecureBootStatus(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    DWORD value;
    DWORD size = sizeof(value);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: UEFI Secure Boot = %s\n", 
                           value ? "Enabled" : "Disabled");
            if (value) {
                detected |= HYPERV_DETECTED_SECURITY;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

static DWORD CheckWindowsDefenderAppGuard(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    DWORD value;
    DWORD size = sizeof(value);
    
    // Check Windows Defender Application Guard (WDAG)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Hvsi", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        detected |= HYPERV_DETECTED_SECURITY;
        AppendToDetails(result, "Security: Windows Defender Application Guard registry found\n");
        
        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            AppendToDetails(result, "Security: WDAG is enabled\n");
        }
        
        RegCloseKey(hKey);
    }
    
    // Check if WDAG container feature is installed
    DWORD attributes = GetFileAttributesA("C:\\Windows\\System32\\hvsisvc.dll");
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        detected |= HYPERV_DETECTED_SECURITY;
        AppendToDetails(result, "Security: WDAG service DLL found\n");
    }
    
    return detected;
}

static DWORD CheckVSMEnclaves(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Check for VSM (Virtual Secure Mode) enclaves
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        // Check for enclave-related APIs (Windows 10+)
        if (GetProcAddress(hKernel32, "CreateEnclave") != NULL) {
            AppendToDetails(result, "Security: Enclave APIs available\n");
            
            // IsEnclaveTypeSupported check
            typedef BOOL (WINAPI *IsEnclaveTypeSupported_t)(DWORD flEnclaveType);
            IsEnclaveTypeSupported_t pIsEnclaveTypeSupported = 
                (IsEnclaveTypeSupported_t)GetProcAddress(hKernel32, "IsEnclaveTypeSupported");
            
            if (pIsEnclaveTypeSupported) {
                // ENCLAVE_TYPE_VBS = 0x10
                if (pIsEnclaveTypeSupported(0x10)) {
                    detected |= HYPERV_DETECTED_SECURITY;
                    AppendToDetails(result, "Security: VBS enclaves supported\n");
                }
                
                // ENCLAVE_TYPE_SGX = 0x1
                if (pIsEnclaveTypeSupported(0x1)) {
                    AppendToDetails(result, "Security: Intel SGX enclaves supported\n");
                }
            }
        }
    }
    
    return detected;
}

static DWORD CheckKernelDMA(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    DWORD value;
    DWORD size = sizeof(value);
    
    // Check Kernel DMA Protection
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        if (RegQueryValueExA(hKey, "HVCIMATRequired", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: HVCIMATRequired = %d\n", value);
            if (value) {
                detected |= HYPERV_DETECTED_SECURITY;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    // Check DMA Guard
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        if (RegQueryValueExA(hKey, "DeviceEnumerationPolicy", NULL, NULL, 
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            AppendToDetails(result, "Security: Kernel DMA Protection policy = %d\n", value);
            detected |= HYPERV_DETECTED_SECURITY;
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

DWORD CheckSecurityFeaturesHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "Security: Checking Hyper-V dependent security features...\n");
    
    detected |= CheckVBSStatus(result);
    detected |= CheckHVCIStatus(result);
    detected |= CheckSecureBootStatus(result);
    detected |= CheckWindowsDefenderAppGuard(result);
    detected |= CheckVSMEnclaves(result);
    detected |= CheckKernelDMA(result);
    
    // Check for Hyper-V partitions in System partition info
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        NtQuerySystemInformation_t pNtQuerySystemInformation = 
            (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        
        if (pNtQuerySystemInformation) {
            BYTE buffer[1024] = {0};
            ULONG returnLength = 0;
            
            // SystemHypervisorInformation = 174
            NTSTATUS status = pNtQuerySystemInformation(174, buffer, sizeof(buffer), &returnLength);
            if (NT_SUCCESS(status) && returnLength > 0) {
                detected |= HYPERV_DETECTED_SECURITY;
                AppendToDetails(result, "Security: SystemHypervisorInformation available (%d bytes)\n", 
                               returnLength);
            }
        }
    }
    
    return detected;
}
