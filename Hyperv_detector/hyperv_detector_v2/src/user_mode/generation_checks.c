/**
 * generation_checks.c - Hyper-V VM Generation Detection
 * 
 * Detects whether VM is Generation 1 (BIOS) or Generation 2 (UEFI).
 * Generation 2 VMs have better performance and security features.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v
 * - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/generation-2-virtual-machine-security-settings-for-hyper-v
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

#define HYPERV_DETECTED_GEN1 0x00800000
#define HYPERV_DETECTED_GEN2 0x01000000

/* Generation characteristics */
typedef struct _VM_GENERATION_INFO {
    int generation;              /* 0=unknown, 1=Gen1, 2=Gen2 */
    BOOL hasUEFI;                /* UEFI firmware (Gen2) */
    BOOL hasSecureBoot;          /* Secure Boot enabled (Gen2) */
    BOOL hasTPM;                 /* Virtual TPM (Gen2) */
    BOOL hasSCSIBoot;            /* SCSI boot device (Gen2) */
    BOOL hasIDEController;       /* IDE controller (Gen1) */
    BOOL hasFloppyController;    /* Floppy controller (Gen1) */
    BOOL hasCOMPorts;            /* COM ports (Gen1) */
    BOOL hasLegacyNIC;           /* Legacy network adapter (Gen1) */
    char firmwareType[32];       /* "BIOS" or "UEFI" */
} VM_GENERATION_INFO, *PVM_GENERATION_INFO;

/*
 * Check if system uses UEFI firmware
 */
static BOOL IsUEFIBoot(void)
{
    FIRMWARE_TYPE firmwareType = FirmwareTypeUnknown;
    
    if (GetFirmwareType(&firmwareType)) {
        return (firmwareType == FirmwareTypeUefi);
    }
    return FALSE;
}

/*
 * Check for Secure Boot status
 */
static BOOL IsSecureBootEnabled(void)
{
    HKEY hKey = NULL;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    LONG res = 0;
    BOOL enabled = FALSE;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        res = RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL,
                              (LPBYTE)&value, &size);
        if (res == ERROR_SUCCESS && value == 1) {
            enabled = TRUE;
        }
        RegCloseKey(hKey);
    }
    
    return enabled;
}

/*
 * Check for Virtual TPM
 */
static BOOL HasVirtualTPM(void)
{
    HKEY hKey = NULL;
    LONG res = 0;
    BOOL hasTPM = FALSE;
    
    /* Check for TPM service */
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\TPM",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        
        /* Check for Hyper-V vTPM specifically */
        res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Enum\\ACPI\\MSFT0101",
            0, KEY_READ, &hKey);
        
        if (res == ERROR_SUCCESS) {
            hasTPM = TRUE;
            RegCloseKey(hKey);
        }
    }
    
    return hasTPM;
}

/*
 * Check for IDE controller (Gen1 indicator)
 */
static BOOL HasIDEController(void)
{
    HKEY hKey = NULL;
    LONG res = 0;
    
    /* Check for IDE controller in registry */
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\pciide",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        DWORD start = 0;
        DWORD size = sizeof(DWORD);
        
        if (RegQueryValueExA(hKey, "Start", NULL, NULL, 
                            (LPBYTE)&start, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (start != 4);  /* 4 = disabled */
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

/*
 * Check for floppy controller (Gen1 indicator)
 */
static BOOL HasFloppyController(void)
{
    HKEY hKey = NULL;
    LONG res = 0;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\flpydisk",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check for COM ports (Gen1 indicator)
 */
static BOOL HasCOMPorts(void)
{
    HKEY hKey = NULL;
    LONG res = 0;
    DWORD subKeys = 0;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DEVICEMAP\\SERIALCOMM",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subKeys, 
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
        return (subKeys > 0);
    }
    
    /* Alternative: check for Serial service */
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\Serial",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check for legacy network adapter (Gen1)
 */
static BOOL HasLegacyNetworkAdapter(void)
{
    /* Legacy adapters use DEC 21140 chipset emulation */
    HKEY hKey = NULL;
    LONG res = 0;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\dc21x4",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check boot device type
 */
static BOOL IsSCSIBoot(void)
{
    char systemDrive[MAX_PATH] = {0};
    char devicePath[MAX_PATH] = {0};
    DWORD result = 0;
    
    /* Get system drive letter */
    result = GetEnvironmentVariableA("SystemDrive", systemDrive, sizeof(systemDrive));
    if (result == 0) {
        return FALSE;
    }
    
    /* For Gen2 VMs, the boot disk is always SCSI */
    /* Gen1 VMs use IDE for boot disk */
    
    /* Check for storvsc (Hyper-V SCSI) driver on boot path */
    HKEY hKey = NULL;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\storvsc",
        0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        DWORD bootFlags = 0;
        DWORD size = sizeof(DWORD);
        
        res = RegQueryValueExA(hKey, "BootFlags", NULL, NULL,
                              (LPBYTE)&bootFlags, &size);
        RegCloseKey(hKey);
        
        if (res == ERROR_SUCCESS && bootFlags != 0) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * Determine VM generation
 */
static int DetermineGeneration(PVM_GENERATION_INFO info)
{
    int gen1Score = 0;
    int gen2Score = 0;
    
    /* Gen2 indicators */
    if (info->hasUEFI) gen2Score += 3;
    if (info->hasSecureBoot) gen2Score += 2;
    if (info->hasTPM) gen2Score += 2;
    if (info->hasSCSIBoot) gen2Score += 2;
    
    /* Gen1 indicators */
    if (info->hasIDEController) gen1Score += 2;
    if (info->hasFloppyController) gen1Score += 2;
    if (info->hasCOMPorts) gen1Score += 1;
    if (info->hasLegacyNIC) gen1Score += 2;
    if (!info->hasUEFI) gen1Score += 3;
    
    if (gen2Score > gen1Score) {
        return 2;
    } else if (gen1Score > gen2Score) {
        return 1;
    }
    
    return 0;  /* Unknown */
}

/*
 * Get VM generation information
 */
void GetVMGenerationInfo(PVM_GENERATION_INFO info)
{
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(VM_GENERATION_INFO));
    
    /* Gather indicators */
    info->hasUEFI = IsUEFIBoot();
    info->hasSecureBoot = IsSecureBootEnabled();
    info->hasTPM = HasVirtualTPM();
    info->hasSCSIBoot = IsSCSIBoot();
    info->hasIDEController = HasIDEController();
    info->hasFloppyController = HasFloppyController();
    info->hasCOMPorts = HasCOMPorts();
    info->hasLegacyNIC = HasLegacyNetworkAdapter();
    
    /* Set firmware type string */
    if (info->hasUEFI) {
        strcpy_s(info->firmwareType, sizeof(info->firmwareType), "UEFI");
    } else {
        strcpy_s(info->firmwareType, sizeof(info->firmwareType), "BIOS");
    }
    
    /* Determine generation */
    info->generation = DetermineGeneration(info);
}

/*
 * Main generation check function
 */
DWORD CheckGenerationHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    VM_GENERATION_INFO info = {0};
    int cpuInfo[4] = {0, 0, 0, 0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Check if we're even in a hypervisor */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        AppendToDetails(result, "Generation: Not in a VM\n");
        return 0;
    }
    
    /* Get generation info */
    GetVMGenerationInfo(&info);
    
    /* Set detection flags */
    if (info.generation == 1) {
        detected = HYPERV_DETECTED_GEN1;
    } else if (info.generation == 2) {
        detected = HYPERV_DETECTED_GEN2;
    }
    
    /* Build details */
    AppendToDetails(result, "VM Generation Detection:\n");
    AppendToDetails(result, "  Generation: %s\n", 
                   info.generation == 1 ? "Generation 1" :
                   info.generation == 2 ? "Generation 2" : "Unknown");
    AppendToDetails(result, "  Firmware: %s\n", info.firmwareType);
    AppendToDetails(result, "  Secure Boot: %s\n", info.hasSecureBoot ? "Enabled" : "Disabled");
    AppendToDetails(result, "  Virtual TPM: %s\n", info.hasTPM ? "Present" : "Not present");
    
    if (info.generation == 1) {
        AppendToDetails(result, "  Gen1 indicators:\n");
        if (info.hasIDEController) AppendToDetails(result, "    - IDE Controller\n");
        if (info.hasFloppyController) AppendToDetails(result, "    - Floppy Controller\n");
        if (info.hasCOMPorts) AppendToDetails(result, "    - COM Ports\n");
        if (info.hasLegacyNIC) AppendToDetails(result, "    - Legacy NIC\n");
    } else if (info.generation == 2) {
        AppendToDetails(result, "  Gen2 features:\n");
        if (info.hasUEFI) AppendToDetails(result, "    - UEFI Boot\n");
        if (info.hasSecureBoot) AppendToDetails(result, "    - Secure Boot\n");
        if (info.hasTPM) AppendToDetails(result, "    - Virtual TPM\n");
        if (info.hasSCSIBoot) AppendToDetails(result, "    - SCSI Boot\n");
    }
    
    return detected;
}

/*
 * Quick generation check
 */
int GetVMGeneration(void)
{
    VM_GENERATION_INFO info = {0};
    GetVMGenerationInfo(&info);
    return info.generation;
}

/*
 * Check if Gen2 VM
 */
BOOL IsGeneration2VM(void)
{
    return GetVMGeneration() == 2;
}
