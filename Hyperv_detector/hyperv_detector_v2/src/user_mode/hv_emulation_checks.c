/**
 * hv_emulation_checks.c - Hyper-V Emulation API Detection
 * 
 * Detects Hyper-V Emulation API availability.
 * The emulation API allows creating software-based device emulators.
 * 
 * Sources:
 * - Windows SDK: WinHvEmulation.h
 * - QEMU WHPX module: https://github.com/qemu/qemu/tree/master/hw/hyperv
 * - VirtualBox NEM: https://www.virtualbox.org/browser/vbox/trunk/src/VBox/VMM/VMMR3/NEMR3Native-win.cpp
 * - Hyntrospect (Diane Dubois): https://github.com/googleprojectzero/Hyntrospect
 * - Fuzzing para-virtualized devices (MSRC): https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_HV_EMULATION 0x00000040

/* Emulation API function types */
typedef HRESULT (WINAPI *PFN_WHvEmulatorCreateEmulator)(
    void* callbacks,
    void** emulator
);

typedef HRESULT (WINAPI *PFN_WHvEmulatorDestroyEmulator)(
    void* emulator
);

/* Emulation detection info */
typedef struct _HV_EMULATION_INFO {
    BOOL emulationDllLoaded;
    BOOL platformDllLoaded;
    BOOL apiAvailable;
    
    BOOL canCreateEmulator;
    BOOL canEmulateIo;
    BOOL canEmulateMmio;
    
    DWORD dllVersion;
} HV_EMULATION_INFO, *PHV_EMULATION_INFO;

/*
 * Check for emulation DLLs
 */
static void CheckEmulationDlls(PHV_EMULATION_INFO info)
{
    HMODULE hEmulation = NULL;
    HMODULE hPlatform = NULL;
    
    if (info == NULL) {
        return;
    }
    
    /* Try to load WinHvEmulation.dll */
    hEmulation = LoadLibraryA("WinHvEmulation.dll");
    if (hEmulation != NULL) {
        info->emulationDllLoaded = TRUE;
        
        /* Check for emulator functions */
        if (GetProcAddress(hEmulation, "WHvEmulatorCreateEmulator") != NULL) {
            info->canCreateEmulator = TRUE;
            info->apiAvailable = TRUE;
        }
        
        if (GetProcAddress(hEmulation, "WHvEmulatorTryIoEmulation") != NULL) {
            info->canEmulateIo = TRUE;
        }
        
        if (GetProcAddress(hEmulation, "WHvEmulatorTryMmioEmulation") != NULL) {
            info->canEmulateMmio = TRUE;
        }
        
        FreeLibrary(hEmulation);
    }
    
    /* Check for platform DLL too */
    hPlatform = LoadLibraryA("WinHvPlatform.dll");
    if (hPlatform != NULL) {
        info->platformDllLoaded = TRUE;
        FreeLibrary(hPlatform);
    }
}

/*
 * Check registry for emulation settings
 */
static BOOL CheckEmulationRegistry(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check for Hyper-V platform emulation settings */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\Emulation",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check for third-party hypervisors using WHPX
 */
static void CheckThirdPartyHypervisors(PHV_EMULATION_INFO info)
{
    HKEY hKey;
    LONG regResult;
    DWORD attrs;
    
    if (info == NULL) {
        return;
    }
    
    /* Check for QEMU */
    attrs = GetFileAttributesA("C:\\Program Files\\qemu\\qemu-system-x86_64.exe");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        /* QEMU found - might use WHPX */
    }
    
    /* Check for VirtualBox */
    regResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Oracle\\VirtualBox",
        0, KEY_READ, &hKey);
    
    if (regResult == ERROR_SUCCESS) {
        /* VirtualBox found - might use NEM/WHPX */
        RegCloseKey(hKey);
    }
}

/*
 * Main emulation check function
 */
DWORD CheckHvEmulationHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HV_EMULATION_INFO info = {0};
    BOOL registryFound;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckEmulationDlls(&info);
    registryFound = CheckEmulationRegistry();
    
    /* Detection */
    if (info.emulationDllLoaded && info.apiAvailable) {
        detected = HYPERV_DETECTED_HV_EMULATION;
    }
    
    /* Build details */
    AppendToDetails(result, "Hyper-V Emulation API Detection:\n");
    
    AppendToDetails(result, "\n  DLL Availability:\n");
    AppendToDetails(result, "    WinHvEmulation.dll: %s\n", 
                   info.emulationDllLoaded ? "Loaded" : "Not found");
    AppendToDetails(result, "    WinHvPlatform.dll: %s\n", 
                   info.platformDllLoaded ? "Loaded" : "Not found");
    
    AppendToDetails(result, "\n  Emulation API:\n");
    AppendToDetails(result, "    API Available: %s\n", 
                   info.apiAvailable ? "YES" : "NO");
    AppendToDetails(result, "    Create Emulator: %s\n", 
                   info.canCreateEmulator ? "Available" : "Not available");
    AppendToDetails(result, "    I/O Emulation: %s\n", 
                   info.canEmulateIo ? "Available" : "Not available");
    AppendToDetails(result, "    MMIO Emulation: %s\n", 
                   info.canEmulateMmio ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Registry:\n");
    AppendToDetails(result, "    Emulation Settings: %s\n", 
                   registryFound ? "Found" : "Not found");
    
    if (info.apiAvailable) {
        AppendToDetails(result, "\n  Note: Emulation API available\n");
        AppendToDetails(result, "        Can be used by QEMU, VirtualBox, etc.\n");
    }
    
    return detected;
}

/*
 * Quick check for emulation API
 */
BOOL HasEmulationApi(void)
{
    HV_EMULATION_INFO info = {0};
    CheckEmulationDlls(&info);
    return info.apiAvailable;
}

/*
 * Check if I/O emulation is available
 */
BOOL CanEmulateIo(void)
{
    HV_EMULATION_INFO info = {0};
    CheckEmulationDlls(&info);
    return info.canEmulateIo;
}

/*
 * Check if MMIO emulation is available
 */
BOOL CanEmulateMmio(void)
{
    HV_EMULATION_INFO info = {0};
    CheckEmulationDlls(&info);
    return info.canEmulateMmio;
}
