/**
 * enclave_checks.c - VBS Enclave and IUM Detection
 * 
 * Detects VBS Enclaves (Isolated User Mode) and related features.
 * 
 * Sources:
 * - Battle of SKM and IUM (Alex Ionescu): https://web.archive.org/web/20190728160948/http://www.alex-ionescu.com/blackhat2015.pdf
 * - Debugging Windows IUM Processes (Francisco Falcon): https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html
 * - Abusing VBS Enclaves (Ori David): https://www.akamai.com/blog/security-research/2025-february-abusing-vbs-enclaves-evasive-malware
 * - VBS Internals (Saar Amar): https://github.com/saaramar/Publications/blob/master/BluehatIL_VBS_meetup/VBS_Internals.pdf
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

/* Detection flag for this module */
#define HYPERV_DETECTED_ENCLAVE 0x00002000

/* Enclave types */
#define ENCLAVE_TYPE_SGX    0x00000001
#define ENCLAVE_TYPE_VBS    0x00000010

/* Function pointer types for enclave API */
typedef BOOL (WINAPI *PFN_IsEnclaveTypeSupported)(DWORD flEnclaveType);
typedef LPVOID (WINAPI *PFN_CreateEnclave)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    SIZE_T dwInitialCommitment,
    DWORD flEnclaveType,
    LPCVOID lpEnclaveInformation,
    DWORD dwInfoLength,
    LPDWORD lpEnclaveError
);

/* Enclave detection info */
typedef struct _ENCLAVE_INFO {
    BOOL enclaveApiAvailable;
    BOOL sgxSupported;
    BOOL vbsSupported;
    
    BOOL secureKernelRunning;
    BOOL iumProcessesEnabled;
    
    BOOL lsaIsoPresent;
    BOOL credentialGuardRunning;
    
    DWORD lastError;
} ENCLAVE_INFO, *PENCLAVE_INFO;

/*
 * Check enclave API support
 */
static void CheckEnclaveApi(PENCLAVE_INFO info)
{
    HMODULE hKernel32 = NULL;
    PFN_IsEnclaveTypeSupported pfnIsEnclaveTypeSupported = NULL;
    
    if (info == NULL) {
        return;
    }
    
    hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        return;
    }
    
    /* Get IsEnclaveTypeSupported function */
    pfnIsEnclaveTypeSupported = (PFN_IsEnclaveTypeSupported)
        GetProcAddress(hKernel32, "IsEnclaveTypeSupported");
    
    if (pfnIsEnclaveTypeSupported == NULL) {
        info->lastError = GetLastError();
        return;
    }
    
    info->enclaveApiAvailable = TRUE;
    
    /* Check SGX support */
    info->sgxSupported = pfnIsEnclaveTypeSupported(ENCLAVE_TYPE_SGX);
    
    /* Check VBS enclave support */
    info->vbsSupported = pfnIsEnclaveTypeSupported(ENCLAVE_TYPE_VBS);
}

/*
 * Check for Secure Kernel
 */
static void CheckSecureKernel(PENCLAVE_INFO info)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    
    if (info == NULL) {
        return;
    }
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return;
    }
    
    /* Check securekernel (if it was a service - it's actually loaded differently) */
    /* Instead, check for Credential Guard / LsaIso */
    hService = OpenServiceA(hSCManager, "SecurityHealthService", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            /* Security Health Service indicates Windows Security is active */
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
}

/*
 * Check for LsaIso (LSA Isolated process - Credential Guard)
 */
static BOOL CheckLsaIso(void)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    BOOL found = FALSE;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "LsaIso.exe") == 0) {
                found = TRUE;
                break;
            }
            if (_stricmp(pe32.szExeFile, "SecureKernel.exe") == 0) {
                found = TRUE;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

/*
 * Check for IUM processes registry
 */
static BOOL CheckIumRegistry(void)
{
    HKEY hKey;
    LONG result;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    
    /* Check for IUM enabled */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    /* Alternative: check for Credential Guard */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Enabled",
            NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value != 0);
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

/*
 * Check for securekernel.exe in system
 */
static BOOL CheckSecureKernelFile(void)
{
    char systemPath[MAX_PATH];
    char filePath[MAX_PATH];
    DWORD attrs;
    
    if (GetSystemDirectoryA(systemPath, MAX_PATH) == 0) {
        return FALSE;
    }
    
    snprintf(filePath, MAX_PATH, "%s\\securekernel.exe", systemPath);
    
    attrs = GetFileAttributesA(filePath);
    return (attrs != INVALID_FILE_ATTRIBUTES);
}

/*
 * Main enclave check function
 */
DWORD CheckEnclaveHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    ENCLAVE_INFO info = {0};
    BOOL iumEnabled;
    BOOL skFilePresent;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckEnclaveApi(&info);
    CheckSecureKernel(&info);
    info.lsaIsoPresent = CheckLsaIso();
    iumEnabled = CheckIumRegistry();
    skFilePresent = CheckSecureKernelFile();
    
    /* Detection */
    if (info.vbsSupported || info.lsaIsoPresent || iumEnabled) {
        detected = HYPERV_DETECTED_ENCLAVE;
    }
    
    /* Build details */
    AppendToDetails(result, "VBS Enclave / IUM Detection:\n");
    
    AppendToDetails(result, "\n  Enclave API:\n");
    AppendToDetails(result, "    IsEnclaveTypeSupported: %s\n", 
                   info.enclaveApiAvailable ? "Available" : "Not available");
    AppendToDetails(result, "    SGX Enclaves: %s\n", 
                   info.sgxSupported ? "Supported" : "Not supported");
    AppendToDetails(result, "    VBS Enclaves: %s\n", 
                   info.vbsSupported ? "Supported" : "Not supported");
    
    AppendToDetails(result, "\n  Isolated User Mode (IUM):\n");
    AppendToDetails(result, "    IUM Enabled (Registry): %s\n", 
                   iumEnabled ? "YES" : "NO");
    AppendToDetails(result, "    securekernel.exe: %s\n", 
                   skFilePresent ? "Present" : "Not found");
    
    AppendToDetails(result, "\n  IUM Processes:\n");
    AppendToDetails(result, "    LsaIso.exe: %s\n", 
                   info.lsaIsoPresent ? "Running" : "Not running");
    
    if (info.vbsSupported) {
        AppendToDetails(result, "\n  Note: VBS Enclaves are supported\n");
        AppendToDetails(result, "        Secure code execution is available\n");
    }
    
    if (info.lsaIsoPresent) {
        AppendToDetails(result, "\n  Note: Credential Guard is ACTIVE\n");
        AppendToDetails(result, "        LSASS credentials are protected in VTL1\n");
    }
    
    return detected;
}

/*
 * Quick check for VBS enclave support
 */
BOOL HasVbsEnclaveSupport(void)
{
    ENCLAVE_INFO info = {0};
    CheckEnclaveApi(&info);
    return info.vbsSupported;
}

/*
 * Check if SGX is supported
 */
BOOL HasSgxSupport(void)
{
    ENCLAVE_INFO info = {0};
    CheckEnclaveApi(&info);
    return info.sgxSupported;
}

/*
 * Check if LsaIso is running (Credential Guard active)
 */
BOOL IsCredentialGuardActive(void)
{
    return CheckLsaIso();
}

/*
 * Check if any IUM process is present
 */
BOOL HasIumProcess(void)
{
    return CheckLsaIso() || CheckIumRegistry();
}
