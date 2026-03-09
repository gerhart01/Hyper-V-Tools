/*
 * Hyper-V Detector Tests
 * Tests for each detection method
 * 
 * Usage: hyperv_detector_tests.exe [--json] [--config <n>]
 */

#define _CRT_SECURE_NO_WARNINGS
#include "test_framework.h"
#include "../user_mode/hyperv_detector.h"
/* intrin.h included conditionally via common.h */
#include <tlhelp32.h>
#include <pdh.h>
#include <iphlpapi.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* Forward declarations for detection functions */
extern DWORD CheckCpuidHyperV(PDETECTION_RESULT result);
extern DWORD CheckRegistryHyperV(PDETECTION_RESULT result);
extern DWORD CheckServicesHyperV(PDETECTION_RESULT result);
extern DWORD CheckDevicesHyperV(PDETECTION_RESULT result);
extern DWORD CheckFilesHyperV(PDETECTION_RESULT result);
extern DWORD CheckProcessesHyperV(PDETECTION_RESULT result);
extern DWORD CheckBiosHyperV(PDETECTION_RESULT result);
extern DWORD CheckWMIHyperV(PDETECTION_RESULT result);
extern DWORD CheckMACAddressHyperV(PDETECTION_RESULT result);
extern DWORD CheckFirmwareHyperV(PDETECTION_RESULT result);
extern DWORD CheckTimingHyperV(PDETECTION_RESULT result);
extern DWORD CheckPerfCountersHyperV(PDETECTION_RESULT result);
extern DWORD CheckEventLogsHyperV(PDETECTION_RESULT result);
extern DWORD CheckSecurityFeaturesHyperV(PDETECTION_RESULT result);
extern DWORD CheckDescriptorTablesHyperV(PDETECTION_RESULT result);
extern DWORD CheckEnvHyperV(PDETECTION_RESULT result);
extern DWORD CheckNetworkHyperV(PDETECTION_RESULT result);
extern DWORD CheckDLLHyperV(PDETECTION_RESULT result);
extern DWORD CheckStorageHyperV(PDETECTION_RESULT result);
extern DWORD CheckWindowsFeaturesHyperV(PDETECTION_RESULT result);

/* New detection modules */
extern DWORD CheckIntegrationServicesHyperV(PDETECTION_RESULT result);
extern DWORD CheckMSRHyperV(PDETECTION_RESULT result);
extern DWORD CheckEnlightenmentsHyperV(PDETECTION_RESULT result);
extern DWORD CheckGenerationHyperV(PDETECTION_RESULT result);
extern DWORD CheckAcpiHyperV(PDETECTION_RESULT result);
extern DWORD CheckSyntheticDevicesHyperV(PDETECTION_RESULT result);

/* Quick check functions */
extern BOOL HasIntegrationServicesQuick(void);
extern BOOL HasWAETTable(void);
extern BOOL HasVmBus(void);
extern int GetVMGeneration(void);
extern BOOL IsIsolatedVM(void);
extern DWORD CheckNtQueryHyperV(PDETECTION_RESULT result);
extern BOOL HasHypervisorNtQuery(void);
extern DWORD CheckWmiNamespaceHyperV(PDETECTION_RESULT result);
extern BOOL HasHyperVWmiNamespace(void);
extern BOOL IsHyperVHost(void);
extern DWORD CheckNestedVirtHyperV(PDETECTION_RESULT result);
extern BOOL IsNestedVirtualization(void);
extern BOOL IsConfidentialVM(void);
extern int GetIsolationType(void);
extern DWORD CheckVsmHyperV(PDETECTION_RESULT result);
extern BOOL IsVsmEnabled(void);
extern BOOL IsHvciEnabled(void);
extern BOOL IsCredentialGuardEnabled(void);
extern DWORD GetVtlLevel(void);
extern DWORD CheckPartitionHyperV(PDETECTION_RESULT result);
extern BOOL HasHv1Interface(void);
extern BOOL IsRootPartitionByPrivileges(void);
extern UINT64 GetPartitionPrivilegeMask(void);
extern DWORD CheckSyntheticMsrHyperV(PDETECTION_RESULT result);
extern BOOL HasSyntheticMsrSupport(void);
extern BOOL HasSynicSupport(void);
extern BOOL HasCrashMsrSupport(void);
extern int GetSyntheticMsrCount(void);
extern DWORD CheckRecommendationsHyperV(PDETECTION_RESULT result);
extern BOOL HasHypervisorRecommendations(void);
extern BOOL IsNestedByRecommendation(void);
extern BOOL IsEnlightenedVmcsRecommended(void);
extern DWORD GetSpinlockRetryCount(void);
extern DWORD CheckLimitsHyperV(PDETECTION_RESULT result);
extern BOOL HasImplementationLimits(void);
extern DWORD GetMaxVirtualProcessors(void);
extern DWORD GetMaxLogicalProcessors(void);
extern DWORD CheckHwFeaturesHyperV(PDETECTION_RESULT result);
extern BOOL HasHardwareFeatures(void);
extern BOOL HasSlatEnabled(void);
extern BOOL HasDmaRemapping(void);
extern DWORD GetHardwareFeaturesBitmask(void);
extern DWORD CheckVersionHyperV(PDETECTION_RESULT result);
extern BOOL HasHypervisorVersion(void);
extern DWORD GetHypervisorBuildNumber(void);
extern WORD GetHypervisorMajorVersion(void);
extern WORD GetHypervisorMinorVersion(void);
extern DWORD CheckHvSocketHyperV(PDETECTION_RESULT result);
extern BOOL HasHvSocketSupport(void);
extern BOOL IsInVmBySocket(void);
extern DWORD CheckWhpHyperV(PDETECTION_RESULT result);
extern BOOL HasWhpSupport(void);
extern BOOL IsWhpApiAvailable(void);
extern UINT64 GetWhpFeatures(void);
extern DWORD CheckHcsHyperV(PDETECTION_RESULT result);
extern BOOL HasHcsSupport(void);
extern BOOL IsComputeServiceRunning(void);
extern BOOL IsHyperVHostByHcs(void);
extern DWORD CheckGpuPvHyperV(PDETECTION_RESULT result);
extern BOOL HasGpuPv(void);
extern BOOL HasHyperVVideo(void);
extern BOOL IsBasicDisplayOnly(void);
extern DWORD CheckEnclaveHyperV(PDETECTION_RESULT result);
extern BOOL HasVbsEnclaveSupport(void);
extern BOOL HasSgxSupport(void);
extern BOOL IsCredentialGuardActive(void);
extern BOOL HasIumProcess(void);
extern DWORD CheckVmwpHyperV(PDETECTION_RESULT result);
extern BOOL HasVmwpProcess(void);
extern DWORD GetRunningVmCount(void);
extern BOOL IsVmmsRunning(void);
extern BOOL IsHyperVHostByVmwp(void);
extern DWORD CheckHypercallInterfaceHyperV(PDETECTION_RESULT result);
extern BOOL HasHypercallInterface(void);
extern BOOL CanPostMessage(void);
extern BOOL CanSignalEvent(void);
extern BOOL IsRootByHypercallPrivileges(void);
extern DWORD CheckSavedStateHyperV(PDETECTION_RESULT result);
extern BOOL HasSavedStateApi(void);
extern BOOL HasVmDirectory(void);
extern BOOL HasSavedStateFiles(void);
extern DWORD CheckHvciHyperV(PDETECTION_RESULT result);
extern BOOL IsHvciPolicyEnabled(void);
extern BOOL IsHvciRunning(void);
extern BOOL IsKcfgActive(void);
extern BOOL IsKcetActive(void);
extern DWORD CheckVmbusChannelHyperV(PDETECTION_RESULT result);
extern BOOL HasVmbusChannel(void);
extern DWORD GetVmbusChannelCount(void);
extern BOOL IsGuestByVmbus(void);
extern BOOL IsRootByVmbusr(void);
extern DWORD CheckHyperGuardHyperV(PDETECTION_RESULT result);
extern BOOL IsHyperGuardEnabled(void);
extern BOOL HasSecureKernel(void);
extern BOOL IsSecurePoolEnabled(void);
extern DWORD GetHyperGuardState(void);
extern DWORD CheckSystemGuardHyperV(PDETECTION_RESULT result);
extern BOOL IsSystemGuardRunning(void);
extern BOOL IsDrtmEnabled(void);
extern BOOL IsSecureBootEnabled(void);
extern BOOL IsTpmPresent(void);
extern DWORD CheckContainerHyperV(PDETECTION_RESULT result);
extern BOOL HasContainerSupport(void);
extern BOOL IsSandboxEnabled(void);
extern BOOL IsWdagEnabled(void);
extern BOOL IsInsideContainer(void);
extern DWORD CheckHvEmulationHyperV(PDETECTION_RESULT result);
extern BOOL HasEmulationApi(void);
extern BOOL CanEmulateIo(void);
extern BOOL CanEmulateMmio(void);
extern DWORD CheckSecureCallsHyperV(PDETECTION_RESULT result);
extern BOOL HasSecureCallsSupport(void);
extern BOOL IsVtl1Active(void);
extern BOOL HasIumProcesses(void);
extern BOOL IsVbsEnabledSecureCalls(void);
extern DWORD CheckExoPartitionHyperV(PDETECTION_RESULT result);
extern BOOL HasExoPartitionApi(void);
extern BOOL IsVidDriverLoaded(void);
extern BOOL HasGuestMemoryAccess(void);
extern BOOL HasForensicsTools(void);
extern DWORD CheckHvDebuggingHyperV(PDETECTION_RESULT result);
extern BOOL IsDebugModeEnabled(void);
extern BOOL IsHypervisorDebugEnabled(void);
extern BOOL IsVmDebuggingEnabled(void);
extern BOOL HasDebuggingTools(void);
extern DWORD CheckVmcsEptHyperV(PDETECTION_RESULT result);
extern BOOL HasVmxSupport(void);
extern BOOL HasEptSupport(void);
extern BOOL IsEnlightenedVmcsEnabled(void);
extern BOOL IsNestedVmxAllowed(void);

/* Root partition checks */
extern BOOL CheckRootPartitionHyperV(void);
extern BOOL IsRootPartitionQuick(void);

/* Global state */
static BOOL g_isAdmin = FALSE;
static BOOL g_hasHypervisor = FALSE;
static BOOL g_jsonOutput = FALSE;
static char g_configName[256] = "unknown";

/*
 * Helper: Check if hypervisor is present
 */
static BOOL CheckHypervisorPresent(void)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & 0x80000000) != 0;
}

/*
 * Helper: Check if running as admin
 */
static BOOL CheckIsAdmin(void)
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, 
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

/* ============================================================================
 * CPUID Tests
 * ============================================================================ */

static TEST_RESULT Test_CPUID_HypervisorPresent(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    BOOL present = FALSE;
    
    __cpuid(cpuInfo, 1);
    present = (cpuInfo[2] & 0x80000000) != 0;
    snprintf(msg, msgSize, "Hypervisor bit: %s", present ? "SET" : "NOT SET");
    return TEST_PASS;
}

static TEST_RESULT Test_CPUID_VendorString(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    char vendor[13] = {0};
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    __cpuid(cpuInfo, 0x40000000);
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    
    snprintf(msg, msgSize, "Vendor: %s", vendor);
    return TEST_PASS;
}

static TEST_RESULT Test_CPUID_MaxLeaf(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    __cpuid(cpuInfo, 0x40000000);
    snprintf(msg, msgSize, "Max leaf: 0x%08X", cpuInfo[0]);
    return TEST_PASS;
}

static TEST_RESULT Test_CPUID_Interface(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    char iface[5] = {0};
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    __cpuid(cpuInfo, 0x40000001);
    memcpy(iface, &cpuInfo[0], 4);
    iface[4] = '\0';
    
    snprintf(msg, msgSize, "Interface: %s", iface);
    return TEST_PASS;
}

static TEST_RESULT Test_CPUID_PrivilegeMask(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    BOOL createPart = FALSE;
    BOOL cpuMgmt = FALSE;
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    __cpuid(cpuInfo, 0x40000003);
    
    createPart = (cpuInfo[1] & 0x01) != 0;
    cpuMgmt = (cpuInfo[1] & 0x1000) != 0;
    
    snprintf(msg, msgSize, "EAX=0x%08X EBX=0x%08X CreatePart=%d CpuMgmt=%d",
        cpuInfo[0], cpuInfo[1], createPart, cpuMgmt);
    return TEST_PASS;
}

static TEST_RESULT Test_CPUID_FullCheck(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckCpuidHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Registry Tests
 * ============================================================================ */

static TEST_RESULT Test_Registry_HyperVKeys(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckRegistryHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Registry_VmBusService(char* msg, size_t msgSize)
{
    HKEY hKey = NULL;
    LONG res = 0;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vmbus", 0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        snprintf(msg, msgSize, "VMBus service found");
    } else {
        snprintf(msg, msgSize, "VMBus service not found");
    }
    return TEST_PASS;
}

static TEST_RESULT Test_Registry_VmBusrService(char* msg, size_t msgSize)
{
    HKEY hKey = NULL;
    LONG res = 0;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vmbusr", 0, KEY_READ, &hKey);
    
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        snprintf(msg, msgSize, "VMBusr service found (ROOT PARTITION)");
    } else {
        snprintf(msg, msgSize, "VMBusr service not found");
    }
    return TEST_PASS;
}

/* ============================================================================
 * Service Tests
 * ============================================================================ */

static TEST_RESULT Test_Services_HyperVServices(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckServicesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Device Tests
 * ============================================================================ */

static TEST_RESULT Test_Devices_HyperVDevices(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckDevicesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * File Tests
 * ============================================================================ */

static TEST_RESULT Test_Files_VmBusDriver(char* msg, size_t msgSize)
{
    char path[MAX_PATH] = {0};
    DWORD attr = 0;
    
    GetSystemDirectoryA(path, sizeof(path));
    strcat_s(path, sizeof(path), "\\drivers\\vmbus.sys");
    
    attr = GetFileAttributesA(path);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        snprintf(msg, msgSize, "vmbus.sys found");
    } else {
        snprintf(msg, msgSize, "vmbus.sys not found");
    }
    return TEST_PASS;
}

static TEST_RESULT Test_Files_VmBusrDriver(char* msg, size_t msgSize)
{
    char path[MAX_PATH] = {0};
    DWORD attr = 0;
    
    GetSystemDirectoryA(path, sizeof(path));
    strcat_s(path, sizeof(path), "\\drivers\\vmbusr.sys");
    
    attr = GetFileAttributesA(path);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        snprintf(msg, msgSize, "vmbusr.sys found (ROOT PARTITION)");
    } else {
        snprintf(msg, msgSize, "vmbusr.sys not found");
    }
    return TEST_PASS;
}

static TEST_RESULT Test_Files_FullCheck(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckFilesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Process Tests
 * ============================================================================ */

static TEST_RESULT Test_Processes_HyperVProcesses(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckProcessesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * BIOS/SMBIOS Tests
 * ============================================================================ */

static TEST_RESULT Test_BIOS_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckBiosHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * WMI Tests
 * ============================================================================ */

static TEST_RESULT Test_WMI_ComputerSystem(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckWMIHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * MAC Address Tests
 * ============================================================================ */

static TEST_RESULT Test_MAC_HyperVRange(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckMACAddressHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Firmware Tests
 * ============================================================================ */

static TEST_RESULT Test_Firmware_UEFI(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    if (!g_isAdmin) {
        snprintf(msg, msgSize, "Requires admin");
        return TEST_SKIP;
    }
    
    flags = CheckFirmwareHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Timing Tests
 * ============================================================================ */

static TEST_RESULT Test_Timing_CPUID(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckTimingHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Performance Counter Tests
 * ============================================================================ */

static TEST_RESULT Test_PerfCounter_HyperV(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckPerfCountersHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_PerfCounter_RootVP(char* msg, size_t msgSize)
{
    PDH_HQUERY hQuery = NULL;
    PDH_HCOUNTER hCounter = NULL;
    PDH_STATUS status = 0;
    
    status = PdhOpenQueryA(NULL, 0, &hQuery);
    if (status != ERROR_SUCCESS) {
        snprintf(msg, msgSize, "Failed to open PDH query");
        return TEST_ERROR;
    }
    
    status = PdhAddCounterA(hQuery, 
        "\\Hyper-V Hypervisor Root Virtual Processor(*)\\% Total Run Time",
        0, &hCounter);
    
    PdhCloseQuery(hQuery);
    
    if (status == ERROR_SUCCESS) {
        snprintf(msg, msgSize, "Root VP counters found (ROOT PARTITION)");
    } else {
        snprintf(msg, msgSize, "Root VP counters not found");
    }
    return TEST_PASS;
}

/* ============================================================================
 * Event Log Tests
 * ============================================================================ */

static TEST_RESULT Test_EventLog_HyperV(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckEventLogsHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Security Features Tests
 * ============================================================================ */

static TEST_RESULT Test_Security_VBS(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckSecurityFeaturesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Descriptor Table Tests
 * ============================================================================ */

static TEST_RESULT Test_Descriptor_Tables(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckDescriptorTablesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Environment Tests
 * ============================================================================ */

static TEST_RESULT Test_Environment_Variables(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckEnvHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Network Tests
 * ============================================================================ */

static TEST_RESULT Test_Network_Adapters(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckNetworkHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * DLL Tests
 * ============================================================================ */

static TEST_RESULT Test_DLL_HyperVModules(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckDLLHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Storage Tests
 * ============================================================================ */

static TEST_RESULT Test_Storage_VirtualDisks(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckStorageHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Features Tests
 * ============================================================================ */

static TEST_RESULT Test_Features_HyperVFeatures(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckWindowsFeaturesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

/* ============================================================================
 * Root Partition Tests
 * ============================================================================ */

static TEST_RESULT Test_RootPartition_Quick(char* msg, size_t msgSize)
{
    BOOL isRoot = FALSE;
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    isRoot = IsRootPartitionQuick();
    snprintf(msg, msgSize, "%s", isRoot ? "ROOT PARTITION" : "CHILD PARTITION");
    return TEST_PASS;
}

static TEST_RESULT Test_RootPartition_CreatePartitions(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    BOOL hasPriv = FALSE;
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    __cpuid(cpuInfo, 0x40000003);
    hasPriv = (cpuInfo[1] & 0x01) != 0;
    
    snprintf(msg, msgSize, "CreatePartitions: %s", hasPriv ? "YES (ROOT)" : "NO (GUEST)");
    return TEST_PASS;
}

static TEST_RESULT Test_RootPartition_CpuManagement(char* msg, size_t msgSize)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    BOOL hasPriv = FALSE;
    
    if (!g_hasHypervisor) {
        snprintf(msg, msgSize, "No hypervisor");
        return TEST_SKIP;
    }
    
    __cpuid(cpuInfo, 0x40000003);
    hasPriv = (cpuInfo[1] & 0x1000) != 0;
    
    snprintf(msg, msgSize, "CpuManagement: %s", hasPriv ? "YES (ROOT)" : "NO (GUEST)");
    return TEST_PASS;
}

static TEST_RESULT Test_RootPartition_VMBusr(char* msg, size_t msgSize)
{
    HKEY hKey = NULL;
    BOOL hasVmbusr = FALSE;
    LONG res = 0;
    
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\vmbusr", 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) {
        hasVmbusr = TRUE;
        RegCloseKey(hKey);
    }
    
    snprintf(msg, msgSize, "VMBusr: %s", hasVmbusr ? "PRESENT (ROOT)" : "NOT PRESENT");
    return TEST_PASS;
}

/* ============================================================================
 * New Module Tests (Phase 7)
 * ============================================================================ */

static TEST_RESULT Test_IntegrationServices_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckIntegrationServicesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_IntegrationServices_Quick(char* msg, size_t msgSize)
{
    BOOL hasIC = HasIntegrationServicesQuick();
    snprintf(msg, msgSize, "IC Present: %s", hasIC ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_MSR_Permissions(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckMSRHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Enlightenments_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckEnlightenmentsHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Enlightenments_Isolated(char* msg, size_t msgSize)
{
    BOOL isolated = IsIsolatedVM();
    snprintf(msg, msgSize, "Isolated/CoCo VM: %s", isolated ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_Generation_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckGenerationHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Generation_Quick(char* msg, size_t msgSize)
{
    int gen = GetVMGeneration();
    snprintf(msg, msgSize, "Generation: %s", 
             gen == 1 ? "Gen1 (BIOS)" : 
             gen == 2 ? "Gen2 (UEFI)" : "Unknown");
    return TEST_PASS;
}

static TEST_RESULT Test_ACPI_Tables(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckAcpiHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_ACPI_WAET(char* msg, size_t msgSize)
{
    BOOL hasWaet = HasWAETTable();
    snprintf(msg, msgSize, "WAET Table: %s", hasWaet ? "Present (VM)" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_Synthetic_Devices(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckSyntheticDevicesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Synthetic_VMBus(char* msg, size_t msgSize)
{
    BOOL hasVmbus = HasVmBus();
    snprintf(msg, msgSize, "VMBus: %s", hasVmbus ? "Present" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_NtQuery_Hypervisor(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckNtQueryHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_NtQuery_Quick(char* msg, size_t msgSize)
{
    BOOL hasHv = HasHypervisorNtQuery();
    snprintf(msg, msgSize, "NtQuery Hypervisor: %s", hasHv ? "Present" : "Not found");
    return TEST_PASS;
}

/* WMI Namespace Tests */
static TEST_RESULT Test_WmiNamespace_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckWmiNamespaceHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_WmiNamespace_Quick(char* msg, size_t msgSize)
{
    BOOL hasNs = HasHyperVWmiNamespace();
    snprintf(msg, msgSize, "WMI Namespace: %s", hasNs ? "Present (HOST)" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_WmiNamespace_IsHost(char* msg, size_t msgSize)
{
    BOOL isHost = IsHyperVHost();
    snprintf(msg, msgSize, "Is Hyper-V Host: %s", isHost ? "YES" : "NO");
    return TEST_PASS;
}

/* Nested Virtualization Tests */
static TEST_RESULT Test_NestedVirt_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckNestedVirtHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_NestedVirt_Quick(char* msg, size_t msgSize)
{
    BOOL isNested = IsNestedVirtualization();
    snprintf(msg, msgSize, "Nested Virt: %s", isNested ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_NestedVirt_CoCo(char* msg, size_t msgSize)
{
    BOOL isCoCo = IsConfidentialVM();
    int isoType = GetIsolationType();
    const char* typeName = "None";
    
    switch (isoType) {
        case 1: typeName = "VBS"; break;
        case 2: typeName = "SEV-SNP"; break;
        case 3: typeName = "TDX"; break;
    }
    
    snprintf(msg, msgSize, "CoCo VM: %s (Type: %s)", isCoCo ? "YES" : "NO", typeName);
    return TEST_PASS;
}

/* VSM Tests */
static TEST_RESULT Test_Vsm_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckVsmHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Vsm_Quick(char* msg, size_t msgSize)
{
    BOOL vsmEnabled = IsVsmEnabled();
    snprintf(msg, msgSize, "VBS/VSM: %s", vsmEnabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_Vsm_Hvci(char* msg, size_t msgSize)
{
    BOOL hvciEnabled = IsHvciEnabled();
    snprintf(msg, msgSize, "HVCI: %s", hvciEnabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_Vsm_CredGuard(char* msg, size_t msgSize)
{
    BOOL cgEnabled = IsCredentialGuardEnabled();
    snprintf(msg, msgSize, "Credential Guard: %s", cgEnabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_Vsm_Vtl(char* msg, size_t msgSize)
{
    DWORD vtl = GetVtlLevel();
    snprintf(msg, msgSize, "Current VTL: %d", vtl);
    return TEST_PASS;
}

/* Partition Tests */
static TEST_RESULT Test_Partition_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckPartitionHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Partition_Interface(char* msg, size_t msgSize)
{
    BOOL hasHv1 = HasHv1Interface();
    snprintf(msg, msgSize, "Hv#1 Interface: %s", hasHv1 ? "Present" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_Partition_IsRoot(char* msg, size_t msgSize)
{
    BOOL isRoot = IsRootPartitionByPrivileges();
    snprintf(msg, msgSize, "Root Partition: %s", isRoot ? "YES" : "NO (Guest)");
    return TEST_PASS;
}

static TEST_RESULT Test_Partition_Privileges(char* msg, size_t msgSize)
{
    UINT64 privMask = GetPartitionPrivilegeMask();
    snprintf(msg, msgSize, "Privilege Mask: 0x%016llX", privMask);
    return TEST_PASS;
}

/* Synthetic MSR Tests */
static TEST_RESULT Test_SynthMsr_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckSyntheticMsrHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_SynthMsr_Quick(char* msg, size_t msgSize)
{
    BOOL hasMsr = HasSyntheticMsrSupport();
    snprintf(msg, msgSize, "Synthetic MSRs: %s", hasMsr ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_SynthMsr_Synic(char* msg, size_t msgSize)
{
    BOOL hasSynic = HasSynicSupport();
    snprintf(msg, msgSize, "SynIC: %s", hasSynic ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_SynthMsr_Crash(char* msg, size_t msgSize)
{
    BOOL hasCrash = HasCrashMsrSupport();
    snprintf(msg, msgSize, "Crash MSRs: %s", hasCrash ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_SynthMsr_Count(char* msg, size_t msgSize)
{
    int count = GetSyntheticMsrCount();
    snprintf(msg, msgSize, "Available MSRs: ~%d", count);
    return TEST_PASS;
}

/* Recommendations Tests */
static TEST_RESULT Test_Recommendations_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckRecommendationsHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Recommendations_Quick(char* msg, size_t msgSize)
{
    BOOL hasRec = HasHypervisorRecommendations();
    snprintf(msg, msgSize, "Recommendations: %s", hasRec ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_Recommendations_Nested(char* msg, size_t msgSize)
{
    BOOL isNested = IsNestedByRecommendation();
    snprintf(msg, msgSize, "Nested (by hint): %s", isNested ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_Recommendations_Spinlock(char* msg, size_t msgSize)
{
    DWORD retries = GetSpinlockRetryCount();
    if (retries == 0xFFFFFFFF) {
        snprintf(msg, msgSize, "Spinlock: Never notify");
    } else {
        snprintf(msg, msgSize, "Spinlock Retries: %u", retries);
    }
    return TEST_PASS;
}

/* Limits Tests */
static TEST_RESULT Test_Limits_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckLimitsHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Limits_Quick(char* msg, size_t msgSize)
{
    BOOL hasLimits = HasImplementationLimits();
    snprintf(msg, msgSize, "Implementation Limits: %s", hasLimits ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_Limits_MaxVP(char* msg, size_t msgSize)
{
    DWORD maxVp = GetMaxVirtualProcessors();
    snprintf(msg, msgSize, "Max Virtual Processors: %u", maxVp);
    return TEST_PASS;
}

static TEST_RESULT Test_Limits_MaxLP(char* msg, size_t msgSize)
{
    DWORD maxLp = GetMaxLogicalProcessors();
    snprintf(msg, msgSize, "Max Logical Processors: %u", maxLp);
    return TEST_PASS;
}

/* HW Features Tests */
static TEST_RESULT Test_HwFeatures_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHwFeaturesHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_HwFeatures_Quick(char* msg, size_t msgSize)
{
    BOOL hasHw = HasHardwareFeatures();
    snprintf(msg, msgSize, "Hardware Features: %s", hasHw ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_HwFeatures_Slat(char* msg, size_t msgSize)
{
    BOOL hasSlat = HasSlatEnabled();
    snprintf(msg, msgSize, "SLAT (EPT/NPT): %s", hasSlat ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_HwFeatures_Bitmask(char* msg, size_t msgSize)
{
    DWORD bitmask = GetHardwareFeaturesBitmask();
    snprintf(msg, msgSize, "HW Features Bitmask: 0x%08X", bitmask);
    return TEST_PASS;
}

/* Version Tests */
static TEST_RESULT Test_Version_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckVersionHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Version_Build(char* msg, size_t msgSize)
{
    DWORD build = GetHypervisorBuildNumber();
    snprintf(msg, msgSize, "Build Number: %u", build);
    return TEST_PASS;
}

static TEST_RESULT Test_Version_Major(char* msg, size_t msgSize)
{
    WORD major = GetHypervisorMajorVersion();
    WORD minor = GetHypervisorMinorVersion();
    snprintf(msg, msgSize, "Version: %u.%u", major, minor);
    return TEST_PASS;
}

/* HvSocket Tests */
static TEST_RESULT Test_HvSocket_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHvSocketHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_HvSocket_Support(char* msg, size_t msgSize)
{
    BOOL hasSupport = HasHvSocketSupport();
    snprintf(msg, msgSize, "AF_HYPERV: %s", hasSupport ? "Supported" : "Not supported");
    return TEST_PASS;
}

static TEST_RESULT Test_HvSocket_InVm(char* msg, size_t msgSize)
{
    BOOL inVm = IsInVmBySocket();
    snprintf(msg, msgSize, "In VM (by socket): %s", inVm ? "YES" : "NO");
    return TEST_PASS;
}

/* WHP Tests */
static TEST_RESULT Test_Whp_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckWhpHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Whp_Support(char* msg, size_t msgSize)
{
    BOOL hasSupport = HasWhpSupport();
    snprintf(msg, msgSize, "WHP: %s", hasSupport ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_Whp_Api(char* msg, size_t msgSize)
{
    BOOL apiAvail = IsWhpApiAvailable();
    snprintf(msg, msgSize, "WHP API: %s", apiAvail ? "Available" : "Not available");
    return TEST_PASS;
}

/* HCS Tests */
static TEST_RESULT Test_Hcs_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHcsHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Hcs_Support(char* msg, size_t msgSize)
{
    BOOL hasSupport = HasHcsSupport();
    snprintf(msg, msgSize, "HCS API: %s", hasSupport ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_Hcs_Service(char* msg, size_t msgSize)
{
    BOOL running = IsComputeServiceRunning();
    snprintf(msg, msgSize, "Compute Service: %s", running ? "Running" : "Not running");
    return TEST_PASS;
}

static TEST_RESULT Test_Hcs_IsHost(char* msg, size_t msgSize)
{
    BOOL isHost = IsHyperVHostByHcs();
    snprintf(msg, msgSize, "Is Host (HCS): %s", isHost ? "YES" : "NO");
    return TEST_PASS;
}

/* GPU-PV Tests */
static TEST_RESULT Test_GpuPv_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckGpuPvHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_GpuPv_HasGpu(char* msg, size_t msgSize)
{
    BOOL hasGpu = HasGpuPv();
    snprintf(msg, msgSize, "GPU-PV: %s", hasGpu ? "Detected" : "Not detected");
    return TEST_PASS;
}

static TEST_RESULT Test_GpuPv_HvVideo(char* msg, size_t msgSize)
{
    BOOL hvVideo = HasHyperVVideo();
    snprintf(msg, msgSize, "Hyper-V Video: %s", hvVideo ? "Found" : "Not found");
    return TEST_PASS;
}

/* Enclave Tests */
static TEST_RESULT Test_Enclave_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckEnclaveHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Enclave_Vbs(char* msg, size_t msgSize)
{
    BOOL vbs = HasVbsEnclaveSupport();
    snprintf(msg, msgSize, "VBS Enclaves: %s", vbs ? "Supported" : "Not supported");
    return TEST_PASS;
}

static TEST_RESULT Test_Enclave_Sgx(char* msg, size_t msgSize)
{
    BOOL sgx = HasSgxSupport();
    snprintf(msg, msgSize, "SGX: %s", sgx ? "Supported" : "Not supported");
    return TEST_PASS;
}

static TEST_RESULT Test_Enclave_CredGuard(char* msg, size_t msgSize)
{
    BOOL active = IsCredentialGuardActive();
    snprintf(msg, msgSize, "Credential Guard: %s", active ? "Active" : "Not active");
    return TEST_PASS;
}

/* VMWP Tests */
static TEST_RESULT Test_Vmwp_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckVmwpHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Vmwp_Found(char* msg, size_t msgSize)
{
    BOOL found = HasVmwpProcess();
    snprintf(msg, msgSize, "vmwp.exe: %s", found ? "Found" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_Vmwp_VmCount(char* msg, size_t msgSize)
{
    DWORD count = GetRunningVmCount();
    snprintf(msg, msgSize, "Running VMs: %u", count);
    return TEST_PASS;
}

static TEST_RESULT Test_Vmwp_IsHost(char* msg, size_t msgSize)
{
    BOOL isHost = IsHyperVHostByVmwp();
    snprintf(msg, msgSize, "Is Host (VMWP): %s", isHost ? "YES" : "NO");
    return TEST_PASS;
}

/* Hypercall Interface Tests */
static TEST_RESULT Test_HypercallIf_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHypercallInterfaceHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_HypercallIf_Available(char* msg, size_t msgSize)
{
    BOOL avail = HasHypercallInterface();
    snprintf(msg, msgSize, "Hypercall Interface: %s", avail ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_HypercallIf_PostMsg(char* msg, size_t msgSize)
{
    BOOL can = CanPostMessage();
    snprintf(msg, msgSize, "PostMessage: %s", can ? "Allowed" : "Denied");
    return TEST_PASS;
}

static TEST_RESULT Test_HypercallIf_IsRoot(char* msg, size_t msgSize)
{
    BOOL isRoot = IsRootByHypercallPrivileges();
    snprintf(msg, msgSize, "Is Root (Hypercall): %s", isRoot ? "YES" : "NO");
    return TEST_PASS;
}

/* Saved State Tests */
static TEST_RESULT Test_SavedState_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckSavedStateHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_SavedState_Api(char* msg, size_t msgSize)
{
    BOOL hasApi = HasSavedStateApi();
    snprintf(msg, msgSize, "Saved State API: %s", hasApi ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_SavedState_VmDir(char* msg, size_t msgSize)
{
    BOOL hasDir = HasVmDirectory();
    snprintf(msg, msgSize, "VM Directory: %s", hasDir ? "Found" : "Not found");
    return TEST_PASS;
}

/* HVCI Tests */
static TEST_RESULT Test_Hvci_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHvciHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Hvci_Enabled(char* msg, size_t msgSize)
{
    BOOL enabled = IsHvciPolicyEnabled();
    snprintf(msg, msgSize, "HVCI Enabled: %s", enabled ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_Hvci_Running(char* msg, size_t msgSize)
{
    BOOL running = IsHvciRunning();
    snprintf(msg, msgSize, "HVCI Running: %s", running ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_Hvci_Kcfg(char* msg, size_t msgSize)
{
    BOOL active = IsKcfgActive();
    snprintf(msg, msgSize, "KCFG: %s", active ? "Active" : "Not active");
    return TEST_PASS;
}

/* VMBus Channel Tests */
static TEST_RESULT Test_VmbusChannel_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckVmbusChannelHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_VmbusChannel_HasChannel(char* msg, size_t msgSize)
{
    BOOL has = HasVmbusChannel();
    snprintf(msg, msgSize, "VMBus Channel: %s", has ? "Found" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_VmbusChannel_Count(char* msg, size_t msgSize)
{
    DWORD count = GetVmbusChannelCount();
    snprintf(msg, msgSize, "Channel Count: %u", count);
    return TEST_PASS;
}

static TEST_RESULT Test_VmbusChannel_IsGuest(char* msg, size_t msgSize)
{
    BOOL isGuest = IsGuestByVmbus();
    snprintf(msg, msgSize, "Is Guest (VMBus): %s", isGuest ? "YES" : "NO");
    return TEST_PASS;
}

/* HyperGuard Tests */
static TEST_RESULT Test_HyperGuard_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHyperGuardHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_HyperGuard_Enabled(char* msg, size_t msgSize)
{
    BOOL enabled = IsHyperGuardEnabled();
    snprintf(msg, msgSize, "HyperGuard: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_HyperGuard_SecureKernel(char* msg, size_t msgSize)
{
    BOOL present = HasSecureKernel();
    snprintf(msg, msgSize, "Secure Kernel: %s", present ? "Present" : "Not found");
    return TEST_PASS;
}

static TEST_RESULT Test_HyperGuard_SecurePool(char* msg, size_t msgSize)
{
    BOOL enabled = IsSecurePoolEnabled();
    snprintf(msg, msgSize, "Secure Pool: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

/* System Guard Tests */
static TEST_RESULT Test_SystemGuard_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckSystemGuardHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_SystemGuard_Running(char* msg, size_t msgSize)
{
    BOOL running = IsSystemGuardRunning();
    snprintf(msg, msgSize, "System Guard: %s", running ? "Running" : "Not running");
    return TEST_PASS;
}

static TEST_RESULT Test_SystemGuard_SecureBoot(char* msg, size_t msgSize)
{
    BOOL enabled = IsSecureBootEnabled();
    snprintf(msg, msgSize, "Secure Boot: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_SystemGuard_Tpm(char* msg, size_t msgSize)
{
    BOOL present = IsTpmPresent();
    snprintf(msg, msgSize, "TPM: %s", present ? "Present" : "Not detected");
    return TEST_PASS;
}

/* Container Tests */
static TEST_RESULT Test_Container_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckContainerHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_Container_Support(char* msg, size_t msgSize)
{
    BOOL support = HasContainerSupport();
    snprintf(msg, msgSize, "Container Support: %s", support ? "YES" : "NO");
    return TEST_PASS;
}

static TEST_RESULT Test_Container_Sandbox(char* msg, size_t msgSize)
{
    BOOL enabled = IsSandboxEnabled();
    snprintf(msg, msgSize, "Windows Sandbox: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_Container_Wdag(char* msg, size_t msgSize)
{
    BOOL enabled = IsWdagEnabled();
    snprintf(msg, msgSize, "WDAG: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

/* HV Emulation Tests */
static TEST_RESULT Test_HvEmulation_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHvEmulationHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_HvEmulation_Api(char* msg, size_t msgSize)
{
    BOOL available = HasEmulationApi();
    snprintf(msg, msgSize, "Emulation API: %s", available ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_HvEmulation_Io(char* msg, size_t msgSize)
{
    BOOL canIo = CanEmulateIo();
    snprintf(msg, msgSize, "I/O Emulation: %s", canIo ? "Available" : "Not available");
    return TEST_PASS;
}

/* Secure Calls Tests */
static TEST_RESULT Test_SecureCalls_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckSecureCallsHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_SecureCalls_Support(char* msg, size_t msgSize)
{
    BOOL support = HasSecureCallsSupport();
    snprintf(msg, msgSize, "Secure Calls: %s", support ? "Supported" : "Not supported");
    return TEST_PASS;
}

static TEST_RESULT Test_SecureCalls_Vtl1(char* msg, size_t msgSize)
{
    BOOL active = IsVtl1Active();
    snprintf(msg, msgSize, "VTL1: %s", active ? "Active" : "Not active");
    return TEST_PASS;
}

static TEST_RESULT Test_SecureCalls_Ium(char* msg, size_t msgSize)
{
    BOOL hasIum = HasIumProcesses();
    snprintf(msg, msgSize, "IUM Processes: %s", hasIum ? "Found" : "Not found");
    return TEST_PASS;
}

/* EXO Partition Tests */
static TEST_RESULT Test_ExoPartition_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckExoPartitionHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_ExoPartition_Api(char* msg, size_t msgSize)
{
    BOOL hasApi = HasExoPartitionApi();
    snprintf(msg, msgSize, "EXO Partition API: %s", hasApi ? "Available" : "Not available");
    return TEST_PASS;
}

static TEST_RESULT Test_ExoPartition_Vid(char* msg, size_t msgSize)
{
    BOOL loaded = IsVidDriverLoaded();
    snprintf(msg, msgSize, "VID Driver: %s", loaded ? "Loaded" : "Not loaded");
    return TEST_PASS;
}

static TEST_RESULT Test_ExoPartition_Forensics(char* msg, size_t msgSize)
{
    BOOL hasTools = HasForensicsTools();
    snprintf(msg, msgSize, "Forensics Tools: %s", hasTools ? "Found" : "Not found");
    return TEST_PASS;
}

/* HV Debugging Tests */
static TEST_RESULT Test_HvDebugging_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckHvDebuggingHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_HvDebugging_Mode(char* msg, size_t msgSize)
{
    BOOL enabled = IsDebugModeEnabled();
    snprintf(msg, msgSize, "Debug Mode: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_HvDebugging_Hypervisor(char* msg, size_t msgSize)
{
    BOOL enabled = IsHypervisorDebugEnabled();
    snprintf(msg, msgSize, "Hypervisor Debug: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

static TEST_RESULT Test_HvDebugging_Tools(char* msg, size_t msgSize)
{
    BOOL hasTools = HasDebuggingTools();
    snprintf(msg, msgSize, "Debug Tools: %s", hasTools ? "Found" : "Not found");
    return TEST_PASS;
}

/* VMCS/EPT Tests */
static TEST_RESULT Test_VmcsEpt_Check(char* msg, size_t msgSize)
{
    DETECTION_RESULT result = {0};
    DWORD flags = 0;
    
    flags = CheckVmcsEptHyperV(&result);
    snprintf(msg, msgSize, "Flags=0x%08X", flags);
    return TEST_PASS;
}

static TEST_RESULT Test_VmcsEpt_Vmx(char* msg, size_t msgSize)
{
    BOOL hasVmx = HasVmxSupport();
    snprintf(msg, msgSize, "VMX: %s", hasVmx ? "Supported" : "Not supported");
    return TEST_PASS;
}

static TEST_RESULT Test_VmcsEpt_Ept(char* msg, size_t msgSize)
{
    BOOL hasEpt = HasEptSupport();
    snprintf(msg, msgSize, "EPT: %s", hasEpt ? "Supported" : "Not supported");
    return TEST_PASS;
}

static TEST_RESULT Test_VmcsEpt_Enlightened(char* msg, size_t msgSize)
{
    BOOL enabled = IsEnlightenedVmcsEnabled();
    snprintf(msg, msgSize, "Enlightened VMCS: %s", enabled ? "Enabled" : "Disabled");
    return TEST_PASS;
}

/* ============================================================================
 * Test Registration
 * ============================================================================ */

static TEST_CASE g_testCases[] = {
    /* CPUID Tests */
    {"Hypervisor Present Bit", "CPUID", Test_CPUID_HypervisorPresent, FALSE, FALSE},
    {"Vendor String", "CPUID", Test_CPUID_VendorString, FALSE, TRUE},
    {"Max Hypervisor Leaf", "CPUID", Test_CPUID_MaxLeaf, FALSE, TRUE},
    {"Hypervisor Interface", "CPUID", Test_CPUID_Interface, FALSE, TRUE},
    {"Privilege Mask", "CPUID", Test_CPUID_PrivilegeMask, FALSE, TRUE},
    {"Full CPUID Check", "CPUID", Test_CPUID_FullCheck, FALSE, FALSE},
    
    /* Registry Tests */
    {"Hyper-V Registry Keys", "Registry", Test_Registry_HyperVKeys, FALSE, FALSE},
    {"VMBus Service", "Registry", Test_Registry_VmBusService, FALSE, FALSE},
    {"VMBusr Service", "Registry", Test_Registry_VmBusrService, FALSE, FALSE},
    
    /* Service Tests */
    {"Hyper-V Services", "Services", Test_Services_HyperVServices, FALSE, FALSE},
    
    /* Device Tests */
    {"Hyper-V Devices", "Devices", Test_Devices_HyperVDevices, FALSE, FALSE},
    
    /* File Tests */
    {"vmbus.sys Driver", "Files", Test_Files_VmBusDriver, FALSE, FALSE},
    {"vmbusr.sys Driver", "Files", Test_Files_VmBusrDriver, FALSE, FALSE},
    {"Full File Check", "Files", Test_Files_FullCheck, FALSE, FALSE},
    
    /* Process Tests */
    {"Hyper-V Processes", "Processes", Test_Processes_HyperVProcesses, FALSE, FALSE},
    
    /* BIOS Tests */
    {"BIOS/SMBIOS Check", "BIOS", Test_BIOS_Check, FALSE, FALSE},
    
    /* WMI Tests */
    {"WMI Computer System", "WMI", Test_WMI_ComputerSystem, FALSE, FALSE},
    
    /* MAC Tests */
    {"MAC Address Range", "MAC", Test_MAC_HyperVRange, FALSE, FALSE},
    
    /* Firmware Tests */
    {"UEFI Firmware", "Firmware", Test_Firmware_UEFI, TRUE, FALSE},
    
    /* Timing Tests */
    {"CPUID Timing", "Timing", Test_Timing_CPUID, FALSE, FALSE},
    
    /* Performance Counter Tests */
    {"Hyper-V Counters", "PerfCounter", Test_PerfCounter_HyperV, FALSE, FALSE},
    {"Root VP Counters", "PerfCounter", Test_PerfCounter_RootVP, FALSE, FALSE},
    
    /* Event Log Tests */
    {"Hyper-V Event Logs", "EventLog", Test_EventLog_HyperV, FALSE, FALSE},
    
    /* Security Tests */
    {"VBS/Security Features", "Security", Test_Security_VBS, FALSE, FALSE},
    
    /* Descriptor Tests */
    {"Descriptor Tables", "Descriptor", Test_Descriptor_Tables, FALSE, FALSE},
    
    /* Environment Tests */
    {"Environment Variables", "Environment", Test_Environment_Variables, FALSE, FALSE},
    
    /* Network Tests */
    {"Network Adapters", "Network", Test_Network_Adapters, FALSE, FALSE},
    
    /* DLL Tests */
    {"Hyper-V DLLs", "DLL", Test_DLL_HyperVModules, FALSE, FALSE},
    
    /* Storage Tests */
    {"Virtual Storage", "Storage", Test_Storage_VirtualDisks, FALSE, FALSE},
    
    /* Features Tests */
    {"Hyper-V Features", "Features", Test_Features_HyperVFeatures, FALSE, FALSE},
    
    /* Root Partition Tests */
    {"Quick Root Check", "RootPartition", Test_RootPartition_Quick, FALSE, TRUE},
    {"CreatePartitions Privilege", "RootPartition", Test_RootPartition_CreatePartitions, FALSE, TRUE},
    {"CpuManagement Privilege", "RootPartition", Test_RootPartition_CpuManagement, FALSE, TRUE},
    {"VMBusr Presence", "RootPartition", Test_RootPartition_VMBusr, FALSE, FALSE},
    
    /* Integration Services Tests */
    {"IC Full Check", "IntegrationServices", Test_IntegrationServices_Check, FALSE, FALSE},
    {"IC Quick Check", "IntegrationServices", Test_IntegrationServices_Quick, FALSE, FALSE},
    
    /* MSR Tests */
    {"MSR Permissions", "MSR", Test_MSR_Permissions, FALSE, TRUE},
    
    /* Enlightenments Tests */
    {"Enlightenments Check", "Enlightenments", Test_Enlightenments_Check, FALSE, TRUE},
    {"Isolated VM Check", "Enlightenments", Test_Enlightenments_Isolated, FALSE, TRUE},
    
    /* Generation Tests */
    {"Generation Full Check", "Generation", Test_Generation_Check, FALSE, FALSE},
    {"Generation Quick Check", "Generation", Test_Generation_Quick, FALSE, FALSE},
    
    /* ACPI Tests */
    {"ACPI Tables Check", "ACPI", Test_ACPI_Tables, FALSE, FALSE},
    {"WAET Table Check", "ACPI", Test_ACPI_WAET, FALSE, FALSE},
    
    /* Synthetic Devices Tests */
    {"Synthetic Devices Check", "SyntheticDevices", Test_Synthetic_Devices, FALSE, FALSE},
    {"VMBus Check", "SyntheticDevices", Test_Synthetic_VMBus, FALSE, FALSE},
    
    /* NtQuery Tests */
    {"NtQuery Full Check", "NtQuery", Test_NtQuery_Hypervisor, FALSE, FALSE},
    {"NtQuery Quick Check", "NtQuery", Test_NtQuery_Quick, FALSE, FALSE},
    
    /* WMI Namespace Tests */
    {"WMI Namespace Full Check", "WmiNamespace", Test_WmiNamespace_Check, FALSE, FALSE},
    {"WMI Namespace Quick Check", "WmiNamespace", Test_WmiNamespace_Quick, FALSE, FALSE},
    {"Is Hyper-V Host", "WmiNamespace", Test_WmiNamespace_IsHost, FALSE, FALSE},
    
    /* Nested Virtualization Tests */
    {"Nested Virt Full Check", "NestedVirt", Test_NestedVirt_Check, FALSE, TRUE},
    {"Nested Virt Quick Check", "NestedVirt", Test_NestedVirt_Quick, FALSE, TRUE},
    {"Confidential VM Check", "NestedVirt", Test_NestedVirt_CoCo, FALSE, TRUE},
    
    /* VSM Tests */
    {"VSM Full Check", "VSM", Test_Vsm_Check, FALSE, FALSE},
    {"VSM Quick Check", "VSM", Test_Vsm_Quick, FALSE, FALSE},
    {"HVCI Status", "VSM", Test_Vsm_Hvci, FALSE, FALSE},
    {"Credential Guard Status", "VSM", Test_Vsm_CredGuard, FALSE, FALSE},
    {"Current VTL", "VSM", Test_Vsm_Vtl, FALSE, TRUE},
    
    /* Partition Tests */
    {"Partition Full Check", "Partition", Test_Partition_Check, FALSE, TRUE},
    {"Hv#1 Interface", "Partition", Test_Partition_Interface, FALSE, TRUE},
    {"Is Root Partition", "Partition", Test_Partition_IsRoot, FALSE, TRUE},
    {"Partition Privileges", "Partition", Test_Partition_Privileges, FALSE, TRUE},
    
    /* Synthetic MSR Tests */
    {"Synth MSR Full Check", "SynthMSR", Test_SynthMsr_Check, FALSE, TRUE},
    {"Synth MSR Quick Check", "SynthMSR", Test_SynthMsr_Quick, FALSE, TRUE},
    {"SynIC Available", "SynthMSR", Test_SynthMsr_Synic, FALSE, TRUE},
    {"Crash MSR Available", "SynthMSR", Test_SynthMsr_Crash, FALSE, TRUE},
    {"Synth MSR Count", "SynthMSR", Test_SynthMsr_Count, FALSE, TRUE},
    
    /* Recommendations Tests */
    {"Recommendations Full Check", "Recommendations", Test_Recommendations_Check, FALSE, TRUE},
    {"Recommendations Quick Check", "Recommendations", Test_Recommendations_Quick, FALSE, TRUE},
    {"Nested (by hint)", "Recommendations", Test_Recommendations_Nested, FALSE, TRUE},
    {"Spinlock Retries", "Recommendations", Test_Recommendations_Spinlock, FALSE, TRUE},
    
    /* Limits Tests */
    {"Limits Full Check", "Limits", Test_Limits_Check, FALSE, TRUE},
    {"Limits Quick Check", "Limits", Test_Limits_Quick, FALSE, TRUE},
    {"Max Virtual Processors", "Limits", Test_Limits_MaxVP, FALSE, TRUE},
    {"Max Logical Processors", "Limits", Test_Limits_MaxLP, FALSE, TRUE},
    
    /* Hardware Features Tests */
    {"HW Features Full Check", "HwFeatures", Test_HwFeatures_Check, FALSE, TRUE},
    {"HW Features Quick Check", "HwFeatures", Test_HwFeatures_Quick, FALSE, TRUE},
    {"SLAT (EPT/NPT)", "HwFeatures", Test_HwFeatures_Slat, FALSE, TRUE},
    {"HW Features Bitmask", "HwFeatures", Test_HwFeatures_Bitmask, FALSE, TRUE},
    
    /* Version Tests */
    {"Version Full Check", "Version", Test_Version_Check, FALSE, TRUE},
    {"Build Number", "Version", Test_Version_Build, FALSE, TRUE},
    {"Version Number", "Version", Test_Version_Major, FALSE, TRUE},
    
    /* HvSocket Tests */
    {"HvSocket Full Check", "HvSocket", Test_HvSocket_Check, FALSE, FALSE},
    {"AF_HYPERV Support", "HvSocket", Test_HvSocket_Support, FALSE, FALSE},
    {"In VM (Socket)", "HvSocket", Test_HvSocket_InVm, FALSE, FALSE},
    
    /* WHP Tests */
    {"WHP Full Check", "WHP", Test_Whp_Check, FALSE, FALSE},
    {"WHP Support", "WHP", Test_Whp_Support, FALSE, FALSE},
    {"WHP API", "WHP", Test_Whp_Api, FALSE, FALSE},
    
    /* HCS Tests */
    {"HCS Full Check", "HCS", Test_Hcs_Check, FALSE, FALSE},
    {"HCS API Support", "HCS", Test_Hcs_Support, FALSE, FALSE},
    {"Compute Service", "HCS", Test_Hcs_Service, FALSE, FALSE},
    {"Is Host (HCS)", "HCS", Test_Hcs_IsHost, FALSE, FALSE},
    
    /* GPU-PV Tests */
    {"GPU-PV Full Check", "GpuPv", Test_GpuPv_Check, FALSE, FALSE},
    {"GPU-PV Detection", "GpuPv", Test_GpuPv_HasGpu, FALSE, FALSE},
    {"Hyper-V Video", "GpuPv", Test_GpuPv_HvVideo, FALSE, FALSE},
    
    /* Enclave Tests */
    {"Enclave Full Check", "Enclave", Test_Enclave_Check, FALSE, FALSE},
    {"VBS Enclaves", "Enclave", Test_Enclave_Vbs, FALSE, FALSE},
    {"SGX Support", "Enclave", Test_Enclave_Sgx, FALSE, FALSE},
    {"Credential Guard", "Enclave", Test_Enclave_CredGuard, FALSE, FALSE},
    
    /* VMWP Tests */
    {"VMWP Full Check", "VMWP", Test_Vmwp_Check, FALSE, FALSE},
    {"vmwp.exe Found", "VMWP", Test_Vmwp_Found, FALSE, FALSE},
    {"Running VM Count", "VMWP", Test_Vmwp_VmCount, FALSE, FALSE},
    {"Is Host (VMWP)", "VMWP", Test_Vmwp_IsHost, FALSE, FALSE},
    
    /* Hypercall Interface Tests */
    {"Hypercall IF Full Check", "HypercallIF", Test_HypercallIf_Check, FALSE, TRUE},
    {"Hypercall IF Available", "HypercallIF", Test_HypercallIf_Available, FALSE, TRUE},
    {"PostMessage Allowed", "HypercallIF", Test_HypercallIf_PostMsg, FALSE, TRUE},
    {"Is Root (Hypercall)", "HypercallIF", Test_HypercallIf_IsRoot, FALSE, TRUE},
    
    /* Saved State Tests */
    {"Saved State Full Check", "SavedState", Test_SavedState_Check, FALSE, FALSE},
    {"Saved State API", "SavedState", Test_SavedState_Api, FALSE, FALSE},
    {"VM Directory", "SavedState", Test_SavedState_VmDir, FALSE, FALSE},
    
    /* HVCI Tests */
    {"HVCI Full Check", "HVCI", Test_Hvci_Check, FALSE, FALSE},
    {"HVCI Enabled", "HVCI", Test_Hvci_Enabled, FALSE, FALSE},
    {"HVCI Running", "HVCI", Test_Hvci_Running, FALSE, FALSE},
    {"KCFG Active", "HVCI", Test_Hvci_Kcfg, FALSE, FALSE},
    
    /* VMBus Channel Tests */
    {"VMBus Channel Full Check", "VmbusChannel", Test_VmbusChannel_Check, FALSE, FALSE},
    {"Has VMBus Channel", "VmbusChannel", Test_VmbusChannel_HasChannel, FALSE, FALSE},
    {"VMBus Channel Count", "VmbusChannel", Test_VmbusChannel_Count, FALSE, FALSE},
    {"Is Guest (VMBus)", "VmbusChannel", Test_VmbusChannel_IsGuest, FALSE, FALSE},
    
    /* HyperGuard Tests */
    {"HyperGuard Full Check", "HyperGuard", Test_HyperGuard_Check, FALSE, FALSE},
    {"HyperGuard Enabled", "HyperGuard", Test_HyperGuard_Enabled, FALSE, FALSE},
    {"Secure Kernel", "HyperGuard", Test_HyperGuard_SecureKernel, FALSE, FALSE},
    {"Secure Pool", "HyperGuard", Test_HyperGuard_SecurePool, FALSE, FALSE},
    
    /* System Guard Tests */
    {"System Guard Full Check", "SystemGuard", Test_SystemGuard_Check, FALSE, FALSE},
    {"System Guard Running", "SystemGuard", Test_SystemGuard_Running, FALSE, FALSE},
    {"Secure Boot", "SystemGuard", Test_SystemGuard_SecureBoot, FALSE, FALSE},
    {"TPM Present", "SystemGuard", Test_SystemGuard_Tpm, FALSE, FALSE},
    
    /* Container Tests */
    {"Container Full Check", "Container", Test_Container_Check, FALSE, FALSE},
    {"Container Support", "Container", Test_Container_Support, FALSE, FALSE},
    {"Windows Sandbox", "Container", Test_Container_Sandbox, FALSE, FALSE},
    {"WDAG", "Container", Test_Container_Wdag, FALSE, FALSE},
    
    /* HV Emulation Tests */
    {"HV Emulation Full Check", "HvEmulation", Test_HvEmulation_Check, FALSE, FALSE},
    {"Emulation API", "HvEmulation", Test_HvEmulation_Api, FALSE, FALSE},
    {"I/O Emulation", "HvEmulation", Test_HvEmulation_Io, FALSE, FALSE},
    
    /* Secure Calls Tests */
    {"Secure Calls Full Check", "SecureCalls", Test_SecureCalls_Check, FALSE, FALSE},
    {"Secure Calls Support", "SecureCalls", Test_SecureCalls_Support, FALSE, FALSE},
    {"VTL1 Active", "SecureCalls", Test_SecureCalls_Vtl1, FALSE, FALSE},
    {"IUM Processes", "SecureCalls", Test_SecureCalls_Ium, FALSE, FALSE},
    
    /* EXO Partition Tests */
    {"EXO Partition Full Check", "ExoPartition", Test_ExoPartition_Check, FALSE, FALSE},
    {"EXO Partition API", "ExoPartition", Test_ExoPartition_Api, FALSE, FALSE},
    {"VID Driver", "ExoPartition", Test_ExoPartition_Vid, FALSE, FALSE},
    {"Forensics Tools", "ExoPartition", Test_ExoPartition_Forensics, FALSE, FALSE},
    
    /* HV Debugging Tests */
    {"HV Debugging Full Check", "HvDebugging", Test_HvDebugging_Check, FALSE, FALSE},
    {"Debug Mode", "HvDebugging", Test_HvDebugging_Mode, FALSE, FALSE},
    {"Hypervisor Debug", "HvDebugging", Test_HvDebugging_Hypervisor, FALSE, FALSE},
    {"Debug Tools", "HvDebugging", Test_HvDebugging_Tools, FALSE, FALSE},
    
    /* VMCS/EPT Tests */
    {"VMCS/EPT Full Check", "VmcsEpt", Test_VmcsEpt_Check, FALSE, TRUE},
    {"VMX Support", "VmcsEpt", Test_VmcsEpt_Vmx, FALSE, TRUE},
    {"EPT Support", "VmcsEpt", Test_VmcsEpt_Ept, FALSE, TRUE},
    {"Enlightened VMCS", "VmcsEpt", Test_VmcsEpt_Enlightened, FALSE, TRUE},
    
    /* End marker */
    {NULL, NULL, NULL, FALSE, FALSE}
};

/* ============================================================================
 * Main
 * ============================================================================ */

static void PrintUsage(const char* progName)
{
    printf("Hyper-V Detector Test Suite\n\n");
    printf("Usage: %s [options]\n\n", progName);
    printf("Options:\n");
    printf("  --json           Output results in JSON format\n");
    printf("  --config <n>  Configuration name for reporting\n");
    printf("  --help           Show this help\n");
    printf("\nExamples:\n");
    printf("  %s                           Run all tests\n", progName);
    printf("  %s --json --config \"VM-01\"   Run with JSON output\n", progName);
}

static void DetectConfiguration(void)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    char vendor[13] = {0};
    
    /* Auto-detect configuration */
    if (!g_hasHypervisor) {
        strcpy_s(g_configName, sizeof(g_configName), "BareMetal");
        return;
    }
    
    /* Check for Microsoft Hyper-V */
    __cpuid(cpuInfo, 0x40000000);
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    
    if (strcmp(vendor, "Microsoft Hv") == 0) {
        /* Check if root partition */
        __cpuid(cpuInfo, 0x40000003);
        if (cpuInfo[1] & 0x01) {
            strcpy_s(g_configName, sizeof(g_configName), "HyperV-RootPartition");
        } else {
            strcpy_s(g_configName, sizeof(g_configName), "HyperV-GuestVM");
        }
    } else {
        snprintf(g_configName, sizeof(g_configName), "OtherHypervisor-%s", vendor);
    }
}

int main(int argc, char* argv[])
{
    const char* currentCategory = NULL;
    int i = 0;
    
    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            g_jsonOutput = TRUE;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            strcpy_s(g_configName, sizeof(g_configName), argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    /* Initialize */
    EnableConsoleColors();
    g_isAdmin = CheckIsAdmin();
    g_hasHypervisor = CheckHypervisorPresent();
    
    if (strcmp(g_configName, "unknown") == 0) {
        DetectConfiguration();
    }
    
    /* Print header */
    if (!g_jsonOutput) {
        printf("\n");
        printf("%s========================================%s\n", COLOR_CYAN, COLOR_RESET);
        printf("     HYPER-V DETECTOR TEST SUITE\n");
        printf("%s========================================%s\n", COLOR_CYAN, COLOR_RESET);
        printf("  Configuration: %s\n", g_configName);
        printf("  Administrator: %s\n", g_isAdmin ? "Yes" : "No");
        printf("  Hypervisor:    %s\n", g_hasHypervisor ? "Present" : "Not detected");
        printf("%s========================================%s\n", COLOR_CYAN, COLOR_RESET);
    }
    
    /* Run tests */
    g_testStats.startTime = GetTickCount();
    
    for (i = 0; g_testCases[i].name != NULL; i++) {
        /* Print category header if changed */
        if (!g_jsonOutput && 
            (currentCategory == NULL || strcmp(currentCategory, g_testCases[i].category) != 0)) {
            currentCategory = g_testCases[i].category;
            PrintCategoryHeader(currentCategory);
        }
        
        RunTest(&g_testCases[i], g_isAdmin, g_hasHypervisor);
    }
    
    g_testStats.endTime = GetTickCount();
    
    /* Print summary */
    if (g_jsonOutput) {
        PrintJsonResult(g_configName);
    } else {
        PrintTestSummary();
    }
    
    return (g_testStats.failed > 0 || g_testStats.errors > 0) ? 1 : 0;
}
