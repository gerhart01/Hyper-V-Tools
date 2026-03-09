/*
 * root_partition_checks.c
 * 
 * Hyper-V Root Partition Detection
 * Distinguishes between running in the root partition (host with VBS/Hyper-V)
 * and running as a guest VM in a child partition.
 * 
 * Key differences:
 * - Root partition has CreatePartitions privilege (can create child VMs)
 * - Root partition has CpuManagement privilege
 * - Root partition has different CPUID 0x40000007 flags
 * - Root partition has "Root Virtual Processor" performance counters
 * - Guest VMs have "Virtual Machine" as System Model
 */

#include "../common/common.h"
#include <pdh.h>
#include <wbemidl.h>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

/* Detection flag for root partition */
#define HYPERV_DETECTED_ROOT_PARTITION  0x04000000

/* HV_PARTITION_PRIVILEGE_MASK bit definitions */
/* EAX bits (0-31) - Access to virtual MSRs */
#define HV_ACCESS_VP_RUNTIME_REG            (1ULL << 0)
#define HV_ACCESS_PARTITION_REF_COUNTER     (1ULL << 1)
#define HV_ACCESS_SYNIC_REGS                (1ULL << 2)
#define HV_ACCESS_SYNTHETIC_TIMER_REGS      (1ULL << 3)
#define HV_ACCESS_INTR_CTRL_REGS            (1ULL << 4)
#define HV_ACCESS_HYPERCALL_MSRS            (1ULL << 5)
#define HV_ACCESS_VP_INDEX                  (1ULL << 6)
#define HV_ACCESS_RESET_REG                 (1ULL << 7)
#define HV_ACCESS_STATS_REG                 (1ULL << 8)
#define HV_ACCESS_PARTITION_REF_TSC         (1ULL << 9)
#define HV_ACCESS_GUEST_IDLE_REG            (1ULL << 10)
#define HV_ACCESS_FREQUENCY_REGS            (1ULL << 11)
#define HV_ACCESS_DEBUG_REGS                (1ULL << 12)
#define HV_ACCESS_REENLIGHTENMENT_CTRLS     (1ULL << 13)

/* EBX bits (32-63) - Access to hypercalls */
#define HV_CREATE_PARTITIONS                (1ULL << 32)  /* Root only! */
#define HV_ACCESS_PARTITION_ID              (1ULL << 33)
#define HV_ACCESS_MEMORY_POOL               (1ULL << 34)
#define HV_ADJUST_MESSAGE_BUFFERS           (1ULL << 35)
#define HV_POST_MESSAGES                    (1ULL << 36)
#define HV_SIGNAL_EVENTS                    (1ULL << 37)
#define HV_CREATE_PORT                      (1ULL << 38)
#define HV_CONNECT_PORT                     (1ULL << 39)
#define HV_ACCESS_STATS                     (1ULL << 40)
/* Reserved bits 41-42 */
#define HV_DEBUGGING                        (1ULL << 43)
#define HV_CPU_MANAGEMENT                   (1ULL << 44)  /* Root only! */
/* Reserved bits 45-47 */
#define HV_ACCESS_VSM                       (1ULL << 48)
#define HV_ACCESS_VP_REGISTERS              (1ULL << 49)
/* Reserved bits 50-51 */
#define HV_ENABLE_EXTENDED_HYPERCALLS       (1ULL << 52)
#define HV_START_VIRTUAL_PROCESSOR          (1ULL << 53)

/* CPUID leaf definitions */
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define HYPERV_CPUID_INTERFACE                  0x40000001
#define HYPERV_CPUID_VERSION                    0x40000002
#define HYPERV_CPUID_FEATURES                   0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO           0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS           0x40000005
#define HYPERV_CPUID_HARDWARE_FEATURES          0x40000006
#define HYPERV_CPUID_CPU_MANAGEMENT_FEATURES    0x40000007
#define HYPERV_CPUID_NESTED_FEATURES            0x4000000A

/* Hypercall codes (from TLFS) */
#define HV_CALL_CREATE_PARTITION            0x0040
#define HV_CALL_INITIALIZE_PARTITION        0x0041
#define HV_CALL_FINALIZE_PARTITION          0x0042
#define HV_CALL_DELETE_PARTITION            0x0043
#define HV_CALL_GET_PARTITION_PROPERTY      0x0044
#define HV_CALL_SET_PARTITION_PROPERTY      0x0045
#define HV_CALL_GET_PARTITION_ID            0x0046
#define HV_CALL_GET_NEXT_CHILD_PARTITION    0x0047
#define HV_CALL_DEPOSIT_MEMORY              0x0048
#define HV_CALL_WITHDRAW_MEMORY             0x0049
#define HV_CALL_MAP_GPA_PAGES               0x004B
#define HV_CALL_UNMAP_GPA_PAGES             0x004C

/* Hypercall status codes */
#define HV_STATUS_SUCCESS                   0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE    0x0002
#define HV_STATUS_INVALID_HYPERCALL_INPUT   0x0003
#define HV_STATUS_ACCESS_DENIED             0x0006
#define HV_STATUS_INVALID_PARTITION_STATE   0x0007
#define HV_STATUS_OPERATION_DENIED          0x0008

/* Root partition detection results */
typedef struct _ROOT_PARTITION_INFO {
    BOOL isHyperVPresent;
    BOOL isRootPartition;
    BOOL isChildPartition;
    
    /* CPUID-based detection */
    BOOL hasCreatePartitionsPrivilege;      /* EBX bit 0 */
    BOOL hasCpuManagementPrivilege;         /* EBX bit 12 */
    BOOL hasReservedIdentityBit;            /* 0x40000007 EAX bit 31 */
    UINT64 partitionPrivilegeMask;
    
    /* Additional info */
    UINT32 maxHypervisorLeaf;
    char hypervisorVendor[16];
    char hypervisorInterface[8];
    
    /* Performance counter based */
    BOOL hasRootVpCounters;
    DWORD partitionCount;
    
    /* WMI based */
    BOOL systemModelIsVirtualMachine;
    char systemModel[256];
    
    /* VMBus detection (kernel-level indicator) */
    BOOL hasVmBus;      /* VMBus present = guest partition */
    BOOL hasVmBusr;     /* VMBusr (VMBus Root) present = root partition */
    
    /* Detailed privilege flags */
    BOOL canAccessVpRuntime;
    BOOL canAccessHypercallMsrs;
    BOOL canPostMessages;
    BOOL canSignalEvents;
    BOOL canAccessVSM;
    BOOL canStartVirtualProcessor;
    
} ROOT_PARTITION_INFO, *PROOT_PARTITION_INFO;


/*
 * Check if hypervisor is present (CPUID.1 ECX bit 31)
 */
static BOOL IsHypervisorPresent(void)
{
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & 0x80000000) != 0;
}

/*
 * Check if this is Microsoft Hyper-V hypervisor
 */
static BOOL IsMicrosoftHyperV(char* vendorOut, int vendorSize, UINT32* maxLeafOut)
{
    int cpuInfo[4] = {0};
    char vendor[13] = {0};
    
    __cpuid(cpuInfo, HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
    
    if (maxLeafOut) {
        *maxLeafOut = cpuInfo[0];
    }
    
    /* Vendor is in EBX, ECX, EDX */
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    
    if (vendorOut && vendorSize > 0) {
        strncpy_s(vendorOut, vendorSize, vendor, _TRUNCATE);
    }
    
    return (strcmp(vendor, "Microsoft Hv") == 0);
}

/*
 * Check hypervisor interface (should be "Hv#1" for TLFS-conformant)
 */
static BOOL CheckHypervisorInterface(char* interfaceOut, int interfaceSize)
{
    int cpuInfo[4] = {0};
    char ifaceStr[5] = {0};
    
    __cpuid(cpuInfo, HYPERV_CPUID_INTERFACE);
    
    memcpy(ifaceStr, &cpuInfo[0], 4);
    ifaceStr[4] = '\0';
    
    if (interfaceOut && interfaceSize > 0) {
        strncpy_s(interfaceOut, interfaceSize, ifaceStr, _TRUNCATE);
    }
    
    return (strcmp(ifaceStr, "Hv#1") == 0);
}

/*
 * Get partition privilege mask from CPUID 0x40000003
 * This is the primary method for root partition detection
 * 
 * Root partition indicators:
 * - CreatePartitions (EBX bit 0) = 1
 * - CpuManagement (EBX bit 12) = 1
 */
static UINT64 GetPartitionPrivilegeMask(PROOT_PARTITION_INFO info)
{
    int cpuInfo[4] = {0};
    UINT64 privilegeMask;
    
    __cpuid(cpuInfo, HYPERV_CPUID_FEATURES);
    
    /* EAX = bits 0-31, EBX = bits 32-63 */
    privilegeMask = ((UINT64)cpuInfo[1] << 32) | (UINT32)cpuInfo[0];
    
    if (info) {
        info->partitionPrivilegeMask = privilegeMask;
        
        /* Check root partition privileges */
        info->hasCreatePartitionsPrivilege = (cpuInfo[1] & 0x00000001) != 0;  /* EBX bit 0 */
        info->hasCpuManagementPrivilege = (cpuInfo[1] & 0x00001000) != 0;     /* EBX bit 12 */
        
        /* Check other privilege flags */
        info->canAccessVpRuntime = (cpuInfo[0] & 0x00000001) != 0;
        info->canAccessHypercallMsrs = (cpuInfo[0] & 0x00000020) != 0;
        info->canPostMessages = (cpuInfo[1] & 0x00000010) != 0;
        info->canSignalEvents = (cpuInfo[1] & 0x00000020) != 0;
        info->canAccessVSM = (cpuInfo[1] & 0x00010000) != 0;
        info->canStartVirtualProcessor = (cpuInfo[1] & 0x00200000) != 0;
    }
    
    return privilegeMask;
}

/*
 * Check CPUID 0x40000007 for CPU management features
 * The ReservedIdentityBit (EAX bit 31) indicates root partition
 * Note: This is less documented and may change
 */
static BOOL CheckCpuManagementFeatures(PROOT_PARTITION_INFO info, UINT32 maxLeaf)
{
    int cpuInfo[4] = {0};
    
    if (maxLeaf < HYPERV_CPUID_CPU_MANAGEMENT_FEATURES) {
        return FALSE;
    }
    
    __cpuid(cpuInfo, HYPERV_CPUID_CPU_MANAGEMENT_FEATURES);
    
    /* EAX bit 31 = ReservedIdentityBit (root partition indicator) */
    BOOL hasIdentityBit = (cpuInfo[0] & 0x80000000) != 0;
    
    if (info) {
        info->hasReservedIdentityBit = hasIdentityBit;
    }
    
    /* Also check other CPU management features */
    /* EAX bit 0 = StartLogicalProcessor */
    /* EAX bit 1 = CreateRootVirtualProcessor */
    
    return hasIdentityBit;
}

/*
 * Check for "Hyper-V Hypervisor Root Virtual Processor" performance counters
 * These counters only exist on the root partition
 */
static BOOL CheckRootVpPerformanceCounters(PROOT_PARTITION_INFO info)
{
    PDH_STATUS status;
    PDH_HQUERY query = NULL;
    PDH_HCOUNTER counter = NULL;
    BOOL hasRootVpCounters = FALSE;
    
    status = PdhOpenQuery(NULL, 0, &query);
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    
    /* Try to add Root Virtual Processor counter - only exists on root partition */
    status = PdhAddEnglishCounterA(query, 
        "\\Hyper-V Hypervisor Root Virtual Processor(_Total)\\% Total Run Time",
        0, &counter);
    
    if (status == ERROR_SUCCESS) {
        hasRootVpCounters = TRUE;
        PdhRemoveCounter(counter);
    }
    
    PdhCloseQuery(query);
    
    if (info) {
        info->hasRootVpCounters = hasRootVpCounters;
    }
    
    return hasRootVpCounters;
}

/*
 * Get partition count from Hyper-V Hypervisor performance counters
 * Root partition: Partitions >= 1
 * If Partitions > 1, there are child VMs running
 */
static DWORD GetHypervisorPartitionCount(void)
{
    PDH_STATUS status;
    PDH_HQUERY query = NULL;
    PDH_HCOUNTER counter = NULL;
    PDH_FMT_COUNTERVALUE value;
    DWORD partitionCount = 0;
    
    status = PdhOpenQuery(NULL, 0, &query);
    if (status != ERROR_SUCCESS) {
        return 0;
    }
    
    status = PdhAddEnglishCounterA(query, 
        "\\Hyper-V Hypervisor\\Partitions",
        0, &counter);
    
    if (status == ERROR_SUCCESS) {
        status = PdhCollectQueryData(query);
        if (status == ERROR_SUCCESS) {
            status = PdhGetFormattedCounterValue(counter, PDH_FMT_LONG, NULL, &value);
            if (status == ERROR_SUCCESS) {
                partitionCount = value.longValue;
            }
        }
        PdhRemoveCounter(counter);
    }
    
    PdhCloseQuery(query);
    
    return partitionCount;
}

/*
 * Check System Model via WMI
 * In a guest VM, System Model = "Virtual Machine"
 * In root partition, System Model = actual hardware model
 */
static BOOL CheckSystemModelWMI(PROOT_PARTITION_INFO info)
{
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pObj = NULL;
    ULONG returned = 0;
    BOOL isVirtualMachine = FALSE;
    
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return FALSE;
    }
    
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    hr = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\CIMV2", NULL, NULL,
        NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    hr = CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    
    hr = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL",
        L"SELECT Model FROM Win32_ComputerSystem",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pObj, &returned);
    if (SUCCEEDED(hr) && returned > 0) {
        VARIANT vtModel;
        VariantInit(&vtModel);
        
        hr = pObj->lpVtbl->Get(pObj, L"Model", 0, &vtModel, NULL, NULL);
        if (SUCCEEDED(hr) && vtModel.vt == VT_BSTR) {
            char modelStr[256] = {0};
            WideCharToMultiByte(CP_ACP, 0, vtModel.bstrVal, -1,
                modelStr, sizeof(modelStr) - 1, NULL, NULL);
            
            if (info) {
                strncpy_s(info->systemModel, sizeof(info->systemModel), modelStr, _TRUNCATE);
            }
            
            /* Check if it's "Virtual Machine" */
            if (strstr(modelStr, "Virtual Machine") != NULL) {
                isVirtualMachine = TRUE;
            }
        }
        VariantClear(&vtModel);
        pObj->lpVtbl->Release(pObj);
    }
    
cleanup:
    if (pEnumerator) pEnumerator->lpVtbl->Release(pEnumerator);
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
    
    if (info) {
        info->systemModelIsVirtualMachine = isVirtualMachine;
    }
    
    return isVirtualMachine;
}

/*
 * Check for VMBus device presence via registry
 * VMBus (guest partition) vs VMBusr (root partition)
 * 
 * VMBus: Present in guest VMs, provides synthetic device interface
 * VMBusr: Present only in root partition (Hyper-V host)
 * 
 * Registry locations:
 * - HKLM\SYSTEM\CurrentControlSet\Services\vmbus
 * - HKLM\SYSTEM\CurrentControlSet\Services\vmbusr
 */
static BOOL CheckVmBusRegistry(PROOT_PARTITION_INFO info)
{
    HKEY hKey;
    LONG result;
    BOOL vmBusFound = FALSE;
    BOOL vmBusrFound = FALSE;
    
    /* Check for VMBus service (guest partition indicator) */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\vmbus", 
        0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        vmBusFound = TRUE;
        RegCloseKey(hKey);
    }
    
    /* Check for VMBusr service (root partition indicator) */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\vmbusr", 
        0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        vmBusrFound = TRUE;
        RegCloseKey(hKey);
    }
    
    if (info) {
        info->hasVmBus = vmBusFound;
        info->hasVmBusr = vmBusrFound;
    }
    
    return vmBusrFound;  /* Return TRUE if root partition */
}

/*
 * Check for VMBus driver files
 * vmbus.sys - guest partition
 * vmbusr.sys - root partition only
 */
static BOOL CheckVmBusDriverFiles(PROOT_PARTITION_INFO info)
{
    char systemRoot[MAX_PATH];
    char driverPath[MAX_PATH];
    DWORD attr;
    BOOL vmBusFound = FALSE;
    BOOL vmBusrFound = FALSE;
    
    if (!GetEnvironmentVariableA("SystemRoot", systemRoot, sizeof(systemRoot))) {
        strcpy_s(systemRoot, sizeof(systemRoot), "C:\\Windows");
    }
    
    /* Check for vmbus.sys */
    snprintf(driverPath, sizeof(driverPath), "%s\\System32\\drivers\\vmbus.sys", systemRoot);
    attr = GetFileAttributesA(driverPath);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        vmBusFound = TRUE;
    }
    
    /* Check for vmbusr.sys (root partition only) */
    snprintf(driverPath, sizeof(driverPath), "%s\\System32\\drivers\\vmbusr.sys", systemRoot);
    attr = GetFileAttributesA(driverPath);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        vmBusrFound = TRUE;
    }
    
    if (info) {
        /* Only update if not already set */
        if (!info->hasVmBus) info->hasVmBus = vmBusFound;
        if (!info->hasVmBusr) info->hasVmBusr = vmBusrFound;
    }
    
    return vmBusrFound;
}

/*
 * Comprehensive VMBus-based partition detection
 * Combines registry and file checks
 */
static void CheckVmBusPresenceUserMode(PROOT_PARTITION_INFO info)
{
    /* Check registry first */
    CheckVmBusRegistry(info);
    
    /* Also check driver files */
    CheckVmBusDriverFiles(info);
    
    if (info->hasVmBusr) {
        printf("[ROOT_PARTITION] VMBusr detected - ROOT PARTITION\n");
    } else if (info->hasVmBus) {
        printf("[ROOT_PARTITION] VMBus detected (no VMBusr) - GUEST PARTITION\n");
    }
}

/*
 * Print detailed root partition analysis
 */
static void PrintRootPartitionDetails(PROOT_PARTITION_INFO info)
{
    printf("\n=== Root Partition Detection Details ===\n\n");
    
    printf("Hypervisor Information:\n");
    printf("  Vendor: %s\n", info->hypervisorVendor);
    printf("  Interface: %s\n", info->hypervisorInterface);
    printf("  Max CPUID Leaf: 0x%08X\n", info->maxHypervisorLeaf);
    
    printf("\nPartition Privilege Mask: 0x%016llX\n", info->partitionPrivilegeMask);
    
    printf("\nRoot Partition Indicators:\n");
    printf("  CreatePartitions privilege (EBX bit 0):  %s\n", 
        info->hasCreatePartitionsPrivilege ? "YES (ROOT)" : "NO (GUEST)");
    printf("  CpuManagement privilege (EBX bit 12):    %s\n",
        info->hasCpuManagementPrivilege ? "YES (ROOT)" : "NO (GUEST)");
    printf("  ReservedIdentityBit (0x40000007 bit 31): %s\n",
        info->hasReservedIdentityBit ? "YES (ROOT)" : "NO (GUEST)");
    
    printf("\nOther Privileges:\n");
    printf("  AccessVpRuntime:        %s\n", info->canAccessVpRuntime ? "Yes" : "No");
    printf("  AccessHypercallMsrs:    %s\n", info->canAccessHypercallMsrs ? "Yes" : "No");
    printf("  PostMessages:           %s\n", info->canPostMessages ? "Yes" : "No");
    printf("  SignalEvents:           %s\n", info->canSignalEvents ? "Yes" : "No");
    printf("  AccessVSM:              %s\n", info->canAccessVSM ? "Yes" : "No");
    printf("  StartVirtualProcessor:  %s\n", info->canStartVirtualProcessor ? "Yes" : "No");
    
    printf("\nPerformance Counter Detection:\n");
    printf("  Root VP Counters present:  %s\n", 
        info->hasRootVpCounters ? "YES (ROOT)" : "NO (GUEST)");
    printf("  Partition count:           %lu\n", info->partitionCount);
    
    printf("\nWMI System Model:\n");
    printf("  Model: %s\n", info->systemModel);
    printf("  Is 'Virtual Machine': %s\n",
        info->systemModelIsVirtualMachine ? "YES (GUEST)" : "NO (ROOT or bare metal)");
    
    printf("\nVMBus Detection:\n");
    printf("  VMBus (guest):   %s\n", info->hasVmBus ? "Present" : "Not found");
    printf("  VMBusr (root):   %s\n", info->hasVmBusr ? "Present (ROOT)" : "Not found");
    
    printf("\n=== Final Determination ===\n");
    if (info->isRootPartition) {
        printf("  Running in: ROOT PARTITION (Hyper-V host / VBS enabled)\n");
    } else if (info->isChildPartition) {
        printf("  Running in: CHILD PARTITION (Guest VM)\n");
    } else if (!info->isHyperVPresent) {
        printf("  Running on: BARE METAL (no hypervisor)\n");
    } else {
        printf("  Running in: UNKNOWN hypervisor environment\n");
    }
}

/*
 * Main detection function
 * Returns TRUE if running in root partition
 */
BOOL CheckRootPartitionHyperV(void)
{
    ROOT_PARTITION_INFO info = {0};
    int rootIndicators = 0;
    int guestIndicators = 0;
    
    /* Step 1: Check if any hypervisor is present */
    if (!IsHypervisorPresent()) {
        printf("[ROOT_PARTITION] No hypervisor present (bare metal)\n");
        return FALSE;
    }
    info.isHyperVPresent = TRUE;
    
    /* Step 2: Check if it's Microsoft Hyper-V */
    if (!IsMicrosoftHyperV(info.hypervisorVendor, sizeof(info.hypervisorVendor), 
                          &info.maxHypervisorLeaf)) {
        printf("[ROOT_PARTITION] Hypervisor is not Microsoft Hyper-V: %s\n", 
            info.hypervisorVendor);
        return FALSE;
    }
    printf("[ROOT_PARTITION] Microsoft Hyper-V detected\n");
    
    /* Step 3: Check hypervisor interface */
    CheckHypervisorInterface(info.hypervisorInterface, sizeof(info.hypervisorInterface));
    
    /* Step 4: Get partition privileges (PRIMARY METHOD) */
    GetPartitionPrivilegeMask(&info);
    
    if (info.hasCreatePartitionsPrivilege) {
        printf("[ROOT_PARTITION] CreatePartitions privilege detected (ROOT)\n");
        rootIndicators++;
    } else {
        guestIndicators++;
    }
    
    if (info.hasCpuManagementPrivilege) {
        printf("[ROOT_PARTITION] CpuManagement privilege detected (ROOT)\n");
        rootIndicators++;
    } else {
        guestIndicators++;
    }
    
    /* Step 5: Check CPU management features (leaf 0x40000007) */
    if (CheckCpuManagementFeatures(&info, info.maxHypervisorLeaf)) {
        printf("[ROOT_PARTITION] ReservedIdentityBit set (ROOT)\n");
        rootIndicators++;
    }
    
    /* Step 6: Check for Root VP performance counters */
    if (CheckRootVpPerformanceCounters(&info)) {
        printf("[ROOT_PARTITION] Root Virtual Processor counters present (ROOT)\n");
        rootIndicators++;
    } else {
        printf("[ROOT_PARTITION] Root Virtual Processor counters not present (GUEST)\n");
        guestIndicators++;
    }
    
    /* Step 7: Get partition count */
    info.partitionCount = GetHypervisorPartitionCount();
    if (info.partitionCount > 0) {
        printf("[ROOT_PARTITION] Partition count: %lu\n", info.partitionCount);
        if (info.partitionCount >= 1 && info.hasCreatePartitionsPrivilege) {
            rootIndicators++;
        }
    }
    
    /* Step 8: Check System Model via WMI */
    CheckSystemModelWMI(&info);
    if (info.systemModelIsVirtualMachine) {
        printf("[ROOT_PARTITION] System Model is 'Virtual Machine' (GUEST)\n");
        guestIndicators++;
    } else if (info.systemModel[0] != '\0') {
        printf("[ROOT_PARTITION] System Model: %s (likely ROOT or bare metal)\n", 
            info.systemModel);
        rootIndicators++;
    }
    
    /* Step 9: Check VMBus/VMBusr presence */
    CheckVmBusPresenceUserMode(&info);
    if (info.hasVmBusr) {
        printf("[ROOT_PARTITION] VMBusr driver found (ROOT)\n");
        rootIndicators += 2;  /* Strong indicator */
    } else if (info.hasVmBus && !info.hasVmBusr) {
        printf("[ROOT_PARTITION] VMBus found but no VMBusr (GUEST)\n");
        guestIndicators++;
    }
    
    /* Determine final result */
    /* Primary criteria: CreatePartitions privilege or VMBusr presence */
    if (info.hasCreatePartitionsPrivilege || info.hasCpuManagementPrivilege || info.hasVmBusr) {
        info.isRootPartition = TRUE;
        info.isChildPartition = FALSE;
    } else {
        info.isRootPartition = FALSE;
        info.isChildPartition = TRUE;
    }
    
    /* Print detailed analysis */
    PrintRootPartitionDetails(&info);
    
    printf("\n[ROOT_PARTITION] Root indicators: %d, Guest indicators: %d\n",
        rootIndicators, guestIndicators);
    
    if (info.isRootPartition) {
        printf("[ROOT_PARTITION] RESULT: Running in ROOT PARTITION\n");
    } else {
        printf("[ROOT_PARTITION] RESULT: Running in CHILD PARTITION (Guest VM)\n");
    }
    
    return info.isRootPartition;
}

/*
 * Quick check - just returns root partition status without verbose output
 */
BOOL IsRootPartitionQuick(void)
{
    int cpuInfo[4] = {0};
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return FALSE;  /* No hypervisor */
    }
    
    /* Check if Microsoft Hyper-V */
    __cpuid(cpuInfo, HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strcmp(vendor, "Microsoft Hv") != 0) {
        return FALSE;  /* Not Hyper-V */
    }
    
    /* Check CreatePartitions privilege */
    __cpuid(cpuInfo, HYPERV_CPUID_FEATURES);
    
    /* EBX bit 0 = CreatePartitions, EBX bit 12 = CpuManagement */
    return (cpuInfo[1] & 0x00001001) != 0;
}

/*
 * Get detailed partition info structure
 */
BOOL GetRootPartitionInfo(PROOT_PARTITION_INFO info)
{
    if (!info) {
        return FALSE;
    }
    
    memset(info, 0, sizeof(ROOT_PARTITION_INFO));
    
    info->isHyperVPresent = IsHypervisorPresent();
    if (!info->isHyperVPresent) {
        return TRUE;
    }
    
    if (!IsMicrosoftHyperV(info->hypervisorVendor, sizeof(info->hypervisorVendor),
                          &info->maxHypervisorLeaf)) {
        return TRUE;
    }
    
    CheckHypervisorInterface(info->hypervisorInterface, sizeof(info->hypervisorInterface));
    GetPartitionPrivilegeMask(info);
    CheckCpuManagementFeatures(info, info->maxHypervisorLeaf);
    CheckRootVpPerformanceCounters(info);
    info->partitionCount = GetHypervisorPartitionCount();
    CheckSystemModelWMI(info);
    CheckVmBusRegistry(info);
    CheckVmBusDriverFiles(info);
    
    /* Determine partition type */
    if (info->hasCreatePartitionsPrivilege || info->hasCpuManagementPrivilege || info->hasVmBusr) {
        info->isRootPartition = TRUE;
        info->isChildPartition = FALSE;
    } else {
        info->isRootPartition = FALSE;
        info->isChildPartition = TRUE;
    }
    
    return TRUE;
}

/*
 * List root-only hypercalls that would fail in child partition
 * These require CreatePartitions or related privileges
 */
void PrintRootOnlyHypercalls(void)
{
    printf("\n=== Root Partition Only Hypercalls (from TLFS) ===\n");
    printf("These hypercalls require CreatePartitions or CpuManagement privilege:\n\n");
    
    printf("Partition Management (require CreatePartitions):\n");
    printf("  0x0040  HvCallCreatePartition\n");
    printf("  0x0041  HvCallInitializePartition\n");
    printf("  0x0042  HvCallFinalizePartition\n");
    printf("  0x0043  HvCallDeletePartition\n");
    printf("  0x0044  HvCallGetPartitionProperty\n");
    printf("  0x0045  HvCallSetPartitionProperty\n");
    printf("  0x0047  HvCallGetNextChildPartition\n");
    
    printf("\nMemory Management (require AccessMemoryPool):\n");
    printf("  0x0048  HvCallDepositMemory\n");
    printf("  0x0049  HvCallWithdrawMemory\n");
    printf("  0x004A  HvCallGetMemoryBalance\n");
    printf("  0x004B  HvCallMapGpaPages\n");
    printf("  0x004C  HvCallUnmapGpaPages\n");
    
    printf("\nVirtual Processor (require CpuManagement):\n");
    printf("  0x004D  HvCallInstallIntercept\n");
    printf("  0x0052  HvCallTranslateVirtualAddress\n");
    printf("  0x005E  HvCallCreateVp\n");
    printf("  0x0099  HvCallStartVirtualProcessor\n");
    
    printf("\nVTL Management (require AccessVSM):\n");
    printf("  0x000D  HvCallEnablePartitionVtl\n");
    printf("  0x000F  HvCallEnableVpVtl\n");
    printf("  0x0011  HvCallVtlCall\n");
    printf("  0x0012  HvCallVtlReturn\n");
    
    printf("\nDebugging (require Debugging):\n");
    printf("  0x000A  HvCallInvokeHypervisorDebugger\n");
    printf("  0x0060  HvCallPostDebugData\n");
    printf("  0x0061  HvCallRetrieveDebugData\n");
    
    printf("\nStatistics (require AccessStats):\n");
    printf("  0x006E  HvCallMapStatsPage\n");
    printf("  0x006F  HvCallUnmapStatsPage\n");
    
    printf("\nNote: Child partitions calling these receive HV_STATUS_ACCESS_DENIED (0x0006)\n");
}

#ifdef TEST_ROOT_PARTITION
int main(void)
{
    printf("Hyper-V Root Partition Detection Test\n");
    printf("=====================================\n\n");
    
    /* Quick check */
    BOOL isRoot = IsRootPartitionQuick();
    printf("Quick check result: %s\n\n", isRoot ? "ROOT PARTITION" : "CHILD PARTITION/BARE METAL");
    
    /* Detailed check */
    CheckRootPartitionHyperV();
    
    /* Print root-only hypercalls */
    PrintRootOnlyHypercalls();
    
    return 0;
}
#endif
