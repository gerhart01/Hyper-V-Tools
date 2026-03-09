/**
 * perfcounter_checks.c - Performance Counter based Hyper-V detection
 * 
 * Detects Hyper-V through Windows Performance Counters that are
 * specific to Hyper-V virtualization.
 */

#include "hyperv_detector.h"
#include <pdh.h>
#include <pdhmsg.h>

#pragma comment(lib, "pdh.lib")

// Detection flag for performance counters
#define HYPERV_DETECTED_PERFCOUNTER 0x00020000

// Hyper-V specific performance counter paths
static const char* HYPERV_PERF_COUNTERS[] = {
    "\\Hyper-V Hypervisor\\Logical Processors",
    "\\Hyper-V Hypervisor\\Virtual Processors",
    "\\Hyper-V Hypervisor\\Partitions",
    "\\Hyper-V Hypervisor Logical Processor(*)\\% Guest Run Time",
    "\\Hyper-V Hypervisor Logical Processor(*)\\% Hypervisor Run Time",
    "\\Hyper-V Hypervisor Logical Processor(*)\\% Total Run Time",
    "\\Hyper-V Hypervisor Virtual Processor(*)\\% Guest Run Time",
    "\\Hyper-V Hypervisor Virtual Processor(*)\\% Hypervisor Run Time",
    "\\Hyper-V Hypervisor Root Virtual Processor(*)\\% Guest Run Time",
    "\\Hyper-V Virtual Machine Health Summary\\Health Ok",
    "\\Hyper-V Virtual Machine Bus Provider Pipes(*)\\Bytes Read/sec",
    "\\Hyper-V Virtual Storage Device(*)\\Read Bytes/sec",
    "\\Hyper-V Virtual Network Adapter(*)\\Bytes Received/sec",
    "\\Hyper-V Virtual IDE Controller (Emulated)(*)\\Read Bytes/sec",
    "\\Hyper-V Virtual Switch(*)\\Bytes/sec",
    "\\Hyper-V VM Vid Driver(*)\\Remote Physical Pages",
    "\\Hyper-V VM Vid Partition(*)\\Physical Pages Allocated",
    NULL
};

// Counter object names to enumerate
static const char* HYPERV_COUNTER_OBJECTS[] = {
    "Hyper-V Hypervisor",
    "Hyper-V Hypervisor Logical Processor",
    "Hyper-V Hypervisor Virtual Processor",
    "Hyper-V Hypervisor Root Virtual Processor",
    "Hyper-V Virtual Machine Health Summary",
    "Hyper-V Virtual Machine Bus Provider Pipes",
    "Hyper-V Virtual Storage Device",
    "Hyper-V Virtual Network Adapter",
    "Hyper-V Virtual IDE Controller (Emulated)",
    "Hyper-V Virtual Switch",
    "Hyper-V VM Vid Driver",
    "Hyper-V VM Vid Partition",
    "Hyper-V Dynamic Memory VM",
    "Hyper-V Dynamic Memory Integration Service",
    "Hyper-V Replica VM",
    NULL
};

static BOOL CheckPerfCounterExists(const char* counterPath) {
    PDH_HQUERY hQuery;
    PDH_HCOUNTER hCounter;
    PDH_STATUS status;
    
    status = PdhOpenQuery(NULL, 0, &hQuery);
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    
    status = PdhAddCounterA(hQuery, counterPath, 0, &hCounter);
    PdhCloseQuery(hQuery);
    
    return (status == ERROR_SUCCESS);
}

static BOOL GetPerfCounterValue(const char* counterPath, double* value) {
    PDH_HQUERY hQuery;
    PDH_HCOUNTER hCounter;
    PDH_STATUS status;
    PDH_FMT_COUNTERVALUE counterValue;
    
    *value = 0.0;
    
    status = PdhOpenQuery(NULL, 0, &hQuery);
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    
    status = PdhAddCounterA(hQuery, counterPath, 0, &hCounter);
    if (status != ERROR_SUCCESS) {
        PdhCloseQuery(hQuery);
        return FALSE;
    }
    
    status = PdhCollectQueryData(hQuery);
    if (status != ERROR_SUCCESS) {
        PdhCloseQuery(hQuery);
        return FALSE;
    }
    
    Sleep(100);  // Wait for second sample
    
    status = PdhCollectQueryData(hQuery);
    if (status != ERROR_SUCCESS) {
        PdhCloseQuery(hQuery);
        return FALSE;
    }
    
    status = PdhGetFormattedCounterValue(hCounter, PDH_FMT_DOUBLE, NULL, &counterValue);
    if (status == ERROR_SUCCESS) {
        *value = counterValue.doubleValue;
    }
    
    PdhCloseQuery(hQuery);
    return (status == ERROR_SUCCESS);
}

static BOOL EnumeratePerfCounterObject(const char* objectName, PDETECTION_RESULT result) {
    DWORD counterListSize = 0;
    DWORD instanceListSize = 0;
    PDH_STATUS status;
    
    // Get buffer sizes
    status = PdhEnumObjectItemsA(
        NULL, NULL, objectName,
        NULL, &counterListSize,
        NULL, &instanceListSize,
        PERF_DETAIL_WIZARD, 0
    );
    
    if (status != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        return FALSE;
    }
    
    if (counterListSize == 0 && instanceListSize == 0) {
        return FALSE;
    }
    
    char* counterList = (char*)malloc(counterListSize);
    char* instanceList = (char*)malloc(instanceListSize);
    
    if (!counterList || !instanceList) {
        free(counterList);
        free(instanceList);
        return FALSE;
    }
    
    status = PdhEnumObjectItemsA(
        NULL, NULL, objectName,
        counterList, &counterListSize,
        instanceList, &instanceListSize,
        PERF_DETAIL_WIZARD, 0
    );
    
    BOOL found = FALSE;
    if (status == ERROR_SUCCESS) {
        found = TRUE;
        
        // List instances
        char* instance = instanceList;
        int instanceCount = 0;
        while (*instance) {
            instanceCount++;
            instance += strlen(instance) + 1;
        }
        
        if (instanceCount > 0) {
            AppendToDetails(result, "PerfCounter: %s has %d instance(s)\n", objectName, instanceCount);
        }
    }
    
    free(counterList);
    free(instanceList);
    return found;
}

DWORD CheckPerfCountersHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    double value;
    
    AppendToDetails(result, "PerfCounter: Checking Hyper-V performance counters...\n");
    
    // Check for Hyper-V counter objects
    for (int i = 0; HYPERV_COUNTER_OBJECTS[i] != NULL; i++) {
        if (EnumeratePerfCounterObject(HYPERV_COUNTER_OBJECTS[i], result)) {
            detected |= HYPERV_DETECTED_PERFCOUNTER;
            AppendToDetails(result, "PerfCounter: Found object: %s\n", HYPERV_COUNTER_OBJECTS[i]);
        }
    }
    
    // Check specific counters and get values
    for (int i = 0; HYPERV_PERF_COUNTERS[i] != NULL; i++) {
        if (CheckPerfCounterExists(HYPERV_PERF_COUNTERS[i])) {
            detected |= HYPERV_DETECTED_PERFCOUNTER;
            
            if (GetPerfCounterValue(HYPERV_PERF_COUNTERS[i], &value)) {
                AppendToDetails(result, "PerfCounter: %s = %.2f\n", 
                               HYPERV_PERF_COUNTERS[i], value);
            } else {
                AppendToDetails(result, "PerfCounter: Found: %s\n", HYPERV_PERF_COUNTERS[i]);
            }
        }
    }
    
    // Check for VM-specific counters
    if (CheckPerfCounterExists("\\Hyper-V VM Vid Partition(*)\\Physical Pages Allocated")) {
        detected |= HYPERV_DETECTED_PERFCOUNTER;
        AppendToDetails(result, "PerfCounter: Running as Hyper-V guest (VID partition detected)\n");
    }
    
    // Check hypervisor partition counter
    if (GetPerfCounterValue("\\Hyper-V Hypervisor\\Partitions", &value) && value > 0) {
        AppendToDetails(result, "PerfCounter: Hypervisor managing %.0f partition(s)\n", value);
        detected |= HYPERV_DETECTED_PERFCOUNTER;
    }
    
    return detected;
}

// ETW (Event Tracing for Windows) provider check
DWORD CheckETWProvidersHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Known Hyper-V ETW provider GUIDs
    static const char* HYPERV_ETW_PROVIDERS[] = {
        "{F3A71A4B-6118-4257-8CCB-39A33BA059D4}",  // Hyper-V Worker
        "{E7F9D17F-3699-4F98-98A2-3C39999F6028}",  // Hyper-V VMMS
        "{52FC89F8-995E-434C-A91E-199986449890}",  // Hyper-V VMBus
        "{4CC09F6C-E8B0-4C1D-A88D-91D0AD3E4FC9}",  // Hyper-V VmSwitch
        "{67DC0D66-3695-47C0-9642-33F76F7BD7AD}",  // Hyper-V Integration Components
        "{AE3F5BF8-AB9F-56D6-29C8-8C312AAA59A0}",  // Hyper-V VMSP
        "{5931D877-4860-4EE7-A95C-610A5F0D1407}",  // Hyper-V VID
        NULL
    };
    
    // Check if providers are registered
    HKEY hKey;
    char keyPath[256];
    
    for (int i = 0; HYPERV_ETW_PROVIDERS[i] != NULL; i++) {
        snprintf(keyPath, sizeof(keyPath), 
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\%s",
                HYPERV_ETW_PROVIDERS[i]);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            detected |= HYPERV_DETECTED_PERFCOUNTER;
            
            char providerName[256];
            DWORD size = sizeof(providerName);
            if (RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)providerName, &size) == ERROR_SUCCESS) {
                AppendToDetails(result, "ETW: Found Hyper-V provider: %s\n", providerName);
            } else {
                AppendToDetails(result, "ETW: Found Hyper-V provider: %s\n", HYPERV_ETW_PROVIDERS[i]);
            }
            
            RegCloseKey(hKey);
        }
    }
    
    return detected;
}
