/**
 * network_checks.c - Deep Network Stack Detection for Hyper-V
 * 
 * Analyzes network configuration for Hyper-V indicators:
 * - Virtual switch detection
 * - Network adapter properties
 * - Hyper-V network extensions
 * - vNIC characteristics
 * - NAT and port forwarding
 */

#include "hyperv_detector.h"
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#ifndef HYPERV_DETECTED_NETWORK
#define HYPERV_DETECTED_NETWORK 0x02000000
#endif

// Hyper-V virtual switch names
static const char* HYPERV_SWITCH_NAMES[] = {
    "Default Switch",
    "DockerNAT",
    "WSL",
    "nat",
    "External Switch",
    "Internal Switch",
    "Private Switch",
    "vEthernet",
    "Hyper-V Virtual Ethernet",
    "Container NIC",
    NULL
};

// Virtual adapter description patterns
static const char* VM_ADAPTER_PATTERNS[] = {
    "Hyper-V Virtual Ethernet Adapter",
    "Microsoft Hyper-V Network Adapter",
    "Microsoft Virtual",
    "vEthernet",
    "Virtual Switch",
    "Container Virtual NIC",
    "Kernel Debug Network Adapter",
    "Microsoft Wi-Fi Direct Virtual Adapter",
    NULL
};

/**
 * Check network adapters for VM indicators
 */
static DWORD CheckNetworkAdapters(PDETECTION_RESULT result) {
    DWORD detected = 0;
    ULONG bufferSize = 0;
    PIP_ADAPTER_INFO adapterInfo = NULL;
    PIP_ADAPTER_INFO currentAdapter;
    
    // Get required buffer size
    if (GetAdaptersInfo(NULL, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (PIP_ADAPTER_INFO)malloc(bufferSize);
    }
    
    if (adapterInfo && GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        currentAdapter = adapterInfo;
        
        while (currentAdapter) {
            AppendToDetails(result, "NET: Adapter: %s\n", currentAdapter->Description);
            AppendToDetails(result, "NET:   Name: %s\n", currentAdapter->AdapterName);
            AppendToDetails(result, "NET:   Type: %d\n", currentAdapter->Type);
            
            // Check description for VM patterns
            for (int i = 0; VM_ADAPTER_PATTERNS[i] != NULL; i++) {
                if (strstr(currentAdapter->Description, VM_ADAPTER_PATTERNS[i])) {
                    detected |= HYPERV_DETECTED_NETWORK;
                    AppendToDetails(result, "NET:   -> Hyper-V adapter detected\n");
                    break;
                }
            }
            
            // Check adapter name for switch names
            for (int i = 0; HYPERV_SWITCH_NAMES[i] != NULL; i++) {
                if (strstr(currentAdapter->AdapterName, HYPERV_SWITCH_NAMES[i]) ||
                    strstr(currentAdapter->Description, HYPERV_SWITCH_NAMES[i])) {
                    detected |= HYPERV_DETECTED_NETWORK;
                    AppendToDetails(result, "NET:   -> Virtual switch: %s\n", 
                                   HYPERV_SWITCH_NAMES[i]);
                    break;
                }
            }
            
            currentAdapter = currentAdapter->Next;
        }
    }
    
    if (adapterInfo) free(adapterInfo);
    return detected;
}

/**
 * Check detailed adapter addresses
 */
static DWORD CheckAdapterAddresses(PDETECTION_RESULT result) {
    DWORD detected = 0;
    ULONG bufferSize = 0;
    PIP_ADAPTER_ADDRESSES addresses = NULL;
    PIP_ADAPTER_ADDRESSES current;
    
    // Request all info including DNS
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | 
                  GAA_FLAG_INCLUDE_GATEWAYS |
                  GAA_FLAG_INCLUDE_ALL_INTERFACES;
    
    // Get required size
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &bufferSize) 
        == ERROR_BUFFER_OVERFLOW) {
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    }
    
    if (addresses && GetAdaptersAddresses(AF_UNSPEC, flags, NULL, 
                                          addresses, &bufferSize) == NO_ERROR) {
        current = addresses;
        
        while (current) {
            // Check adapter types
            switch (current->IfType) {
                case IF_TYPE_ETHERNET_CSMACD:
                    // Check for virtual Ethernet
                    if (wcsstr(current->Description, L"Virtual") ||
                        wcsstr(current->Description, L"Hyper-V") ||
                        wcsstr(current->Description, L"vEthernet")) {
                        detected |= HYPERV_DETECTED_NETWORK;
                        AppendToDetails(result, "NET: Virtual Ethernet: %ls\n", 
                                       current->Description);
                    }
                    break;
                    
                case IF_TYPE_SOFTWARE_LOOPBACK:
                    // Normal
                    break;
                    
                case IF_TYPE_TUNNEL:
                    AppendToDetails(result, "NET: Tunnel interface: %ls\n", 
                                   current->Description);
                    break;
                    
                default:
                    break;
            }
            
            // Check connection type
            if (current->ConnectionType == NET_IF_CONNECTION_DEDICATED) {
                // Physical-like connection
            }
            
            // Check for virtual adapter indicators
            if (current->Flags & IP_ADAPTER_RECEIVE_ONLY) {
                AppendToDetails(result, "NET: Receive-only adapter: %ls\n", 
                               current->Description);
            }
            
            // Check physical address length
            if (current->PhysicalAddressLength == 6) {
                BYTE* mac = current->PhysicalAddress;
                
                // Check for Hyper-V OUI
                if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) {
                    detected |= HYPERV_DETECTED_NETWORK;
                    AppendToDetails(result, "NET: Hyper-V MAC found on: %ls\n", 
                                   current->FriendlyName);
                }
                
                // Check for Microsoft Virtual PC OUI
                if (mac[0] == 0x00 && mac[1] == 0x03 && mac[2] == 0xFF) {
                    detected |= HYPERV_DETECTED_NETWORK;
                    AppendToDetails(result, "NET: MS Virtual PC MAC found on: %ls\n", 
                                   current->FriendlyName);
                }
            }
            
            // Check DNS suffix for VM patterns
            if (current->DnsSuffix && wcslen(current->DnsSuffix) > 0) {
                AppendToDetails(result, "NET: DNS Suffix: %ls\n", current->DnsSuffix);
            }
            
            current = current->Next;
        }
    }
    
    if (addresses) free(addresses);
    return detected;
}

/**
 * Check for Hyper-V virtual switch device interfaces
 */
static DWORD CheckVirtualSwitchDevices(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Try to open VMSwitch device
    HANDLE hSwitch = CreateFileA("\\\\.\\VMSwitch", 
                                  GENERIC_READ, 
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, 
                                  OPEN_EXISTING, 
                                  0, 
                                  NULL);
    
    if (hSwitch != INVALID_HANDLE_VALUE) {
        detected |= HYPERV_DETECTED_NETWORK;
        AppendToDetails(result, "NET: VMSwitch device accessible\n");
        CloseHandle(hSwitch);
    }
    
    // Try to open VMNetworkAdapter device
    hSwitch = CreateFileA("\\\\.\\VMNetworkAdapter",
                          GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL,
                          OPEN_EXISTING,
                          0,
                          NULL);
    
    if (hSwitch != INVALID_HANDLE_VALUE) {
        detected |= HYPERV_DETECTED_NETWORK;
        AppendToDetails(result, "NET: VMNetworkAdapter device accessible\n");
        CloseHandle(hSwitch);
    }
    
    return detected;
}

/**
 * Check registry for virtual switch configuration
 */
static DWORD CheckVirtualSwitchRegistry(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check for Hyper-V virtual switch service
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\VMSMP",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        detected |= HYPERV_DETECTED_NETWORK;
        AppendToDetails(result, "NET: Hyper-V Virtual Switch service found\n");
        RegCloseKey(hKey);
    }
    
    // Check for virtual switch extensions
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\VMSMP\\Parameters\\SwitchList",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD index = 0;
        char switchId[256];
        
        while (RegEnumKeyA(hKey, index++, switchId, sizeof(switchId)) == ERROR_SUCCESS) {
            detected |= HYPERV_DETECTED_NETWORK;
            AppendToDetails(result, "NET: Virtual switch ID: %s\n", switchId);
        }
        
        RegCloseKey(hKey);
    }
    
    // Check for network extensions
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\Network",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD index = 0;
        char subKey[256];
        
        while (RegEnumKeyA(hKey, index++, subKey, sizeof(subKey)) == ERROR_SUCCESS) {
            if (strstr(subKey, "HNS") || strstr(subKey, "hvn") || 
                strstr(subKey, "vms")) {
                detected |= HYPERV_DETECTED_NETWORK;
                AppendToDetails(result, "NET: Virtual network component: %s\n", subKey);
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

/**
 * Check for Host Network Service (HNS)
 */
static DWORD CheckHNS(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Check for HNS service
    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager) {
        SC_HANDLE hnsService = OpenServiceA(scManager, "hns", SERVICE_QUERY_STATUS);
        if (hnsService) {
            detected |= HYPERV_DETECTED_NETWORK;
            AppendToDetails(result, "NET: Host Network Service (HNS) found\n");
            
            SERVICE_STATUS_PROCESS status;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(hnsService, SC_STATUS_PROCESS_INFO,
                                    (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    AppendToDetails(result, "NET: HNS is running\n");
                }
            }
            
            CloseServiceHandle(hnsService);
        }
        CloseServiceHandle(scManager);
    }
    
    // Try to open HNS named pipe
    HANDLE hPipe = CreateFileA("\\\\.\\pipe\\HNS",
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               0,
                               NULL);
    
    if (hPipe != INVALID_HANDLE_VALUE) {
        detected |= HYPERV_DETECTED_NETWORK;
        AppendToDetails(result, "NET: HNS named pipe accessible\n");
        CloseHandle(hPipe);
    }
    
    return detected;
}

/**
 * Check network compartments (Windows containers)
 */
static DWORD CheckNetworkCompartments(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    typedef DWORD (WINAPI *GetCurrentThreadCompartmentId_t)(void);
    typedef DWORD (WINAPI *GetSessionCompartmentId_t)(DWORD);
    
    HMODULE hIphlpapi = LoadLibraryA("iphlpapi.dll");
    if (hIphlpapi) {
        GetCurrentThreadCompartmentId_t pGetCurrentThreadCompartmentId = 
            (GetCurrentThreadCompartmentId_t)GetProcAddress(hIphlpapi, 
                                                            "GetCurrentThreadCompartmentId");
        
        if (pGetCurrentThreadCompartmentId) {
            DWORD compartmentId = pGetCurrentThreadCompartmentId();
            AppendToDetails(result, "NET: Current compartment ID: %d\n", compartmentId);
            
            // Non-zero compartment ID may indicate container
            if (compartmentId != 1) {  // 1 is default
                detected |= HYPERV_DETECTED_NETWORK;
                AppendToDetails(result, "NET: Running in non-default network compartment\n");
            }
        }
        
        FreeLibrary(hIphlpapi);
    }
    
    return detected;
}

/**
 * Check for NAT configuration
 */
static DWORD CheckNATConfiguration(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check for Hyper-V NAT
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\WinNat",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        detected |= HYPERV_DETECTED_NETWORK;
        AppendToDetails(result, "NET: Windows NAT service found\n");
        RegCloseKey(hKey);
    }
    
    // Check for ICS (Internet Connection Sharing)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD enabled = 0;
        DWORD size = sizeof(enabled);
        if (RegQueryValueExA(hKey, "EnableRebootPersistConnection", 
                            NULL, NULL, (LPBYTE)&enabled, &size) == ERROR_SUCCESS) {
            if (enabled) {
                AppendToDetails(result, "NET: ICS enabled\n");
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return detected;
}

/**
 * Check TCP/IP stack for VM indicators
 */
static DWORD CheckTCPIPStack(PDETECTION_RESULT result) {
    DWORD detected = 0;
    MIB_TCPSTATS tcpStats;
    MIB_UDPSTATS udpStats;
    
    if (GetTcpStatistics(&tcpStats) == NO_ERROR) {
        AppendToDetails(result, "NET: TCP Active Opens: %u\n", tcpStats.dwActiveOpens);
        AppendToDetails(result, "NET: TCP Current Established: %u\n", tcpStats.dwCurrEstab);
    }
    
    if (GetUdpStatistics(&udpStats) == NO_ERROR) {
        AppendToDetails(result, "NET: UDP Datagrams: %u in, %u out\n", 
                       udpStats.dwInDatagrams, udpStats.dwOutDatagrams);
    }
    
    // Get IP forward table for routing analysis
    PMIB_IPFORWARDTABLE forwardTable = NULL;
    ULONG size = 0;
    
    if (GetIpForwardTable(NULL, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        forwardTable = (PMIB_IPFORWARDTABLE)malloc(size);
        
        if (forwardTable && GetIpForwardTable(forwardTable, &size, FALSE) == NO_ERROR) {
            AppendToDetails(result, "NET: Route entries: %d\n", forwardTable->dwNumEntries);
            
            // Check for virtual switch routes
            for (DWORD i = 0; i < forwardTable->dwNumEntries; i++) {
                // Interface index patterns common in VMs
                if (forwardTable->table[i].dwForwardIfIndex > 100) {
                    // High interface indices are often virtual
                }
            }
        }
        
        if (forwardTable) free(forwardTable);
    }
    
    return detected;
}

/**
 * Check for VMBus network provider
 */
static DWORD CheckVMBusNetworkProvider(PDETECTION_RESULT result) {
    DWORD detected = 0;
    HKEY hKey;
    
    // Check for VMBus network integration
    const char* vmbusNetKeys[] = {
        "SYSTEM\\CurrentControlSet\\Services\\netvsc",
        "SYSTEM\\CurrentControlSet\\Services\\netvsc_vfpp",
        "SYSTEM\\CurrentControlSet\\Enum\\VMBUS\\{f8615163-df3e-46c5-913f-f2d2f965ed0e}",
        NULL
    };
    
    for (int i = 0; vmbusNetKeys[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmbusNetKeys[i], 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            detected |= HYPERV_DETECTED_NETWORK;
            AppendToDetails(result, "NET: VMBus network component: %s\n", vmbusNetKeys[i]);
            RegCloseKey(hKey);
        }
    }
    
    return detected;
}

/**
 * Main network check function
 */
DWORD CheckNetworkHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "\n=== Network Stack Checks ===\n");
    
    detected |= CheckNetworkAdapters(result);
    detected |= CheckAdapterAddresses(result);
    detected |= CheckVirtualSwitchDevices(result);
    detected |= CheckVirtualSwitchRegistry(result);
    detected |= CheckHNS(result);
    detected |= CheckNetworkCompartments(result);
    detected |= CheckNATConfiguration(result);
    detected |= CheckTCPIPStack(result);
    detected |= CheckVMBusNetworkProvider(result);
    
    return detected;
}

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
