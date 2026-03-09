/**
 * mac_checks.c - MAC Address based Hyper-V detection
 * 
 * Hyper-V synthetic network adapters use specific MAC address prefixes:
 * - 00:15:5D:xx:xx:xx - Microsoft Hyper-V
 * - 00:03:FF:xx:xx:xx - Microsoft Virtual PC (legacy)
 */

#include "hyperv_detector.h"
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Detection flag for MAC address
#define HYPERV_DETECTED_MAC 0x00004000

// Known Hyper-V MAC OUI prefixes
static const BYTE HYPERV_MAC_PREFIX[] = { 0x00, 0x15, 0x5D };  // Microsoft Hyper-V
static const BYTE MSVPC_MAC_PREFIX[] = { 0x00, 0x03, 0xFF };   // Microsoft Virtual PC
static const BYTE HYPERV_ALT_PREFIX[] = { 0x00, 0x1D, 0xD8 };  // Microsoft (alternative)

typedef struct _MAC_PREFIX_INFO {
    const BYTE* prefix;
    size_t prefixLen;
    const char* description;
} MAC_PREFIX_INFO;

static const MAC_PREFIX_INFO KNOWN_VM_MAC_PREFIXES[] = {
    { HYPERV_MAC_PREFIX, 3, "Microsoft Hyper-V" },
    { MSVPC_MAC_PREFIX, 3, "Microsoft Virtual PC" },
    { HYPERV_ALT_PREFIX, 3, "Microsoft (Alternative)" },
    { NULL, 0, NULL }
};

static BOOL IsMACPrefixMatch(const BYTE* mac, const BYTE* prefix, size_t prefixLen) {
    return memcmp(mac, prefix, prefixLen) == 0;
}

static void FormatMAC(const BYTE* mac, char* buffer, size_t bufSize) {
    snprintf(buffer, bufSize, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

DWORD CheckMACAddressHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    char macStr[32];
    
    // First call to get the buffer size
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        AppendToDetails(result, "MAC: Memory allocation failed\n");
        return 0;
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            AppendToDetails(result, "MAC: Memory allocation failed\n");
            return 0;
        }
    }
    
    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (dwRetVal != NO_ERROR) {
        AppendToDetails(result, "MAC: GetAdaptersInfo failed with error: %d\n", dwRetVal);
        free(pAdapterInfo);
        return 0;
    }
    
    pAdapter = pAdapterInfo;
    while (pAdapter) {
        if (pAdapter->AddressLength >= 6) {
            FormatMAC(pAdapter->Address, macStr, sizeof(macStr));
            
            // Check against known Hyper-V prefixes
            for (int i = 0; KNOWN_VM_MAC_PREFIXES[i].prefix != NULL; i++) {
                if (IsMACPrefixMatch(pAdapter->Address, 
                                    KNOWN_VM_MAC_PREFIXES[i].prefix, 
                                    KNOWN_VM_MAC_PREFIXES[i].prefixLen)) {
                    detected |= HYPERV_DETECTED_MAC;
                    AppendToDetails(result, "MAC: %s detected - Adapter: %s, MAC: %s\n",
                                   KNOWN_VM_MAC_PREFIXES[i].description,
                                   pAdapter->Description, macStr);
                }
            }
            
            // Check adapter description for virtual indicators
            if (strstr(pAdapter->Description, "Hyper-V") ||
                strstr(pAdapter->Description, "Virtual") ||
                strstr(pAdapter->Description, "Microsoft Network Adapter Multiplexor")) {
                detected |= HYPERV_DETECTED_MAC;
                AppendToDetails(result, "MAC: Virtual adapter detected: %s (MAC: %s)\n",
                               pAdapter->Description, macStr);
            }
        }
        pAdapter = pAdapter->Next;
    }
    
    free(pAdapterInfo);
    
    // Also check using GetAdaptersAddresses for more detailed info (Windows Vista+)
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    ULONG outBufLen = 15000;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses == NULL) {
        return detected;
    }
    
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL) {
            return detected;
        }
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    }
    
    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->PhysicalAddressLength >= 6) {
                FormatMAC(pCurrAddresses->PhysicalAddress, macStr, sizeof(macStr));
                
                // Check for Hyper-V specific adapter names
                char adapterName[256];
                WideCharToMultiByte(CP_UTF8, 0, pCurrAddresses->FriendlyName, -1, 
                                   adapterName, sizeof(adapterName), NULL, NULL);
                
                if (strstr(adapterName, "vEthernet") ||
                    strstr(adapterName, "Hyper-V") ||
                    strstr(adapterName, "Default Switch")) {
                    detected |= HYPERV_DETECTED_MAC;
                    AppendToDetails(result, "MAC: Hyper-V network found: %s (MAC: %s)\n",
                                   adapterName, macStr);
                }
                
                // Check adapter type
                if (pCurrAddresses->IfType == IF_TYPE_ETHERNET_CSMACD ||
                    pCurrAddresses->IfType == IF_TYPE_IEEE80211) {
                    // Check MAC prefix
                    for (int i = 0; KNOWN_VM_MAC_PREFIXES[i].prefix != NULL; i++) {
                        if (IsMACPrefixMatch(pCurrAddresses->PhysicalAddress, 
                                            KNOWN_VM_MAC_PREFIXES[i].prefix, 
                                            KNOWN_VM_MAC_PREFIXES[i].prefixLen)) {
                            detected |= HYPERV_DETECTED_MAC;
                            AppendToDetails(result, "MAC: %s MAC prefix on %s: %s\n",
                                           KNOWN_VM_MAC_PREFIXES[i].description,
                                           adapterName, macStr);
                        }
                    }
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    free(pAddresses);
    return detected;
}
