/**
 * eventlog_checks.c - Windows Event Log based Hyper-V detection
 * 
 * Searches Windows Event Logs for Hyper-V related events and providers.
 */

#include "hyperv_detector.h"
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

// Detection flag for event logs
#define HYPERV_DETECTED_EVENTLOG 0x00040000

// Hyper-V Event Log channels
static const wchar_t* HYPERV_EVENT_CHANNELS[] = {
    L"Microsoft-Windows-Hyper-V-Compute-Admin",
    L"Microsoft-Windows-Hyper-V-Compute-Operational",
    L"Microsoft-Windows-Hyper-V-Config-Admin",
    L"Microsoft-Windows-Hyper-V-Config-Operational",
    L"Microsoft-Windows-Hyper-V-Guest-Drivers/Admin",
    L"Microsoft-Windows-Hyper-V-Guest-Drivers/Operational",
    L"Microsoft-Windows-Hyper-V-Hypervisor-Admin",
    L"Microsoft-Windows-Hyper-V-Hypervisor-Operational",
    L"Microsoft-Windows-Hyper-V-StorageVSP-Admin",
    L"Microsoft-Windows-Hyper-V-VID-Admin",
    L"Microsoft-Windows-Hyper-V-VMMS-Admin",
    L"Microsoft-Windows-Hyper-V-VMMS-Operational",
    L"Microsoft-Windows-Hyper-V-VMSP-Admin",
    L"Microsoft-Windows-Hyper-V-VmSwitch-Operational",
    L"Microsoft-Windows-Hyper-V-Worker-Admin",
    L"Microsoft-Windows-Hyper-V-Worker-Operational",
    L"Microsoft-Windows-HostNetworkService-Admin",
    L"Microsoft-Windows-HostComputeService-Admin",
    NULL
};

// Event Log providers to check
static const wchar_t* HYPERV_EVENT_PROVIDERS[] = {
    L"Microsoft-Windows-Hyper-V-Compute",
    L"Microsoft-Windows-Hyper-V-Config",
    L"Microsoft-Windows-Hyper-V-Guest-Drivers",
    L"Microsoft-Windows-Hyper-V-Hypervisor",
    L"Microsoft-Windows-Hyper-V-Integration",
    L"Microsoft-Windows-Hyper-V-Netvsc",
    L"Microsoft-Windows-Hyper-V-StorageVSP",
    L"Microsoft-Windows-Hyper-V-VID",
    L"Microsoft-Windows-Hyper-V-VMMS",
    L"Microsoft-Windows-Hyper-V-VMSP",
    L"Microsoft-Windows-Hyper-V-VmSwitch",
    L"Microsoft-Windows-Hyper-V-Worker",
    L"Microsoft-Windows-HostNetworkService",
    L"Microsoft-Windows-HostComputeService",
    NULL
};

static BOOL CheckEventChannelExists(const wchar_t* channelPath) {
    EVT_HANDLE hChannel = EvtOpenChannelConfig(NULL, channelPath, 0);
    if (hChannel == NULL) {
        return FALSE;
    }
    EvtClose(hChannel);
    return TRUE;
}

static DWORD GetEventCount(const wchar_t* channelPath) {
    EVT_HANDLE hResults = NULL;
    EVT_HANDLE hEvent = NULL;
    DWORD eventCount = 0;
    DWORD returned = 0;
    
    // Simple query to count events
    wchar_t query[512];
    swprintf(query, sizeof(query)/sizeof(wchar_t), L"*");
    
    hResults = EvtQuery(NULL, channelPath, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hResults == NULL) {
        return 0;
    }
    
    // Count up to 100 events
    while (eventCount < 100) {
        if (!EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned)) {
            break;
        }
        eventCount++;
        EvtClose(hEvent);
    }
    
    EvtClose(hResults);
    return eventCount;
}

static BOOL GetLatestEventTime(const wchar_t* channelPath, SYSTEMTIME* pTime) {
    EVT_HANDLE hResults = NULL;
    EVT_HANDLE hEvent = NULL;
    DWORD returned = 0;
    BOOL success = FALSE;
    
    hResults = EvtQuery(NULL, channelPath, L"*", EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hResults == NULL) {
        return FALSE;
    }
    
    if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned) && returned > 0) {
        EVT_HANDLE hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
        if (hContext) {
            DWORD bufferSize = 0;
            DWORD propertyCount = 0;
            
            EvtRender(hContext, hEvent, EvtRenderEventValues, 0, NULL, &bufferSize, &propertyCount);
            
            PEVT_VARIANT pRenderedValues = (PEVT_VARIANT)malloc(bufferSize);
            if (pRenderedValues) {
                if (EvtRender(hContext, hEvent, EvtRenderEventValues, bufferSize, 
                             pRenderedValues, &bufferSize, &propertyCount)) {
                    // TimeCreated is at index EvtSystemTimeCreated (17)
                    if (propertyCount > 17 && pRenderedValues[17].Type == EvtVarTypeFileTime) {
                        FILETIME ft;
                        ft.dwLowDateTime = pRenderedValues[17].FileTimeVal & 0xFFFFFFFF;
                        ft.dwHighDateTime = (pRenderedValues[17].FileTimeVal >> 32) & 0xFFFFFFFF;
                        FileTimeToSystemTime(&ft, pTime);
                        success = TRUE;
                    }
                }
                free(pRenderedValues);
            }
            EvtClose(hContext);
        }
        EvtClose(hEvent);
    }
    
    EvtClose(hResults);
    return success;
}

static BOOL CheckEventProviderRegistered(const wchar_t* providerName) {
    EVT_HANDLE hPublisher = EvtOpenPublisherMetadata(NULL, providerName, NULL, 0, 0);
    if (hPublisher == NULL) {
        return FALSE;
    }
    EvtClose(hPublisher);
    return TRUE;
}

DWORD CheckEventLogsHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    char channelNameA[256];
    
    AppendToDetails(result, "EventLog: Checking Hyper-V event log channels...\n");
    
    // Check for Hyper-V event log channels
    for (int i = 0; HYPERV_EVENT_CHANNELS[i] != NULL; i++) {
        if (CheckEventChannelExists(HYPERV_EVENT_CHANNELS[i])) {
            detected |= HYPERV_DETECTED_EVENTLOG;
            
            WideCharToMultiByte(CP_UTF8, 0, HYPERV_EVENT_CHANNELS[i], -1, 
                               channelNameA, sizeof(channelNameA), NULL, NULL);
            
            DWORD eventCount = GetEventCount(HYPERV_EVENT_CHANNELS[i]);
            AppendToDetails(result, "EventLog: Found channel: %s (%d events)\n", 
                           channelNameA, eventCount);
            
            // Get latest event time if any events exist
            if (eventCount > 0) {
                SYSTEMTIME latestTime;
                if (GetLatestEventTime(HYPERV_EVENT_CHANNELS[i], &latestTime)) {
                    AppendToDetails(result, "EventLog: Latest event: %04d-%02d-%02d %02d:%02d:%02d\n",
                                   latestTime.wYear, latestTime.wMonth, latestTime.wDay,
                                   latestTime.wHour, latestTime.wMinute, latestTime.wSecond);
                }
            }
        }
    }
    
    // Check for Hyper-V event providers
    AppendToDetails(result, "EventLog: Checking Hyper-V event providers...\n");
    
    for (int i = 0; HYPERV_EVENT_PROVIDERS[i] != NULL; i++) {
        if (CheckEventProviderRegistered(HYPERV_EVENT_PROVIDERS[i])) {
            detected |= HYPERV_DETECTED_EVENTLOG;
            
            WideCharToMultiByte(CP_UTF8, 0, HYPERV_EVENT_PROVIDERS[i], -1, 
                               channelNameA, sizeof(channelNameA), NULL, NULL);
            AppendToDetails(result, "EventLog: Found provider: %s\n", channelNameA);
        }
    }
    
    // Check System event log for Hyper-V related events
    EVT_HANDLE hResults = EvtQuery(NULL, L"System", 
        L"*[System[Provider[@Name='Microsoft-Windows-Hyper-V-Hypervisor' or "
        L"@Name='Microsoft-Windows-Hyper-V-VID' or "
        L"@Name='Microsoft-Windows-Kernel-HvSocket']]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);
    
    if (hResults != NULL) {
        EVT_HANDLE hEvent;
        DWORD returned;
        DWORD systemEventCount = 0;
        
        while (systemEventCount < 10 && EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned)) {
            systemEventCount++;
            EvtClose(hEvent);
        }
        
        if (systemEventCount > 0) {
            detected |= HYPERV_DETECTED_EVENTLOG;
            AppendToDetails(result, "EventLog: Found %d Hyper-V events in System log\n", systemEventCount);
        }
        
        EvtClose(hResults);
    }
    
    // Check for recent Hyper-V related application events
    hResults = EvtQuery(NULL, L"Application", 
        L"*[System[(Level=1 or Level=2 or Level=3) and "
        L"(Provider[@Name='Hyper-V-VmSwitch'] or "
        L"Provider[@Name='vmms'] or "
        L"Provider[@Name='vmcompute'])]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);
    
    if (hResults != NULL) {
        EVT_HANDLE hEvent;
        DWORD returned;
        DWORD appEventCount = 0;
        
        while (appEventCount < 10 && EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned)) {
            appEventCount++;
            EvtClose(hEvent);
        }
        
        if (appEventCount > 0) {
            detected |= HYPERV_DETECTED_EVENTLOG;
            AppendToDetails(result, "EventLog: Found %d Hyper-V events in Application log\n", appEventCount);
        }
        
        EvtClose(hResults);
    }
    
    return detected;
}

// Additional check: Security event log for Hyper-V related security events
DWORD CheckSecurityEventsHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    // Check for Hyper-V VM connect/disconnect events (Event ID 4656, 4624 with HvSocket)
    EVT_HANDLE hResults = EvtQuery(NULL, L"Security",
        L"*[System[(EventID=4624 or EventID=4656)] and "
        L"EventData[Data[@Name='LogonType']='10']]",
        EvtQueryChannelPath | EvtQueryReverseDirection);
    
    if (hResults != NULL) {
        EVT_HANDLE hEvent;
        DWORD returned;
        DWORD secEventCount = 0;
        
        while (secEventCount < 5 && EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned)) {
            secEventCount++;
            EvtClose(hEvent);
        }
        
        if (secEventCount > 0) {
            AppendToDetails(result, "EventLog: Found %d potential Hyper-V security events\n", secEventCount);
        }
        
        EvtClose(hResults);
    }
    
    return detected;
}
