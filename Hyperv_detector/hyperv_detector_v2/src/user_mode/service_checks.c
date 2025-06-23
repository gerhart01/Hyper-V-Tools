#include "hyperv_detector.h"

static const char* HYPERV_SERVICES[] = {
    "vmms",           // Hyper-V Virtual Machine Management Service
    "vmcompute",      // Hyper-V Host Compute Service
    "vmickvpexchange", // Hyper-V Data Exchange Service
    "vmicheartbeat",  // Hyper-V Heartbeat Service
    "vmicshutdown",   // Hyper-V Guest Shutdown Service
    "vmictimesync",   // Hyper-V Time Synchronization Service
    "vmicvss",        // Hyper-V Volume Shadow Copy Requestor
    "vmicrdv",        // Hyper-V Remote Desktop Virtualization Service
    "vmicguestinterface", // Hyper-V Guest Service Interface
    "vmicvmsession",  // Hyper-V PowerShell Direct Service
    "HvHost",         // HvHost Service
    "vmbus",          // Hyper-V Virtual Machine Bus Provider
    "hyperkbd",       // Hyper-V Keyboard Filter Driver
    "hypermouse",     // Hyper-V Mouse Filter Driver
    "hvsocket",       // Hyper-V Socket
    "storvsc",        // Hyper-V Virtual Storage
    "netvsc",         // Hyper-V Virtual Network
    "Vmmem",          // Virtual Machine Memory
    "WslService",     // Windows Subsystem for Linux Service
    "LxssManager",    // LxssManager
    "docker",         // Docker Engine
    "com.docker.service", // Docker Desktop Service
    NULL
};

DWORD CheckServicesHyperV(PDETECTION_RESULT result) {
    SC_HANDLE scManager;
    SC_HANDLE scService;
    DWORD detected = 0;
    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;
    
    scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scManager == NULL) {
        AppendToDetails(result, "Service: Failed to open Service Control Manager\n");
        return 0;
    }
    
    for (int i = 0; HYPERV_SERVICES[i] != NULL; i++) {
        scService = OpenServiceA(scManager, HYPERV_SERVICES[i], SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (scService != NULL) {
            detected |= HYPERV_DETECTED_SERVICES;
            
            // Query service status
            if (QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, 
                                   (LPBYTE)&serviceStatus, sizeof(serviceStatus), &bytesNeeded)) {
                const char* stateStr = "Unknown";
                switch (serviceStatus.dwCurrentState) {
                    case SERVICE_RUNNING: stateStr = "Running"; break;
                    case SERVICE_STOPPED: stateStr = "Stopped"; break;
                    case SERVICE_PAUSED: stateStr = "Paused"; break;
                    case SERVICE_START_PENDING: stateStr = "Starting"; break;
                    case SERVICE_STOP_PENDING: stateStr = "Stopping"; break;
                    case SERVICE_CONTINUE_PENDING: stateStr = "Resuming"; break;
                    case SERVICE_PAUSE_PENDING: stateStr = "Pausing"; break;
                }
                
                AppendToDetails(result, "Service: %s - %s (PID: %d)\n", 
                               HYPERV_SERVICES[i], stateStr, serviceStatus.dwProcessId);
                
                if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                    if (strcmp(HYPERV_SERVICES[i], "vmms") == 0) {
                        AppendToDetails(result, "Service: Hyper-V is actively running\n");
                    }
                    if (strcmp(HYPERV_SERVICES[i], "Vmmem") == 0) {
                        AppendToDetails(result, "Service: WSL2/Windows Sandbox is running\n");
                    }
                    if (strcmp(HYPERV_SERVICES[i], "docker") == 0 || 
                        strcmp(HYPERV_SERVICES[i], "com.docker.service") == 0) {
                        AppendToDetails(result, "Service: Docker with Hyper-V backend is running\n");
                    }
                }
            }
            
            CloseServiceHandle(scService);
        }
    }
    
    CloseServiceHandle(scManager);
    return detected;
}