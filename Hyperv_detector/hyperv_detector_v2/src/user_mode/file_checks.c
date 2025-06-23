#include "hyperv_detector.h"

static const char* HYPERV_FILES[] = {
    "C:\\Windows\\System32\\drivers\\vmbus.sys",
    "C:\\Windows\\System32\\drivers\\VMBusHID.sys",
    "C:\\Windows\\System32\\drivers\\hyperkbd.sys",
    "C:\\Windows\\System32\\drivers\\hypermouse.sys",
    "C:\\Windows\\System32\\drivers\\hvsocket.sys",
    "C:\\Windows\\System32\\drivers\\vmstorfl.sys",
    "C:\\Windows\\System32\\drivers\\storvsc.sys",
    "C:\\Windows\\System32\\drivers\\netvsc.sys",
    "C:\\Windows\\System32\\drivers\\vmicvss.sys",
    "C:\\Windows\\System32\\drivers\\vmictimesync.sys",
    "C:\\Windows\\System32\\drivers\\vmicshutdown.sys",
    "C:\\Windows\\System32\\drivers\\vmicrdv.sys",
    "C:\\Windows\\System32\\drivers\\vmickvpexchange.sys",
    "C:\\Windows\\System32\\drivers\\vmicheartbeat.sys",
    "C:\\Windows\\System32\\drivers\\vmicguestinterface.sys",
    "C:\\Windows\\System32\\drivers\\vmicvmsession.sys",
    "C:\\Windows\\System32\\vmms.exe",
    "C:\\Windows\\System32\\vmwp.exe",
    "C:\\Windows\\System32\\Vmcompute.exe",
    "C:\\Windows\\System32\\VmComputeAgent.exe",
    "C:\\Windows\\System32\\WindowsSandbox.exe",
    "C:\\Windows\\System32\\WindowsSandboxClient.exe",
    "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V",
    "C:\\Users\\Public\\Documents\\Hyper-V",
    NULL
};

static const char* HYPERV_DIRECTORIES[] = {
    "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V",
    "C:\\Users\\Public\\Documents\\Hyper-V",
    "C:\\Windows\\System32\\HostNetworkService",
    "C:\\Windows\\System32\\vmms",
    NULL
};

DWORD CheckFilesHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    
    // Check for Hyper-V files
    for (int i = 0; HYPERV_FILES[i] != NULL; i++) {
        DWORD attributes = GetFileAttributesA(HYPERV_FILES[i]);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            detected |= HYPERV_DETECTED_FILES;
            AppendToDetails(result, "File: Found %s\n", HYPERV_FILES[i]);
            
            // Get file version info for drivers
            if (strstr(HYPERV_FILES[i], ".sys") || strstr(HYPERV_FILES[i], ".exe")) {
                DWORD versionInfoSize = GetFileVersionInfoSizeA(HYPERV_FILES[i], NULL);
                if (versionInfoSize > 0) {
                    LPVOID versionInfo = malloc(versionInfoSize);
                    if (versionInfo && GetFileVersionInfoA(HYPERV_FILES[i], 0, versionInfoSize, versionInfo)) {
                        VS_FIXEDFILEINFO* fileInfo;
                        UINT fileInfoSize;
                        if (VerQueryValueA(versionInfo, "\\", (LPVOID*)&fileInfo, &fileInfoSize)) {
                            AppendToDetails(result, "File: %s version %d.%d.%d.%d\n", 
                                           HYPERV_FILES[i],
                                           HIWORD(fileInfo->dwFileVersionMS),
                                           LOWORD(fileInfo->dwFileVersionMS),
                                           HIWORD(fileInfo->dwFileVersionLS),
                                           LOWORD(fileInfo->dwFileVersionLS));
                        }
                    }
                    free(versionInfo);
                }
            }
        }
    }
    
    // Check for Hyper-V directories
    for (int i = 0; HYPERV_DIRECTORIES[i] != NULL; i++) {
        DWORD attributes = GetFileAttributesA(HYPERV_DIRECTORIES[i]);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            detected |= HYPERV_DETECTED_FILES;
            AppendToDetails(result, "Directory: Found %s\n", HYPERV_DIRECTORIES[i]);
        }
    }
    
    // Check for Virtual Machine files in common locations
    char searchPath[MAX_PATH];
    const char* vmPaths[] = {
        "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\Virtual Machines\\*.vmcx",
        "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual hard disks\\*.vhdx",
        "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual hard disks\\*.vhd",
        NULL
    };
    
    for (int i = 0; vmPaths[i] != NULL; i++) {
        hFind = FindFirstFileA(vmPaths[i], &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            detected |= HYPERV_DETECTED_FILES;
            AppendToDetails(result, "VM File: Found %s\n", findData.cFileName);
            FindClose(hFind);
        }
    }
    
    return detected;
}