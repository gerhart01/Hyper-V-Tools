/**
 * hyperv_socket_checks.c - Hyper-V Socket Detection
 * 
 * Detects Hyper-V sockets (AF_HYPERV / hvsocket) availability.
 * Hyper-V sockets allow communication between host and guest without
 * network configuration.
 * 
 * Sources:
 * - https://xakep.ru/2017/08/09/hyper-v-internals
 * - https://hvinternals.blogspot.com/2017/09/hyperv-socket-internals.html
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service
 * - https://github.com/awakecoding/VMBusPipe
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* Detection flag for this module */
#define HYPERV_DETECTED_HVSOCKET 0x00000200

/* Hyper-V socket constants */
#define AF_HYPERV           34
#define HV_PROTOCOL_RAW     1

/* Hyper-V socket GUID structure */
typedef struct _SOCKADDR_HV {
    ADDRESS_FAMILY Family;       /* AF_HYPERV */
    USHORT Reserved;
    GUID VmId;                   /* VM GUID or well-known value */
    GUID ServiceId;              /* Service GUID */
} SOCKADDR_HV, *PSOCKADDR_HV;

/* Well-known VM IDs */
static const GUID HV_GUID_ZERO = {0};
static const GUID HV_GUID_WILDCARD = {0xFFFFFFFF, 0xFFFF, 0xFFFF, 
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
static const GUID HV_GUID_BROADCAST = {0xFFFFFFFF, 0xFFFF, 0xFFFF, 
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}};
static const GUID HV_GUID_CHILDREN = {0x90DB8B89, 0x0D35, 0x4F79, 
    {0x8C, 0xE9, 0x49, 0xEA, 0x0A, 0xC8, 0xB7, 0xCD}};
static const GUID HV_GUID_LOOPBACK = {0xE0E16197, 0xDD56, 0x4A10, 
    {0x91, 0x95, 0x5E, 0xE7, 0xA1, 0x55, 0xA8, 0x38}};
static const GUID HV_GUID_PARENT = {0xA42E7CDA, 0xD03F, 0x480C, 
    {0x9C, 0xC2, 0xA4, 0xDE, 0x20, 0xAB, 0xB8, 0x78}};

/* Socket detection info */
typedef struct _HVSOCKET_INFO {
    BOOL wsaInitialized;
    BOOL afHypervSupported;
    BOOL canCreateSocket;
    
    int wsaError;
    int socketError;
    
    DWORD wsaVersion;
} HVSOCKET_INFO, *PHVSOCKET_INFO;

/*
 * Initialize Winsock
 */
static BOOL InitWinsock(PHVSOCKET_INFO info)
{
    WSADATA wsaData;
    int result;
    
    if (info == NULL) {
        return FALSE;
    }
    
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        info->wsaError = result;
        return FALSE;
    }
    
    info->wsaInitialized = TRUE;
    info->wsaVersion = wsaData.wVersion;
    return TRUE;
}

/*
 * Cleanup Winsock
 */
static void CleanupWinsock(PHVSOCKET_INFO info)
{
    if (info != NULL && info->wsaInitialized) {
        WSACleanup();
        info->wsaInitialized = FALSE;
    }
}

/*
 * Check if AF_HYPERV is supported
 */
static void CheckHvSocketSupport(PHVSOCKET_INFO info)
{
    SOCKET sock;
    
    if (info == NULL) {
        return;
    }
    
    /* Try to create AF_HYPERV socket */
    sock = socket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW);
    
    if (sock == INVALID_SOCKET) {
        info->socketError = WSAGetLastError();
        info->afHypervSupported = FALSE;
        info->canCreateSocket = FALSE;
        
        /* WSAEAFNOSUPPORT (10047) = address family not supported */
        /* WSAEPROTONOSUPPORT (10043) = protocol not supported */
        if (info->socketError != WSAEAFNOSUPPORT && 
            info->socketError != WSAEPROTONOSUPPORT) {
            /* Other error - might still be supported */
            info->afHypervSupported = TRUE;
        }
    } else {
        info->afHypervSupported = TRUE;
        info->canCreateSocket = TRUE;
        closesocket(sock);
    }
}

/*
 * Check for HvSocket driver
 */
static BOOL CheckHvSocketDriver(void)
{
    /* Check for hvsocket.sys or vmbusr.sys driver */
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL result = FALSE;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return FALSE;
    }
    
    /* Try hvsocket */
    hService = OpenServiceA(hSCManager, "hvsocket", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            result = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
        if (result) {
            CloseServiceHandle(hSCManager);
            return TRUE;
        }
    }
    
    /* Try vmbusr as fallback */
    hService = OpenServiceA(hSCManager, "vmbusr", SERVICE_QUERY_STATUS);
    if (hService != NULL) {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            result = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return result;
}

/*
 * Check HvSocket registry
 */
static BOOL CheckHvSocketRegistry(void)
{
    HKEY hKey;
    LONG result;
    
    /* Check for Hyper-V sockets protocol registration */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\hvsocket",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Main socket check function
 */
DWORD CheckHvSocketHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    HVSOCKET_INFO info = {0};
    BOOL driverFound = FALSE;
    BOOL registryFound = FALSE;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Initialize Winsock */
    if (!InitWinsock(&info)) {
        AppendToDetails(result, "Hyper-V Socket Detection:\n");
        AppendToDetails(result, "  Winsock Init: FAILED (Error: %d)\n", info.wsaError);
        return detected;
    }
    
    /* Check socket support */
    CheckHvSocketSupport(&info);
    
    /* Cleanup Winsock */
    CleanupWinsock(&info);
    
    /* Check driver and registry */
    driverFound = CheckHvSocketDriver();
    registryFound = CheckHvSocketRegistry();
    
    /* Detection */
    if (info.afHypervSupported || driverFound || registryFound) {
        detected = HYPERV_DETECTED_HVSOCKET;
    }
    
    /* Build details */
    AppendToDetails(result, "Hyper-V Socket Detection:\n");
    AppendToDetails(result, "  Winsock Version: %u.%u\n", 
                   LOBYTE(info.wsaVersion), HIBYTE(info.wsaVersion));
    
    AppendToDetails(result, "\n  AF_HYPERV (34) Support:\n");
    AppendToDetails(result, "    Address Family Supported: %s\n", 
                   info.afHypervSupported ? "YES" : "NO");
    AppendToDetails(result, "    Can Create Socket: %s\n", 
                   info.canCreateSocket ? "YES" : "NO");
    
    if (!info.afHypervSupported && info.socketError != 0) {
        AppendToDetails(result, "    Socket Error: %d\n", info.socketError);
        if (info.socketError == WSAEAFNOSUPPORT) {
            AppendToDetails(result, "    (WSAEAFNOSUPPORT - not in a VM)\n");
        }
    }
    
    AppendToDetails(result, "\n  Driver/Registry:\n");
    AppendToDetails(result, "    HvSocket Driver: %s\n", driverFound ? "Running" : "Not found");
    AppendToDetails(result, "    HvSocket Registry: %s\n", registryFound ? "Present" : "Not found");
    
    if (info.canCreateSocket) {
        AppendToDetails(result, "\n  Note: System supports Hyper-V sockets\n");
        AppendToDetails(result, "        Can communicate with host/parent partition\n");
    }
    
    return detected;
}

/*
 * Quick check for HvSocket
 */
BOOL HasHvSocketSupport(void)
{
    HVSOCKET_INFO info = {0};
    
    if (!InitWinsock(&info)) {
        return FALSE;
    }
    
    CheckHvSocketSupport(&info);
    CleanupWinsock(&info);
    
    return info.afHypervSupported;
}

/*
 * Check if running in VM (based on socket availability)
 */
BOOL IsInVmBySocket(void)
{
    HVSOCKET_INFO info = {0};
    
    if (!InitWinsock(&info)) {
        return FALSE;
    }
    
    CheckHvSocketSupport(&info);
    CleanupWinsock(&info);
    
    return info.canCreateSocket;
}
