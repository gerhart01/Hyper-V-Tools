#include "driver_loader.h"
#include <stdio.h>

#define DRIVER_SERVICE_NAME "HyperVDetector"
#define DRIVER_SYS_NAME     "hyperv_driver.sys"

/* ------------------------------------------------------------------ */
/* Internal helpers — mirror the pattern from install.c               */
/* (Windows-driver-samples/general/event/exe/install.c)               */
/* ------------------------------------------------------------------ */

/*
 * GetDriverPath — locate hyperv_driver.sys in the same directory as
 * the running EXE (the same approach SetupDriverName uses, but based
 * on the EXE path rather than the current directory so the program
 * works regardless of where it is launched from).
 */
static BOOL GetDriverPath(char *buf, DWORD bufSize)
{
    char  exePath[MAX_PATH];
    char *lastSlash;

    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH))
        return FALSE;

    lastSlash = strrchr(exePath, '\\');
    if (!lastSlash)
        return FALSE;
    *lastSlash = '\0';

    if (_snprintf_s(buf, bufSize, _TRUNCATE, "%s\\%s", exePath, DRIVER_SYS_NAME) < 0)
        return FALSE;

    return GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES;
}

/*
 * InstallDriver — create a new service entry for the kernel driver.
 * Returns TRUE if the service was created or already existed.
 */
static BOOL InstallDriver(SC_HANDLE hSCM, LPCSTR driverName, LPCSTR servicePath)
{
    SC_HANDLE hService;
    DWORD     err;

    hService = CreateServiceA(
        hSCM,
        driverName,
        driverName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        servicePath,
        NULL,   /* no load-order group */
        NULL,   /* no tag              */
        NULL,   /* no dependencies     */
        NULL,   /* LocalSystem account */
        NULL);  /* no password         */

    if (hService == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            return TRUE;
        }
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            fprintf(stderr, "[driver] Previous instance not fully deleted. Retry later.\n");
            return FALSE;
        }
        fprintf(stderr, "[driver] CreateService failed: %lu\n", err);
        return FALSE;
    }

    CloseServiceHandle(hService);
    return TRUE;
}

/*
 * RemoveDriver — mark the service for deletion.
 */
static BOOL RemoveDriver(SC_HANDLE hSCM, LPCSTR driverName)
{
    SC_HANDLE hService;
    BOOL      result;

    hService = OpenServiceA(hSCM, driverName, SERVICE_ALL_ACCESS);
    if (!hService) {
        fprintf(stderr, "[driver] OpenService failed: %lu\n", GetLastError());
        return FALSE;
    }

    result = DeleteService(hService);
    if (!result)
        fprintf(stderr, "[driver] DeleteService failed: %lu\n", GetLastError());

    CloseServiceHandle(hService);
    return result;
}

/*
 * StartDriver — start execution of an installed driver service.
 */
static BOOL StartDriver(SC_HANDLE hSCM, LPCSTR driverName)
{
    SC_HANDLE hService;
    DWORD     err;

    hService = OpenServiceA(hSCM, driverName, SERVICE_ALL_ACCESS);
    if (!hService) {
        fprintf(stderr, "[driver] OpenService failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!StartServiceA(hService, 0, NULL)) {
        err = GetLastError();
        CloseServiceHandle(hService);
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
            return TRUE;
        fprintf(stderr, "[driver] StartService failed: %lu\n", err);
        return FALSE;
    }

    CloseServiceHandle(hService);
    return TRUE;
}

/*
 * StopDriver — send a stop control request to the driver service.
 */
static BOOL StopDriver(SC_HANDLE hSCM, LPCSTR driverName)
{
    SC_HANDLE      hService;
    SERVICE_STATUS svcStatus;
    BOOL           result = TRUE;

    hService = OpenServiceA(hSCM, driverName, SERVICE_ALL_ACCESS);
    if (!hService)
        return FALSE;

    if (!ControlService(hService, SERVICE_CONTROL_STOP, &svcStatus)) {
        fprintf(stderr, "[driver] ControlService stop failed: %lu\n", GetLastError());
        result = FALSE;
    }

    CloseServiceHandle(hService);
    return result;
}

/* ------------------------------------------------------------------ */
/* Public interface                                                    */
/* ------------------------------------------------------------------ */

DRIVER_LOAD_STATUS LoadDriver(void)
{
    char           driverPath[MAX_PATH];
    SC_HANDLE      hSCM     = NULL;
    SC_HANDLE      hService = NULL;
    SERVICE_STATUS svcStatus;

    if (!GetDriverPath(driverPath, MAX_PATH)) {
        printf("[driver] %s not found next to the executable.\n", DRIVER_SYS_NAME);
        return DRIVER_STATUS_NOT_FOUND;
    }

    hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        if (GetLastError() == ERROR_ACCESS_DENIED)
            return DRIVER_STATUS_ACCESS_DENIED;
        return DRIVER_STATUS_LOAD_FAILED;
    }

    /* Check whether the driver is already running. */
    hService = OpenServiceA(hSCM, DRIVER_SERVICE_NAME,
                            SERVICE_QUERY_STATUS);
    if (hService) {
        if (QueryServiceStatus(hService, &svcStatus) &&
            svcStatus.dwCurrentState == SERVICE_RUNNING) {
            printf("[driver] Driver is already loaded.\n");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return DRIVER_STATUS_ALREADY_LOADED;
        }
        CloseServiceHandle(hService);
    }

    /* Install then start — matches ManageDriver(DRIVER_FUNC_INSTALL). */
    if (!InstallDriver(hSCM, DRIVER_SERVICE_NAME, driverPath)) {
        CloseServiceHandle(hSCM);
        return DRIVER_STATUS_LOAD_FAILED;
    }

    if (!StartDriver(hSCM, DRIVER_SERVICE_NAME)) {
        RemoveDriver(hSCM, DRIVER_SERVICE_NAME);
        CloseServiceHandle(hSCM);
        return DRIVER_STATUS_LOAD_FAILED;
    }

    printf("[driver] Driver loaded successfully.\n");
    CloseServiceHandle(hSCM);
    return DRIVER_STATUS_LOADED;
}

void UnloadDriver(void)
{
    SC_HANDLE hSCM;

    hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return;

    /* Matches ManageDriver(DRIVER_FUNC_REMOVE). */
    StopDriver(hSCM, DRIVER_SERVICE_NAME);
    RemoveDriver(hSCM, DRIVER_SERVICE_NAME);

    printf("[driver] Driver unloaded.\n");
    CloseServiceHandle(hSCM);
}
