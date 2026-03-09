#pragma once
#ifndef DRIVER_LOADER_H
#define DRIVER_LOADER_H

#include <windows.h>

typedef enum _DRIVER_LOAD_STATUS {
    DRIVER_STATUS_NOT_FOUND = 0,   // hyperv_driver.sys not found next to EXE
    DRIVER_STATUS_ACCESS_DENIED,   // insufficient privileges
    DRIVER_STATUS_ALREADY_LOADED,  // driver was already running (not touched on exit)
    DRIVER_STATUS_LOADED,          // driver loaded by us (stopped + deleted on exit)
    DRIVER_STATUS_LOAD_FAILED,     // SCM error
} DRIVER_LOAD_STATUS;

/*
 * Locate hyperv_driver.sys next to the current EXE, install it as a
 * kernel-mode service, and start it.  Returns the load status.
 *
 * DRIVER_STATUS_LOADED        – driver is now running, call UnloadDriver() on exit.
 * DRIVER_STATUS_ALREADY_LOADED – driver was already running, do NOT call UnloadDriver().
 * Other values                – driver is not available.
 */
DRIVER_LOAD_STATUS LoadDriver(void);

/*
 * Stop the driver service and delete its SCM entry.
 * Only call this when LoadDriver() returned DRIVER_STATUS_LOADED.
 */
void UnloadDriver(void);

#endif /* DRIVER_LOADER_H */
