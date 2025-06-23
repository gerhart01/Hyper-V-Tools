#pragma once
#ifndef HYPERV_DRIVER_H
#define HYPERV_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include "minwindef.h"
#include "../common/shared_structs.h"

// Driver function declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD HyperVDetectorEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL HyperVDetectorEvtIoDeviceControl;

#define HV_STATUS_INVALID_HYPERCALL_CODE 0x0002

//
// Hypercall function pointer type
//
typedef UINT64(*HYPERCALL_PROC)(
    UINT64 Control,
    UINT64 InputParam,
    UINT64 OutputParam
    );

// Hypercall function declarations
NTSTATUS PerformHypercall(DWORD hypercallCode, DWORD inputParamCount, DWORD outputParamCount, PDWORD result);
NTSTATUS ReadMsr(DWORD msrIndex, PULONGLONG value);
NTSTATUS CheckVmBusPresence(PDWORD result);

// Utility functions
BOOLEAN IsHyperVPresent();
NTSTATUS GetHyperVVersion(PDWORD version);
UINT64 HvMakeHypercall(
    _In_ UINT64 Control,
    _In_opt_ UINT64 InputParam,
    _In_opt_ UINT64 OutputParam
);

UINT64 HvReadMsr(UINT32 MsrIndex);
extern VOID HvWriteMsr(UINT32 MsrIndex, UINT64 Value);
extern UINT64 HvCallHypercall(
    HYPERCALL_PROC HypercallProc,
    UINT64 Control,
    UINT64 InputParam,
    UINT64 OutputParam
);

#define HYPERV_DETECTOR_DEVICE_NAME L"\\Device\\HyperVDetector"
#define HYPERV_DETECTOR_SYMBOLIC_NAME L"\\DosDevices\\HyperVDetector"

#define HV_POOL_TAG 'vycH'

//
// Guest OS ID value
//
#define HV_GUEST_OS_ID_VALUE    0x0001000000000000ULL

//
// Hypercall page enable bit
//
#define HV_HYPERCALL_ENABLE     0x0000000000000001ULL

#endif // HYPERV_DRIVER_H