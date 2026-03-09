#pragma once
#ifndef HYPERV_DRIVER_H
#define HYPERV_DRIVER_H

#include <ntddk.h>
#include "minwindef.h"
#include "../common/shared_structs.h"

// Driver function declarations (WDM)
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD HyperVDetectorDriverUnload;
DRIVER_DISPATCH HyperVDetectorCreate;
DRIVER_DISPATCH HyperVDetectorClose;
DRIVER_DISPATCH HyperVDetectorDeviceControl;

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
NTSTATUS CheckVmBusRootPresence(PDWORD result);
NTSTATUS DetectPartitionType(PDWORD partitionType);

// Partition type constants
#define PARTITION_TYPE_BARE_METAL   0
#define PARTITION_TYPE_GUEST        1
#define PARTITION_TYPE_ROOT         2

// Utility functions
NTSTATUS GetHyperVVersion(PDWORD version);
UINT64 HvMakeHypercall(
    _In_ UINT64 Control,
    _In_ UINT64 InputParam,
    _In_ UINT64 OutputParam
);

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64)
/* ASM64.asm exports (x86/x64 only) */
BOOLEAN IsHyperVPresent();
UINT64 HvReadMsr(UINT32 MsrIndex);
extern VOID HvWriteMsr(UINT32 MsrIndex, UINT64 Value);
extern UINT64 HvCallHypercall(
    HYPERCALL_PROC HypercallProc,
    UINT64 Control,
    UINT64 InputParam,
    UINT64 OutputParam
);
#else
/* ARM64 stubs — no CPUID/MSR/VMCALL available */
static __inline BOOLEAN IsHyperVPresent(void) { return FALSE; }
static __inline UINT64 HvReadMsr(UINT32 MsrIndex) { UNREFERENCED_PARAMETER(MsrIndex); return 0; }
static __inline VOID HvWriteMsr(UINT32 MsrIndex, UINT64 Value) { UNREFERENCED_PARAMETER(MsrIndex); UNREFERENCED_PARAMETER(Value); }
static __inline UINT64 HvCallHypercall(HYPERCALL_PROC p, UINT64 c, UINT64 i, UINT64 o) {
    UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(o);
    return HV_STATUS_INVALID_HYPERCALL_CODE;
}
#endif

#define HYPERV_DETECTOR_DEVICE_NAME  L"\\Device\\HyperVDetector"
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
