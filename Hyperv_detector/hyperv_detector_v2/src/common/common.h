#pragma once
#ifndef COMMON_H
#define COMMON_H

/* Prevent winsock.h inclusion - use winsock2.h instead */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK2API_
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Architecture detection */
#if defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64)
#define ARCH_X86_OR_X64 1
#include <intrin.h>
#else
#define ARCH_X86_OR_X64 0
/* Provide stub intrinsics so x86-specific detection code compiles on ARM64.
   All stubs return zeroes, making detection functions report "not detected". */
static __inline void __cpuid(int cpuInfo[4], int function) {
    (void)function;
    cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
}
static __inline void __cpuidex(int cpuInfo[4], int function, int subLeaf) {
    (void)function; (void)subLeaf;
    cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
}
static __inline unsigned __int64 __rdtsc(void) { return 0; }
static __inline unsigned __int64 __rdtscp(unsigned int *aux) { if (aux) *aux = 0; return 0; }
#endif

// Detection result flags
#define HYPERV_DETECTED_NONE        0x00000000
#define HYPERV_DETECTED_CPUID       0x00000001
#define HYPERV_DETECTED_REGISTRY    0x00000002
#define HYPERV_DETECTED_FILES       0x00000004
#define HYPERV_DETECTED_SERVICES    0x00000008
#define HYPERV_DETECTED_DEVICES     0x00000010
#define HYPERV_DETECTED_BIOS        0x00000020
#define HYPERV_DETECTED_PROCESSES   0x00000040
#define HYPERV_DETECTED_HYPERCALLS  0x00000080
#define HYPERV_DETECTED_OBJECTS     0x00000100
#define HYPERV_DETECTED_NESTED      0x00000200
#define HYPERV_DETECTED_SANDBOX     0x00000400
#define HYPERV_DETECTED_DOCKER      0x00000800
#define HYPERV_DETECTED_REMOVED     0x00001000

// CPUID constants
#define CPUID_HYPERVISOR_PRESENT    0x40000000
#define CPUID_HYPERV_VENDOR_NEUTRAL 0x40000001
#define CPUID_HYPERV_INTERFACE      0x40000002
#define CPUID_HYPERV_VERSION        0x40000003
#define CPUID_HYPERV_FEATURES       0x40000004

// Hyper-V MSR constants
#define HV_X64_MSR_GUEST_OS_ID      0x40000000
#define HV_X64_MSR_HYPERCALL        0x40000001
#define HV_X64_MSR_VP_INDEX         0x40000002
#define HV_X64_MSR_RESET            0x40000003
#define HV_X64_MSR_VP_RUNTIME       0x40000010

// Hypercall codes
#define HVCALL_POST_MESSAGE         0x005C
#define HVCALL_SIGNAL_EVENT         0x005D
#define HVCALL_GET_PARTITION_ID     0x0046
#define HVCALL_GET_VP_REGISTERS     0x0050

typedef struct _DETECTION_RESULT {
    DWORD DetectionFlags;
    char Details[4096];
    DWORD ProcessId;
    char ProcessName[256];
} DETECTION_RESULT, * PDETECTION_RESULT;

typedef struct _CPUID_RESULT {
    DWORD eax;
    DWORD ebx;
    DWORD ecx;
    DWORD edx;
} CPUID_RESULT, * PCPUID_RESULT;

#endif // COMMON_H