#pragma once
#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>


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