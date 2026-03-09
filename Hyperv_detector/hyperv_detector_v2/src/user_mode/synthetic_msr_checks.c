/**
 * synthetic_msr_checks.c - Hyper-V Synthetic MSR Detection
 * 
 * Detects Hyper-V synthetic MSRs including crash enlightenment,
 * synthetic timers, clocksources, and SynIC.
 * 
 * Sources:
 * - https://www.qemu.org/docs/master/system/i386/hyperv.html
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/partition-properties
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_crash_ctl_reg_contents
 * - FOSDEM 2019: Enlightening KVM
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

/* Detection flag for this module */
#define HYPERV_DETECTED_SYNTH_MSR 0x00010000

/* Synthetic MSR addresses */
#define HV_X64_MSR_GUEST_OS_ID          0x40000000
#define HV_X64_MSR_HYPERCALL            0x40000001
#define HV_X64_MSR_VP_INDEX             0x40000002
#define HV_X64_MSR_RESET                0x40000003
#define HV_X64_MSR_VP_RUNTIME           0x40000010
#define HV_X64_MSR_TIME_REF_COUNT       0x40000020
#define HV_X64_MSR_REFERENCE_TSC        0x40000021
#define HV_X64_MSR_TSC_FREQUENCY        0x40000022
#define HV_X64_MSR_APIC_FREQUENCY       0x40000023

/* SynIC MSRs */
#define HV_X64_MSR_SCONTROL             0x40000080
#define HV_X64_MSR_SVERSION             0x40000081
#define HV_X64_MSR_SIEFP                0x40000082
#define HV_X64_MSR_SIMP                 0x40000083
#define HV_X64_MSR_EOM                  0x40000084
#define HV_X64_MSR_SINT0                0x40000090
#define HV_X64_MSR_SINT15               0x4000009F

/* Synthetic Timer MSRs */
#define HV_X64_MSR_STIMER0_CONFIG       0x400000B0
#define HV_X64_MSR_STIMER0_COUNT        0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG       0x400000B2
#define HV_X64_MSR_STIMER1_COUNT        0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG       0x400000B4
#define HV_X64_MSR_STIMER2_COUNT        0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG       0x400000B6
#define HV_X64_MSR_STIMER3_COUNT        0x400000B7

/* Crash MSRs */
#define HV_X64_MSR_CRASH_P0             0x40000100
#define HV_X64_MSR_CRASH_P1             0x40000101
#define HV_X64_MSR_CRASH_P2             0x40000102
#define HV_X64_MSR_CRASH_P3             0x40000103
#define HV_X64_MSR_CRASH_P4             0x40000104
#define HV_X64_MSR_CRASH_CTL            0x40000105

/* Re-enlightenment MSRs */
#define HV_X64_MSR_REENLIGHTENMENT_CONTROL  0x40000106
#define HV_X64_MSR_TSC_EMULATION_CONTROL    0x40000107
#define HV_X64_MSR_TSC_EMULATION_STATUS     0x40000108

/* Privilege flags from CPUID 0x40000003 EAX */
#define HV_MSR_VP_RUNTIME_AVAILABLE         (1 << 0)
#define HV_MSR_TIME_REF_COUNT_AVAILABLE     (1 << 1)
#define HV_MSR_SYNIC_AVAILABLE              (1 << 2)
#define HV_MSR_SYNTIMER_AVAILABLE           (1 << 3)
#define HV_MSR_APIC_ACCESS_AVAILABLE        (1 << 4)
#define HV_MSR_HYPERCALL_AVAILABLE          (1 << 5)
#define HV_MSR_VP_INDEX_AVAILABLE           (1 << 6)
#define HV_MSR_RESET_AVAILABLE              (1 << 7)
#define HV_MSR_STATS_AVAILABLE              (1 << 8)
#define HV_MSR_REFERENCE_TSC_AVAILABLE      (1 << 9)
#define HV_MSR_GUEST_IDLE_AVAILABLE         (1 << 10)
#define HV_MSR_FREQUENCY_AVAILABLE          (1 << 11)

/* Features from CPUID 0x40000003 EDX */
#define HV_FEATURE_MWAIT_AVAILABLE          (1 << 0)
#define HV_FEATURE_GUEST_DEBUGGING          (1 << 1)
#define HV_FEATURE_PERF_MON                 (1 << 2)
#define HV_FEATURE_CPU_GROUPS               (1 << 3)
#define HV_FEATURE_CRASH_MSR_AVAILABLE      (1 << 10)

/* Synthetic MSR detection info */
typedef struct _SYNTH_MSR_INFO {
    BOOL isHypervisorPresent;
    
    /* MSR availability from CPUID */
    DWORD msrAvailability;      /* EAX */
    DWORD miscFeatures;         /* EDX */
    
    /* Individual MSR availability */
    BOOL hasVpRuntime;
    BOOL hasTimeRefCount;
    BOOL hasSynic;
    BOOL hasSyntheticTimers;
    BOOL hasApicAccess;
    BOOL hasHypercallMsr;
    BOOL hasVpIndex;
    BOOL hasResetMsr;
    BOOL hasStatsMsr;
    BOOL hasReferenceTsc;
    BOOL hasGuestIdle;
    BOOL hasFrequency;
    BOOL hasCrashMsr;
    
    /* Feature flags */
    BOOL supportsMwait;
    BOOL supportsGuestDebugging;
    BOOL supportsPerfMon;
    BOOL supportsCpuGroups;
    
    /* Count of available MSRs */
    int availableMsrCount;
} SYNTH_MSR_INFO, *PSYNTH_MSR_INFO;

/*
 * Check synthetic MSR availability from CPUID
 */
static void CheckSyntheticMsrAvailability(PSYNTH_MSR_INFO info)
{
    int cpuInfo[4] = {0};
    
    if (info == NULL) {
        return;
    }
    
    /* Check hypervisor present */
    __cpuid(cpuInfo, 1);
    info->isHypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!info->isHypervisorPresent) {
        return;
    }
    
    /* Check max leaf */
    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[0] < 0x40000003) {
        return;
    }
    
    /* Get MSR availability from CPUID 0x40000003 */
    __cpuid(cpuInfo, 0x40000003);
    
    info->msrAvailability = (DWORD)cpuInfo[0];  /* EAX */
    info->miscFeatures = (DWORD)cpuInfo[3];     /* EDX */
    
    /* Parse individual MSR availability */
    info->hasVpRuntime = (info->msrAvailability & HV_MSR_VP_RUNTIME_AVAILABLE) != 0;
    info->hasTimeRefCount = (info->msrAvailability & HV_MSR_TIME_REF_COUNT_AVAILABLE) != 0;
    info->hasSynic = (info->msrAvailability & HV_MSR_SYNIC_AVAILABLE) != 0;
    info->hasSyntheticTimers = (info->msrAvailability & HV_MSR_SYNTIMER_AVAILABLE) != 0;
    info->hasApicAccess = (info->msrAvailability & HV_MSR_APIC_ACCESS_AVAILABLE) != 0;
    info->hasHypercallMsr = (info->msrAvailability & HV_MSR_HYPERCALL_AVAILABLE) != 0;
    info->hasVpIndex = (info->msrAvailability & HV_MSR_VP_INDEX_AVAILABLE) != 0;
    info->hasResetMsr = (info->msrAvailability & HV_MSR_RESET_AVAILABLE) != 0;
    info->hasStatsMsr = (info->msrAvailability & HV_MSR_STATS_AVAILABLE) != 0;
    info->hasReferenceTsc = (info->msrAvailability & HV_MSR_REFERENCE_TSC_AVAILABLE) != 0;
    info->hasGuestIdle = (info->msrAvailability & HV_MSR_GUEST_IDLE_AVAILABLE) != 0;
    info->hasFrequency = (info->msrAvailability & HV_MSR_FREQUENCY_AVAILABLE) != 0;
    
    /* Crash MSR from EDX */
    info->hasCrashMsr = (info->miscFeatures & HV_FEATURE_CRASH_MSR_AVAILABLE) != 0;
    
    /* Parse misc features */
    info->supportsMwait = (info->miscFeatures & HV_FEATURE_MWAIT_AVAILABLE) != 0;
    info->supportsGuestDebugging = (info->miscFeatures & HV_FEATURE_GUEST_DEBUGGING) != 0;
    info->supportsPerfMon = (info->miscFeatures & HV_FEATURE_PERF_MON) != 0;
    info->supportsCpuGroups = (info->miscFeatures & HV_FEATURE_CPU_GROUPS) != 0;
    
    /* Count available MSRs */
    info->availableMsrCount = 0;
    if (info->hasVpRuntime) info->availableMsrCount++;
    if (info->hasTimeRefCount) info->availableMsrCount++;
    if (info->hasSynic) info->availableMsrCount += 22;  /* SynIC has many MSRs */
    if (info->hasSyntheticTimers) info->availableMsrCount += 8;  /* 4 timers x 2 */
    if (info->hasHypercallMsr) info->availableMsrCount += 2;  /* Guest OS ID + Hypercall */
    if (info->hasVpIndex) info->availableMsrCount++;
    if (info->hasResetMsr) info->availableMsrCount++;
    if (info->hasReferenceTsc) info->availableMsrCount++;
    if (info->hasFrequency) info->availableMsrCount += 2;  /* TSC + APIC */
    if (info->hasCrashMsr) info->availableMsrCount += 6;  /* P0-P4 + CTL */
}

/*
 * Main synthetic MSR check function
 */
DWORD CheckSyntheticMsrHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    SYNTH_MSR_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    CheckSyntheticMsrAvailability(&info);
    
    /* Detection based on hypercall MSR availability */
    if (info.hasHypercallMsr) {
        detected = HYPERV_DETECTED_SYNTH_MSR;
    }
    
    /* Build details */
    AppendToDetails(result, "Synthetic MSR Detection:\n");
    AppendToDetails(result, "  Hypervisor Present: %s\n", 
                   info.isHypervisorPresent ? "YES" : "NO");
    
    if (!info.isHypervisorPresent) {
        return detected;
    }
    
    AppendToDetails(result, "  MSR Availability (EAX): 0x%08X\n", info.msrAvailability);
    AppendToDetails(result, "  Misc Features (EDX): 0x%08X\n", info.miscFeatures);
    AppendToDetails(result, "  Total Available MSRs: ~%d\n", info.availableMsrCount);
    
    AppendToDetails(result, "\n  Core MSRs:\n");
    AppendToDetails(result, "    Guest OS ID (0x40000000): %s\n", 
                   info.hasHypercallMsr ? "Available" : "Not available");
    AppendToDetails(result, "    Hypercall (0x40000001): %s\n", 
                   info.hasHypercallMsr ? "Available" : "Not available");
    AppendToDetails(result, "    VP Index (0x40000002): %s\n", 
                   info.hasVpIndex ? "Available" : "Not available");
    AppendToDetails(result, "    Reset (0x40000003): %s\n", 
                   info.hasResetMsr ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Timing MSRs:\n");
    AppendToDetails(result, "    VP Runtime (0x40000010): %s\n", 
                   info.hasVpRuntime ? "Available" : "Not available");
    AppendToDetails(result, "    Time Ref Count (0x40000020): %s\n", 
                   info.hasTimeRefCount ? "Available" : "Not available");
    AppendToDetails(result, "    Reference TSC (0x40000021): %s\n", 
                   info.hasReferenceTsc ? "Available" : "Not available");
    AppendToDetails(result, "    TSC/APIC Frequency (0x40000022-23): %s\n", 
                   info.hasFrequency ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  SynIC & Timers:\n");
    AppendToDetails(result, "    SynIC (0x40000080-9F): %s\n", 
                   info.hasSynic ? "Available" : "Not available");
    AppendToDetails(result, "    Synthetic Timers (0x400000B0-B7): %s\n", 
                   info.hasSyntheticTimers ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Crash Enlightenment:\n");
    AppendToDetails(result, "    Crash MSRs (0x40000100-105): %s\n", 
                   info.hasCrashMsr ? "Available" : "Not available");
    
    AppendToDetails(result, "\n  Additional Features:\n");
    AppendToDetails(result, "    MWAIT: %s\n", info.supportsMwait ? "Supported" : "Not supported");
    AppendToDetails(result, "    Guest Debugging: %s\n", 
                   info.supportsGuestDebugging ? "Supported" : "Not supported");
    AppendToDetails(result, "    Performance Monitoring: %s\n", 
                   info.supportsPerfMon ? "Supported" : "Not supported");
    
    return detected;
}

/*
 * Quick check for synthetic MSR support
 */
BOOL HasSyntheticMsrSupport(void)
{
    SYNTH_MSR_INFO info = {0};
    CheckSyntheticMsrAvailability(&info);
    return info.hasHypercallMsr;
}

/*
 * Check if SynIC is available
 */
BOOL HasSynicSupport(void)
{
    SYNTH_MSR_INFO info = {0};
    CheckSyntheticMsrAvailability(&info);
    return info.hasSynic;
}

/*
 * Check if crash MSRs are available
 */
BOOL HasCrashMsrSupport(void)
{
    SYNTH_MSR_INFO info = {0};
    CheckSyntheticMsrAvailability(&info);
    return info.hasCrashMsr;
}

/*
 * Get count of available synthetic MSRs
 */
int GetSyntheticMsrCount(void)
{
    SYNTH_MSR_INFO info = {0};
    CheckSyntheticMsrAvailability(&info);
    return info.availableMsrCount;
}
