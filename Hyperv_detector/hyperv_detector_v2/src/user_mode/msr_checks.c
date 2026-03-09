/**
 * msr_checks.c - Hyper-V Synthetic MSR Detection
 * 
 * Detects Hyper-V through synthetic Model-Specific Registers (MSRs).
 * These MSRs are exposed to guest VMs for paravirtualization.
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
 * - https://www.qemu.org/docs/master/system/i386/hyperv.html
 * - https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/hyperv-tlfs.h
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
/* intrin.h included conditionally via common.h */

#define HYPERV_DETECTED_MSR 0x00200000

/*
 * Hyper-V Synthetic MSR addresses
 * From Microsoft TLFS and Linux kernel headers
 */
#define HV_X64_MSR_GUEST_OS_ID           0x40000000
#define HV_X64_MSR_HYPERCALL             0x40000001
#define HV_X64_MSR_VP_INDEX              0x40000002
#define HV_X64_MSR_RESET                 0x40000003
#define HV_X64_MSR_VP_RUNTIME            0x40000010
#define HV_X64_MSR_TIME_REF_COUNT        0x40000020
#define HV_X64_MSR_REFERENCE_TSC         0x40000021
#define HV_X64_MSR_TSC_FREQUENCY         0x40000022
#define HV_X64_MSR_APIC_FREQUENCY        0x40000023
#define HV_X64_MSR_EOI                   0x40000070
#define HV_X64_MSR_ICR                   0x40000071
#define HV_X64_MSR_TPR                   0x40000072
#define HV_X64_MSR_VP_ASSIST_PAGE        0x40000073
#define HV_X64_MSR_SCONTROL              0x40000080
#define HV_X64_MSR_SVERSION              0x40000081
#define HV_X64_MSR_SIEFP                 0x40000082
#define HV_X64_MSR_SIMP                  0x40000083
#define HV_X64_MSR_EOM                   0x40000084
#define HV_X64_MSR_SINT0                 0x40000090
#define HV_X64_MSR_SINT15                0x4000009F
#define HV_X64_MSR_STIMER0_CONFIG        0x400000B0
#define HV_X64_MSR_STIMER0_COUNT         0x400000B1
#define HV_X64_MSR_STIMER3_COUNT         0x400000B7
#define HV_X64_MSR_CRASH_P0              0x40000100
#define HV_X64_MSR_CRASH_P4              0x40000104
#define HV_X64_MSR_CRASH_CTL             0x40000105
#define HV_X64_MSR_REENLIGHTENMENT_CONTROL 0x40000106
#define HV_X64_MSR_TSC_EMULATION_CONTROL   0x40000107
#define HV_X64_MSR_TSC_EMULATION_STATUS    0x40000108

/* MSR info structure */
typedef struct _MSR_INFO {
    DWORD msrAddress;
    const char* name;
    const char* description;
    BOOL rootOnly;
} MSR_INFO, *PMSR_INFO;

static const MSR_INFO g_HyperVMSRs[] = {
    {HV_X64_MSR_GUEST_OS_ID,       "HV_X64_MSR_GUEST_OS_ID",       "Guest OS identification",    FALSE},
    {HV_X64_MSR_HYPERCALL,         "HV_X64_MSR_HYPERCALL",         "Hypercall page setup",       FALSE},
    {HV_X64_MSR_VP_INDEX,          "HV_X64_MSR_VP_INDEX",          "Virtual processor index",    FALSE},
    {HV_X64_MSR_VP_RUNTIME,        "HV_X64_MSR_VP_RUNTIME",        "VP runtime (100ns units)",   FALSE},
    {HV_X64_MSR_TIME_REF_COUNT,    "HV_X64_MSR_TIME_REF_COUNT",    "Reference time counter",     FALSE},
    {HV_X64_MSR_REFERENCE_TSC,     "HV_X64_MSR_REFERENCE_TSC",     "Reference TSC page",         FALSE},
    {HV_X64_MSR_TSC_FREQUENCY,     "HV_X64_MSR_TSC_FREQUENCY",     "TSC frequency (Hz)",         FALSE},
    {HV_X64_MSR_APIC_FREQUENCY,    "HV_X64_MSR_APIC_FREQUENCY",    "APIC frequency (Hz)",        FALSE},
    {HV_X64_MSR_VP_ASSIST_PAGE,    "HV_X64_MSR_VP_ASSIST_PAGE",    "VP Assist page",             FALSE},
    {HV_X64_MSR_SCONTROL,          "HV_X64_MSR_SCONTROL",          "SynIC control",              FALSE},
    {HV_X64_MSR_CRASH_CTL,         "HV_X64_MSR_CRASH_CTL",         "Crash control MSR",          FALSE},
    {0, NULL, NULL, FALSE}
};

/*
 * Check CPUID for MSR access permissions
 * CPUID 0x40000003 EAX contains MSR access flags
 */
typedef struct _MSR_PERMISSIONS {
    BOOL accessVpRunTime;           /* Bit 0 */
    BOOL accessPartitionRefCounter; /* Bit 1 */
    BOOL accessSynicRegs;           /* Bit 2 */
    BOOL accessSyntheticTimerRegs;  /* Bit 3 */
    BOOL accessIntrCtrlRegs;        /* Bit 4 */
    BOOL accessHypercallMsrs;       /* Bit 5 */
    BOOL accessVpIndex;             /* Bit 6 */
    BOOL accessResetReg;            /* Bit 7 */
    BOOL accessStatsReg;            /* Bit 8 */
    BOOL accessPartitionRefTsc;     /* Bit 9 */
    BOOL accessGuestIdleReg;        /* Bit 10 */
    BOOL accessFrequencyRegs;       /* Bit 11 */
    BOOL accessDebugRegs;           /* Bit 12 */
    BOOL accessReenlightenment;     /* Bit 13 */
} MSR_PERMISSIONS, *PMSR_PERMISSIONS;

/*
 * Get MSR permissions from CPUID
 */
static void GetMSRPermissions(PMSR_PERMISSIONS perms)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    DWORD eax = 0;
    
    if (perms == NULL) {
        return;
    }
    
    memset(perms, 0, sizeof(MSR_PERMISSIONS));
    
    /* Check hypervisor presence first */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return;  /* No hypervisor */
    }
    
    /* Get MSR permissions from CPUID 0x40000003 */
    __cpuid(cpuInfo, 0x40000003);
    eax = (DWORD)cpuInfo[0];
    
    perms->accessVpRunTime = (eax & 0x0001) != 0;
    perms->accessPartitionRefCounter = (eax & 0x0002) != 0;
    perms->accessSynicRegs = (eax & 0x0004) != 0;
    perms->accessSyntheticTimerRegs = (eax & 0x0008) != 0;
    perms->accessIntrCtrlRegs = (eax & 0x0010) != 0;
    perms->accessHypercallMsrs = (eax & 0x0020) != 0;
    perms->accessVpIndex = (eax & 0x0040) != 0;
    perms->accessResetReg = (eax & 0x0080) != 0;
    perms->accessStatsReg = (eax & 0x0100) != 0;
    perms->accessPartitionRefTsc = (eax & 0x0200) != 0;
    perms->accessGuestIdleReg = (eax & 0x0400) != 0;
    perms->accessFrequencyRegs = (eax & 0x0800) != 0;
    perms->accessDebugRegs = (eax & 0x1000) != 0;
    perms->accessReenlightenment = (eax & 0x2000) != 0;
}

/*
 * Count granted MSR permissions
 */
static int CountMSRPermissions(void)
{
    MSR_PERMISSIONS perms = {0};
    int count = 0;
    
    GetMSRPermissions(&perms);
    
    if (perms.accessVpRunTime) count++;
    if (perms.accessPartitionRefCounter) count++;
    if (perms.accessSynicRegs) count++;
    if (perms.accessSyntheticTimerRegs) count++;
    if (perms.accessIntrCtrlRegs) count++;
    if (perms.accessHypercallMsrs) count++;
    if (perms.accessVpIndex) count++;
    if (perms.accessResetReg) count++;
    if (perms.accessStatsReg) count++;
    if (perms.accessPartitionRefTsc) count++;
    if (perms.accessGuestIdleReg) count++;
    if (perms.accessFrequencyRegs) count++;
    if (perms.accessDebugRegs) count++;
    if (perms.accessReenlightenment) count++;
    
    return count;
}

/*
 * Main MSR check function
 */
DWORD CheckMSRHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    int cpuInfo[4] = {0, 0, 0, 0};
    MSR_PERMISSIONS perms = {0};
    int permCount = 0;
    DWORD eax = 0;
    DWORD ebx = 0;
    
    if (result == NULL) {
        return 0;
    }
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        AppendToDetails(result, "MSR Check: No hypervisor present\n");
        return 0;
    }
    
    /* Get CPUID 0x40000003 for MSR info */
    __cpuid(cpuInfo, 0x40000003);
    eax = (DWORD)cpuInfo[0];
    ebx = (DWORD)cpuInfo[1];
    
    /* Get permissions */
    GetMSRPermissions(&perms);
    permCount = CountMSRPermissions();
    
    if (permCount > 0) {
        detected = HYPERV_DETECTED_MSR;
    }
    
    /* Build details */
    AppendToDetails(result, "Synthetic MSR Detection:\n");
    AppendToDetails(result, "  CPUID 0x40000003 EAX: 0x%08X\n", eax);
    AppendToDetails(result, "  CPUID 0x40000003 EBX: 0x%08X\n", ebx);
    AppendToDetails(result, "  MSR Permissions granted: %d\n", permCount);
    
    /* List key permissions */
    if (perms.accessHypercallMsrs) {
        AppendToDetails(result, "  - Hypercall MSRs: YES\n");
    }
    if (perms.accessVpIndex) {
        AppendToDetails(result, "  - VP Index MSR: YES\n");
    }
    if (perms.accessFrequencyRegs) {
        AppendToDetails(result, "  - Frequency MSRs: YES\n");
    }
    if (perms.accessSynicRegs) {
        AppendToDetails(result, "  - SynIC MSRs: YES\n");
    }
    if (perms.accessPartitionRefTsc) {
        AppendToDetails(result, "  - Reference TSC: YES\n");
    }
    
    return detected;
}

/*
 * Get raw MSR permission flags
 */
DWORD GetMSRPermissionFlags(void)
{
    int cpuInfo[4] = {0, 0, 0, 0};
    
    /* Check hypervisor presence */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & 0x80000000)) {
        return 0;
    }
    
    __cpuid(cpuInfo, 0x40000003);
    return (DWORD)cpuInfo[0];
}

/*
 * Check if specific MSR permission is granted
 */
BOOL HasMSRPermission(DWORD bitIndex)
{
    DWORD flags = GetMSRPermissionFlags();
    return (flags & (1 << bitIndex)) != 0;
}
