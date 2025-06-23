#include "hyperv_detector.h"

void ExecuteCpuid(DWORD function, PCPUID_RESULT result) {
    int cpuInfo[4];
    __cpuid(cpuInfo, function);
    result->eax = cpuInfo[0];
    result->ebx = cpuInfo[1];
    result->ecx = cpuInfo[2];
    result->edx = cpuInfo[3];
}

DWORD CheckCpuidHyperV(PDETECTION_RESULT result) {
    CPUID_RESULT cpuid_result;
    DWORD detected = 0;
    
    // Check for hypervisor presence
    ExecuteCpuid(1, &cpuid_result);
    if (cpuid_result.ecx & (1 << 31)) {
        detected |= HYPERV_DETECTED_CPUID;
        AppendToDetails(result, "CPUID: Hypervisor present bit set\n");
        
        // Check hypervisor vendor
        ExecuteCpuid(CPUID_HYPERVISOR_PRESENT, &cpuid_result);
        char vendor[13] = {0};
        memcpy(vendor, &cpuid_result.ebx, 4);
        memcpy(vendor + 4, &cpuid_result.ecx, 4);
        memcpy(vendor + 8, &cpuid_result.edx, 4);
        
        AppendToDetails(result, "CPUID: Hypervisor vendor: %s\n", vendor);
        
        if (strcmp(vendor, "Microsoft Hv") == 0) {
            AppendToDetails(result, "CPUID: Microsoft Hyper-V detected\n");
            
            // Check Hyper-V interface
            ExecuteCpuid(CPUID_HYPERV_INTERFACE, &cpuid_result);
            AppendToDetails(result, "CPUID: Hyper-V interface signature: %08X\n", cpuid_result.eax);
            
            // Check Hyper-V version
            ExecuteCpuid(CPUID_HYPERV_VERSION, &cpuid_result);
            AppendToDetails(result, "CPUID: Hyper-V version: %d.%d.%d\n", 
                           cpuid_result.ebx >> 16, 
                           cpuid_result.ebx & 0xFFFF, 
                           cpuid_result.eax);
            
            // Check Hyper-V features
            ExecuteCpuid(CPUID_HYPERV_FEATURES, &cpuid_result);
            AppendToDetails(result, "CPUID: Hyper-V features: EAX=%08X, EBX=%08X, ECX=%08X, EDX=%08X\n",
                           cpuid_result.eax, cpuid_result.ebx, cpuid_result.ecx, cpuid_result.edx);
            
            // Check for enlightenments
            if (cpuid_result.eax & 0x01) {
                AppendToDetails(result, "CPUID: VP Runtime MSR available\n");
            }
            if (cpuid_result.eax & 0x02) {
                AppendToDetails(result, "CPUID: Partition Reference Counter MSR available\n");
            }
            if (cpuid_result.eax & 0x04) {
                AppendToDetails(result, "CPUID: Synthetic Interrupt Controller available\n");
            }
            if (cpuid_result.eax & 0x08) {
                AppendToDetails(result, "CPUID: Synthetic Timers available\n");
            }
            if (cpuid_result.eax & 0x10) {
                AppendToDetails(result, "CPUID: APIC Access MSRs available\n");
            }
            if (cpuid_result.eax & 0x20) {
                AppendToDetails(result, "CPUID: Hypercall MSRs available\n");
            }
        }
    }
    
    return detected;
}