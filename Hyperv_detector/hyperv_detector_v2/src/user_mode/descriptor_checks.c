/**
 * descriptor_checks.c - Descriptor Table based Hyper-V detection
 * 
 * Analyzes IDT (Interrupt Descriptor Table), GDT (Global Descriptor Table),
 * and LDT (Local Descriptor Table) for virtualization indicators.
 * 
 * In VMs, these tables are often relocated to specific memory regions
 * or have different base addresses than on bare metal.
 */

#include "hyperv_detector.h"

// Detection flag for descriptor tables
#define HYPERV_DETECTED_DESCRIPTOR 0x00100000

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_TABLE_REGISTER {
    WORD Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, *PDESCRIPTOR_TABLE_REGISTER;

typedef struct _SEGMENT_SELECTOR {
    WORD RPL : 2;
    WORD TI : 1;    // Table Indicator: 0 = GDT, 1 = LDT
    WORD Index : 13;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;
#pragma pack(pop)

// Store IDT base using SIDT instruction
static void GetIDTBase(PDESCRIPTOR_TABLE_REGISTER pIDT) {
#if defined(_M_IX86)
    __asm {
        mov eax, pIDT
        sidt [eax]
    }
#else
    // x64: MSVC doesn't have __sidt intrinsic; ARM64: no equivalent
    memset(pIDT, 0, sizeof(*pIDT));
#endif
}

// Store GDT base using SGDT instruction
static void GetGDTBase(PDESCRIPTOR_TABLE_REGISTER pGDT) {
#if defined(_M_IX86)
    __asm {
        mov eax, pGDT
        sgdt [eax]
    }
#else
    memset(pGDT, 0, sizeof(*pGDT));
#endif
}

// Store LDT selector using SLDT instruction
static WORD GetLDTSelector(void) {
    WORD selector = 0;
#if defined(_M_IX86)
    __asm {
        sldt selector
    }
#endif
    return selector;
}

// Store TR (Task Register) using STR instruction
static WORD GetTRSelector(void) {
    WORD selector = 0;
#if defined(_M_IX86)
    __asm {
        str selector
    }
#endif
    return selector;
}

// Known VM IDT/GDT base address patterns
static BOOL IsVMAddressPattern(ULONG_PTR address) {
#if !ARCH_X86_OR_X64
    (void)address;
    return FALSE;
#elif defined(_M_X64)
    // On x64, kernel addresses typically start with 0xFFFF
    // VM hypervisors may relocate tables to different regions
    
    // Get high bits
    ULONG_PTR highBits = address >> 48;
    
    // Normal Windows kernel: 0xFFFF80xxxxxxxx or 0xFFFFF80xxxxxxxx
    // VMs sometimes use slightly different mappings
    
    // This is a heuristic - actual detection needs baseline
    return FALSE;
#else
    // On x86, addresses above 0x80000000 are kernel space
    // Some VMs relocate to specific regions
    
    // VirtualPC/Virtual Server often used 0xE8XXXXXX
    if ((address & 0xFF000000) == 0xE8000000) {
        return TRUE;
    }
    
    // VMware often used 0xFFFFXXXX
    if ((address & 0xFFFF0000) == 0xFFFF0000) {
        return TRUE;
    }
    
    return FALSE;
#endif
}

// Check for IDT entry hooking (common in older VMs)
static BOOL CheckIDTHooking(ULONG_PTR idtBase, WORD idtLimit) {
    // Note: Reading IDT from user mode requires special access
    // This is more of a kernel-mode technique
    // Here we just log the base and limit
    return FALSE;
}

// Analyze descriptor table consistency across CPUs
static DWORD CheckDescriptorConsistency(PDETECTION_RESULT result) {
    DWORD detected = 0;
    SYSTEM_INFO sysInfo;
    DESCRIPTOR_TABLE_REGISTER idtFirst = {0};
    DESCRIPTOR_TABLE_REGISTER gdtFirst = {0};
    
    GetSystemInfo(&sysInfo);
    
    // Get descriptor tables on current CPU
    DWORD_PTR originalAffinity = SetThreadAffinityMask(GetCurrentThread(), 1);
    GetIDTBase(&idtFirst);
    GetGDTBase(&gdtFirst);
    
    AppendToDetails(result, "Descriptor: CPU 0 - IDT Base: 0x%p, Limit: 0x%04X\n",
                   (void*)idtFirst.Base, idtFirst.Limit);
    AppendToDetails(result, "Descriptor: CPU 0 - GDT Base: 0x%p, Limit: 0x%04X\n",
                   (void*)gdtFirst.Base, gdtFirst.Limit);
    
    // Check each CPU for consistency (VMs sometimes have per-CPU differences)
    BOOL inconsistent = FALSE;
    for (DWORD cpu = 1; cpu < sysInfo.dwNumberOfProcessors && cpu < 64; cpu++) {
        DWORD_PTR cpuMask = (DWORD_PTR)1 << cpu;
        
        if (SetThreadAffinityMask(GetCurrentThread(), cpuMask)) {
            // Give scheduler time to switch CPU
            SwitchToThread();
            
            DESCRIPTOR_TABLE_REGISTER idt = {0};
            DESCRIPTOR_TABLE_REGISTER gdt = {0};
            
            GetIDTBase(&idt);
            GetGDTBase(&gdt);
            
            // Check for unexpected differences
            // In bare metal, all CPUs typically have same GDT/IDT base
            // Some VMs allocate per-CPU tables
            
            if (gdt.Base != gdtFirst.Base) {
                AppendToDetails(result, "Descriptor: CPU %d - Different GDT Base: 0x%p\n",
                               cpu, (void*)gdt.Base);
                inconsistent = TRUE;
            }
            
            // IDT is often per-CPU even on bare metal, so check differently
            // Look for unusual patterns
            
            AppendToDetails(result, "Descriptor: CPU %d - IDT Base: 0x%p\n",
                           cpu, (void*)idt.Base);
        }
    }
    
    // Restore original affinity
    SetThreadAffinityMask(GetCurrentThread(), originalAffinity);
    
    if (inconsistent) {
        detected |= HYPERV_DETECTED_DESCRIPTOR;
        AppendToDetails(result, "Descriptor: Inconsistent descriptor tables across CPUs\n");
    }
    
    return detected;
}

// Check for specific Hyper-V descriptor patterns
static DWORD CheckHyperVDescriptors(PDETECTION_RESULT result) {
    DWORD detected = 0;
    DESCRIPTOR_TABLE_REGISTER idt = {0};
    DESCRIPTOR_TABLE_REGISTER gdt = {0};
    
    GetIDTBase(&idt);
    GetGDTBase(&gdt);
    
    // In Hyper-V guest, descriptor tables are in guest physical address space
    // mapped by hypervisor. The exact addresses depend on Windows version.
    
    // Check IDT limit
    // Standard x64 Windows IDT has 256 entries * 16 bytes = 4096 bytes
    // Limit should be 0xFFF or similar
    if (idt.Limit > 0x1000) {
        AppendToDetails(result, "Descriptor: Unusual IDT limit: 0x%04X\n", idt.Limit);
    }
    
    // Check GDT limit
    // Standard Windows GDT is relatively small
    if (gdt.Limit > 0x200) {
        AppendToDetails(result, "Descriptor: Unusual GDT limit: 0x%04X\n", gdt.Limit);
    }
    
    // Check LDT selector
    WORD ldtSelector = GetLDTSelector();
    AppendToDetails(result, "Descriptor: LDT Selector: 0x%04X\n", ldtSelector);
    
    // Check Task Register
    WORD trSelector = GetTRSelector();
    AppendToDetails(result, "Descriptor: TR Selector: 0x%04X\n", trSelector);
    
    // Analyze selector values
    SEGMENT_SELECTOR* pLdt = (SEGMENT_SELECTOR*)&ldtSelector;
    SEGMENT_SELECTOR* pTr = (SEGMENT_SELECTOR*)&trSelector;
    
    AppendToDetails(result, "Descriptor: LDT Index: %d, TI: %d, RPL: %d\n",
                   pLdt->Index, pLdt->TI, pLdt->RPL);
    AppendToDetails(result, "Descriptor: TR Index: %d, TI: %d, RPL: %d\n",
                   pTr->Index, pTr->TI, pTr->RPL);
    
    // Check for VM-specific patterns
    if (IsVMAddressPattern(idt.Base) || IsVMAddressPattern(gdt.Base)) {
        detected |= HYPERV_DETECTED_DESCRIPTOR;
        AppendToDetails(result, "Descriptor: VM-specific address pattern detected\n");
    }
    
    return detected;
}

// Check STR (Store Task Register) timing - VMs often have overhead
static DWORD CheckSTRTiming(PDETECTION_RESULT result) {
#if !ARCH_X86_OR_X64
    AppendToDetails(result, "Descriptor: STR timing not available on ARM64\n");
    return 0;
#else
    DWORD detected = 0;
    UINT64 totalCycles = 0;
    const int iterations = 1000;
    
    // Set high priority and pin to CPU
    HANDLE hThread = GetCurrentThread();
    int oldPriority = GetThreadPriority(hThread);
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
    DWORD_PTR oldAffinity = SetThreadAffinityMask(hThread, 1);
    
    // Warm up
    for (int i = 0; i < 100; i++) {
        volatile WORD dummy = GetTRSelector();
        (void)dummy;
    }
    
    // Measure STR timing
    UINT64 minCycles = ULLONG_MAX;
    UINT64 maxCycles = 0;
    
    for (int i = 0; i < iterations; i++) {
        UINT64 start = __rdtsc();
        volatile WORD tr = GetTRSelector();
        UINT64 end = __rdtsc();
        (void)tr;
        
        UINT64 cycles = end - start;
        totalCycles += cycles;
        
        if (cycles < minCycles) minCycles = cycles;
        if (cycles > maxCycles) maxCycles = cycles;
    }
    
    // Restore thread settings
    SetThreadAffinityMask(hThread, oldAffinity);
    SetThreadPriority(hThread, oldPriority);
    
    UINT64 avgCycles = totalCycles / iterations;
    
    AppendToDetails(result, "Descriptor: STR timing - Min: %llu, Max: %llu, Avg: %llu cycles\n",
                   minCycles, maxCycles, avgCycles);
    
    // High average or variance indicates VM
    // STR is typically very fast on bare metal (< 50 cycles)
    // VMs may show > 200 cycles average
    if (avgCycles > 200 || (maxCycles - minCycles) > 500) {
        detected |= HYPERV_DETECTED_DESCRIPTOR;
        AppendToDetails(result, "Descriptor: High STR overhead suggests VM\n");
    }
    
    return detected;
#endif /* ARCH_X86_OR_X64 */
}

DWORD CheckDescriptorTablesHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    
    AppendToDetails(result, "Descriptor: Analyzing descriptor tables...\n");
    
    detected |= CheckHyperVDescriptors(result);
    detected |= CheckDescriptorConsistency(result);
    detected |= CheckSTRTiming(result);
    
    return detected;
}
