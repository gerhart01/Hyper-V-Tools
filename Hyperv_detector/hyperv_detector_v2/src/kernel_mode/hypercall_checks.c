#include "hyperv_driver.h"

//BOOLEAN IsHyperVPresent() {
//    int cpuInfo[4] = {0};
//    
//    // Check CPUID for hypervisor presence
//    __cpuid(cpuInfo, 1);
//    if (!(cpuInfo[2] & (1 << 31))) {
//        return FALSE;
//    }
//    
//    // Check for Microsoft Hyper-V signature
//    __cpuid(cpuInfo, 0x40000000);
//    return (cpuInfo[1] == 0x7263694D && // "Micr"
//            cpuInfo[2] == 0x666F736F && // "osof"
//            cpuInfo[3] == 0x76482074);  // "t Hv"
//}

NTSTATUS GetHyperVVersion(PDWORD version) {
    int cpuInfo[4];
    
    if (!IsHyperVPresent()) {
        return STATUS_NOT_SUPPORTED;
    }
    
    __cpuid(cpuInfo, 0x40000003);
    *version = cpuInfo[0];
    
    return STATUS_SUCCESS;
}

NTSTATUS ReadMsr(DWORD msrIndex, PULONGLONG value) {
    __try {
        *value = __readmsr(msrIndex);
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("HyperV Detector: Failed to read MSR 0x%x\n", msrIndex));
        return STATUS_PRIVILEGE_NOT_HELD;
    }
}

NTSTATUS PerformHypercall(DWORD hypercallCode, DWORD inputParamCount, DWORD outputParamCount, PDWORD result) {
    ULONGLONG hypercallPage;
    ULONGLONG hypercallInput = 0;
    ULONGLONG hypercallOutput = 0;
    NTSTATUS status;
    
    *result = 0;
    
    if (!IsHyperVPresent()) {
        return STATUS_NOT_SUPPORTED;
    }
    
    // Read hypercall MSR to get hypercall page
    status = ReadMsr(HV_X64_MSR_HYPERCALL, &hypercallPage);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    if (!(hypercallPage & 1)) {
        KdPrint(("HyperV Detector: Hypercall page not enabled\n"));
        return STATUS_NOT_SUPPORTED;
    }
    
    // Prepare hypercall input
    hypercallInput = ((ULONGLONG)hypercallCode << 16) | 
                     ((ULONGLONG)inputParamCount << 32) |
                     ((ULONGLONG)outputParamCount << 48);
    
    __try {
        // Perform the hypercall
        // Note: This is a simplified version. Real hypercalls require proper setup
        // of input/output pages and handling of the hypercall interface

        ULONGLONG hypercallResult = HvMakeHypercall(hypercallCode, hypercallInput, hypercallOutput);
        
        //
        //
        //// Call the hypercall function at the hypercall page
        //// This would typically be done via inline assembly or a specific calling convention
        //__asm {
        //    mov rcx, hypercallInput
        //    mov rdx, 0  // Input parameters GPA (not used in this simple example)
        //    mov r8, 0   // Output parameters GPA (not used in this simple example)
        //    call qword ptr [hypercallPage]
        //    mov hypercallResult, rax
        //}
        
        // Check hypercall result
        if ((hypercallResult & 0xFFFF) == 0) {
            *result = (DWORD)(hypercallResult >> 32);
            KdPrint(("HyperV Detector: Hypercall 0x%x successful, result: 0x%x\n", hypercallCode, *result));
            return STATUS_SUCCESS;
        } else {
            KdPrint(("HyperV Detector: Hypercall 0x%x failed with code: 0x%llx\n", hypercallCode, hypercallResult & 0xFFFF));
            return STATUS_UNSUCCESSFUL;
        }
        
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("HyperV Detector: Exception during hypercall execution\n"));
        return STATUS_ACCESS_VIOLATION;
    }
}

NTSTATUS CheckVmBusPresence(PDWORD result) {
    UNICODE_STRING deviceName;
    PDEVICE_OBJECT deviceObject = NULL;
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status;
    
    *result = 0;
    
    // Try to get VMBus device object
    RtlInitUnicodeString(&deviceName, L"\\Device\\VmBus");
    
    status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &fileObject, &deviceObject);
    if (NT_SUCCESS(status)) {
        *result = 1;
        KdPrint(("HyperV Detector: VMBus device found\n"));
        
        if (fileObject) {
            ObDereferenceObject(fileObject);
        }
        
        return STATUS_SUCCESS;
    }
    
    KdPrint(("HyperV Detector: VMBus device not found (0x%x)\n", status));
    return STATUS_NOT_FOUND;
}