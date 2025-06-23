#include "hyperv_driver.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    
    KdPrint(("HyperV Detector Driver: DriverEntry\n"));
    
    WDF_DRIVER_CONFIG_INIT(&config, HyperVDetectorEvtDeviceAdd);
    
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("HyperV Detector Driver: WdfDriverCreate failed with status 0x%x\n", status));
    }
    
    return status;
}

NTSTATUS HyperVDetectorEvtDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit) {
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    
    UNREFERENCED_PARAMETER(Driver);
    
    KdPrint(("HyperV Detector Driver: HyperVDetectorEvtDeviceAdd\n"));
    
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = HyperVDetectorEvtIoDeviceControl;
    
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    return status;
}

VOID HyperVDetectorEvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, 
                                      size_t InputBufferLength, ULONG IoControlCode) {
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytesReturned = 0;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    
    UNREFERENCED_PARAMETER(Queue);
    
    switch (IoControlCode) {
        case IOCTL_HYPERV_CHECK_HYPERCALL: {
            if (InputBufferLength < sizeof(HYPERCALL_INPUT) || OutputBufferLength < sizeof(HYPERCALL_OUTPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(HYPERCALL_INPUT), &inputBuffer, NULL);
            if (!NT_SUCCESS(status)) break;
            
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(HYPERCALL_OUTPUT), &outputBuffer, NULL);
            if (!NT_SUCCESS(status)) break;
            
            PHYPERCALL_INPUT hypercallInput = (PHYPERCALL_INPUT)inputBuffer;
            PHYPERCALL_OUTPUT hypercallOutput = (PHYPERCALL_OUTPUT)outputBuffer;
            
            DWORD result;
            status = PerformHypercall(hypercallInput->HypercallCode, 
                                    hypercallInput->InputParamCount,
                                    hypercallInput->OutputParamCount, 
                                    &result);
            
            hypercallOutput->Result = NT_SUCCESS(status) ? 0 : 1;
            hypercallOutput->OutputValue = result;
            bytesReturned = sizeof(HYPERCALL_OUTPUT);
            break;
        }
        
        case IOCTL_HYPERV_CHECK_MSR: {
            if (InputBufferLength < sizeof(MSR_INPUT) || OutputBufferLength < sizeof(MSR_OUTPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(MSR_INPUT), &inputBuffer, NULL);
            if (!NT_SUCCESS(status)) break;
            
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(MSR_OUTPUT), &outputBuffer, NULL);
            if (!NT_SUCCESS(status)) break;
            
            PMSR_INPUT msrInput = (PMSR_INPUT)inputBuffer;
            PMSR_OUTPUT msrOutput = (PMSR_OUTPUT)outputBuffer;
            
            ULONGLONG value;
            status = ReadMsr(msrInput->MsrIndex, &value);
            
            msrOutput->Result = NT_SUCCESS(status) ? 0 : 1;
            msrOutput->Value = value;
            bytesReturned = sizeof(MSR_OUTPUT);
            break;
        }
        
        case IOCTL_HYPERV_CHECK_VMBUS: {
            if (OutputBufferLength < sizeof(DWORD)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DWORD), &outputBuffer, NULL);
            if (!NT_SUCCESS(status)) break;
            
            PDWORD result = (PDWORD)outputBuffer;
            status = CheckVmBusPresence(result);
            bytesReturned = sizeof(DWORD);
            break;
        }
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}