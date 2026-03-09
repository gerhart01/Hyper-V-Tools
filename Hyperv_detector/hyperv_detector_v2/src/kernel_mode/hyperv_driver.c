#include "hyperv_driver.h"

/*
 * DriverUnload — clean up device and symbolic link on unload.
 */
VOID HyperVDetectorDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName;

    KdPrint(("HyperV Detector Driver: Unload\n"));

    RtlInitUnicodeString(&symbolicLinkName, HYPERV_DETECTOR_SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

/*
 * IRP_MJ_CREATE — allow applications to open the device.
 */
NTSTATUS HyperVDetectorCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * IRP_MJ_CLOSE — nothing to do on close.
 */
NTSTATUS HyperVDetectorClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * IRP_MJ_DEVICE_CONTROL — handle IOCTLs.
 *
 * All IOCTLs use METHOD_BUFFERED: SystemBuffer holds input on entry
 * and output on completion. Copy inputs before writing outputs when
 * the two structures overlap.
 */
NTSTATUS HyperVDetectorDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status    = STATUS_INVALID_DEVICE_REQUEST;
    SIZE_T bytesOut    = 0;
    PVOID  buf         = Irp->AssociatedIrp.SystemBuffer;
    ULONG  inLen       = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  outLen      = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG  ioCode      = stack->Parameters.DeviceIoControl.IoControlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (ioCode) {

        case IOCTL_HYPERV_CHECK_HYPERCALL: {
            HYPERCALL_INPUT  inputCopy;
            PHYPERCALL_OUTPUT output = (PHYPERCALL_OUTPUT)buf;
            DWORD result;

            if (inLen < sizeof(HYPERCALL_INPUT) || outLen < sizeof(HYPERCALL_OUTPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            /* Copy input before we overwrite the shared buffer with output. */
            RtlCopyMemory(&inputCopy, buf, sizeof(HYPERCALL_INPUT));

            status = PerformHypercall(inputCopy.HypercallCode,
                                      inputCopy.InputParamCount,
                                      inputCopy.OutputParamCount,
                                      &result);

            output->Result      = NT_SUCCESS(status) ? 0 : 1;
            output->OutputValue = result;
            bytesOut = sizeof(HYPERCALL_OUTPUT);
            status   = STATUS_SUCCESS;
            break;
        }

        case IOCTL_HYPERV_CHECK_MSR: {
            MSR_INPUT   inputCopy;
            PMSR_OUTPUT output = (PMSR_OUTPUT)buf;
            ULONGLONG   value  = 0;

            if (inLen < sizeof(MSR_INPUT) || outLen < sizeof(MSR_OUTPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            RtlCopyMemory(&inputCopy, buf, sizeof(MSR_INPUT));

            status = ReadMsr(inputCopy.MsrIndex, &value);

            output->Result = NT_SUCCESS(status) ? 0 : 1;
            output->Value  = value;
            bytesOut = sizeof(MSR_OUTPUT);
            status   = STATUS_SUCCESS;
            break;
        }

        case IOCTL_HYPERV_CHECK_VMBUS: {
            PDWORD result = (PDWORD)buf;

            if (outLen < sizeof(DWORD)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            status   = CheckVmBusPresence(result);
            bytesOut = sizeof(DWORD);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytesOut;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*
 * DriverEntry — create device object, symbolic link, and set dispatch table.
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS       status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("HyperV Detector Driver: DriverEntry\n"));

    RtlInitUnicodeString(&deviceName,      HYPERV_DETECTOR_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, HYPERV_DETECTOR_SYMBOLIC_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status)) {
        KdPrint(("HyperV Detector Driver: IoCreateDevice failed 0x%x\n", status));
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("HyperV Detector Driver: IoCreateSymbolicLink failed 0x%x\n", status));
        IoDeleteDevice(deviceObject);
        return status;
    }

    /* Use buffered I/O so the I/O manager handles user/kernel buffer copies. */
    deviceObject->Flags |= DO_BUFFERED_IO;

    DriverObject->DriverUnload                          = HyperVDetectorDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = HyperVDetectorCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = HyperVDetectorClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = HyperVDetectorDeviceControl;

    KdPrint(("HyperV Detector Driver: Loaded successfully\n"));
    return STATUS_SUCCESS;
}
