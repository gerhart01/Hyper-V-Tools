#include "hyperv_driver.h"

PVOID g_HypercallPage = NULL;
BOOLEAN g_HyperVInitialized = FALSE;

NTSTATUS InitializeHyperV(VOID)
{
    PHYSICAL_ADDRESS PhysAddr;
    UINT64 GuestOsId;

    // Allocate hypercall page (must be page-aligned)
    g_HypercallPage = ExAllocatePool2(
        NonPagedPool,
        PAGE_SIZE,
        HV_POOL_TAG
    );

    if (!g_HypercallPage)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_HypercallPage, PAGE_SIZE);

    // Set Guest OS ID (required before enabling hypercalls)
    GuestOsId = HV_GUEST_OS_ID_VALUE;
    HvWriteMsr(HV_X64_MSR_GUEST_OS_ID, GuestOsId);

    // Get physical address of hypercall page
    PhysAddr = MmGetPhysicalAddress(g_HypercallPage);

    // Enable hypercall page
    HvWriteMsr(HV_X64_MSR_HYPERCALL, PhysAddr.QuadPart | HV_HYPERCALL_ENABLE);

    g_HyperVInitialized = TRUE;

    return STATUS_SUCCESS;
}

UINT64 HvMakeHypercall(
    _In_ UINT64 Control,
    _In_opt_ UINT64 InputParam,
    _In_opt_ UINT64 OutputParam
)
{
    if (!g_HyperVInitialized || !g_HypercallPage)
    {
        return HV_STATUS_INVALID_HYPERCALL_CODE;
    }

    // Call assembly function to perform the actual hypercall
    return HvCallHypercall(
        (HYPERCALL_PROC)g_HypercallPage,
        Control,
        InputParam,
        OutputParam
    );
}

UINT32 HvGetCurrentVpIndex(VOID)
{
    if (!g_HyperVInitialized)
    {
        return (UINT32)-1;
    }

    return (UINT32)HvReadMsr(HV_X64_MSR_VP_INDEX);
}