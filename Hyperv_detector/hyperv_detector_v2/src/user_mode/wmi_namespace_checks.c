/**
 * wmi_namespace_checks.c - WMI Hyper-V Namespace Detection
 * 
 * Checks for presence of Hyper-V WMI namespaces (root\virtualization and root\virtualization\v2)
 * which are only present on Hyper-V hosts (not in guest VMs).
 * 
 * Sources:
 * - https://learn.microsoft.com/en-us/archive/blogs/virtual_pc_guy/the-v2-wmi-namespace-in-hyper-v-on-windows-8
 * - https://learn.microsoft.com/en-us/archive/blogs/richard_macdonald/programming-hyper-v-with-wmi-and-c-getting-started
 * - https://virtualizationdojo.com/hyper-v/undocumented-changes-hyper-v-2016-wmi/
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#define HYPERV_DETECTED_WMI_NAMESPACE 0x10000000

/* WMI namespace paths */
static const wchar_t* g_HyperVNamespaces[] = {
    L"ROOT\\virtualization\\v2",    /* Windows Server 2012+ / Windows 8+ */
    L"ROOT\\virtualization",        /* Windows Server 2008/2008R2 (legacy) */
    NULL
};

/* Key WMI classes in Hyper-V namespace */
static const wchar_t* g_HyperVWmiClasses[] = {
    L"Msvm_ComputerSystem",
    L"Msvm_VirtualSystemManagementService",
    L"Msvm_VirtualSwitch",
    L"Msvm_VirtualEthernetSwitch",
    L"Msvm_SummaryInformation",
    NULL
};

/* WMI namespace detection info */
typedef struct _WMI_NAMESPACE_INFO {
    BOOL hasVirtualizationV2;
    BOOL hasVirtualizationV1;
    BOOL hasMsvmComputerSystem;
    BOOL hasMsvmVSMS;
    BOOL hasMsvmVirtualSwitch;
    int vmCount;
    BOOL isHyperVHost;
    char hostName[256];
} WMI_NAMESPACE_INFO, *PWMI_NAMESPACE_INFO;

/*
 * Check if a WMI namespace exists
 */
static BOOL CheckWmiNamespaceExists(const wchar_t* namespacePath)
{
    HRESULT hr = S_OK;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    BOOL exists = FALSE;
    
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return FALSE;
    }
    
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    
    /* Create WMI locator */
    hr = CoCreateInstance(
        &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void**)&pLocator);
    
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }
    
    /* Try to connect to namespace */
    hr = pLocator->lpVtbl->ConnectServer(
        pLocator, (BSTR)namespacePath,
        NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    
    if (SUCCEEDED(hr)) {
        exists = TRUE;
        pServices->lpVtbl->Release(pServices);
    }
    
    pLocator->lpVtbl->Release(pLocator);
    CoUninitialize();
    
    return exists;
}

/*
 * Query Msvm_ComputerSystem to count VMs (host detection)
 */
static int CountVirtualMachines(void)
{
    HRESULT hr = S_OK;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pClassObj = NULL;
    ULONG uReturn = 0;
    int vmCount = 0;
    
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return 0;
    }
    
    hr = CoCreateInstance(
        &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void**)&pLocator);
    
    if (FAILED(hr)) {
        CoUninitialize();
        return 0;
    }
    
    /* Connect to v2 namespace first */
    hr = pLocator->lpVtbl->ConnectServer(
        pLocator, L"ROOT\\virtualization\\v2",
        NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    
    if (FAILED(hr)) {
        /* Try legacy namespace */
        hr = pLocator->lpVtbl->ConnectServer(
            pLocator, L"ROOT\\virtualization",
            NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    }
    
    if (FAILED(hr)) {
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return 0;
    }
    
    /* Set security on proxy */
    hr = CoSetProxyBlanket(
        (IUnknown*)pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    
    /* Query for VMs (exclude host entry) */
    hr = pServices->lpVtbl->ExecQuery(
        pServices, L"WQL",
        L"SELECT * FROM Msvm_ComputerSystem WHERE Caption = 'Virtual Machine'",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);
    
    if (SUCCEEDED(hr)) {
        while (pEnumerator) {
            hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pClassObj, &uReturn);
            if (uReturn == 0) break;
            vmCount++;
            pClassObj->lpVtbl->Release(pClassObj);
        }
        pEnumerator->lpVtbl->Release(pEnumerator);
    }
    
    pServices->lpVtbl->Release(pServices);
    pLocator->lpVtbl->Release(pLocator);
    CoUninitialize();
    
    return vmCount;
}

/*
 * Check if Msvm_VirtualSystemManagementService exists (host only)
 */
static BOOL CheckVSMSExists(void)
{
    HRESULT hr = S_OK;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pClassObj = NULL;
    ULONG uReturn = 0;
    BOOL exists = FALSE;
    
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return FALSE;
    }
    
    hr = CoCreateInstance(
        &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void**)&pLocator);
    
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }
    
    hr = pLocator->lpVtbl->ConnectServer(
        pLocator, L"ROOT\\virtualization\\v2",
        NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    
    if (FAILED(hr)) {
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return FALSE;
    }
    
    hr = CoSetProxyBlanket(
        (IUnknown*)pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    
    hr = pServices->lpVtbl->ExecQuery(
        pServices, L"WQL",
        L"SELECT * FROM Msvm_VirtualSystemManagementService",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);
    
    if (SUCCEEDED(hr)) {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pClassObj, &uReturn);
        if (uReturn > 0) {
            exists = TRUE;
            pClassObj->lpVtbl->Release(pClassObj);
        }
        pEnumerator->lpVtbl->Release(pEnumerator);
    }
    
    pServices->lpVtbl->Release(pServices);
    pLocator->lpVtbl->Release(pLocator);
    CoUninitialize();
    
    return exists;
}

/*
 * Gather WMI namespace info
 */
static void GatherWmiNamespaceInfo(PWMI_NAMESPACE_INFO info)
{
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(WMI_NAMESPACE_INFO));
    
    /* Check for v2 namespace (Windows 8 / Server 2012+) */
    info->hasVirtualizationV2 = CheckWmiNamespaceExists(L"ROOT\\virtualization\\v2");
    
    /* Check for v1 namespace (legacy) */
    info->hasVirtualizationV1 = CheckWmiNamespaceExists(L"ROOT\\virtualization");
    
    /* If v2 exists, check for management service */
    if (info->hasVirtualizationV2) {
        info->hasMsvmVSMS = CheckVSMSExists();
        info->vmCount = CountVirtualMachines();
    }
    
    /* Determine if this is a Hyper-V host */
    info->isHyperVHost = info->hasVirtualizationV2 && info->hasMsvmVSMS;
    
    /* Get host name */
    DWORD size = sizeof(info->hostName);
    GetComputerNameA(info->hostName, &size);
}

/*
 * Main WMI namespace check function
 */
DWORD CheckWmiNamespaceHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    WMI_NAMESPACE_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather info */
    GatherWmiNamespaceInfo(&info);
    
    /* Determine detection - presence of v2 namespace indicates Hyper-V host */
    if (info.isHyperVHost) {
        detected = HYPERV_DETECTED_WMI_NAMESPACE;
    }
    
    /* Build details */
    AppendToDetails(result, "WMI Hyper-V Namespace Detection:\n");
    AppendToDetails(result, "  Host: %s\n", info.hostName);
    AppendToDetails(result, "  root\\virtualization\\v2: %s\n", 
                   info.hasVirtualizationV2 ? "Present" : "Not found");
    AppendToDetails(result, "  root\\virtualization (legacy): %s\n", 
                   info.hasVirtualizationV1 ? "Present" : "Not found");
    
    if (info.hasVirtualizationV2) {
        AppendToDetails(result, "  Msvm_VirtualSystemManagementService: %s\n",
                       info.hasMsvmVSMS ? "Present" : "Not found");
        AppendToDetails(result, "  Virtual Machines found: %d\n", info.vmCount);
    }
    
    AppendToDetails(result, "  Is Hyper-V Host: %s\n", 
                   info.isHyperVHost ? "YES" : "NO");
    
    if (info.isHyperVHost) {
        AppendToDetails(result, "  Note: This system is a Hyper-V HOST (root partition)\n");
    } else if (info.hasVirtualizationV2) {
        AppendToDetails(result, "  Note: Namespace exists but no VSMS - may be partial install\n");
    }
    
    return detected;
}

/*
 * Quick check for Hyper-V WMI namespace
 */
BOOL HasHyperVWmiNamespace(void)
{
    return CheckWmiNamespaceExists(L"ROOT\\virtualization\\v2");
}

/*
 * Check if system is Hyper-V host
 */
BOOL IsHyperVHost(void)
{
    WMI_NAMESPACE_INFO info = {0};
    GatherWmiNamespaceInfo(&info);
    return info.isHyperVHost;
}
