/**
 * wmi_checks.c - WMI-based Hyper-V detection
 * 
 * Uses Windows Management Instrumentation to detect Hyper-V presence
 * through various WMI classes and namespaces.
 */

#include "hyperv_detector.h"
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Detection flag for WMI
#define HYPERV_DETECTED_WMI 0x00002000

static BOOL InitializeCOM(void) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return FALSE;
    }
    
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );
    
    return SUCCEEDED(hr) || hr == RPC_E_TOO_LATE;
}

static IWbemServices* ConnectToWMI(const wchar_t* namespace_path) {
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    HRESULT hr;
    
    hr = CoCreateInstance(
        &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (LPVOID*)&pLocator
    );
    
    if (FAILED(hr)) {
        return NULL;
    }
    
    BSTR bstrNamespace = SysAllocString(namespace_path);
    hr = pLocator->lpVtbl->ConnectServer(
        pLocator, bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &pServices
    );
    SysFreeString(bstrNamespace);
    
    pLocator->lpVtbl->Release(pLocator);
    
    if (FAILED(hr)) {
        return NULL;
    }
    
    CoSetProxyBlanket(
        (IUnknown*)pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE
    );
    
    return pServices;
}

static BOOL QueryWMIProperty(IWbemServices* pServices, const wchar_t* query, 
                            const wchar_t* property, char* outBuffer, size_t bufSize) {
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pClassObject = NULL;
    ULONG returned = 0;
    HRESULT hr;
    BOOL found = FALSE;
    
    BSTR bstrQuery = SysAllocString(query);
    BSTR bstrWQL = SysAllocString(L"WQL");
    
    hr = pServices->lpVtbl->ExecQuery(
        pServices, bstrWQL, bstrQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator
    );
    
    SysFreeString(bstrQuery);
    SysFreeString(bstrWQL);
    
    if (FAILED(hr)) {
        return FALSE;
    }
    
    while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pClassObject, &returned) == S_OK) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        
        hr = pClassObject->lpVtbl->Get(pClassObject, property, 0, &vtProp, NULL, NULL);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
            WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, outBuffer, (int)bufSize, NULL, NULL);
            found = TRUE;
        }
        
        VariantClear(&vtProp);
        pClassObject->lpVtbl->Release(pClassObject);
        
        if (found) break;
    }
    
    pEnumerator->lpVtbl->Release(pEnumerator);
    return found;
}

DWORD CheckWMIHyperV(PDETECTION_RESULT result) {
    DWORD detected = 0;
    char buffer[1024];
    IWbemServices* pServices = NULL;
    
    if (!InitializeCOM()) {
        AppendToDetails(result, "WMI: Failed to initialize COM\n");
        return 0;
    }
    
    // Check Win32_ComputerSystem for virtual machine model
    pServices = ConnectToWMI(L"ROOT\\CIMV2");
    if (pServices) {
        // Check Model
        if (QueryWMIProperty(pServices, L"SELECT Model FROM Win32_ComputerSystem", 
                            L"Model", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: ComputerSystem Model: %s\n", buffer);
            if (strstr(buffer, "Virtual Machine") || strstr(buffer, "Hyper-V")) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: Hyper-V Virtual Machine detected via ComputerSystem\n");
            }
        }
        
        // Check Manufacturer
        if (QueryWMIProperty(pServices, L"SELECT Manufacturer FROM Win32_ComputerSystem", 
                            L"Manufacturer", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: ComputerSystem Manufacturer: %s\n", buffer);
            if (strstr(buffer, "Microsoft Corporation")) {
                detected |= HYPERV_DETECTED_WMI;
            }
        }
        
        // Check HypervisorPresent property (Windows 8+)
        if (QueryWMIProperty(pServices, L"SELECT HypervisorPresent FROM Win32_ComputerSystem", 
                            L"HypervisorPresent", buffer, sizeof(buffer))) {
            if (strcmp(buffer, "True") == 0 || strcmp(buffer, "1") == 0) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: HypervisorPresent = True\n");
            }
        }
        
        // Check Win32_BIOS
        if (QueryWMIProperty(pServices, L"SELECT SerialNumber FROM Win32_BIOS", 
                            L"SerialNumber", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: BIOS SerialNumber: %s\n", buffer);
            // Hyper-V VMs often have specific serial number patterns
            if (strstr(buffer, "-") && strlen(buffer) > 30) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: Potential Hyper-V BIOS serial detected\n");
            }
        }
        
        if (QueryWMIProperty(pServices, L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS", 
                            L"SMBIOSBIOSVersion", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: SMBIOS BIOS Version: %s\n", buffer);
            if (strstr(buffer, "Hyper-V") || strstr(buffer, "VRTUAL") || strstr(buffer, "090008")) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: Hyper-V BIOS version detected\n");
            }
        }
        
        // Check Win32_BaseBoard
        if (QueryWMIProperty(pServices, L"SELECT Manufacturer FROM Win32_BaseBoard", 
                            L"Manufacturer", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: BaseBoard Manufacturer: %s\n", buffer);
            if (strstr(buffer, "Microsoft Corporation")) {
                detected |= HYPERV_DETECTED_WMI;
            }
        }
        
        if (QueryWMIProperty(pServices, L"SELECT Product FROM Win32_BaseBoard", 
                            L"Product", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: BaseBoard Product: %s\n", buffer);
            if (strstr(buffer, "Virtual Machine")) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: Hyper-V baseboard detected\n");
            }
        }
        
        // Check Win32_DiskDrive for virtual disks
        if (QueryWMIProperty(pServices, L"SELECT Model FROM Win32_DiskDrive", 
                            L"Model", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: DiskDrive Model: %s\n", buffer);
            if (strstr(buffer, "Virtual") || strstr(buffer, "Msft Virtual Disk")) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: Hyper-V virtual disk detected\n");
            }
        }
        
        // Check Win32_VideoController
        if (QueryWMIProperty(pServices, L"SELECT Name FROM Win32_VideoController", 
                            L"Name", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: VideoController: %s\n", buffer);
            if (strstr(buffer, "Hyper-V") || strstr(buffer, "Microsoft Hyper-V Video")) {
                detected |= HYPERV_DETECTED_WMI;
                AppendToDetails(result, "WMI: Hyper-V video adapter detected\n");
            }
        }
        
        pServices->lpVtbl->Release(pServices);
    }
    
    // Check Hyper-V specific WMI namespace
    pServices = ConnectToWMI(L"ROOT\\virtualization\\v2");
    if (pServices) {
        detected |= HYPERV_DETECTED_WMI;
        AppendToDetails(result, "WMI: Hyper-V virtualization namespace (v2) accessible\n");
        
        // Query Msvm_ComputerSystem for VMs
        if (QueryWMIProperty(pServices, L"SELECT ElementName FROM Msvm_ComputerSystem", 
                            L"ElementName", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: Found Hyper-V VM: %s\n", buffer);
        }
        
        // Check for virtual switches
        if (QueryWMIProperty(pServices, L"SELECT ElementName FROM Msvm_VirtualEthernetSwitch", 
                            L"ElementName", buffer, sizeof(buffer))) {
            AppendToDetails(result, "WMI: Found Hyper-V virtual switch: %s\n", buffer);
        }
        
        pServices->lpVtbl->Release(pServices);
    }
    
    // Check legacy Hyper-V namespace
    pServices = ConnectToWMI(L"ROOT\\virtualization");
    if (pServices) {
        detected |= HYPERV_DETECTED_WMI;
        AppendToDetails(result, "WMI: Hyper-V virtualization namespace (legacy) accessible\n");
        pServices->lpVtbl->Release(pServices);
    }
    
    CoUninitialize();
    return detected;
}
