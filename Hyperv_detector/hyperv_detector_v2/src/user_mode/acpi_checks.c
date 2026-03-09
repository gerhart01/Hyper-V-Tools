/**
 * acpi_checks.c - ACPI Table Based Hyper-V Detection
 * 
 * Detects Hyper-V through ACPI tables like WAET, SRAT, and OEM IDs.
 * The WAET (Windows ACPI Emulated Devices Table) is particularly useful
 * as it's present in most hypervisors to optimize Windows guests.
 * 
 * Sources:
 * - https://wiki.osdev.org/WAET
 * - https://download.microsoft.com/download/7/E/7/7E7662CF-CBEA-470B-A97E-CE7CE0D98DC2/WAET.docx
 * - https://revers.engineering/evading-trivial-acpi-checks/
 * - https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/
 */

#define _CRT_SECURE_NO_WARNINGS
#include "hyperv_detector.h"
#include <stdio.h>

#define HYPERV_DETECTED_ACPI 0x02000000

/* ACPI table signatures */
#define ACPI_SIG_WAET  0x54454157  /* "WAET" - Windows ACPI Emulated Devices Table */
#define ACPI_SIG_SRAT  0x54415253  /* "SRAT" - System Resource Affinity Table */
#define ACPI_SIG_FACP  0x50434146  /* "FACP" - Fixed ACPI Description Table */
#define ACPI_SIG_APIC  0x43495041  /* "APIC" - Multiple APIC Description Table */
#define ACPI_SIG_HPET  0x54455048  /* "HPET" - High Precision Event Timer */
#define ACPI_SIG_MCFG  0x4746434D  /* "MCFG" - PCI Memory Mapped Configuration */
#define ACPI_SIG_SLIC  0x43494C53  /* "SLIC" - Software Licensing */
#define ACPI_SIG_MSDM  0x4D44534D  /* "MSDM" - Microsoft Data Management */
#define ACPI_SIG_WSMT  0x544D5357  /* "WSMT" - Windows SMM Security Mitigation */
#define ACPI_SIG_IVRS  0x53525649  /* "IVRS" - I/O Virtualization Reporting Structure */
#define ACPI_SIG_DMAR  0x52414D44  /* "DMAR" - DMA Remapping Table */

/* Firmware table provider signatures */
#define ACPI_PROVIDER  0x41435049  /* 'ACPI' */
#define FIRM_PROVIDER  0x4649524D  /* 'FIRM' */
#define RSMB_PROVIDER  0x52534D42  /* 'RSMB' - Raw SMBIOS */

/* WAET Emulated Device Flags */
#define ACPI_WAET_RTC_GOOD       (1 << 0)  /* RTC device doesn't lose time */
#define ACPI_WAET_PM_TIMER_GOOD  (1 << 1)  /* ACPI PM timer good for single read */

/* ACPI table header structure */
#pragma pack(push, 1)
typedef struct _ACPI_TABLE_HEADER {
    DWORD Signature;
    DWORD Length;
    BYTE  Revision;
    BYTE  Checksum;
    CHAR  OemId[6];
    CHAR  OemTableId[8];
    DWORD OemRevision;
    CHAR  CreatorId[4];
    DWORD CreatorRevision;
} ACPI_TABLE_HEADER, *PACPI_TABLE_HEADER;

/* WAET table structure */
typedef struct _ACPI_TABLE_WAET {
    ACPI_TABLE_HEADER Header;
    DWORD EmulatedDeviceFlags;
} ACPI_TABLE_WAET, *PACPI_TABLE_WAET;
#pragma pack(pop)

/* Known VM OEM IDs */
typedef struct _OEM_ID_INFO {
    const char* oemId;
    const char* vmType;
    BOOL isHyperV;
} OEM_ID_INFO;

static const OEM_ID_INFO g_KnownOemIds[] = {
    {"VRTUAL", "Hyper-V", TRUE},
    {"MSFT  ", "Hyper-V", TRUE},
    {"Msft  ", "Hyper-V", TRUE},
    {"MSHYPR", "Hyper-V", TRUE},
    {"VMWARE", "VMware", FALSE},
    {"VBOX  ", "VirtualBox", FALSE},
    {"QEMU  ", "QEMU", FALSE},
    {"BOCHS ", "Bochs", FALSE},
    {"AMAZON", "AWS", FALSE},
    {"Google", "GCP", FALSE},
    {"INTEL ", "Intel", FALSE},  /* May appear in various VMs */
    {NULL, NULL, FALSE}
};

/* ACPI detection results */
typedef struct _ACPI_DETECTION_INFO {
    BOOL hasWAET;
    BOOL hasSRAT;
    BOOL hasWSMT;
    BOOL hasDMAR;
    BOOL hasIVRS;
    DWORD waetFlags;
    char oemId[8];
    char oemTableId[12];
    char creatorId[8];
    const char* detectedVmType;
    BOOL isHyperV;
    int tableCount;
} ACPI_DETECTION_INFO, *PACPI_DETECTION_INFO;

/*
 * Get list of available ACPI tables
 */
static DWORD EnumerateAcpiTables(DWORD** signatures, DWORD* count)
{
    DWORD bufferSize = 0;
    DWORD* buffer = NULL;
    DWORD result = 0;
    
    *signatures = NULL;
    *count = 0;
    
    /* Get required buffer size */
    bufferSize = EnumSystemFirmwareTables(ACPI_PROVIDER, NULL, 0);
    if (bufferSize == 0) {
        return GetLastError();
    }
    
    buffer = (DWORD*)malloc(bufferSize);
    if (buffer == NULL) {
        return ERROR_OUTOFMEMORY;
    }
    
    result = EnumSystemFirmwareTables(ACPI_PROVIDER, buffer, bufferSize);
    if (result == 0) {
        free(buffer);
        return GetLastError();
    }
    
    *signatures = buffer;
    *count = result / sizeof(DWORD);
    return ERROR_SUCCESS;
}

/*
 * Get specific ACPI table
 */
static BOOL GetAcpiTable(DWORD signature, void** table, DWORD* size)
{
    DWORD bufferSize = 0;
    void* buffer = NULL;
    
    *table = NULL;
    *size = 0;
    
    /* Get required buffer size */
    bufferSize = GetSystemFirmwareTable(ACPI_PROVIDER, signature, NULL, 0);
    if (bufferSize == 0) {
        return FALSE;
    }
    
    buffer = malloc(bufferSize);
    if (buffer == NULL) {
        return FALSE;
    }
    
    if (GetSystemFirmwareTable(ACPI_PROVIDER, signature, buffer, bufferSize) == 0) {
        free(buffer);
        return FALSE;
    }
    
    *table = buffer;
    *size = bufferSize;
    return TRUE;
}

/*
 * Check if OEM ID indicates a VM
 */
static const char* CheckOemIdForVM(const char* oemId, BOOL* isHyperV)
{
    int i;
    char normalizedId[8] = {0};
    
    /* Normalize OEM ID (copy first 6 chars) */
    memcpy(normalizedId, oemId, 6);
    
    for (i = 0; g_KnownOemIds[i].oemId != NULL; i++) {
        if (strncmp(normalizedId, g_KnownOemIds[i].oemId, 6) == 0) {
            if (isHyperV) {
                *isHyperV = g_KnownOemIds[i].isHyperV;
            }
            return g_KnownOemIds[i].vmType;
        }
    }
    
    if (isHyperV) {
        *isHyperV = FALSE;
    }
    return NULL;
}

/*
 * Check WAET table
 */
static BOOL CheckWAETTable(PACPI_DETECTION_INFO info)
{
    PACPI_TABLE_WAET waet = NULL;
    DWORD size = 0;
    
    if (!GetAcpiTable(ACPI_SIG_WAET, (void**)&waet, &size)) {
        return FALSE;
    }
    
    if (size >= sizeof(ACPI_TABLE_WAET)) {
        info->hasWAET = TRUE;
        info->waetFlags = waet->EmulatedDeviceFlags;
        
        /* Copy OEM info */
        memcpy(info->oemId, waet->Header.OemId, 6);
        info->oemId[6] = '\0';
        memcpy(info->oemTableId, waet->Header.OemTableId, 8);
        info->oemTableId[8] = '\0';
        memcpy(info->creatorId, waet->Header.CreatorId, 4);
        info->creatorId[4] = '\0';
        
        /* Check OEM ID for VM type */
        info->detectedVmType = CheckOemIdForVM(info->oemId, &info->isHyperV);
    }
    
    free(waet);
    return TRUE;
}

/*
 * Gather all ACPI detection info
 */
static void GatherAcpiInfo(PACPI_DETECTION_INFO info)
{
    DWORD* signatures = NULL;
    DWORD count = 0;
    DWORD i;
    PACPI_TABLE_HEADER header = NULL;
    DWORD size = 0;
    
    if (info == NULL) {
        return;
    }
    
    memset(info, 0, sizeof(ACPI_DETECTION_INFO));
    
    /* Enumerate all tables */
    if (EnumerateAcpiTables(&signatures, &count) == ERROR_SUCCESS) {
        info->tableCount = (int)count;
        
        for (i = 0; i < count; i++) {
            switch (signatures[i]) {
                case ACPI_SIG_WAET:
                    info->hasWAET = TRUE;
                    break;
                case ACPI_SIG_SRAT:
                    info->hasSRAT = TRUE;
                    break;
                case ACPI_SIG_WSMT:
                    info->hasWSMT = TRUE;
                    break;
                case ACPI_SIG_DMAR:
                    info->hasDMAR = TRUE;
                    break;
                case ACPI_SIG_IVRS:
                    info->hasIVRS = TRUE;
                    break;
            }
        }
        free(signatures);
    }
    
    /* Get detailed WAET info */
    if (info->hasWAET) {
        CheckWAETTable(info);
    }
    
    /* If no VM detected from WAET, try FACP */
    if (info->detectedVmType == NULL) {
        if (GetAcpiTable(ACPI_SIG_FACP, (void**)&header, &size)) {
            if (size >= sizeof(ACPI_TABLE_HEADER)) {
                memcpy(info->oemId, header->OemId, 6);
                info->oemId[6] = '\0';
                info->detectedVmType = CheckOemIdForVM(info->oemId, &info->isHyperV);
            }
            free(header);
        }
    }
}

/*
 * Main ACPI check function
 */
DWORD CheckAcpiHyperV(PDETECTION_RESULT result)
{
    DWORD detected = 0;
    ACPI_DETECTION_INFO info = {0};
    
    if (result == NULL) {
        return 0;
    }
    
    /* Gather ACPI info */
    GatherAcpiInfo(&info);
    
    /* Determine detection */
    if (info.isHyperV) {
        detected = HYPERV_DETECTED_ACPI;
    } else if (info.hasWAET) {
        /* WAET presence alone suggests VM (not necessarily Hyper-V) */
        detected = HYPERV_DETECTED_ACPI;
    }
    
    /* Build details */
    AppendToDetails(result, "ACPI Table Detection:\n");
    AppendToDetails(result, "  Total tables: %d\n", info.tableCount);
    AppendToDetails(result, "  WAET (VM indicator): %s\n", info.hasWAET ? "Present" : "Not found");
    
    if (info.hasWAET) {
        AppendToDetails(result, "    RTC Good: %s\n", 
                       (info.waetFlags & ACPI_WAET_RTC_GOOD) ? "Yes" : "No");
        AppendToDetails(result, "    PM Timer Good: %s\n", 
                       (info.waetFlags & ACPI_WAET_PM_TIMER_GOOD) ? "Yes" : "No");
    }
    
    AppendToDetails(result, "  OEM ID: '%s'\n", info.oemId);
    AppendToDetails(result, "  OEM Table ID: '%s'\n", info.oemTableId);
    
    if (info.detectedVmType) {
        AppendToDetails(result, "  Detected VM: %s\n", info.detectedVmType);
    }
    
    AppendToDetails(result, "  Other tables:\n");
    AppendToDetails(result, "    SRAT: %s\n", info.hasSRAT ? "Yes" : "No");
    AppendToDetails(result, "    WSMT: %s\n", info.hasWSMT ? "Yes" : "No");
    AppendToDetails(result, "    DMAR: %s\n", info.hasDMAR ? "Yes" : "No");
    AppendToDetails(result, "    IVRS: %s\n", info.hasIVRS ? "Yes" : "No");
    
    return detected;
}

/*
 * Quick WAET check
 */
BOOL HasWAETTable(void)
{
    void* table = NULL;
    DWORD size = 0;
    BOOL result = FALSE;
    
    result = GetAcpiTable(ACPI_SIG_WAET, &table, &size);
    if (table) {
        free(table);
    }
    return result;
}

/*
 * Get ACPI OEM ID
 */
BOOL GetAcpiOemId(char* buffer, size_t bufferSize)
{
    PACPI_TABLE_HEADER header = NULL;
    DWORD size = 0;
    
    if (buffer == NULL || bufferSize < 7) {
        return FALSE;
    }
    
    if (GetAcpiTable(ACPI_SIG_FACP, (void**)&header, &size)) {
        if (size >= sizeof(ACPI_TABLE_HEADER)) {
            memcpy(buffer, header->OemId, 6);
            buffer[6] = '\0';
            free(header);
            return TRUE;
        }
        free(header);
    }
    
    return FALSE;
}
