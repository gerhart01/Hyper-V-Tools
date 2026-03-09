/**
 * hyperv_detector.h - Comprehensive Hyper-V Detection Header
 * 
 * Extended with new detection methods:
 * - WMI checks
 * - MAC address checks
 * - Firmware/SMBIOS checks
 * - Timing analysis
 * - Performance counters
 * - Event logs
 * - Security features (VBS, HVCI, Credential Guard)
 * - Descriptor tables (IDT/GDT)
 * - Windows features
 * - Storage/disk analysis
 */

#pragma once
#ifndef HYPERV_DETECTOR_H
#define HYPERV_DETECTOR_H

#include "../common/common.h"
#include "../common/shared_structs.h"

// ============================================================================
// Detection Result Flags (Extended)
// ============================================================================

// Original flags (from common.h)
// #define HYPERV_DETECTED_NONE        0x00000000
// #define HYPERV_DETECTED_CPUID       0x00000001
// #define HYPERV_DETECTED_REGISTRY    0x00000002
// #define HYPERV_DETECTED_FILES       0x00000004
// #define HYPERV_DETECTED_SERVICES    0x00000008
// #define HYPERV_DETECTED_DEVICES     0x00000010
// #define HYPERV_DETECTED_BIOS        0x00000020
// #define HYPERV_DETECTED_PROCESSES   0x00000040
// #define HYPERV_DETECTED_HYPERCALLS  0x00000080
// #define HYPERV_DETECTED_OBJECTS     0x00000100
// #define HYPERV_DETECTED_NESTED      0x00000200
// #define HYPERV_DETECTED_SANDBOX     0x00000400
// #define HYPERV_DETECTED_DOCKER      0x00000800
// #define HYPERV_DETECTED_REMOVED     0x00001000

// New detection flags
#define HYPERV_DETECTED_WMI         0x00002000  // WMI-based detection
#define HYPERV_DETECTED_MAC         0x00004000  // MAC address detection
#define HYPERV_DETECTED_FIRMWARE    0x00008000  // Firmware/SMBIOS detection
#define HYPERV_DETECTED_TIMING      0x00010000  // Timing-based detection
#define HYPERV_DETECTED_PERFCOUNTER 0x00020000  // Performance counter detection
#define HYPERV_DETECTED_EVENTLOG    0x00040000  // Event log detection
#define HYPERV_DETECTED_SECURITY    0x00080000  // Security features detection
#define HYPERV_DETECTED_DESCRIPTOR  0x00100000  // Descriptor table detection
#define HYPERV_DETECTED_FEATURES    0x00200000  // Windows features detection
#define HYPERV_DETECTED_STORAGE     0x00400000  // Storage/disk detection
#define HYPERV_DETECTED_ENV         0x00800000  // Environment variables detection
#define HYPERV_DETECTED_NETWORK     0x01000000  // Network topology detection
#define HYPERV_DETECTED_DLL         0x02000000  // DLL/module detection
#define HYPERV_DETECTED_ROOT_PART   0x04000000  // Root partition detection

// ============================================================================
// Original Detection Functions
// ============================================================================

DWORD CheckCpuidHyperV(PDETECTION_RESULT result);
DWORD CheckRegistryHyperV(PDETECTION_RESULT result);
DWORD CheckFilesHyperV(PDETECTION_RESULT result);
DWORD CheckServicesHyperV(PDETECTION_RESULT result);
DWORD CheckDevicesHyperV(PDETECTION_RESULT result);
DWORD CheckBiosHyperV(PDETECTION_RESULT result);
DWORD CheckProcessesHyperV(PDETECTION_RESULT result);
DWORD CheckWindowsObjectsHyperV(PDETECTION_RESULT result);
DWORD CheckNestedHyperV(PDETECTION_RESULT result);
DWORD CheckWindowsSandbox(PDETECTION_RESULT result);
DWORD CheckDockerHyperV(PDETECTION_RESULT result);
DWORD CheckRemovedHyperV(PDETECTION_RESULT result);

// ============================================================================
// New Detection Functions
// ============================================================================

/**
 * WMI-based detection
 * Queries WMI for virtualization indicators:
 * - Win32_ComputerSystem, Win32_BIOS, Win32_BaseBoard
 * - Hyper-V specific WMI namespaces (root\virtualization\v2)
 */
DWORD CheckWMIHyperV(PDETECTION_RESULT result);

/**
 * MAC address based detection
 * Checks network adapter MAC addresses for Hyper-V OUI prefixes:
 * - 00:15:5D (Microsoft Hyper-V)
 * - 00:03:FF (Microsoft Virtual PC)
 */
DWORD CheckMACAddressHyperV(PDETECTION_RESULT result);

/**
 * Firmware and SMBIOS table detection
 * Uses GetSystemFirmwareTable() to read SMBIOS/ACPI tables
 * for Hyper-V signatures in BIOS, System, and Baseboard info.
 */
DWORD CheckFirmwareHyperV(PDETECTION_RESULT result);
DWORD CheckUEFIVariablesHyperV(PDETECTION_RESULT result);

/**
 * Timing-based detection
 * Analyzes timing discrepancies that indicate virtualization:
 * - RDTSC timing consistency
 * - CPUID execution timing
 * - VM exit overhead detection
 */
DWORD CheckTimingHyperV(PDETECTION_RESULT result);

/**
 * Performance counter detection
 * Checks for Hyper-V specific Windows performance counters
 * and ETW providers.
 */
DWORD CheckPerfCountersHyperV(PDETECTION_RESULT result);
DWORD CheckETWProvidersHyperV(PDETECTION_RESULT result);

/**
 * Event log detection
 * Searches Windows Event Logs for Hyper-V related events
 * and checks for Hyper-V event log channels.
 */
DWORD CheckEventLogsHyperV(PDETECTION_RESULT result);
DWORD CheckSecurityEventsHyperV(PDETECTION_RESULT result);

/**
 * Security features detection
 * Checks for Hyper-V dependent security features:
 * - Virtualization-Based Security (VBS)
 * - Hypervisor-protected Code Integrity (HVCI)
 * - Credential Guard
 * - Windows Defender Application Guard
 */
DWORD CheckSecurityFeaturesHyperV(PDETECTION_RESULT result);

/**
 * Descriptor table detection
 * Analyzes IDT, GDT, LDT for virtualization indicators:
 * - Base address patterns
 * - Cross-CPU consistency
 * - STR instruction timing
 */
DWORD CheckDescriptorTablesHyperV(PDETECTION_RESULT result);

/**
 * Windows features detection
 * Checks installed Windows optional features for Hyper-V:
 * - Microsoft-Hyper-V feature family
 * - Container features
 * - Virtual Machine Platform
 */
DWORD CheckWindowsFeaturesHyperV(PDETECTION_RESULT result);

/**
 * Storage and disk detection
 * Analyzes storage devices for Hyper-V signatures:
 * - Virtual disk vendors/products
 * - SCSI controller types
 * - VHD/VHDX files
 */
DWORD CheckStorageHyperV(PDETECTION_RESULT result);

/**
 * Environment and resource detection
 * Checks environment variables and system resources for Hyper-V indicators
 */
DWORD CheckEnvironmentHyperV(PDETECTION_RESULT result);

/**
 * Network topology detection
 * Analyzes network configuration for virtual switches
 */
DWORD CheckNetworkHyperV(PDETECTION_RESULT result);

/**
 * DLL and module detection
 * Checks loaded modules and DLL versions for Hyper-V
 */
DWORD CheckDLLsHyperV(PDETECTION_RESULT result);

/**
 * Root partition detection
 * Distinguishes between root partition (host/VBS) and child partition (guest VM)
 * Uses multiple methods:
 * - CPUID 0x40000003 partition privilege flags
 * - CPUID 0x40000007 CPU management features
 * - Performance counters (Root Virtual Processor)
 * - WMI System Model
 */
DWORD CheckRootPartitionHyperV(void);
BOOL IsRootPartitionQuick(void);

// Root partition info structure
typedef struct _ROOT_PARTITION_INFO {
    BOOL isHyperVPresent;
    BOOL isRootPartition;
    BOOL isChildPartition;
    BOOL hasCreatePartitionsPrivilege;
    BOOL hasCpuManagementPrivilege;
    BOOL hasReservedIdentityBit;
    UINT64 partitionPrivilegeMask;
    UINT32 maxHypervisorLeaf;
    char hypervisorVendor[16];
    char hypervisorInterface[8];
    BOOL hasRootVpCounters;
    DWORD partitionCount;
    BOOL systemModelIsVirtualMachine;
    char systemModel[256];
    BOOL hasVmBus;      /* VMBus present = guest partition */
    BOOL hasVmBusr;     /* VMBusr (VMBus Root) present = root partition */
} ROOT_PARTITION_INFO, *PROOT_PARTITION_INFO;

BOOL GetRootPartitionInfo(PROOT_PARTITION_INFO info);
void PrintRootOnlyHypercalls(void);

// ============================================================================
// Helper Functions
// ============================================================================

void ExecuteCpuid(DWORD function, PCPUID_RESULT result);
BOOL IsRunningAsAdmin();
void AppendToDetails(PDETECTION_RESULT result, const char* format, ...);

// ============================================================================
// Detection Level Configuration
// ============================================================================

typedef enum _DETECTION_LEVEL {
    DETECTION_LEVEL_FAST = 0,     // Only fast checks (CPUID, registry, files)
    DETECTION_LEVEL_NORMAL = 1,   // Standard checks (includes services, devices, processes)
    DETECTION_LEVEL_THOROUGH = 2, // All non-invasive checks
    DETECTION_LEVEL_FULL = 3      // All checks including timing analysis
} DETECTION_LEVEL;

/**
 * Run detection with specified level
 */
DWORD RunDetection(PDETECTION_RESULT result, DETECTION_LEVEL level);

/**
 * Get detection flag name
 */
const char* GetDetectionFlagName(DWORD flag);

/**
 * Print detection summary
 */
void PrintDetectionSummary(PDETECTION_RESULT result);

#endif // HYPERV_DETECTOR_H
