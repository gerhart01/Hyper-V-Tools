# Hyper-V Detector

A comprehensive tool for detecting Microsoft Hyper-V virtualization on Windows.

[Русская версия (Russian version)](README_RU.md)

## Project Structure

```
hyperv_detector/
├── hyperv_detector.sln          # Visual Studio solution file
├── hyperv_detector.vcxproj      # UserMode application project
├── hyperv_driver.vcxproj        # KernelMode driver project
├── src/
│   ├── common/                  # Shared headers
│   │   ├── common.h
│   │   └── shared_structs.h
│   ├── user_mode/               # UserMode code (25 detection methods)
│   │   ├── hyperv_detector.h
│   │   ├── hyperv_detector_new.h
│   │   ├── main.c               # Original main
│   │   ├── main_new.c           # Extended main with detection levels
│   │   ├── bios_checks.c
│   │   ├── cpuid_checks.c
│   │   ├── device_checks.c
│   │   ├── file_checks.c
│   │   ├── process_checks.c
│   │   ├── registry_checks.c
│   │   ├── service_checks.c
│   │   ├── wmi_checks.c         # WMI checks
│   │   ├── mac_checks.c         # MAC addresses
│   │   ├── firmware_checks.c    # SMBIOS/ACPI
│   │   ├── timing_checks.c     # Timing analysis
│   │   ├── perfcounter_checks.c # Performance counters
│   │   ├── eventlog_checks.c    # Event logs
│   │   ├── security_checks.c    # VBS/HVCI/Credential Guard
│   │   ├── descriptor_checks.c  # IDT/GDT analysis
│   │   ├── features_checks.c    # Windows features
│   │   ├── storage_checks.c     # Disk analysis
│   │   ├── env_checks.c         # Environment variables
│   │   ├── network_checks.c     # Network topology
│   │   ├── dll_checks.c         # DLL analysis
│   │   └── root_partition_checks.c # Root/Child partition
│   └── kernel_mode/             # KernelMode driver
│       ├── hyperv_driver.h
│       ├── hyperv_driver.c
│       ├── hypercall_checks.c
│       ├── hypercall_perform.c
│       └── ASM64.asm
```

## Detection Flags

| Flag | Value | Method |
|------|-------|--------|
| HYPERV_DETECTED_CPUID | 0x00000001 | CPUID |
| HYPERV_DETECTED_REGISTRY | 0x00000002 | Registry |
| HYPERV_DETECTED_FILES | 0x00000004 | Files |
| HYPERV_DETECTED_SERVICES | 0x00000008 | Services |
| HYPERV_DETECTED_DEVICES | 0x00000010 | Devices |
| HYPERV_DETECTED_BIOS | 0x00000020 | BIOS |
| HYPERV_DETECTED_PROCESSES | 0x00000040 | Processes |
| HYPERV_DETECTED_HYPERCALL | 0x00000080 | Hypercall |
| HYPERV_DETECTED_OBJECTS | 0x00000100 | Windows Objects |
| HYPERV_DETECTED_NESTED | 0x00000200 | Nested Virtualization |
| HYPERV_DETECTED_SANDBOX | 0x00000400 | Windows Sandbox |
| HYPERV_DETECTED_DOCKER | 0x00000800 | Docker/Containers |
| HYPERV_DETECTED_REMOVED | 0x00001000 | Removed Hyper-V Remnants |
| HYPERV_DETECTED_WMI | 0x00002000 | WMI |
| HYPERV_DETECTED_MAC | 0x00004000 | MAC Addresses |
| HYPERV_DETECTED_FIRMWARE | 0x00008000 | Firmware/SMBIOS |
| HYPERV_DETECTED_TIMING | 0x00010000 | Timing Analysis |
| HYPERV_DETECTED_PERFCOUNTER | 0x00020000 | Performance Counters |
| HYPERV_DETECTED_EVENTLOG | 0x00040000 | Event Logs |
| HYPERV_DETECTED_SECURITY | 0x00080000 | Security Features |
| HYPERV_DETECTED_DESCRIPTOR | 0x00100000 | Descriptor Tables |
| HYPERV_DETECTED_FEATURES | 0x00200000 | Windows Features |
| HYPERV_DETECTED_STORAGE | 0x00400000 | Storage |
| HYPERV_DETECTED_ENV | 0x00800000 | Environment |
| HYPERV_DETECTED_NETWORK | 0x01000000 | Network |
| HYPERV_DETECTED_DLL | 0x02000000 | DLL Libraries |
| HYPERV_DETECTED_ROOT_PART | 0x04000000 | Root Partition |

## Root Partition Detection

A special feature for determining the Hyper-V partition type:
- **Root Partition** — host with Hyper-V/VBS enabled (the host itself is not virtualized)
- **Child Partition** — guest virtual machine

### Root Partition Detection Methods

1. **CPUID 0x40000003 (HV_PARTITION_PRIVILEGE_MASK)**
   - EBX bit 0: CreatePartitions — root partition only
   - EBX bit 12: CpuManagement — root partition only

2. **CPUID 0x40000007 (CPU Management Features)**
   - EAX bit 31: ReservedIdentityBit — root partition indicator

3. **Performance Counters**
   - "Hyper-V Hypervisor Root Virtual Processor" — exists only on root

4. **WMI System Model**
   - Guest VM: "Virtual Machine"
   - Root partition: actual hardware model

5. **VMBus vs VMBusr**
   - `vmbus.sys` / `\Device\VmBus` — present in guest VM
   - `vmbusr.sys` / `\Device\VmBusr` — present only in root partition
   - Reliable indicator: VMBusr = root, VMBus without VMBusr = guest

### Root Partition–Only Hypercalls

| Code | Hypercall | Privilege |
|------|-----------|-----------|
| 0x0040 | HvCallCreatePartition | CreatePartitions |
| 0x0041 | HvCallInitializePartition | CreatePartitions |
| 0x0048 | HvCallDepositMemory | AccessMemoryPool |
| 0x005E | HvCallCreateVp | CpuManagement |
| 0x0099 | HvCallStartVirtualProcessor | CpuManagement |

Child partitions receive `HV_STATUS_ACCESS_DENIED (0x0006)` when attempting these calls.

## Required Libraries

The following additional libraries are needed for the detection modules:
- `ole32.lib` — COM initialization
- `oleaut32.lib` — OLE Automation
- `wbemuuid.lib` — WMI
- `pdh.lib` — Performance Data Helper
- `wevtapi.lib` — Windows Event Log API
- `iphlpapi.lib` — IP Helper API
- `ws2_32.lib` — Winsock
- `ntdll.lib` — NT API (for NtQuerySystemInformation)

## Building

1. Open `hyperv_detector.sln` in Visual Studio 2022
2. Select configuration (Debug/Release) and platform (x64)
3. Build the solution (Ctrl+Shift+B)

Windows Driver Kit (WDK) is required to build the driver.

## Usage

```
hyperv_detector.exe [options]

Options:
  --fast      Quick check (CPUID, registry, files)
  --thorough  Thorough check
  --full      Full check (including timing and descriptor)
  --json      JSON output
  --quiet     Minimal output
  --details   Verbose output
```

## Notes

- To use main_new.c, replace main.c in the project
- Administrator privileges are recommended for full functionality
- x64 architecture is required for descriptor_checks and timing_checks

## Test Project

The solution includes a `hyperv_detector_tests` project for validating each detection method across different configurations.

### Running Tests

```
hyperv_detector_tests.exe [options]

Options:
  --json           JSON output
  --config <name>  Configuration name for the report
  --help           Help
```

### Examples

```bash
# Run on a guest VM
hyperv_detector_tests.exe --config "VM-Windows11"

# JSON output for automation
hyperv_detector_tests.exe --json --config "HyperV-Host"
```

### Test Categories

| Category | Description |
|----------|-------------|
| CPUID | Hypervisor CPUID leaf checks |
| Registry | Hyper-V registry keys |
| Services | Hyper-V services |
| Devices | Hyper-V devices |
| Files | Driver files (vmbus.sys, vmbusr.sys) |
| Processes | Hyper-V processes |
| WMI | WMI queries |
| MAC | Virtual adapter MAC addresses |
| PerfCounter | Performance counters |
| RootPartition | Root/guest partition detection |

### Auto-Detection of Configuration

Tests automatically determine the system type:
- `BareMetal` — no hypervisor
- `HyperV-RootPartition` — Hyper-V host
- `HyperV-GuestVM` — guest VM
- `OtherHypervisor-<vendor>` — other hypervisor

## License

GPL3
