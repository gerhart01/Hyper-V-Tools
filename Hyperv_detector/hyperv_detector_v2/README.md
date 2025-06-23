AI generated with modifications

# Hyper-V Virtual Machine Detector

A comprehensive Windows tool for detecting if the system is running inside a Hyper-V virtual machine. This project includes both user-mode and kernel-mode components for thorough detection.

## Features

### User-Mode Detection Methods
- **CPUID Instructions**: Checks hypervisor presence and vendor information
- **Registry Keys**: Scans for Hyper-V specific registry entries
- **Files**: Looks for Hyper-V related system files and drivers
- **Services**: Detects running Hyper-V integration services
- **Drivers**: Enumerates loaded Hyper-V drivers
- **Devices**: Checks for VMBus and synthetic devices
- **BIOS/UEFI**: Examines SMBIOS data for virtualization indicators
- **ACPI Tables**: Analyzes ACPI tables for Hyper-V signatures
- **Windows Objects**: Searches for Hyper-V mutexes, devices, and kernel objects
- **Enlightenments**: Detects Hyper-V performance optimizations

### Special Environment Detection
- Nested Hyper-V virtualization
- Root partition with active Hyper-V
- Windows Sandbox
- Docker containers with Hyper-V
- Removed Hyper-V traces

### Kernel-Mode Detection (Optional)
- Hypercall availability
- MSR (Model Specific Register) access
- Advanced nested virtualization checks

## Building

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- Windows Driver Kit (WDK) for kernel driver

### User-Mode Application
```cmd
cd hyperv_detector
nmake
```

Or open `hyperv_detector.sln` in Visual Studio and build.

### Kernel Driver
1. Install Windows Driver Kit (WDK)
2. Open `hyperv_detector_driver` project in Visual Studio
3. Build for desired architecture (x64/x86)

## Usage

### Basic Usage
```cmd
hyperv_detector.exe
```

### With Kernel-Mode Checks (Administrator Required)
```cmd
hyperv_detector.exe -k
```

### Verbose Output
```cmd
hyperv_detector.exe -v
```

### Command Line Options
- `-k, --kernel`: Include kernel-mode detection methods
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

## Output

The tool provides detailed information about:
- Detection status (Hyper-V detected/not detected)
- Detection methods that triggered
- Hypervisor vendor information
- Version details
- Specific environment type (VM, Sandbox, Docker, etc.)

## Detection Methods Details

### CPUID Detection
- Checks CPUID leaf 1, ECX bit 31 for hypervisor presence
- Reads hypervisor vendor signature from CPUID 0x40000000
- Verifies Hyper-V interface signature "Hv#1"
- Extracts version and feature information

### Registry Detection
- Scans HKLM\SOFTWARE\Microsoft\Hyper-V
- Checks for integration services in CurrentControlSet\Services
- Examines BIOS information in HARDWARE\DESCRIPTION\System
- Looks for VMBus enumeration in SYSTEM\CurrentControlSet\Enum

### File System Detection
- Checks for vmms.exe, vmwp.exe, and other Hyper-V executables
- Looks for VMBus and integration service drivers
- Searches for Hyper-V configuration directories

### Device Detection
- Enumerates devices with "VMBUS" hardware IDs
- Checks for synthetic network, storage, and display adapters
- Looks for Hyper-V Generation Counter device

## Security Considerations

- The kernel driver requires administrator privileges
- Some detection methods may be blocked by security software
- Results should be used for legitimate purposes only

## Limitations

- Some detection methods may have false positives in certain configurations
- Kernel driver must be signed for use on 64-bit Windows
- Detection can be evaded by sophisticated hypervisor hiding techniques

## License

GPL3

## Contributing

Contributions are welcome! Please submit pull requests with:
- New detection methods
- Bug fixes
- Performance improvements
- Documentation updates
