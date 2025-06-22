# AI generated

# Hyper-V Virtual Machine Detector

A comprehensive C program that detects if Windows is running inside a Microsoft Hyper-V virtual machine environment using multiple detection techniques.

## Features

This detector implements 15 different detection methods:

### 1. **File System Detection**
- Checks for Hyper-V specific system files and drivers
- Files like `vmbus.sys`, `storvsc.sys`, `vmicheartbeat.dll`, etc.

### 2. **Registry Key Detection**
- Scans for Hyper-V related registry entries
- Service configurations, device parameters, and VM guest information

### 3. **Service Detection**
- Identifies running Hyper-V integration services
- VMBus, heartbeat, time sync, and other VM services

### 4. **Driver Detection**
- Enumerates system devices looking for VMBus and Hyper-V drivers
- Checks for Microsoft vendor IDs and virtual device signatures

### 5. **CPU Instruction Detection (CPUID)**
- Uses CPUID instruction to detect hypervisor presence
- Identifies Microsoft Hyper-V hypervisor signature
- Extracts Hyper-V version information

### 6. **Process Detection**
- Looks for Hyper-V management processes
- VM worker processes and management services

### 7. **VMBus Device Detection**
- Scans for VMBus device class and instances
- Virtual machine bus enumeration

### 8. **BIOS/UEFI Detection**
- Checks BIOS version strings for virtualization signatures
- System manufacturer identification

### 9. **ACPI Table Detection**
- Searches for Hyper-V specific ACPI tables
- DSDT and FADT table signatures

### 10. **Hypervisor Vendor Detection**
- CPUID-based hypervisor vendor string identification
- Confirms Microsoft Hyper-V signature

### 11. **Windows Internal Objects (Mutexes)**
- Checks for Hyper-V specific named mutexes
- Internal synchronization objects

### 12. **Hypercall Detection**
- Detects availability of Hyper-V hypercall interface
- MSR (Model Specific Register) accessibility

### 13. **Enlightenment Detection**
- Identifies Hyper-V enlightenments and optimizations
- APIC, timing, and DMA enlightenments

### 14. **Ring Buffer Detection**
- Looks for VMBus channel ring buffer structures
- Communication mechanism between host and guest

### 15. **Hyper-V Specific Features**
- Comprehensive CPUID feature detection
- VP Runtime, SynIC, synthetic timers, and more

## Build Instructions

### Prerequisites
- Microsoft Visual Studio 2019 or later
- Windows SDK 10.0 or later
- Administrator privileges recommended for full functionality

### Building with Visual Studio
1. Open `HyperVDetector.sln` in Visual Studio
2. Select your desired configuration (Debug/Release) and platform (x86/x64)
3. Build the solution (Ctrl+Shift+B)

### Building from Command Line
```cmd
msbuild HyperVDetector.sln /p:Configuration=Release /p:Platform=x64
```

## Usage

### Running the Detector
```cmd
HyperVDetector.exe
```

### Sample Output
```
=== Hyper-V Virtual Machine Detector ===

[1] Checking specific files...
    Found: C:\Windows\System32\drivers\vmbus.sys
    [+] Hyper-V files detected!

[2] Checking registry keys...
    Found: HKLM\SYSTEM\CurrentControlSet\Services\vmbus
    [+] Hyper-V registry keys detected!

...

=== Detection Summary ===
Detection methods triggered: 12/15
RESULT: Running inside Hyper-V virtual machine
Confidence level: Very High
```

## Technical Details

### Required Libraries
- `setupapi.lib` - Device enumeration
- `cfgmgr32.lib` - Configuration Manager
- `advapi32.lib` - Registry and security functions
- `ntdll.lib` - Native API access

### Privilege Requirements
- **User Mode**: Most detection methods work
- **Administrator**: Full functionality, including some registry keys and system information
- **Kernel Mode**: Not required, but some hypercall detection methods would benefit

### Compatibility
- Windows 7 and later
- Both x86 and x64 architectures
- Works on Windows Server editions

## Detection Accuracy

The tool uses a confidence scoring system:
- **Very High (10+ detections)**: Extremely confident of Hyper-V presence
- **High (5-9 detections)**: High confidence
- **Medium (3-4 detections)**: Moderate confidence
- **Low (1-2 detections)**: Some indicators present

## Limitations

1. **Admin Privileges**: Some checks require administrator privileges
2. **Kernel Access**: Hypercall detection is limited without kernel-mode access
3. **Version Dependent**: Some signatures may vary between Hyper-V versions
4. **False Positives**: Other Microsoft virtualization technologies might trigger some checks

## Security Considerations

This tool is designed for:
- Legitimate system administration
- Security research and analysis
- Virtualization environment detection
- Compliance and audit purposes

## Contributing

When adding new detection methods:
1. Add the detection function
2. Update the main detection loop
3. Increment the total detection count
4. Update this README with the new method

## License

This code is provided for educational and research purposes. Use responsibly and in accordance with applicable laws and policies.

## References

- [Hyper-V Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/)
- [Microsoft Hypervisor CPUID Leaves](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs)
- [VMBus Protocol Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/vmbuskernelmodeclientlibapi/)
