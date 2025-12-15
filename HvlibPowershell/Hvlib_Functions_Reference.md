# Hvlib PowerShell Module - Function Reference (beta version)

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](https://github.com/gerhart01/Hyper-V-Tools/tree/main/HvlibPowershell)
[![PowerShell](https://img.shields.io/badge/powershell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red.svg)](LICENSE)

> PowerShell wrapper for hvlib.dll - Hyper-V Memory Manager Plugin. Provides comprehensive API for VM memory operations, partition management, and process introspection.

**Author:** Arthur Khudyaev (www.x.com/gerhart_x)  
**Project:** [Hvlib Powershell module](https://github.com/gerhart01/Hyper-V-Tools/tree/main/HvlibPowershell)

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Function Categories](#function-categories)
  - [Library Management](#library-management)
    - [1. Get-Hvlib](#1-get-hvlib)
    - [2. Get-HvlibPreferredSettings](#2-get-hvlibpreferredsettings)
  - [Partition Enumeration and Selection](#partition-enumeration-and-selection)
    - [3. Get-HvlibAllPartitions](#3-get-hvliballpartitions)
    - [4. Get-HvlibPartition](#4-get-hvlibpartition)
    - [5. Select-HvlibPartition](#5-select-hvlibpartition)
  - [Partition Information](#partition-information)
    - [6. Get-HvlibPartitionName](#6-get-hvlibpartitionname)
    - [7. Get-HvlibPartitionGuid](#7-get-hvlibpartitionguid)
    - [8. Get-HvlibPartitionId](#8-get-hvlibpartitionid)
    - [9. Get-HvlibData](#9-get-hvlibdata)
    - [10. Get-HvlibData2](#10-get-hvlibdata2)
  - [Physical Memory Operations](#physical-memory-operations)
    - [11. Get-HvlibVmPhysicalMemory](#11-get-hvlibvmphysicalmemory)
    - [12. Set-HvlibVmPhysicalMemory](#12-set-hvlibvmphysicalmemory)
    - [13. Set-HvlibVmPhysicalMemoryBytes](#13-set-hvlibvmphysicalmemorybytes)
  - [Virtual Memory Operations](#virtual-memory-operations)
    - [14. Get-HvlibVmVirtualMemory](#14-get-hvlibvmvirtualmemory)
    - [15. Set-HvlibVmVirtualMemory](#15-set-hvlibvmvirtualmemory)
    - [16. Set-HvlibVmVirtualMemoryBytes](#16-set-hvlibvmvirtualmemorybytes)
  - [Process and System Information](#process-and-system-information)
    - [17. Get-HvlibProcessesList](#17-get-hvlibprocesseslist)
    - [18. Get-HvlibCr3](#18-get-hvlibcr3)
  - [VM State Control](#vm-state-control)
    - [19. Suspend-HvlibVm](#19-suspend-hvlibvm)
    - [20. Resume-HvlibVm](#20-resume-hvlibvm)
  - [Advanced Memory Operations](#advanced-memory-operations)
    - [21. Get-HvlibPhysicalAddress](#21-get-hvlibphysicaladdress)
    - [22. Set-HvlibPartitionData](#22-set-hvlibpartitiondata)
  - [VM Introspection](#vm-introspection)
    - [23. Get-HvlibMachineType](#23-get-hvlibmachinetype)
    - [24. Get-HvlibCurrentVtl](#24-get-hvlibcurrentvtl)
  - [CPU Register Access](#cpu-register-access)
    - [25. Get-HvlibVpRegister](#25-get-hvlibvpregister)
    - [26. Set-HvlibVpRegister](#26-set-hvlibvpregister)
  - [Resource Management](#resource-management)
    - [27. Close-HvlibPartitions](#27-close-hvlibpartitions)
    - [28. Close-HvlibPartition](#28-close-hvlibpartition)
  - [Utilities](#utilities)
    - [29. Get-HexValue](#29-get-hexvalue)
- [Special Constants and Values](#special-constants-and-values)
- [Examples](#examples)
- [Workflow Scenarios](#workflow-scenarios)
- [Best Practices and Tips](#best-practices-and-tips)
- [Troubleshooting](#troubleshooting)
- [Version History](#version-history)

---

## Overview

Hvlib PowerShell Module provides 29 cmdlets for interacting with Hyper-V virtual machines at the memory and hypervisor level. It enables:

- **VM Memory Operations**: Read/write physical and virtual memory
- **Process Introspection**: Enumerate processes and retrieve system structures
- **VM State Control**: Suspend and resume virtual machines
- **Advanced Debugging**: CPU register access, address translation, VTL detection
- **Partition Management**: Enumerate and manage VM partitions

---

## Installation

### Prerequisites
- PowerShell 7.0 or higher
- Windows with Hyper-V enabled
- Administrator privileges
- hvlibdotnet.dll

### Import Module

```powershell
# Import the module
Import-Module .\Hvlib.psd1

# Load the library (required before using any functions)
Get-Hvlib -path_to_dll "C:\path\to\hvlibdotnet.dll"
```

---

## Quick Start

```powershell
# 1. Load library
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"

# 2. List all VMs
$vms = Get-HvlibAllPartitions
$vms | Format-Table VMName, VmHandle

# 3. Select a VM
$handle = Get-HvlibPartition -VmName "Windows 11"

# 4. Read physical memory
$data = Get-HvlibVmPhysicalMemory -prtnHandle $handle -start_position 0x1000 -size 0x1000

# 5. Get processes ID list
$processes = Get-HvlibProcessesList -PartitionHandle $handle

# 6. Clean up
Close-HvlibPartition -handle $handle
```

---

## Function Categories

### Library Management

Functions for initializing and configuring the Hvlib library.

---

### 1. Get-Hvlib

Load Hvlib library if not already loaded.

**Syntax:**
```powershell
Get-Hvlib -path_to_dll <String>
```

**Parameters:**
- **path_to_dll** (String, Mandatory): Path to hvlibdotnet.dll

**Returns:** Boolean indicating success or failure

**Example:**
```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
```

---

### 2. Get-HvlibPreferredSettings

Get default plugin configuration with recommended settings.

**Syntax:**
```powershell
Get-HvlibPreferredSettings
```

**Returns:** VM_OPERATIONS_CONFIG structure with default settings

**Example:**
```powershell
$cfg = Get-HvlibPreferredSettings
Write-Host "Debug Mode: $($cfg.DebugMode)"
```

---

### Partition Enumeration and Selection

Functions for discovering and selecting Hyper-V VM partitions.

---

### 3. Get-HvlibAllPartitions

Enumerate all active Hyper-V partitions.

**Syntax:**
```powershell
Get-HvlibAllPartitions
```

**Returns:** Array of partition objects with VMName and VmHandle properties

**Example:**
```powershell
$vms = Get-HvlibAllPartitions
foreach ($vm in $vms) {
    Write-Host "$($vm.VMName): 0x$($vm.VmHandle.ToString('X'))"
}
```

---

### 4. Get-HvlibPartition

Select partition by VM name.

**Syntax:**
```powershell
Get-HvlibPartition -VmName <String>
```

**Parameters:**
- **VmName** (String, Mandatory): Name of the virtual machine

**Returns:** UInt64 partition handle, or $null if not found

**Example:**
```powershell
$handle = Get-HvlibPartition -VmName "Windows 11"
if ($handle) {
    Write-Host "VM handle: 0x$($handle.ToString('X16'))"
}
```

---

### 5. Select-HvlibPartition

Select partition by handle.

**Syntax:**
```powershell
Select-HvlibPartition -PartitionHandle <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition

**Returns:** Boolean indicating success

**Example:**
```powershell
Select-HvlibPartition -PartitionHandle 0x100000000000
```

---

### Partition Information

Functions for retrieving partition metadata and configuration.

---

### 6. Get-HvlibPartitionName

Get partition friendly name.

**Syntax:**
```powershell
Get-HvlibPartitionName -PartitionHandle <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition

**Returns:** String containing VM friendly name

**Example:**
```powershell
$name = Get-HvlibPartitionName -PartitionHandle $handle
Write-Host "VM Name: $name"
```

---

### 7. Get-HvlibPartitionGuid

Get partition GUID string.

**Syntax:**
```powershell
Get-HvlibPartitionGuid -PartitionHandle <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition

**Returns:** String containing partition GUID

**Example:**
```powershell
$guid = Get-HvlibPartitionGuid -PartitionHandle $handle
Write-Host "Partition GUID: $guid"
```

---

### 8. Get-HvlibPartitionId

Get partition ID.

**Syntax:**
```powershell
Get-HvlibPartitionId -PartitionHandle <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition

**Returns:** UInt64 partition ID

**Example:**
```powershell
$id = Get-HvlibPartitionId -PartitionHandle $handle
Write-Host "Partition ID: $id"
```

---

### 9. Get-HvlibData

Get partition data (out parameter version).

**Syntax:**
```powershell
Get-HvlibData -PartitionHandle <UInt64> -InformationClass <HVDD_INFORMATION_CLASS> -Information <Ref>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **InformationClass** (HVDD_INFORMATION_CLASS, Mandatory): Type of information to retrieve
- **Information** (Ref, Mandatory): Output variable for information

**Returns:** Boolean indicating success

**Example:**
```powershell
$info = $null
$result = Get-HvlibData -PartitionHandle $handle `
    -InformationClass HvddKernelBase `
    -Information ([ref]$info)
if ($result) {
    Write-Host "Kernel Base: 0x$($info.ToUInt64().ToString('X16'))"
}
```

---

### 10. Get-HvlibData2

Get partition data (return value version).

**Syntax:**
```powershell
Get-HvlibData2 -PartitionHandle <UInt64> -InformationClass <HVDD_INFORMATION_CLASS>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **InformationClass** (HVDD_INFORMATION_CLASS, Mandatory): Type of information to retrieve

**Returns:** UInt64 value or 0 on failure

**Example:**
```powershell
$kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass HvddKernelBase
Write-Host "Kernel Base: 0x$($kernelBase.ToString('X16'))"
```

**Common Information Classes:**
- `HvddKernelBase` - Kernel base address
- `HvddPsLoadedModuleList` - Loaded module list
- `HvddPsActiveProcessHead` - Active process list head
- `HvddEprocess` - EPROCESS structure address

---

### Physical Memory Operations

Functions for reading and writing VM physical memory.

---

### 11. Get-HvlibVmPhysicalMemory

Read physical memory from VM.

**Syntax:**
```powershell
Get-HvlibVmPhysicalMemory -prtnHandle <UInt64> -start_position <UInt64> -size <UInt64>
```

**Parameters:**
- **prtnHandle** (UInt64, Mandatory): Partition handle
- **start_position** (UInt64, Mandatory): Starting physical address
- **size** (UInt64, Mandatory): Number of bytes to read (1 to Int32.MaxValue)

**Returns:** Byte array containing memory contents, or $null on failure

**Example:**
```powershell
# Read 4KB from physical address
$data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
    -start_position 0x1000 -size 0x1000

# Display first 16 bytes in hex
$data[0..15] | ForEach-Object { "{0:X2}" -f $_ }
```

---

### 12. Set-HvlibVmPhysicalMemory

Write physical memory from file.

**Syntax:**
```powershell
Set-HvlibVmPhysicalMemory -filename <String> -prtnHandle <UInt64>
```

**Parameters:**
- **filename** (String, Mandatory): Path to input file (must exist)
- **prtnHandle** (UInt64, Mandatory): Partition handle

**Returns:** Boolean indicating success

**Example:**
```powershell
Set-HvlibVmPhysicalMemory -filename "C:\data\memory.bin" -prtnHandle $handle
```

---

### 13. Set-HvlibVmPhysicalMemoryBytes

Write byte array to physical memory.

**Syntax:**
```powershell
Set-HvlibVmPhysicalMemoryBytes -PartitionHandle <UInt64> -StartPosition <UInt64> -Data <Byte[]>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Partition handle
- **StartPosition** (UInt64, Mandatory): Starting physical address
- **Data** (Byte[], Mandatory): Byte array to write

**Returns:** Boolean indicating success

**Example:**
```powershell
# Write NOP instructions (0x90) followed by RET (0xC3)
$patch = [byte[]]@(0x90, 0x90, 0x90, 0xC3)
Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $handle `
    -StartPosition 0x1000 -Data $patch
```

---

### Virtual Memory Operations

Functions for reading and writing VM virtual memory.

---

### 14. Get-HvlibVmVirtualMemory

Read virtual memory from VM.

**Syntax:**
```powershell
Get-HvlibVmVirtualMemory -prtnHandle <UInt64> -start_position <Object> -size <UInt64>
```

**Parameters:**
- **prtnHandle** (UInt64, Mandatory): Partition handle
- **start_position** (Object, Mandatory): Starting virtual address (accepts string for large addresses)
- **size** (UInt64, Mandatory): Number of bytes to read (1 to Int32.MaxValue)

**Returns:** Byte array containing memory contents, or $null on failure

**Example:**
```powershell
# Read kernel memory (module handles conversion automatically)
$data = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position "0xFFFFF80000000000" -size 0x1000

# Alternative: use variable
$kernelAddr = "0xFFFFF80000000000"
$data = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position $kernelAddr -size 0x1000
```

---

### 15. Set-HvlibVmVirtualMemory

Write virtual memory from file.

**Syntax:**
```powershell
Set-HvlibVmVirtualMemory -filename <String> -prtnHandle <UInt64>
```

**Parameters:**
- **filename** (String, Mandatory): Path to input file (must exist)
- **prtnHandle** (UInt64, Mandatory): Partition handle

**Returns:** Boolean indicating success

**Example:**
```powershell
Set-HvlibVmVirtualMemory -filename "C:\patches\kernel.bin" -prtnHandle $handle
```

---

### 16. Set-HvlibVmVirtualMemoryBytes

Write byte array to virtual memory.

**Syntax:**
```powershell
Set-HvlibVmVirtualMemoryBytes -PartitionHandle <UInt64> -StartPosition <UInt64> -Data <Byte[]>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Partition handle
- **StartPosition** (UInt64, Mandatory): Starting virtual address
- **Data** (Byte[], Mandatory): Byte array to write

**Returns:** Boolean indicating success

**Example:**
```powershell
# Patch kernel function with NOPs
$nops = [byte[]]@(0x90, 0x90, 0x90, 0xC3)
$kernelAddr = "0xFFFFF80000001000"
Set-HvlibVmVirtualMemoryBytes -PartitionHandle $handle `
    -StartPosition $kernelAddr -Data $nops
```

---

### Process and System Information

Functions for process enumeration and system structure retrieval.

---

### 17. Get-HvlibProcessesList

Get list of process IDs in VM.

**Syntax:**
```powershell
Get-HvlibProcessesList -PartitionHandle <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition

**Returns:** Array of UInt64 process IDs (first element is count)

**Example:**
```powershell
$processes = Get-HvlibProcessesList -PartitionHandle $handle
$count = $processes[0]
Write-Host "Found $count processes"

# Display all PIDs
for ($i = 1; $i -le $count; $i++) {
    $pid = $processes[$i]
    Write-Host "PID: $pid (0x$($pid.ToString('X')))"
}
```

---

### 18. Get-HvlibCr3

Get CR3 register value for process.

**Syntax:**
```powershell
Get-HvlibCr3 -PartitionHandle <UInt64> -ProcessId <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **ProcessId** (UInt64, Mandatory): Process ID

**Returns:** UInt64 CR3 value (page directory base), or 0 on failure

**Example:**
```powershell
# Get kernel CR3 (special PID: 0xFFFFFFFE)
$kernelPid = "0xFFFFFFFE"
$cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $kernelPid
Write-Host "Kernel CR3: 0x$($cr3.ToString('X16'))"

# Get CR3 for specific process
$pid = 1234
$cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $pid
```

**Special PIDs:**
- `0xFFFFFFFF` - Hypervisor
- `0xFFFFFFFE` - Kernel

---

### VM State Control

Functions for controlling virtual machine execution state. *(New in v1.2.0)*

---

### 19. Suspend-HvlibVm

Suspend virtual machine execution.

**Syntax:**
```powershell
Suspend-HvlibVm -PartitionHandle <UInt64> [-Method <SUSPEND_RESUME_METHOD>] [-ManageWorkerProcess <Boolean>]
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **Method** (SUSPEND_RESUME_METHOD, Optional): Suspend method (default: PowerShell)
- **ManageWorkerProcess** (Boolean, Optional): Manage worker process (default: false)

**Returns:** Boolean indicating success

**Example:**
```powershell
# Suspend VM using default method
Suspend-HvlibVm -PartitionHandle $handle

# Suspend using special register write method
Suspend-HvlibVm -PartitionHandle $handle `
    -Method SuspendResumeWriteSpecRegister
```

**Available Methods:**
- `SuspendResumePowershell` (default)
- `SuspendResumeWriteSpecRegister`

---

### 20. Resume-HvlibVm

Resume virtual machine execution.

**Syntax:**
```powershell
Resume-HvlibVm -PartitionHandle <UInt64> [-Method <SUSPEND_RESUME_METHOD>] [-ManageWorkerProcess <Boolean>]
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **Method** (SUSPEND_RESUME_METHOD, Optional): Resume method (default: PowerShell)
- **ManageWorkerProcess** (Boolean, Optional): Manage worker process (default: false)

**Returns:** Boolean indicating success

**Example:**
```powershell
# Resume VM
Resume-HvlibVm -PartitionHandle $handle

# Resume using special register write method
Resume-HvlibVm -PartitionHandle $handle `
    -Method SuspendResumeWriteSpecRegister
```

---

### Advanced Memory Operations

Functions for advanced memory management and address translation. *(New in v1.2.0)*

---

### 21. Get-HvlibPhysicalAddress

Translate virtual address to physical address (GVA to GPA).

**Syntax:**
```powershell
Get-HvlibPhysicalAddress -PartitionHandle <UInt64> -VirtualAddress <UInt64> [-AccessType <MEMORY_ACCESS_TYPE>]
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **VirtualAddress** (UInt64, Mandatory): Virtual address to translate
- **AccessType** (MEMORY_ACCESS_TYPE, Optional): Memory access type (default: Virtual)

**Returns:** UInt64 physical address, or 0 on failure

**Example:**
```powershell
# Translate kernel virtual address to physical
$va = "0xFFFFF80000000000"
$pa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $va
Write-Host "GVA: 0x$($va.ToString('X16'))"
Write-Host "GPA: 0x$($pa.ToString('X16'))"
```

**Access Types:**
- `MmVirtualMemory` (default)
- `MmPhysicalMemory`

---

### 22. Set-HvlibPartitionData

Set partition configuration data.

**Syntax:**
```powershell
Set-HvlibPartitionData -PartitionHandle <UInt64> -InformationClass <HVDD_INFORMATION_CLASS> -Information <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **InformationClass** (HVDD_INFORMATION_CLASS, Mandatory): Type of information to set
- **Information** (UInt64, Mandatory): Information value

**Returns:** UInt64 result code (non-zero on success)

**Example:**
```powershell
# Set memory block configuration
$result = Set-HvlibPartitionData -PartitionHandle $handle `
    -InformationClass HvddSetMemoryBlock -Information 1
if ($result -ne 0) {
    Write-Host "Memory block set successfully"
}
```

---

### VM Introspection

Functions for VM architecture detection and Virtual Trust Level (VTL) analysis. *(New in v1.2.0)*

---

### 23. Get-HvlibMachineType

Get VM machine type (architecture).

**Syntax:**
```powershell
Get-HvlibMachineType -PartitionHandle <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition

**Returns:** String indicating machine type

**Example:**
```powershell
$machineType = Get-HvlibMachineType -PartitionHandle $handle
switch ($machineType) {
    'MACHINE_AMD64' { Write-Host "64-bit VM (AMD64/Intel 64)" }
    'MACHINE_X86'   { Write-Host "32-bit VM (x86)" }
}
```

**Return Values:**
- `MACHINE_AMD64` - 64-bit x64 architecture
- `MACHINE_X86` - 32-bit x86 architecture

---

### 24. Get-HvlibCurrentVtl

Get current Virtual Trust Level for address.

**Syntax:**
```powershell
Get-HvlibCurrentVtl -PartitionHandle <UInt64> -VirtualAddress <UInt64>
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **VirtualAddress** (UInt64, Mandatory): Virtual address to check

**Returns:** String indicating VTL level

**Example:**
```powershell
# Check if address is in secure kernel (VTL1)
$kernelAddr = "0xFFFFF80000000000"
$vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $kernelAddr

if ($vtl -eq 'Vtl1') {
    Write-Host "Address is in secure kernel (VTL1)"
} elseif ($vtl -eq 'Vtl0') {
    Write-Host "Address is in normal kernel (VTL0)"
}
```

**VTL Levels:**
- `Vtl0` - Normal mode (standard kernel)
- `Vtl1` - Secure mode (Virtualization-based Security)

---

### CPU Register Access

Functions for reading and writing virtual processor registers. *(New in v1.2.0)*

---

### 25. Get-HvlibVpRegister

Read virtual processor register.

**Syntax:**
```powershell
Get-HvlibVpRegister -PartitionHandle <UInt64> -VpIndex <UInt32> -RegisterCode <UInt32> [-Vtl <VTL_LEVEL>]
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **VpIndex** (UInt32, Mandatory): Virtual processor index (0-64, typically 0 for first CPU)
- **RegisterCode** (UInt32, Mandatory): Register code (see examples)
- **Vtl** (VTL_LEVEL, Optional): Virtual Trust Level (default: Vtl0)

**Returns:** HV_REGISTER_VALUE structure, or $null on failure

**Example:**
```powershell
# Read RIP (instruction pointer)
$rip = Get-HvlibVpRegister -PartitionHandle $handle `
    -VpIndex 0 -RegisterCode 0x00020000
Write-Host "RIP: 0x$($rip.Reg64.ToString('X16'))"

# Read RAX register
$rax = Get-HvlibVpRegister -PartitionHandle $handle `
    -VpIndex 0 -RegisterCode 0x00020003
Write-Host "RAX: 0x$($rax.Reg64.ToString('X16'))"

# Read CR3 register (page directory base)
$cr3 = Get-HvlibVpRegister -PartitionHandle $handle `
    -VpIndex 0 -RegisterCode 0x00020014
Write-Host "CR3: 0x$($cr3.Reg64.ToString('X16'))"

# Read from VTL1 (secure kernel)
$secureRip = Get-HvlibVpRegister -PartitionHandle $handle `
    -VpIndex 0 -RegisterCode 0x00020000 -Vtl Vtl1
Write-Host "VTL1 RIP: 0x$($secureRip.Reg64.ToString('X16'))"

# Read all general purpose registers
$gprCodes = @{
    'RAX' = 0x00020003; 'RCX' = 0x00020004
    'RDX' = 0x00020005; 'RBX' = 0x00020006
    'RSP' = 0x00020002; 'RBP' = 0x00020007
    'RSI' = 0x00020008; 'RDI' = 0x00020009
}

Write-Host "`nGeneral Purpose Registers:"
foreach ($regName in $gprCodes.Keys | Sort-Object) {
    $reg = Get-HvlibVpRegister -PartitionHandle $handle `
        -VpIndex 0 -RegisterCode $gprCodes[$regName]
    Write-Host "$regName : 0x$($reg.Reg64.ToString('X16'))"
}
```

**Register Codes Reference:**

| Register | Code | Description |
|----------|------|-------------|
| **Special Registers** |
| RIP | `0x00020000` | Instruction Pointer (Program Counter) |
| RFLAGS | `0x00020001` | Status and Control Flags |
| RSP | `0x00020002` | Stack Pointer |
| **General Purpose Registers (64-bit)** |
| RAX | `0x00020003` | Accumulator Register |
| RCX | `0x00020004` | Counter Register |
| RDX | `0x00020005` | Data Register |
| RBX | `0x00020006` | Base Register |
| RBP | `0x00020007` | Base Pointer |
| RSI | `0x00020008` | Source Index |
| RDI | `0x00020009` | Destination Index |
| **Control Registers** |
| CR0 | `0x00020012` | Control Register 0 (system control flags) |
| CR2 | `0x00020013` | Page Fault Linear Address |
| CR3 | `0x00020014` | Page Directory Base |
| CR4 | `0x00020015` | Control Register 4 (feature extensions) |
| **Debug Registers** |
| DR0 | `0x00020017` | Debug Register 0 (hardware breakpoint) |

---

### 26. Set-HvlibVpRegister

Write virtual processor register.

**Syntax:**
```powershell
Set-HvlibVpRegister -PartitionHandle <UInt64> -VpIndex <UInt32> -RegisterCode <UInt32> -RegisterValue <Object> [-Vtl <VTL_LEVEL>]
```

**Parameters:**
- **PartitionHandle** (UInt64, Mandatory): Handle to partition
- **VpIndex** (UInt32, Mandatory): Virtual processor index (0-64)
- **RegisterCode** (UInt32, Mandatory): Register code
- **RegisterValue** (Object, Mandatory): Register value structure to write
- **Vtl** (VTL_LEVEL, Optional): Virtual Trust Level (default: Vtl0)

**Returns:** Boolean indicating success

**Example:**
```powershell
# Create new register value structure
$newRip = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
$newRip.Reg64 = "0xFFFFF80000001000"

# Set RIP to new value
Set-HvlibVpRegister -PartitionHandle $handle `
    -VpIndex 0 -RegisterCode 0x00020000 -RegisterValue $newRip

# Modify RAX register
$newRax = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
$newRax.Reg64 = 0x1234567890ABCDEF
Set-HvlibVpRegister -PartitionHandle $handle `
    -VpIndex 0 -RegisterCode 0x00020003 -RegisterValue $newRax
```

---

### Resource Management

Functions for cleaning up partition handles and resources.

---

### 27. Close-HvlibPartitions

Close all open partitions.

**Syntax:**
```powershell
Close-HvlibPartitions
```

**Returns:** Void

**Example:**
```powershell
# Close all partitions at end of script
Close-HvlibPartitions
```

---

### 28. Close-HvlibPartition

Close specific partition.

**Syntax:**
```powershell
Close-HvlibPartition -handle <UInt64>
```

**Parameters:**
- **handle** (UInt64, Mandatory): Partition handle to close

**Returns:** Void

**Example:**
```powershell
# Close specific partition when done
Close-HvlibPartition -handle $handle
```

---

### Utilities

Helper functions for data conversion and formatting.

---

### 29. Get-HexValue

Convert number to hexadecimal string.

**Syntax:**
```powershell
Get-HexValue -num <Object>
```

**Parameters:**
- **num** (Object, Mandatory): Number to convert (accepts various numeric types)

**Returns:** String containing uppercase hexadecimal representation

**Example:**
```powershell
# Convert decimal to hex
$hex = Get-HexValue -num 65536
Write-Host "0x$hex"  # Output: 0x10000

# Convert large number
$hex = Get-HexValue -num 0xFFFFF80000000000
Write-Host "0x$hex"

# Use with string input
$hex = Get-HexValue -num "281474976710656"
Write-Host "0x$hex"
```

---

## Special Constants and Values

### Special Process IDs

These special PID values can be used with `Get-HvlibCr3` to retrieve system-level CR3 values:

| PID Value | Description | Usage |
|-----------|-------------|-------|
| `0xFFFFFFFE` | Kernel | Get kernel CR3 (page directory base) |
| `0xFFFFFFFF` | Hypervisor | Get hypervisor CR3 |

**Important:** When using these values in PowerShell, simply pass them as strings:

```powershell
# Correct method - module handles conversion
$kernelPid = "0xFFFFFFFE"
$cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $kernelPid

# Alternative using variables
$PID_KERNEL = "0xFFFFFFFE"
$cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $PID_KERNEL
```

### Memory Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Page Size | `0x1000` | Standard 4KB page size |
| Large Page Size | `0x200000` | 2MB large page |
| KUSER_SHARED_DATA | `0xFFFFF78000000000` | Kernel shared data region |

### Working with Large Addresses in PowerShell

The module automatically handles conversion of large hexadecimal addresses. You can pass addresses as strings directly to functions.

**Problem (old approach):**
```powershell
# This required manual conversion
$addr = [System.Convert]::ToUInt64("FFFFF80000000000", 16)
Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $addr -size 0x1000
```

**Solution (current approach):**

```powershell
# Method 1: Pass string directly (recommended)
Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position "0xFFFFF80000000000" -size 0x1000

# Method 2: Use variable
$kernelAddr = "0xFFFFF80000000000"
Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $kernelAddr -size 0x1000

# Method 3: Use constants
$ADDR_KUSER = "0xFFFFF78000000000"
Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $ADDR_KUSER -size 0x1000
```

This applies to any functions accepting large memory addresses, particularly for kernel virtual addresses (typically starting with `0xFFFFF...` on x64 systems).

### Information Classes

Common `HVDD_INFORMATION_CLASS` values for `Get-HvlibData2`:

| Class | Description |
|-------|-------------|
| `HvddKernelBase` | Kernel base virtual address |
| `HvddPsLoadedModuleList` | Loaded kernel modules list |
| `HvddPsActiveProcessHead` | Active processes list head |
| `HvddEprocess` | EPROCESS structure address |
| `HvddNumberOfCPU` | Virtual processor count |
| `HvddMmMaximumPhysicalPage` | Maximum physical page number |
| `HvddPartitionFriendlyName` | VM friendly name |
| `HvddVmGuidString` | VM GUID string |
| `HvddPartitionId` | Partition identifier |
| `HvddGetProcessesIds` | Process IDs array |

---

## Examples

### Example 1: Basic VM Memory Dump

```powershell
# Initialize
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"

# Get VM handle
$handle = Get-HvlibPartition -VmName "Windows 11"

# Read first 4KB of physical memory
$data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
    -start_position 0x0 -size 0x1000

# Save to file
[System.IO.File]::WriteAllBytes("C:\dump\physical_0x0.bin", $data)

# Cleanup
Close-HvlibPartition -handle $handle
```

### Example 2: Process Enumeration and Analysis

```powershell
# Initialize and get handle
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Windows Server 2022"

# Get all processes
$processes = Get-HvlibProcessesList -PartitionHandle $handle
$count = $processes[0]

Write-Host "Found $count processes:"
for ($i = 1; $i -le $count; $i++) {
    $pid = $processes[$i]
    $cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $pid
    Write-Host "PID: $pid, CR3: 0x$($cr3.ToString('X16'))"
}

# Get kernel structures
$kernelBase = Get-HvlibData2 -PartitionHandle $handle `
    -InformationClass HvddKernelBase
Write-Host "Kernel Base: 0x$($kernelBase.ToString('X16'))"

Close-HvlibPartition -handle $handle
```

### Example 3: Kernel Memory Patching

```powershell
# Initialize
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Test VM"

# Suspend VM for safe patching
Suspend-HvlibVm -PartitionHandle $handle

# Read current instruction
$targetAddr = "0xFFFFF80000123456"
$original = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position $targetAddr -size 4

# Create patch (replace with NOPs and RET)
$patch = [byte[]]@(0x90, 0x90, 0x90, 0xC3)

# Apply patch
Set-HvlibVmVirtualMemoryBytes -PartitionHandle $handle `
    -StartPosition $targetAddr -Data $patch

# Verify patch
$patched = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position $targetAddr -size 4

# Resume VM
Resume-HvlibVm -PartitionHandle $handle

Write-Host "Original: $([BitConverter]::ToString($original))"
Write-Host "Patched:  $([BitConverter]::ToString($patched))"

Close-HvlibPartition -handle $handle
```

### Example 4: CPU Register Debugging

```powershell
# Initialize
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Debug VM"

# Suspend VM
Suspend-HvlibVm -PartitionHandle $handle

# Read CPU registers (VP 0)
$rip = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000
$rax = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020003
$rsp = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020007
$cr3 = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020014

Write-Host "CPU State:"
Write-Host "RIP: 0x$($rip.Reg64.ToString('X16'))"
Write-Host "RAX: 0x$($rax.Reg64.ToString('X16'))"
Write-Host "RSP: 0x$($rsp.Reg64.ToString('X16'))"
Write-Host "CR3: 0x$($cr3.Reg64.ToString('X16'))"

# Get VTL level for current RIP
$vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $rip.Reg64
Write-Host "VTL: $vtl"

# Get machine type
$machineType = Get-HvlibMachineType -PartitionHandle $handle
Write-Host "Architecture: $machineType"

# Resume VM
Resume-HvlibVm -PartitionHandle $handle

Close-HvlibPartition -handle $handle
```

### Example 5: Address Translation and Memory Mapping

```powershell
# Initialize
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Analysis VM"

# Get kernel base virtual address
$kernelVA = Get-HvlibData2 -PartitionHandle $handle `
    -InformationClass HvddKernelBase

Write-Host "Kernel Virtual Address: 0x$($kernelVA.ToString('X16'))"

# Translate to physical address
$kernelPA = Get-HvlibPhysicalAddress -PartitionHandle $handle `
    -VirtualAddress $kernelVA

Write-Host "Kernel Physical Address: 0x$($kernelPA.ToString('X16'))"

# Read from both virtual and physical
$virtualData = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position $kernelVA -size 0x100

$physicalData = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
    -start_position $kernelPA -size 0x100

# Compare (should be identical)
$match = ($null -eq (Compare-Object $virtualData $physicalData))
Write-Host "Virtual and Physical data match: $match"

Close-HvlibPartition -handle $handle
```

### Example 6: Batch Processing Multiple VMs

```powershell
# Initialize
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"

# Get all VMs
$vms = Get-HvlibAllPartitions

foreach ($vm in $vms) {
    Write-Host "`n=== Processing: $($vm.VMName) ==="
    
    # Select VM
    Select-HvlibPartition -PartitionHandle $vm.VmHandle
    
    # Get info
    $guid = Get-HvlibPartitionGuid -PartitionHandle $vm.VmHandle
    $id = Get-HvlibPartitionId -PartitionHandle $vm.VmHandle
    $machineType = Get-HvlibMachineType -PartitionHandle $vm.VmHandle
    
    Write-Host "GUID: $guid"
    Write-Host "ID: $id"
    Write-Host "Type: $machineType"
    
    # Get process count
    $processes = Get-HvlibProcessesList -PartitionHandle $vm.VmHandle
    if ($processes) {
        Write-Host "Processes: $($processes[0])"
    }
}

# Cleanup all
Close-HvlibPartitions
```

### Example 7: Complete Debug Session (NEW v1.3.0)

```powershell
# Complete debugging workflow with all new v1.3.0 features
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Debug Target"

# Step 1: Suspend VM for safe debugging
Write-Host "Step 1: Suspending VM..."
Suspend-HvlibVm -PartitionHandle $handle

# Step 2: Get architecture info
Write-Host "Step 2: Detecting architecture..."
$machineType = Get-HvlibMachineType -PartitionHandle $handle
Write-Host "Architecture: $machineType"

# Step 3: Get kernel base
Write-Host "Step 3: Getting kernel base..."
$kernelBase = Get-HvlibData2 -PartitionHandle $handle `
    -InformationClass HvddKernelBase
Write-Host "Kernel Base: 0x$($kernelBase.ToString('X16'))"

# Step 4: Check VTL level
Write-Host "Step 4: Checking VTL..."
$vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $kernelBase
Write-Host "VTL Level: $vtl"

# Step 5: Read CPU registers
Write-Host "Step 5: Reading CPU state..."
$rip = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000
$cr3 = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020014
Write-Host "RIP: 0x$($rip.Reg64.ToString('X16'))"
Write-Host "CR3: 0x$($cr3.Reg64.ToString('X16'))"

# Step 6: Translate address
Write-Host "Step 6: Translating virtual to physical..."
$kernelPA = Get-HvlibPhysicalAddress -PartitionHandle $handle `
    -VirtualAddress $kernelBase
Write-Host "Kernel Physical: 0x$($kernelPA.ToString('X16'))"

# Step 7: Read memory
Write-Host "Step 7: Reading kernel memory..."
$memData = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
    -start_position $kernelPA -size 0x100
Write-Host "Read $($memData.Length) bytes"

# Step 8: Resume VM
Write-Host "Step 8: Resuming VM..."
Resume-HvlibVm -PartitionHandle $handle

Close-HvlibPartition -handle $handle
Write-Host "Debug session completed!"
```

---

## Workflow Scenarios

The following workflows combine multiple functions to accomplish complex tasks.

### Workflow 1: Multi-VM Analysis Report

Generate comprehensive report for all VMs on the system.

```powershell
# Initialize
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"

# Get all VMs
$vms = Get-HvlibAllPartitions

Write-Host ("{0,-25} {1,-12} {2,-10} {3}" -f "VM Name", "Architecture", "VTL", "Kernel Base")
Write-Host ('-' * 75)

$report = foreach ($vm in $vms) {
    Select-HvlibPartition -PartitionHandle $vm.VmHandle | Out-Null
    
    # Get architecture
    $machineType = Get-HvlibMachineType -PartitionHandle $vm.VmHandle
    $arch = if ($machineType -eq 'MACHINE_AMD64') { "x64" } else { "x86" }
    
    # Get kernel base
    $kernelBase = Get-HvlibData2 -PartitionHandle $vm.VmHandle `
        -InformationClass HvddKernelBase
    
    # Check VTL
    $vtl = Get-HvlibCurrentVtl -PartitionHandle $vm.VmHandle -VirtualAddress $kernelBase
    
    Write-Host ("{0,-25} {1,-12} {2,-10} 0x{3:X16}" -f $vm.VMName, $arch, $vtl, $kernelBase)
    
    Close-HvlibPartition -handle $vm.VmHandle
    
    [PSCustomObject]@{
        VMName = $vm.VMName
        Architecture = $arch
        VTL = $vtl
        KernelBase = "0x$($kernelBase.ToString('X16'))"
    }
}

# Export report
$report | Export-Csv -Path "C:\reports\vm_analysis.csv" -NoTypeInformation
Write-Host "`nReport exported successfully!"
```

### Workflow 2: VM Information Report

Detailed information for all partitions.

```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"

$vms = Get-HvlibAllPartitions

$report = foreach ($vm in $vms) {
    $handle = $vm.VmHandle
    
    # Get basic info
    $name = Get-HvlibPartitionName -PartitionHandle $handle
    $guid = Get-HvlibPartitionGuid -PartitionHandle $handle
    $partitionId = Get-HvlibPartitionId -PartitionHandle $handle
    
    # Get system info
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass HvddKernelBase
    $cpuCount = Get-HvlibData2 -PartitionHandle $handle -InformationClass HvddNumberOfCPU
    
    [PSCustomObject]@{
        Name = $name
        GUID = $guid
        PartitionID = $partitionId
        Handle = "0x$($handle.ToString('X16'))"
        KernelBase = "0x$($kernelBase.ToString('X16'))"
        CPUs = $cpuCount
    }
}

# Display report
$report | Format-Table -AutoSize

Close-HvlibPartitions
```

### Workflow 3: Memory Analysis

Comprehensive memory layout analysis.

```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Analysis Target"

# Get memory layout
$kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass HvddKernelBase
$maxPage = Get-HvlibData2 -PartitionHandle $handle -InformationClass HvddMmMaximumPhysicalPage

Write-Host "`nMemory Layout Analysis:" -ForegroundColor Cyan
Write-Host "  Kernel Base: 0x$($kernelBase.ToString('X16'))"
Write-Host "  Max Physical Page: 0x$($maxPage.ToString('X16'))"

# Calculate total memory
$PAGE_SIZE = 0x1000
$totalMemoryMB = [Math]::Round(($maxPage * $PAGE_SIZE) / 1MB, 2)
Write-Host "  Total Physical Memory: ~$totalMemoryMB MB"

# Verify kernel PE header
$peHeader = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position $kernelBase -size 0x200

if ($peHeader -and $peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
    Write-Host "  Kernel PE Header: Valid (MZ signature)" -ForegroundColor Green
}

# Read KUSER_SHARED_DATA
$kuserAddr = "0xFFFFF78000000000"
$kuserData = Get-HvlibVmVirtualMemory -prtnHandle $handle `
    -start_position $kuserAddr -size 0x100

if ($kuserData) {
    Write-Host "  KUSER_SHARED_DATA: Accessible" -ForegroundColor Green
}

Close-HvlibPartition -handle $handle
```

### Workflow 4: Process Introspection

Enumerate and analyze processes in VM.

```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Target VM"

# Get kernel CR3
$kernelPid = "0xFFFFFFFE"
$kernelCr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $kernelPid
Write-Host "Kernel CR3: 0x$($kernelCr3.ToString('X16'))" -ForegroundColor Green

# Get hypervisor CR3
$hvPid = "0xFFFFFFFF"
$hvCr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $hvPid
Write-Host "Hypervisor CR3: 0x$($hvCr3.ToString('X16'))" -ForegroundColor Green

# Enumerate processes
$processes = Get-HvlibProcessesList -PartitionHandle $handle

if ($processes) {
    $count = $processes[0]
    Write-Host "`nFound $count processes:" -ForegroundColor Cyan
    
    # Display first 10 processes with their CR3 values
    for ($i = 1; $i -le [Math]::Min(10, $count); $i++) {
        $pid = $processes[$i]
        $cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $pid
        Write-Host "  PID: $pid, CR3: 0x$($cr3.ToString('X16'))"
    }
}

Close-HvlibPartition -handle $handle
```

### Workflow 5: Safe Memory Dump

Dump VM memory pages safely.

```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Target VM"

# Create output directory
$outputPath = "C:\memory_dumps\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

# Get max physical page
$maxPage = Get-HvlibData2 -PartitionHandle $handle `
    -InformationClass HvddMmMaximumPhysicalPage

Write-Host "Starting memory dump..." -ForegroundColor Cyan
Write-Host "Max physical page: 0x$($maxPage.ToString('X16'))"

# Dump first 100 pages (or less)
$pagesToDump = [Math]::Min(100, $maxPage)
$PAGE_SIZE = 0x1000

for ($page = 0; $page -lt $pagesToDump; $page++) {
    $address = $page * $PAGE_SIZE
    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
        -start_position $address -size $PAGE_SIZE
    
    if ($data) {
        $fileName = "page_{0:X4}.bin" -f $page
        $filePath = Join-Path $outputPath $fileName
        [System.IO.File]::WriteAllBytes($filePath, $data)
        
        if (($page % 10) -eq 0) {
            Write-Host "  Dumped $page pages..." -ForegroundColor Gray
        }
    }
}

Write-Host "`nMemory dump completed: $outputPath" -ForegroundColor Green
Close-HvlibPartition -handle $handle
```

### Workflow 6: CPU Context Snapshot

Capture full CPU state with all registers.

```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Target VM"

# Suspend VM for stable snapshot
Suspend-HvlibVm -PartitionHandle $handle

# Define register codes
$registers = @{
    'RIP'    = 0x00020000
    'RFLAGS' = 0x00020001
    'RSP'    = 0x00020002
    'RAX'    = 0x00020003
    'RCX'    = 0x00020004
    'RDX'    = 0x00020005
    'RBX'    = 0x00020006
    'RBP'    = 0x00020007
    'RSI'    = 0x00020008
    'RDI'    = 0x00020009
    'CR0'    = 0x00020012
    'CR3'    = 0x00020014
    'CR4'    = 0x00020015
}

# Capture all registers
Write-Host "CPU Context Snapshot (VP0):" -ForegroundColor Cyan
Write-Host ("{0,-8} {1}" -f "Register", "Value")
Write-Host ('-' * 30)

$context = @{}
foreach ($regName in $registers.Keys | Sort-Object) {
    $regValue = Get-HvlibVpRegister -PartitionHandle $handle `
        -VpIndex 0 -RegisterCode $registers[$regName]
    
    if ($regValue) {
        $value = $regValue.Reg64
        $context[$regName] = $value
        Write-Host ("{0,-8} 0x{1:X16}" -f $regName, $value)
    }
}

# Export to JSON
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportPath = "C:\snapshots\cpu_context_$timestamp.json"
$context | ConvertTo-Json | Out-File -FilePath $exportPath

Write-Host "`nContext exported to: $exportPath" -ForegroundColor Green

# Resume VM
Resume-HvlibVm -PartitionHandle $handle
Close-HvlibPartition -handle $handle
```

### Workflow 7: Virtualization-Based Security (VBS) Detection

Detect if VM has Virtual Secure Mode (VSM) / Credential Guard enabled.

```powershell
Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
$handle = Get-HvlibPartition -VmName "Windows 11"

# Get kernel base address
$kernelBase = Get-HvlibData2 -PartitionHandle $handle `
    -InformationClass HvddKernelBase

# Check multiple kernel addresses for VTL level
$addresses = @(
    $kernelBase,
    $kernelBase + 0x100000,
    $kernelBase + 0x200000
)

Write-Host "Checking VTL levels for VBS detection..." -ForegroundColor Cyan

$hasVtl1 = $false
foreach ($addr in $addresses) {
    $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $addr
    Write-Host "Address 0x$($addr.ToString('X16')): $vtl"
    
    if ($vtl -eq 'Vtl1') {
        $hasVtl1 = $true
    }
}

Write-Host "`nVBS Status:" -ForegroundColor Cyan
if ($hasVtl1) {
    Write-Host "✓ Virtual Based Security (VBS) is ENABLED" -ForegroundColor Green
    Write-Host "✓ Secure kernel (VTL1) detected" -ForegroundColor Green
    Write-Host "  Features: Credential Guard, Device Guard, HVCI" -ForegroundColor Gray
} else {
    Write-Host "✗ Virtual Based Security (VBS) is NOT detected" -ForegroundColor Yellow
    Write-Host "✗ Running in standard mode (VTL0 only)" -ForegroundColor Yellow
}

Close-HvlibPartition -handle $handle
```

---

## Best Practices and Tips

### Safe VM Operations

**Always suspend VMs before critical operations:**
```powershell
# Suspend before reading CPU state or critical memory
Suspend-HvlibVm -PartitionHandle $handle

# Perform operations...
$rip = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000

# Always resume after
Resume-HvlibVm -PartitionHandle $handle
```

**Use error handling:**
```powershell
$handle = Get-HvlibPartition -VmName "Target"
if ($null -eq $handle -or $handle -eq 0) {
    Write-Error "Failed to get VM handle"
    return
}

try {
    # VM operations here
    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle -start_position 0x1000 -size 0x1000
}
finally {
    # Always clean up
    Close-HvlibPartition -handle $handle
}
```

### Performance Optimization

**Reuse partition handles:**
```powershell
# Bad: Multiple lookups
for ($i = 0; $i -lt 100; $i++) {
    $handle = Get-HvlibPartition -VmName "VM"  # Slow
    # ... operations
    Close-HvlibPartition -handle $handle
}

# Good: Single lookup
$handle = Get-HvlibPartition -VmName "VM"
for ($i = 0; $i -lt 100; $i++) {
    # ... operations
}
Close-HvlibPartition -handle $handle
```

### Common Pitfalls

**❌ Don't forget to close partitions:**
```powershell
# Bad: Resource leak
$handle = Get-HvlibPartition -VmName "VM"
# ... operations
# Missing Close-HvlibPartition!

# Good: Always clean up
$handle = Get-HvlibPartition -VmName "VM"
try {
    # ... operations
}
finally {
    Close-HvlibPartition -handle $handle
}
```

**❌ Don't assume memory is readable:**
```powershell
# Bad: No error checking
$data = Get-HvlibVmPhysicalMemory -prtnHandle $handle -start_position $addr -size 0x1000
$value = [BitConverter]::ToUInt64($data, 0)  # May fail if $data is $null

# Good: Validate results
$data = Get-HvlibVmPhysicalMemory -prtnHandle $handle -start_position $addr -size 0x1000
if ($data -and $data.Length -ge 8) {
    $value = [BitConverter]::ToUInt64($data, 0)
    Write-Host "Value: 0x$($value.ToString('X16'))"
} else {
    Write-Warning "Failed to read memory at 0x$($addr.ToString('X16'))"
}
```

---

## Troubleshooting

### Common Issues

**"Invalid partition handle"**
- Ensure VM is running before getting handle
- Check VM name spelling
- Verify Hyper-V is enabled and you have admin rights

**Large addresses not working in PowerShell**
- Module automatically handles address conversion
- Pass addresses as strings: `"0xFFFFF80000000000"`
- See "Working with Large Addresses in PowerShell" section

**Memory read returns null**
- Address may not be mapped in VM
- Try reading physical memory instead of virtual
- Use `Get-HvlibPhysicalAddress` to translate first

**DLL not found**
- Verify path to hvlibdotnet.dll is correct
- Check that hvlib.dll is in same directory
- Ensure DLL is not blocked (right-click → Properties → Unblock)

---

## Version History

### Version 1.3.0 (Current)
**Release Date:** December 2025

**Updates:**
- Updated author information and project links
- Enhanced documentation structure
- Improved examples and workflows

---

### Version 1.2.0 (Major Feature Release)
**Release Date:** December 2024

**New Functions (7):**
- `Set-HvlibPartitionData` - Set partition configuration data
- `Suspend-HvlibVm` / `Resume-HvlibVm` - VM state control
- `Get-HvlibPhysicalAddress` - Virtual to physical address translation (GVA→GPA)
- `Get-HvlibMachineType` - VM architecture detection (x86/AMD64)
- `Get-HvlibCurrentVtl` - Get Virtual Trust Level (VTL0/VTL1)
- `Get-HvlibVpRegister` / `Set-HvlibVpRegister` - CPU register access

**Statistics:**
- Total: 28 public functions (21 + 7 new)
- API Coverage: 95% of HvlibHandle.h (19/20 functions)

---

### Version 1.1.1 (Bug Fix Release)
**Release Date:** November 2024

**Fixes:**
- Removed hard-coded `DEFAULT_DLL_PATH` constant
- Fixed `Export-ModuleMember` errors in dot-sourced files
- `Get-Hvlib` now requires `-path_to_dll` parameter (mandatory)
- DLL path is saved and reused automatically for subsequent calls

**Changes:**
- Updated all examples to include DLL path parameter
- Updated documentation to reflect changes

---

### Version 1.1.0 (Refactored Release)
**Release Date:** October 2025

**Improvements:**
- Complete code refactoring for improved readability and maintainability
- Extracted constants to separate module (`Hvlib.Constants.ps1`)
- Added helper functions module (`Hvlib.Helpers.ps1`)
- Improved parameter validation with PowerShell attributes
- Removed try-catch blocks in favor of explicit validation
- Split large functions into smaller, focused helper functions (under 50 lines)
- Enhanced error handling and user messaging
- Added comprehensive inline documentation
- Improved code organization with logical sections

---

### Version 1.0.1
**Release Date:** September 2025

**Additions:**
- Added missing API functions from hvlibdotnet.cs
- `Get-HvlibPreferredSettings`
- `Get-HvlibAllPartitions`
- `Get-HvlibData` and `Get-HvlibData2`
- Partition information retrieval functions
- Process list and CR3 retrieval functions
- Byte array write functions for memory operations

---

### Version 1.0.0 (Initial Release)
**Release Date:** August 2025

**Features:**
- Basic VM enumeration and selection
- Physical and virtual memory read/write operations
- Partition management functions
- Core library initialization

---

## Additional Resources

- **GitHub Repository:** [gerhart01/Hyper-V-Tools](https://github.com/gerhart01/Hyper-V-Tools)
- **Native Library:** hvlib.dll - Hyper-V Memory Manager Plugin
- **C# Wrapper:** hvlibdotnet.dll
- **PowerShell Version:** 7.0+
- **Required Privileges:** Administrator

---

## License

Copyright (c) All rights reserved  
Author: Arthur Khudyaev (www.x.com/gerhart_x)

---

## Contributing

For bug reports, feature requests, or contributions, please visit the [GitHub repository](https://github.com/gerhart01/Hyper-V-Tools/tree/main/HvlibPowershell).

---

**Last Updated:** December 2025  
**Module Version:** 1.3.0
