# ==============================================================================
# Hvlib-Examples.ps1
# Version: 2.0.0
# Description: Usage examples for Hvlib PowerShell Module
#
# HOW TO USE:
#   1. Place Hvlib-Config.json next to this script (or edit defaults below)
#   2. Run the entire script:  pwsh -NoProfile -File Hvlib-Examples.ps1
#   3. Or dot-source and run individual examples:
#        . .\Hvlib-Examples.ps1
#        Example-SymbolLookupDirect -VmName "Windows Server 2025"
#
# Each example function is self-contained: it opens a partition handle,
# demonstrates the API call(s), and closes the handle. You can copy any
# example function body directly into your own scripts.
#
# CONFIGURATION (priority: JSON file > Registry > hardcoded defaults):
#   JSON:     .\Hvlib-Config.json or C:\Projects\hvlib_launcher\Hvlib-Config.json
#   Registry: HKLM:\SOFTWARE\LiveCloudKd\params (values: DllPath, VmName)
#
# Change Log:
#   v1.0.0 - Sections 1-8: library, partitions, memory, processes, utilities.
#   v1.1.0 - Workflows: VM report, memory analysis, process introspection.
#   v1.3.0 - Sections 9-12: VM state, advanced memory, introspection, registers.
#   v1.5.0 - Section 13: Symbol operations.
#   v1.6.0 - External configuration (JSON + Registry).
#   v2.0.0 - Rewrite: self-contained examples, removed abstraction layers,
#            fixed bugs, consistent handle management, clean entry point.
# ==============================================================================

#requires -Version 7.0

#region Configuration

function Get-HvlibConfig {
    <#
    .SYNOPSIS
    Load configuration from JSON file or Windows Registry.
    .DESCRIPTION
    Searches for DllPath and VmName in JSON config files (script directory and
    C:\Projects\hvlib_launcher\) and then the Windows Registry at
    HKLM:\SOFTWARE\LiveCloudKd\params. First found value wins for each setting.
    .OUTPUTS
    [hashtable] Keys: DllPath, VmName, Source (sub-hashtable showing where each value came from).
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    $config = Get-HvlibConfig
    #>
    $config = @{ DllPath = $null; VmName = $null; Source = @{} }

    # 1. Try JSON config files
    $jsonPaths = @(
        (Join-Path $PSScriptRoot "Hvlib-Config.json")
        "C:\hvlib\Hvlib-Config.json"
    )
    foreach ($path in $jsonPaths) {
        if ((-not $config.DllPath -or -not $config.VmName) -and (Test-Path $path)) {
            try {
                $json = Get-Content $path -Raw | ConvertFrom-Json
                if (-not $config.DllPath -and $json.DllPath) {
                    $config.DllPath = $json.DllPath
                    $config.Source.DllPath = "JSON: $path"
                }
                if (-not $config.VmName -and $json.VmName) {
                    $config.VmName = $json.VmName
                    $config.Source.VmName = "JSON: $path"
                }
                Write-Host "Config loaded from: $path" -ForegroundColor Gray
            } catch {
                Write-Warning "Failed to parse JSON: $path ($_)"
            }
        }
    }

    # 2. Try Windows Registry
    $regPath = "HKLM:\SOFTWARE\LiveCloudKd\Parameters"
    if ((-not $config.DllPath -or -not $config.VmName) -and (Test-Path $regPath)) {
        try {
            $reg = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if (-not $config.DllPath -and $reg.DllPath) {
                $config.DllPath = $reg.DllPath
                $config.Source.DllPath = "Registry: $regPath"
            }
            if (-not $config.VmName -and $reg.VmName) {
                $config.VmName = $reg.VmName
                $config.Source.VmName = "Registry: $regPath"
            }
        } catch {
            Write-Warning "Failed to read registry: $_"
        }
    }

    return $config
}

# Hardcoded defaults (used when JSON and Registry have no values)
$script:DEFAULT_DLL_PATH = "C:\LiveCloudKd_release\hvlibdotnet.dll"
$script:DEFAULT_VM_NAME  = "Windows Server 2025"

# Module version must match Hvlib.psd1 ModuleVersion
$script:MODULE_VERSION = '1.4.0'
$script:SCRIPT_VERSION = '2.0.0'

#endregion

#region Initialization

function Initialize-HvlibExamples {
    <#
    .SYNOPSIS
    Import the Hvlib module and load the native DLL.
    .DESCRIPTION
    Imports the Hvlib PowerShell module with version validation, then loads hvlibdotnet.dll.
    Must be called once before running any example functions.
    .PARAMETER DllPath
    Path to hvlibdotnet.dll.
    .OUTPUTS
    [bool] $true if initialization succeeded.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Initialize-HvlibExamples -DllPath "C:\Distr\LiveCloudKd_public\hvlibdotnet.dll"
    #>
    param(
        [Parameter(Mandatory)]
        [string]$DllPath
    )

    $modules = Import-Module -FullyQualifiedName @{
        ModuleName = 'Hvlib'
        ModuleVersion = $script:MODULE_VERSION
    } -PassThru

    $module = @($modules) | Where-Object { $_.Name -eq 'Hvlib' } | Select-Object -First 1
    Write-Host "Hvlib module loaded: Version $($module.Version)" -ForegroundColor Green

    $result = Get-Hvlib -path_to_dll $DllPath
    if (-not $result) {
        Write-Error "Failed to load library from: $DllPath"
        return $false
    }

    return $true
}

#endregion

# ==============================================================================
#region Section 1: Library and Configuration
# ==============================================================================

function Example-GetHvlib {
    <#
    .SYNOPSIS
    Load the Hvlib native DLL.
    .DESCRIPTION
    Calls Get-Hvlib to load hvlibdotnet.dll from the specified path. Must be called
    before any other Hvlib operations.
    .PARAMETER DllPath
    Path to hvlibdotnet.dll.
    .OUTPUTS
    [bool] $true if the DLL was loaded successfully.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlib -DllPath "C:\Distr\LiveCloudKd_public\hvlibdotnet.dll"
    #>
    param([string]$DllPath = $script:DllPath)

    Write-Host "`n=== 1.1: Get-Hvlib - Load Library ===" -ForegroundColor Cyan

    $result = Get-Hvlib -path_to_dll $DllPath
    Write-Host "Result: $result"
    return $result
}

function Example-GetHvlibPreferredSettings {
    <#
    .SYNOPSIS
    Display current Hvlib configuration settings.
    .DESCRIPTION
    Calls Get-HvlibPreferredSettings to retrieve and display the active configuration
    including read/write methods, suspend method, log level, and freeze/pause flags.
    .OUTPUTS
    Settings object from Get-HvlibPreferredSettings, or $null on failure.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPreferredSettings
    #>

    Write-Host "`n=== 1.2: Get-HvlibPreferredSettings ===" -ForegroundColor Cyan

    $settings = Get-HvlibPreferredSettings
    if (-not $settings) {
        Write-Warning "Failed to retrieve configuration"
        return $null
    }

    Write-Host "  ReadMethod:    $($settings.ReadMethod)"
    Write-Host "  WriteMethod:   $($settings.WriteMethod)"
    Write-Host "  SuspendMethod: $($settings.SuspendMethod)"
    Write-Host "  LogLevel:      $($settings.LogLevel)"
    Write-Host "  ForceFreezeCPU: $($settings.ForceFreezeCPU)"
    Write-Host "  PausePartition: $($settings.PausePartition)"

    return $settings
}

#endregion

# ==============================================================================
#region Section 2: Partition Enumeration and Selection
# ==============================================================================

function Example-GetHvlibAllPartitions {
    <#
    .SYNOPSIS
    List all Hyper-V virtual machines.
    .DESCRIPTION
    Calls Get-HvlibAllPartitions to enumerate all running Hyper-V VMs and displays
    each VM's name and handle.
    .OUTPUTS
    VM array from Get-HvlibAllPartitions, or $null if none found.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibAllPartitions
    #>

    Write-Host "`n=== 2.1: Get-HvlibAllPartitions ===" -ForegroundColor Cyan

    $vms = Get-HvlibAllPartitions
    if (-not $vms -or $vms.Count -eq 0) {
        Write-Warning "No virtual machines found"
        return $null
    }

    Write-Host "Found $($vms.Count) VM(s):" -ForegroundColor Green
    foreach ($vm in $vms) {
        Write-Host "  $($vm.VMName) - Handle: 0x$($vm.VmHandle.ToString('X'))"
    }

    return $vms
}

function Example-GetHvlibPartition {
    <#
    .SYNOPSIS
    Get a partition handle by VM name.
    .DESCRIPTION
    Calls Get-HvlibPartition to open a handle to the specified virtual machine.
    The handle must be closed with Close-HvlibPartition when no longer needed.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [uint64] Partition handle, or $null if the VM was not found.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPartition -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 2.2: Get-HvlibPartition ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) {
        Write-Warning "VM '$VmName' not found"
        return $null
    }

    Write-Host "VM '$VmName' handle: 0x$($handle.ToString('X'))" -ForegroundColor Green
    Close-HvlibPartition -handle $handle
    return $handle
}

function Example-SelectHvlibPartition {
    <#
    .SYNOPSIS
    Select a partition by handle (alternative to Get-HvlibPartition).
    .DESCRIPTION
    Enumerates all partitions, takes the first VM handle, and calls Select-HvlibPartition
    to set it as the active partition. Useful when you already have a handle.
    .OUTPUTS
    [uint64] The selected partition handle.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SelectHvlibPartition
    #>

    Write-Host "`n=== 2.3: Select-HvlibPartition ===" -ForegroundColor Cyan

    $vms = Get-HvlibAllPartitions
    if (-not $vms -or $vms.Count -eq 0) {
        Write-Warning "No VMs found"
        return $null
    }

    $handle = $vms[0].VmHandle
    $result = Select-HvlibPartition -PartitionHandle $handle
    if ($result) {
        Write-Host "Selected partition: 0x$($handle.ToString('X'))" -ForegroundColor Green
    }

    return $handle
}

#endregion

# ==============================================================================
#region Section 3: Partition Information Retrieval
# ==============================================================================

function Example-GetHvlibPartitionName {
    <#
    .SYNOPSIS
    Get the friendly name of a VM.
    .DESCRIPTION
    Calls Get-HvlibPartitionName to retrieve the display name of the virtual machine
    from its partition handle.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [string] VM friendly name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPartitionName -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 3.1: Get-HvlibPartitionName ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $name = Get-HvlibPartitionName -PartitionHandle $handle
    Write-Host "  VM Name: $name" -ForegroundColor Green

    Close-HvlibPartition -handle $handle
    return $name
}

function Example-GetHvlibPartitionGuid {
    <#
    .SYNOPSIS
    Get the GUID of a VM.
    .DESCRIPTION
    Calls Get-HvlibPartitionGuid to retrieve the unique identifier of the virtual machine.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [string] VM GUID.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPartitionGuid -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 3.2: Get-HvlibPartitionGuid ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $guid = Get-HvlibPartitionGuid -PartitionHandle $handle
    Write-Host "  VM GUID: $guid" -ForegroundColor Green

    Close-HvlibPartition -handle $handle
    return $guid
}

function Example-GetHvlibPartitionId {
    <#
    .SYNOPSIS
    Get the partition ID of a VM.
    .DESCRIPTION
    Calls Get-HvlibPartitionId to retrieve the numeric Hyper-V partition identifier.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [int] Partition ID.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPartitionId -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 3.3: Get-HvlibPartitionId ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $id = Get-HvlibPartitionId -PartitionHandle $handle
    Write-Host "  Partition ID: $id" -ForegroundColor Green

    Close-HvlibPartition -handle $handle
    return $id
}

function Example-GetHvlibData2-KernelBase {
    <#
    .SYNOPSIS
    Get the kernel base address via Get-HvlibData2.
    .DESCRIPTION
    Calls Get-HvlibData2 with HvddKernelBase information class to retrieve
    the ntoskrnl base virtual address.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [uint64] Kernel base address.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibData2-KernelBase -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 3.4: Get-HvlibData2 - Kernel Base ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

    Write-Host "  Kernel Base: 0x$($kernelBase.ToString('X'))" -ForegroundColor Green

    Close-HvlibPartition -handle $handle
    return $kernelBase
}

function Example-GetHvlibData2-CpuCount {
    <#
    .SYNOPSIS
    Get the number of virtual CPUs in the VM.
    .DESCRIPTION
    Calls Get-HvlibData2 with HvddNumberOfCPU information class to retrieve
    the virtual processor count.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [int] Number of virtual CPUs.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibData2-CpuCount -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 3.5: Get-HvlibData2 - CPU Count ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $cpuCount = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddNumberOfCPU)

    Write-Host "  CPU Count: $cpuCount" -ForegroundColor Green

    Close-HvlibPartition -handle $handle
    return $cpuCount
}

function Example-GetHvlibData2-MultipleProperties {
    <#
    .SYNOPSIS
    Retrieve multiple system properties via Get-HvlibData2.
    .DESCRIPTION
    Queries kernel base, directory table base, max physical page, and CPU count in a
    single example using Get-HvlibData2 with different HVDD_INFORMATION_CLASS values.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Keys: KernelBase, DTB, MaxPage, CpuCount.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibData2-MultipleProperties -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 3.6: Get-HvlibData2 - Multiple Properties ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $IC = [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]

    $kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddKernelBase
    $dtb        = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddDirectoryTableBase
    $maxPage    = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddMmMaximumPhysicalPage
    $cpuCount   = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddNumberOfCPU

    $totalMB = [Math]::Round($maxPage * 0x1000 / 1MB)
    Write-Host "  Kernel Base:        0x$($kernelBase.ToString('X'))"
    Write-Host "  Directory Table:    0x$($dtb.ToString('X'))"
    Write-Host "  Max Physical Page:  0x$($maxPage.ToString('X')) (~${totalMB} MB)"
    Write-Host "  CPU Count:          $cpuCount"

    Close-HvlibPartition -handle $handle
    return @{ KernelBase=$kernelBase; DTB=$dtb; MaxPage=$maxPage; CpuCount=$cpuCount }
}

#endregion

# ==============================================================================
#region Section 4: Physical Memory Operations
# ==============================================================================

function Example-GetHvlibVmPhysicalMemory-Basic {
    <#
    .SYNOPSIS
    Read one page of physical memory at address 0x1000.
    .DESCRIPTION
    Calls Get-HvlibVmPhysicalMemory to read 4 KB (one page) starting at physical
    address 0x1000 and displays the first 64 bytes as a hex dump.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [byte[]] 4096 bytes of physical memory data.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVmPhysicalMemory-Basic -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 4.1: Get-HvlibVmPhysicalMemory - Basic ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
        -start_position 0x1000 -size 0x1000

    if ($data) {
        Write-Host "  Read $($data.Length) bytes from 0x1000" -ForegroundColor Green
        Write-Host "  First 64 bytes:"
        $data[0..63] | Format-Hex
    }

    Close-HvlibPartition -handle $handle
    return $data
}

function Example-GetHvlibVmPhysicalMemory-Address {
    <#
    .SYNOPSIS
    Read 256 bytes from a specific physical address.
    .DESCRIPTION
    Calls Get-HvlibVmPhysicalMemory with a user-specified physical address and reads
    0x100 bytes. Displays the result as a hex dump.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER PhysicalAddress
    Guest physical address to read from.
    .OUTPUTS
    [byte[]] Data read from the physical address.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVmPhysicalMemory-Address -VmName "Windows Server 2025" -PhysicalAddress 0x10000
    #>
    param(
        [string]$VmName = $script:VmName,
        [uint64]$PhysicalAddress = 0x10000
    )

    Write-Host "`n=== 4.2: Get-HvlibVmPhysicalMemory - Specific Address ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
        -start_position $PhysicalAddress -size 0x100

    if ($data) {
        Write-Host "  Read $($data.Length) bytes from 0x$($PhysicalAddress.ToString('X'))" -ForegroundColor Green
        $data | Format-Hex
    }

    Close-HvlibPartition -handle $handle
    return $data
}

function Example-SetHvlibVmPhysicalMemoryBytes {
    <#
    .SYNOPSIS
    Write bytes to physical memory and verify by reading back.
    .DESCRIPTION
    Writes a NOP sled + RET sequence to a safe low physical address (0x50000) using
    Set-HvlibVmPhysicalMemoryBytes, then reads the same address back to verify the write.
    WARNING: This actually writes to VM physical memory.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [bool] $true if the write succeeded.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibVmPhysicalMemoryBytes -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 4.3: Set-HvlibVmPhysicalMemoryBytes ===" -ForegroundColor Cyan
    Write-Host "  WARNING: This writes to VM physical memory!" -ForegroundColor Red

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    # NOP sled + RET at a safe low address
    $testAddress = [uint64]0x50000
    $testData = [byte[]]@(0x90, 0x90, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00)

    Write-Host "  Address: 0x$($testAddress.ToString('X'))"
    Write-Host "  Data:    $($testData -join ', ')"

    $result = Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $handle `
        -StartPosition $testAddress -Data $testData

    if ($result) {
        Write-Host "  Write successful" -ForegroundColor Green

        # Verify by reading back
        $verify = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
            -start_position $testAddress -size $testData.Length
        Write-Host "  Verification read:"
        $verify | Format-Hex
    }

    Close-HvlibPartition -handle $handle
    return $result
}

function Example-SetHvlibVmPhysicalMemory-FromFile {
    <#
    .SYNOPSIS
    Write data from a file to VM physical memory.
    .DESCRIPTION
    Reads a binary file and writes its contents to physical memory using
    Set-HvlibVmPhysicalMemory. Creates a small test file if the specified path
    does not exist.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER FilePath
    Path to the binary file to write. A test file is created if missing.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibVmPhysicalMemory-FromFile -VmName "Windows Server 2025"
    #>
    param(
        [string]$VmName = $script:VmName,
        [string]$FilePath = "$env:TEMP\hvlib_test_data.bin"
    )

    Write-Host "`n=== 4.4: Set-HvlibVmPhysicalMemory - From File ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    # Create a test file if it doesn't exist
    if (-not (Test-Path $FilePath)) {
        Write-Host "  Creating test file: $FilePath"
        [System.IO.File]::WriteAllBytes($FilePath, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))
    }

    Write-Host "  Writing data from: $FilePath"
    Set-HvlibVmPhysicalMemory -filename $FilePath -prtnHandle $handle

    Close-HvlibPartition -handle $handle
}

#endregion

# ==============================================================================
#region Section 5: Virtual Memory Operations
# ==============================================================================

function Example-GetHvlibVmVirtualMemory-KUserSharedData {
    <#
    .SYNOPSIS
    Read KUSER_SHARED_DATA from the well-known virtual address.
    .DESCRIPTION
    Reads 256 bytes from 0xFFFFF78000000000 using Get-HvlibVmVirtualMemory.
    KUSER_SHARED_DATA is a fixed kernel structure accessible at this address in all
    Windows versions.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [byte[]] First 256 bytes of the KUSER_SHARED_DATA structure.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVmVirtualMemory-KUserSharedData -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 5.1: Get-HvlibVmVirtualMemory - KUSER_SHARED_DATA ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    # KUSER_SHARED_DATA is always at this well-known virtual address
    $kuserAddr = [System.Convert]::ToUInt64("FFFFF78000000000", 16)

    $data = Get-HvlibVmVirtualMemory -prtnHandle $handle `
        -start_position $kuserAddr -size 0x100

    if ($data) {
        Write-Host "  Read $($data.Length) bytes from 0xFFFFF78000000000" -ForegroundColor Green
        Write-Host "  First 64 bytes:"
        $data[0..63] | Format-Hex
    }

    Close-HvlibPartition -handle $handle
    return $data
}

function Example-GetHvlibVmVirtualMemory-KernelAddress {
    <#
    .SYNOPSIS
    Read and verify the kernel PE header via virtual memory.
    .DESCRIPTION
    Gets the kernel base address via Get-HvlibData2, then reads 512 bytes from that VA
    using Get-HvlibVmVirtualMemory. Validates the MZ signature at offset 0.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [byte[]] PE header bytes, or $null on failure.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVmVirtualMemory-KernelAddress -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 5.2: Get-HvlibVmVirtualMemory - Kernel PE Header ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

    Write-Host "  Kernel Base: 0x$($kernelBase.ToString('X'))"

    $data = Get-HvlibVmVirtualMemory -prtnHandle $handle `
        -start_position $kernelBase -size 0x200

    if ($data) {
        Write-Host "  Read PE header ($($data.Length) bytes)" -ForegroundColor Green
        if ($data.Length -ge 2 -and $data[0] -eq 0x4D -and $data[1] -eq 0x5A) {
            Write-Host "  Valid PE header (MZ signature)" -ForegroundColor Green
        }
    }

    Close-HvlibPartition -handle $handle
    return $data
}

function Example-SetHvlibVmVirtualMemoryBytes {
    <#
    .SYNOPSIS
    Demonstrate virtual memory byte write (skipped for safety).
    .DESCRIPTION
    Shows the pattern for writing bytes to virtual memory using Set-HvlibVmVirtualMemoryBytes.
    The actual call is not executed to avoid corrupting the VM.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibVmVirtualMemoryBytes -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 5.3: Set-HvlibVmVirtualMemoryBytes ===" -ForegroundColor Cyan
    Write-Host "  This is a demonstration only!" -ForegroundColor Red

    # In a real scenario, you would:
    # $patch = [byte[]]@(0x90, 0x90, 0x90)  # NOP sled
    # Set-HvlibVmVirtualMemoryBytes -PartitionHandle $handle `
    #     -StartPosition $targetAddress -Data $patch

    Write-Host "  Skipped actual write for safety" -ForegroundColor Yellow
}

function Example-SetHvlibVmVirtualMemory-FromFile {
    <#
    .SYNOPSIS
    Demonstrate virtual memory write from file (skipped for safety).
    .DESCRIPTION
    Shows the pattern for writing file contents to virtual memory using
    Set-HvlibVmVirtualMemory. The actual call is not executed to avoid corrupting the VM.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibVmVirtualMemory-FromFile -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 5.4: Set-HvlibVmVirtualMemory - From File ===" -ForegroundColor Cyan
    Write-Host "  This is a demonstration only!" -ForegroundColor Red

    # In a real scenario, you would:
    # Set-HvlibVmVirtualMemory -filename $FilePath -prtnHandle $handle

    Write-Host "  Skipped actual write for safety" -ForegroundColor Yellow
}

#endregion

# ==============================================================================
#region Section 6: Process and System Information
# ==============================================================================

function Example-GetHvlibProcessesList {
    <#
    .SYNOPSIS
    Enumerate guest OS processes.
    .DESCRIPTION
    Calls Get-HvlibProcessesList to retrieve a list of process IDs running inside the VM.
    The first entry (index 0) is reserved; actual processes start at index 1.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [uint64[]] Array of process identifiers.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibProcessesList -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 6.1: Get-HvlibProcessesList ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $processes = Get-HvlibProcessesList -PartitionHandle $handle

    if ($processes) {
        $count = $processes.Length - 1
        Write-Host "  Found $count process(es)" -ForegroundColor Green
        Write-Host "  First 5 entries:"
        for ($i = 1; $i -lt [Math]::Min(6, $processes.Length); $i++) {
            Write-Host "    Process[$i]: 0x$($processes[$i].ToString('X8'))"
        }
    }

    Close-HvlibPartition -handle $handle
    return $processes
}

function Example-GetHvlibCr3-Kernel {
    <#
    .SYNOPSIS
    Get the CR3 (page directory base) for the kernel process (PID 4).
    .DESCRIPTION
    Calls Get-HvlibCr3 with PID 4 (System process) to retrieve the kernel page table base.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [uint64] Kernel CR3 value.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibCr3-Kernel -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 6.2: Get-HvlibCr3 - Kernel ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId 4
    Write-Host "  Kernel CR3 (PID 4): 0x$($cr3.ToString('X'))" -ForegroundColor Green

    Close-HvlibPartition -handle $handle
    return $cr3
}

function Example-GetHvlibCr3-Process {
    <#
    .SYNOPSIS
    Get the CR3 (page directory base) for a specific process by PID.
    .DESCRIPTION
    Calls Get-HvlibCr3 with the specified process ID to retrieve its page table base address.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER ProcessId
    Guest OS process ID to look up.
    .OUTPUTS
    [uint64] CR3 value for the process.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibCr3-Process -VmName "Windows Server 2025" -ProcessId 1234
    #>
    param(
        [string]$VmName = $script:VmName,
        [uint64]$ProcessId = 1234
    )

    Write-Host "`n=== 6.3: Get-HvlibCr3 - Process ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $ProcessId
    if ($cr3) {
        Write-Host "  CR3 for PID $ProcessId : 0x$($cr3.ToString('X'))" -ForegroundColor Green
    } else {
        Write-Warning "  Process $ProcessId not found"
    }

    Close-HvlibPartition -handle $handle
    return $cr3
}

#endregion

# ==============================================================================
#region Section 7: Resource Management
# ==============================================================================

function Example-CloseHvlibPartition {
    <#
    .SYNOPSIS
    Close a single partition handle.
    .DESCRIPTION
    Opens a partition handle for the specified VM, then closes it with Close-HvlibPartition.
    Demonstrates proper resource cleanup.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-CloseHvlibPartition -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 7.1: Close-HvlibPartition ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return }

    Write-Host "  Closing handle: 0x$($handle.ToString('X'))"
    Close-HvlibPartition -handle $handle
    Write-Host "  Done" -ForegroundColor Green
}

function Example-CloseHvlibPartitions {
    <#
    .SYNOPSIS
    Close all open partition handles.
    .DESCRIPTION
    Calls Close-HvlibPartitions to release all currently open Hyper-V partition handles.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-CloseHvlibPartitions
    #>

    Write-Host "`n=== 7.2: Close-HvlibPartitions ===" -ForegroundColor Cyan

    Close-HvlibPartitions
    Write-Host "  All partitions closed" -ForegroundColor Green
}

#endregion

# ==============================================================================
#region Section 8: Utility Functions
# ==============================================================================

function Example-GetHexValue {
    <#
    .SYNOPSIS
    Convert decimal values to hexadecimal using Get-HexValue.
    .DESCRIPTION
    Demonstrates the Get-HexValue utility function by converting several test values
    (including 0, 0x1000, 65536, and UInt64.MaxValue) to their hex representations.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHexValue
    #>

    Write-Host "`n=== 8.1: Get-HexValue ===" -ForegroundColor Cyan

    $testValues = @(0x1000, 65536, 0, [uint64]::MaxValue)

    foreach ($num in $testValues) {
        $hex = Get-HexValue -num $num
        Write-Host "  Decimal: $num => Hex: 0x$hex" -ForegroundColor Green
    }
}

#endregion

# ==============================================================================
#region Section 9: VM State Control (v1.3.0)
# ==============================================================================

function Example-SuspendHvlibVm-PowerShell {
    <#
    .SYNOPSIS
    Suspend a VM using the default PowerShell method.
    .DESCRIPTION
    Calls Suspend-HvlibVm with default parameters to pause the VM for analysis.
    The VM must be resumed afterwards to continue execution.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [bool] $true if the VM was suspended successfully.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SuspendHvlibVm-PowerShell -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 9.1: Suspend-HvlibVm - PowerShell Method ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $result = Suspend-HvlibVm -PartitionHandle $handle
    if ($result) {
        Write-Host "  VM suspended" -ForegroundColor Green
        Write-Host "  VM is now paused for analysis"
    } else {
        Write-Warning "  Failed to suspend VM"
    }

    Close-HvlibPartition -handle $handle
    return $result
}

function Example-SuspendHvlibVm-RegisterWrite {
    <#
    .SYNOPSIS
    Suspend a VM using the register write method.
    .DESCRIPTION
    Calls Suspend-HvlibVm with the SuspendResumeWriteSpecRegister method, which suspends
    the VM by writing to a special register instead of the default PowerShell method.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [bool] $true if the VM was suspended successfully.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SuspendHvlibVm-RegisterWrite -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 9.2: Suspend-HvlibVm - Register Write Method ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $method = [Hvlibdotnet.Hvlib+SUSPEND_RESUME_METHOD]::SuspendResumeWriteSpecRegister
    $result = Suspend-HvlibVm -PartitionHandle $handle -Method $method

    if ($result) {
        Write-Host "  Suspended via register write method" -ForegroundColor Green
    }

    Close-HvlibPartition -handle $handle
    return $result
}

function Example-ResumeHvlibVm {
    <#
    .SYNOPSIS
    Resume a suspended VM.
    .DESCRIPTION
    Calls Resume-HvlibVm to resume execution of a previously suspended virtual machine.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [bool] $true if the VM was resumed successfully.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-ResumeHvlibVm -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 9.3: Resume-HvlibVm ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $result = Resume-HvlibVm -PartitionHandle $handle
    if ($result) {
        Write-Host "  VM resumed" -ForegroundColor Green
    } else {
        Write-Warning "  Failed to resume VM"
    }

    Close-HvlibPartition -handle $handle
    return $result
}

function Example-SafeMemoryAnalysis {
    <#
    .SYNOPSIS
    Read the kernel PE header while the VM is suspended for a consistent snapshot.
    .DESCRIPTION
    Suspends the VM, reads the kernel base address, then reads 4 KB of the kernel PE header
    via Get-HvlibVmVirtualMemory. Validates the MZ signature and resumes the VM in a
    try/finally block to ensure safe cleanup.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [byte[]] Kernel PE header bytes, or $null on failure.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SafeMemoryAnalysis -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 9.4: Safe Memory Analysis with Suspend/Resume ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) {
        Write-Warning "  Failed to suspend VM"
        Close-HvlibPartition -handle $handle
        return $null
    }

    try {
        # 1. Get kernel base address
        $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
        Write-Host "  1. Kernel Base: 0x$($kernelBase.ToString('X'))"

        # 2. Read PE header
        $pe = Get-HvlibVmVirtualMemory -prtnHandle $handle `
            -start_position $kernelBase -size 0x1000
        if ($pe -and $pe[0] -eq 0x4D -and $pe[1] -eq 0x5A) {
            Write-Host "  2. PE Signature: MZ (valid)" -ForegroundColor Green
            Write-Host "  3. First 64 bytes:"
            $pe[0..63] | Format-Hex | Select-Object -First 4
        }
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Write-Host "  VM resumed"
    }

    Close-HvlibPartition -handle $handle
    return $pe
}

#endregion

# ==============================================================================
#region Section 10: Advanced Memory Operations (v1.3.0)
# ==============================================================================

function Example-GetHvlibPhysicalAddress-KernelVA {
    <#
    .SYNOPSIS
    Translate the kernel base virtual address to a physical address.
    .DESCRIPTION
    Gets the kernel base VA via Get-HvlibData2, then translates it to a PA using
    Get-HvlibPhysicalAddress. Verifies by reading 16 bytes from the resulting PA.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [uint64] Physical address of the kernel base.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPhysicalAddress-KernelVA -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 10.1: Get-HvlibPhysicalAddress - Kernel VA ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelVa = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

    Write-Host "  VA: 0x$($kernelVa.ToString('X'))"

    $kernelPa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $kernelVa

    if ($kernelPa -ne 0) {
        Write-Host "  PA: 0x$($kernelPa.ToString('X'))" -ForegroundColor Green

        # Read from the translated physical address to verify
        $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
            -start_position $kernelPa -size 0x10
        if ($data) {
            Write-Host "  First 16 bytes from PA:"
            Write-Host "  $($data[0..15] | ForEach-Object { $_.ToString('X2') } | Join-String -Separator ' ')"
        }
    } else {
        Write-Warning "  Address translation failed"
    }

    Close-HvlibPartition -handle $handle
    return $kernelPa
}

function Example-GetHvlibPhysicalAddress-UserVA {
    <#
    .SYNOPSIS
    Translate a user-mode virtual address to a physical address.
    .DESCRIPTION
    Calls Get-HvlibPhysicalAddress for a user-space VA. Translation may fail if the
    page is not present in the current process context.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER UserVirtualAddress
    User-mode virtual address to translate.
    .OUTPUTS
    [uint64] Physical address, or 0 if translation failed.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPhysicalAddress-UserVA -VmName "Windows Server 2025"
    #>
    param(
        [string]$VmName = $script:VmName,
        [uint64]$UserVirtualAddress = 0x00007FF000000000
    )

    Write-Host "`n=== 10.2: Get-HvlibPhysicalAddress - User VA ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    Write-Host "  VA: 0x$($UserVirtualAddress.ToString('X'))"

    $pa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $UserVirtualAddress

    if ($pa -ne 0) {
        Write-Host "  PA: 0x$($pa.ToString('X'))" -ForegroundColor Green
    } else {
        Write-Host "  Translation failed (page may not be present)" -ForegroundColor Yellow
    }

    Close-HvlibPartition -handle $handle
    return $pa
}

function Example-GetHvlibPhysicalAddress-Batch {
    <#
    .SYNOPSIS
    Translate multiple virtual addresses to physical addresses.
    .DESCRIPTION
    Translates the kernel base and two offsets from it using Get-HvlibPhysicalAddress.
    Displays results in a formatted table.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibPhysicalAddress-Batch -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 10.3: Get-HvlibPhysicalAddress - Batch Translation ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

    $addresses = @(
        @{ Name = "Kernel Base";     VA = $kernelBase }
        @{ Name = "Kernel +0x1000";  VA = $kernelBase + 0x1000 }
        @{ Name = "Kernel +0x10000"; VA = $kernelBase + 0x10000 }
    )

    Write-Host ("  {0,-20} {1,-18} {2}" -f "Name", "Virtual Address", "Physical Address") -ForegroundColor Cyan
    Write-Host ("  " + '-' * 58)

    foreach ($addr in $addresses) {
        $pa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $addr.VA
        $paStr = if ($pa -ne 0) { "0x$($pa.ToString('X'))" } else { "N/A" }
        Write-Host ("  {0,-20} 0x{1:X16} {2}" -f $addr.Name, $addr.VA, $paStr)
    }

    Close-HvlibPartition -handle $handle
}

function Example-SetHvlibPartitionData {
    <#
    .SYNOPSIS
    Set partition data using an advanced Hvlib operation.
    .DESCRIPTION
    Calls Set-HvlibPartitionData with HvddSetMemoryBlock information class.
    This is an advanced operation that modifies partition-level data. Use with caution.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    Result value from Set-HvlibPartitionData, or $null on failure.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibPartitionData -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 10.4: Set-HvlibPartitionData ===" -ForegroundColor Cyan
    Write-Host "  WARNING: Advanced operation - use with caution!" -ForegroundColor Yellow

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $result = Set-HvlibPartitionData `
        -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddSetMemoryBlock) `
        -Information 1

    if ($result -ne 0) {
        Write-Host "  Partition data set: $result" -ForegroundColor Green
    } else {
        Write-Warning "  Failed to set partition data"
    }

    Close-HvlibPartition -handle $handle
    return $result
}

#endregion

# ==============================================================================
#region Section 11: VM Introspection (v1.3.0)
# ==============================================================================

function Example-GetHvlibMachineType {
    <#
    .SYNOPSIS
    Detect the VM architecture (x64 or x86).
    .DESCRIPTION
    Calls Get-HvlibMachineType to determine whether the VM runs in 64-bit (MACHINE_AMD64)
    or 32-bit (MACHINE_X86) mode.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [string] Machine type string (e.g., "MACHINE_AMD64").
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibMachineType -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 11.1: Get-HvlibMachineType ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $machineType = Get-HvlibMachineType -PartitionHandle $handle

    $arch = switch ($machineType) {
        'MACHINE_AMD64' { "64-bit (x64)" }
        'MACHINE_X86'   { "32-bit (x86)" }
        default         { "Unknown: $machineType" }
    }
    Write-Host "  Machine Type: $machineType" -ForegroundColor Green
    Write-Host "  Architecture: $arch"

    Close-HvlibPartition -handle $handle
    return $machineType
}

function Example-GetHvlibMachineType-Report {
    <#
    .SYNOPSIS
    Print an architecture report for all running VMs.
    .DESCRIPTION
    Enumerates all partitions and displays each VM's architecture (x64/x86) using
    Get-HvlibMachineType. Outputs a formatted table.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibMachineType-Report
    #>

    Write-Host "`n=== 11.2: Get-HvlibMachineType - All VMs Report ===" -ForegroundColor Cyan

    $vms = Get-HvlibAllPartitions
    if (-not $vms -or $vms.Count -eq 0) { Write-Warning "No VMs found"; return $null }

    Write-Host ("  {0,-30} {1}" -f "VM Name", "Architecture") -ForegroundColor Cyan
    Write-Host ("  " + '-' * 50)

    foreach ($vm in $vms) {
        Select-HvlibPartition -PartitionHandle $vm.VmHandle | Out-Null
        $type = Get-HvlibMachineType -PartitionHandle $vm.VmHandle
        $arch = if ($type -eq 'MACHINE_AMD64') { "64-bit (x64)" } else { "32-bit (x86)" }
        Write-Host ("  {0,-30} {1}" -f $vm.VMName, $arch)
        Close-HvlibPartition -handle $vm.VmHandle
    }
}

function Example-GetHvlibCurrentVtl-KernelBase {
    <#
    .SYNOPSIS
    Check the VTL level for the kernel base address.
    .DESCRIPTION
    Retrieves the kernel base via Get-HvlibData2 and queries its VTL level using
    Get-HvlibCurrentVtl. VTL0 = normal kernel, VTL1 = secure kernel (VBS enabled).
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [string] VTL level string (e.g., "Vtl0", "Vtl1").
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibCurrentVtl-KernelBase -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 11.3: Get-HvlibCurrentVtl - Kernel Base ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

    Write-Host "  Kernel Base: 0x$($kernelBase.ToString('X'))"

    $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $kernelBase

    switch ($vtl) {
        'Vtl0' { Write-Host "  VTL: 0 (Normal Kernel)" -ForegroundColor Green }
        'Vtl1' { Write-Host "  VTL: 1 (Secure Kernel - VBS enabled)" -ForegroundColor Yellow }
        default { Write-Host "  VTL: $vtl" }
    }

    Close-HvlibPartition -handle $handle
    return $vtl
}

function Example-GetHvlibCurrentVtl-VBSDetection {
    <#
    .SYNOPSIS
    Detect Virtualization-Based Security by checking VTL levels.
    .DESCRIPTION
    Checks VTL levels at the kernel base and an offset using Get-HvlibCurrentVtl.
    If any address returns VTL1, VBS (Secure Kernel) is active.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [bool] $true if VBS is detected (VTL1 present).
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibCurrentVtl-VBSDetection -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 11.4: Get-HvlibCurrentVtl - VBS Detection ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

    $addresses = @(
        @{ Name = "Kernel Base";      Addr = $kernelBase }
        @{ Name = "Kernel +0x100000"; Addr = $kernelBase + 0x100000 }
    )

    $hasVtl1 = $false
    foreach ($addr in $addresses) {
        $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $addr.Addr
        Write-Host "  $($addr.Name): $vtl"
        if ($vtl -eq 'Vtl1') { $hasVtl1 = $true }
    }

    if ($hasVtl1) {
        Write-Host "  VBS is ENABLED (Secure Kernel detected)" -ForegroundColor Green
    } else {
        Write-Host "  VBS is NOT detected (VTL0 only)" -ForegroundColor Yellow
    }

    Close-HvlibPartition -handle $handle
    return $hasVtl1
}

#endregion

# ==============================================================================
#region Section 12: CPU Register Access (v1.3.0)
# ==============================================================================

function Example-GetHvlibVpRegister-RIP {
    <#
    .SYNOPSIS
    Read the instruction pointer (RIP) register from VP #0.
    .DESCRIPTION
    Suspends the VM and reads the RIP register (code 0x20000) via Get-HvlibVpRegister.
    Shows the current execution address on virtual processor 0.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [uint64] Current RIP value.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVpRegister-RIP -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 12.1: Get-HvlibVpRegister - RIP ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) { Write-Warning "Failed to suspend"; Close-HvlibPartition -handle $handle; return $null }

    try {
        $rip = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 `
            -RegisterCode 0x00020000).Reg64    # 0x20000 = RIP

        Write-Host "  RIP: 0x$($rip.ToString('X16'))" -ForegroundColor Green
        Write-Host "  Current execution address on CPU #0"
        return $rip
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Close-HvlibPartition -handle $handle
    }
}

function Example-GetHvlibVpRegister-GPRs {
    <#
    .SYNOPSIS
    Read all general purpose registers from VP #0.
    .DESCRIPTION
    Suspends the VM and reads RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI via
    Get-HvlibVpRegister with the corresponding register codes.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Register name to 64-bit value mapping.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVpRegister-GPRs -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 12.2: Get-HvlibVpRegister - General Purpose Registers ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) { Write-Warning "Failed to suspend"; Close-HvlibPartition -handle $handle; return $null }

    try {
        # Register codes: RAX=0x20003 RCX=0x20004 RDX=0x20005 RBX=0x20006
        #                  RSP=0x20002 RBP=0x20007 RSI=0x20008 RDI=0x20009
        $regs = @(
            @{ Name='RAX'; Code=0x00020003 }
            @{ Name='RCX'; Code=0x00020004 }
            @{ Name='RDX'; Code=0x00020005 }
            @{ Name='RBX'; Code=0x00020006 }
            @{ Name='RSP'; Code=0x00020002 }
            @{ Name='RBP'; Code=0x00020007 }
            @{ Name='RSI'; Code=0x00020008 }
            @{ Name='RDI'; Code=0x00020009 }
        )

        Write-Host ("  {0,-6} {1}" -f "Reg", "Value") -ForegroundColor Cyan
        Write-Host ("  " + '-' * 26)

        $result = @{}
        foreach ($reg in $regs) {
            $val = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 `
                -RegisterCode $reg.Code).Reg64
            $result[$reg.Name] = $val
            Write-Host ("  {0,-6} 0x{1:X16}" -f $reg.Name, $val)
        }

        return $result
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Close-HvlibPartition -handle $handle
    }
}

function Example-GetHvlibVpRegister-ControlRegisters {
    <#
    .SYNOPSIS
    Read control registers CR0, CR2, CR3, CR4 from VP #0.
    .DESCRIPTION
    Suspends the VM and reads the four control registers via Get-HvlibVpRegister.
    CR0 holds system flags, CR2 the page fault address, CR3 the page directory base,
    and CR4 control extensions.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Register name to value mapping (CR0, CR2, CR3, CR4).
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVpRegister-ControlRegisters -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 12.3: Get-HvlibVpRegister - Control Registers ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) { Write-Warning "Failed to suspend"; Close-HvlibPartition -handle $handle; return $null }

    try {
        $regs = @(
            @{ Name='CR0'; Code=0x00020012; Desc='System flags' }
            @{ Name='CR2'; Code=0x00020013; Desc='Page fault linear address' }
            @{ Name='CR3'; Code=0x00020014; Desc='Page directory base' }
            @{ Name='CR4'; Code=0x00020015; Desc='Control extensions' }
        )

        Write-Host ("  {0,-6} {1,-18} {2}" -f "Reg", "Value", "Description") -ForegroundColor Cyan
        Write-Host ("  " + '-' * 55)

        $result = @{}
        foreach ($reg in $regs) {
            $val = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 `
                -RegisterCode $reg.Code).Reg64
            $result[$reg.Name] = $val
            Write-Host ("  {0,-6} 0x{1:X16} {2}" -f $reg.Name, $val, $reg.Desc)
        }

        return $result
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Close-HvlibPartition -handle $handle
    }
}

function Example-GetHvlibVpRegister-FullContext {
    <#
    .SYNOPSIS
    Read the complete CPU context from VP #0.
    .DESCRIPTION
    Suspends the VM and reads special registers (RIP, RFLAGS), all general purpose
    registers (RAX-RDI), and control registers (CR0-CR4) via Get-HvlibVpRegister.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Contains RIP and RFLAGS values.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibVpRegister-FullContext -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 12.4: Get-HvlibVpRegister - Full CPU Context ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) { Write-Warning "Failed to suspend"; Close-HvlibPartition -handle $handle; return $null }

    try {
        # Special registers
        Write-Host "`n  [ Special Registers ]" -ForegroundColor Cyan
        $rip    = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000).Reg64
        $rflags = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020001).Reg64
        Write-Host ("  RIP:    0x{0:X16}" -f $rip)
        Write-Host ("  RFLAGS: 0x{0:X16}" -f $rflags)

        # General purpose registers
        Write-Host "`n  [ General Purpose ]" -ForegroundColor Cyan
        foreach ($r in @(
            @{N='RAX';C=0x20003}, @{N='RCX';C=0x20004}, @{N='RDX';C=0x20005}, @{N='RBX';C=0x20006},
            @{N='RSP';C=0x20002}, @{N='RBP';C=0x20007}, @{N='RSI';C=0x20008}, @{N='RDI';C=0x20009}
        )) {
            $v = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode $r.C).Reg64
            Write-Host ("  {0,-6} 0x{1:X16}" -f "$($r.N):", $v)
        }

        # Control registers
        Write-Host "`n  [ Control Registers ]" -ForegroundColor Cyan
        foreach ($r in @(
            @{N='CR0';C=0x20012}, @{N='CR2';C=0x20013}, @{N='CR3';C=0x20014}, @{N='CR4';C=0x20015}
        )) {
            $v = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode $r.C).Reg64
            Write-Host ("  {0,-6} 0x{1:X16}" -f "$($r.N):", $v)
        }

        return @{ RIP = $rip; RFLAGS = $rflags }
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Close-HvlibPartition -handle $handle
    }
}

function Example-SetHvlibVpRegister-RIP {
    <#
    .SYNOPSIS
    Demonstrate how to modify the RIP register (not actually executed).
    .DESCRIPTION
    Shows the pattern for writing a new value to RIP via Set-HvlibVpRegister. The actual
    write is commented out for safety. Requires the VM to be suspended first.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibVpRegister-RIP -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 12.5: Set-HvlibVpRegister - RIP (Demonstration) ===" -ForegroundColor Cyan
    Write-Host "  WARNING: Modifying RIP changes execution flow!" -ForegroundColor Red

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) { Write-Warning "Failed to suspend"; Close-HvlibPartition -handle $handle; return $null }

    try {
        $currentRip = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 `
            -RegisterCode 0x00020000).Reg64    # RIP
        Write-Host "  Current RIP: 0x$($currentRip.ToString('X16'))"

        # To actually set RIP, you would:
        # $newRip = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
        # $newRip.Reg64 = $currentRip + 0x10
        # Set-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 `
        #     -RegisterCode 0x00020000 -RegisterValue $newRip

        Write-Host "  NOT actually writing (demonstration only)" -ForegroundColor Yellow
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Close-HvlibPartition -handle $handle
    }
}

function Example-SetHvlibVpRegister-Breakpoint {
    <#
    .SYNOPSIS
    Set a hardware breakpoint via the DR0 debug register.
    .DESCRIPTION
    Suspends the VM, writes a target address to DR0 using Set-HvlibVpRegister (register
    code 0x20017). Note that DR7 must also be configured to activate the breakpoint.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [bool] $true if DR0 was set successfully.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-SetHvlibVpRegister-Breakpoint -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 12.6: Set-HvlibVpRegister - Hardware Breakpoint ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if (-not $suspended) { Write-Warning "Failed to suspend"; Close-HvlibPartition -handle $handle; return $null }

    try {
        $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)

        $bpAddr = $kernelBase + 0x1000
        Write-Host "  Setting DR0 to: 0x$($bpAddr.ToString('X'))"

        $dr0 = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
        $dr0.Reg64 = $bpAddr

        $result = Set-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 `
            -RegisterCode 0x00020017 -RegisterValue $dr0    # 0x20017 = DR0

        if ($result) {
            Write-Host "  DR0 set successfully" -ForegroundColor Green
            Write-Host "  Note: DR7 must also be configured to enable the breakpoint" -ForegroundColor Yellow
        }

        return $result
    } finally {
        Resume-HvlibVm -PartitionHandle $handle | Out-Null
        Close-HvlibPartition -handle $handle
    }
}

#endregion

# ==============================================================================
#region Section 13: Symbol Operations (v1.5.0)
# ==============================================================================

function Example-GetHvlibSymbolAddress {
    <#
    .SYNOPSIS
    Resolve a symbol address by name using full enumeration.
    .DESCRIPTION
    Calls Get-HvlibSymbolAddress which uses GetAllSymbolsForModule internally to enumerate
    all symbols then filters by name. Slower than direct lookup but works without
    SdkSymGetSymbolAddress2 support. Accepts "module!SymbolName" format.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER SymbolFullName
    Symbol in "module!name" format (e.g., "nt!MmCopyVirtualMemory").
    .OUTPUTS
    [uint64] Symbol address, or $null on failure.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibSymbolAddress -VmName "Windows Server 2025" -SymbolFullName "nt!PsGetProcessPeb"
    #>
    param(
        [string]$VmName = $script:VmName,
        [string]$SymbolFullName = "nt!MmCopyVirtualMemory"
    )

    Write-Host "`n=== 13.1: Get-HvlibSymbolAddress ===" -ForegroundColor Cyan
    Write-Host "  Method: full symbol enumeration + filter"

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    Write-Host "  Resolving: $SymbolFullName"

    $addr = Get-HvlibSymbolAddress $handle $SymbolFullName

    if ($addr -and $addr -ne 0) {
        Write-Host "  Address: 0x$($addr.ToString('X'))" -ForegroundColor Green
    } else {
        Write-Warning "  Symbol '$SymbolFullName' not found"
    }

    Close-HvlibPartition -handle $handle
    return $addr
}

function Example-GetHvlibSymbolAddress-Multiple {
    <#
    .SYNOPSIS
    Resolve multiple symbols from different modules.
    .DESCRIPTION
    Calls Get-HvlibSymbolAddress for several well-known symbols across winhv and nt modules.
    Uses the full enumeration method internally (GetAllSymbolsForModule + filter).
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Symbol name to address mapping.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibSymbolAddress-Multiple -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 13.2: Get-HvlibSymbolAddress - Multiple Symbols ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $symbols = @(
        "winhv!WinHvAllocateOverlayPages"
        "winhv!WinHvpDllLoadSuccessful"
        "nt!MmCopyVirtualMemory"
        "nt!PsGetProcessPeb"
    )

    Write-Host ("  {0,-45} {1}" -f "Symbol", "Address") -ForegroundColor Cyan
    Write-Host ("  " + '-' * 65)

    $results = @{}
    foreach ($sym in $symbols) {
        $addr = Get-HvlibSymbolAddress $handle $sym
        $addrStr = if ($addr -and $addr -ne 0) { "0x$($addr.ToString('X'))" } else { "Not found" }
        Write-Host ("  {0,-45} {1}" -f $sym, $addrStr)
        $results[$sym] = $addr
    }

    Close-HvlibPartition -handle $handle
    return $results
}

function Example-GetHvlibSymbolAddressDirect {
    <#
    .SYNOPSIS
    Resolve symbols via direct SDK lookup.
    .DESCRIPTION
    Uses Get-HvlibSymbolAddressDirect (SdkSymGetSymbolAddress2) which performs a direct
    symbol lookup by module and name. Faster than full enumeration. Resolves multiple
    well-known symbols and returns their addresses.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Symbol name to address mapping.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibSymbolAddressDirect -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 13.2b: Get-HvlibSymbolAddressDirect ===" -ForegroundColor Cyan
    Write-Host "  Method: direct SDK lookup (SdkSymGetSymbolAddress2)"

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $symbols = @(
        "winhv!WinHvAllocateOverlayPages"
        "winhv!WinHvpDllLoadSuccessful"
        "nt!MmCopyVirtualMemory"
        "nt!PsGetProcessPeb"
    )

    Write-Host ("  {0,-45} {1}" -f "Symbol", "Address") -ForegroundColor Cyan
    Write-Host ("  " + '-' * 65)

    $results = @{}
    foreach ($sym in $symbols) {
        $addr = Get-HvlibSymbolAddressDirect $handle $sym
        $addrStr = if ($addr -and $addr -ne 0) { "0x$($addr.ToString('X'))" } else { "Not found" }
        Write-Host ("  {0,-45} {1}" -f $sym, $addrStr)
        $results[$sym] = $addr
    }

    Close-HvlibPartition -handle $handle
    return $results
}

function Example-GetHvlibAllSymbols {
    <#
    .SYNOPSIS
    Enumerate all symbols in a driver module.
    .DESCRIPTION
    Calls Get-HvlibAllSymbols (SdkSymEnumAllSymbols) to retrieve the full symbol list
    for the specified driver. Displays the first 10 symbols with name, address, and size.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER DriverName
    Driver module name (e.g., "winhv", "ntoskrnl").
    .OUTPUTS
    [SYMBOL_INFO_PWSH[]] Array of symbol info objects.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibAllSymbols -VmName "Windows Server 2025" -DriverName "winhv"
    #>
    param(
        [string]$VmName = $script:VmName,
        [string]$DriverName = "winhv"
    )

    Write-Host "`n=== 13.3: Get-HvlibAllSymbols ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    Write-Host "  Module: $DriverName"
    $symbols = Get-HvlibAllSymbols $handle $DriverName

    if ($symbols -and $symbols.Count -gt 0) {
        Write-Host "  Total: $($symbols.Count) symbols" -ForegroundColor Green

        Write-Host "`n  First 10:" -ForegroundColor Cyan
        Write-Host ("  {0,-50} {1,-18} {2}" -f "Name", "Address", "Size")
        Write-Host ("  " + '-' * 76)

        $symbols | Select-Object -First 10 | ForEach-Object {
            Write-Host ("  {0,-50} {1,-18} {2}" -f $_.Name, $_.Address, $_.Size)
        }
    } else {
        Write-Warning "  No symbols found for '$DriverName'"
    }

    Close-HvlibPartition -handle $handle
    return $symbols
}

function Example-GetHvlibSymbolTableLength {
    <#
    .SYNOPSIS
    Get symbol table length for multiple driver modules.
    .DESCRIPTION
    Queries the symbol count for each driver using Get-HvlibSymbolTableLength,
    which calls SdkSymEnumAllSymbolsGetTableLength.
    .PARAMETER VmName
    Target virtual machine name.
    .OUTPUTS
    [hashtable] Driver name to symbol count mapping.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Example-GetHvlibSymbolTableLength -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n=== 13.4: Get-HvlibSymbolTableLength ===" -ForegroundColor Cyan

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $drivers = @('ntoskrnl', 'winhv', 'kdcom', 'mcupdate', 'securekernel')

    Write-Host ("  {0,-20} {1}" -f "Driver", "Symbol Count") -ForegroundColor Cyan
    Write-Host ("  " + '-' * 35)

    $counts = @{}
    foreach ($drv in $drivers) {
        $count = Get-HvlibSymbolTableLength $handle $drv
        $counts[$drv] = $count
        $color = if ($count -gt 0) { "Green" } else { "Yellow" }
        $str   = if ($count -gt 0) { $count.ToString() } else { "N/A" }
        Write-Host ("  {0,-20} {1}" -f $drv, $str) -ForegroundColor $color
    }

    Close-HvlibPartition -handle $handle
    return $counts
}

#endregion

# ==============================================================================
#region Workflows
# ==============================================================================

function Workflow-VmInformationReport {
    <#
    .SYNOPSIS
    Generate a report of all running VMs with key properties.
    .DESCRIPTION
    Enumerates all Hyper-V partitions and collects name, GUID, ID, handle, kernel base,
    and CPU count for each VM. Uses Get-HvlibAllPartitions and Get-HvlibData2.
    .OUTPUTS
    [PSCustomObject[]] Array of VM information objects.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-VmInformationReport
    #>

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: VM Information Report" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    $vms = Get-HvlibAllPartitions
    if (-not $vms -or $vms.Count -eq 0) { Write-Warning "No VMs found"; return $null }

    $IC = [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]

    $report = foreach ($vm in $vms) {
        $h = $vm.VmHandle
        [PSCustomObject]@{
            Name       = Get-HvlibPartitionName -PartitionHandle $h
            GUID       = Get-HvlibPartitionGuid -PartitionHandle $h
            ID         = Get-HvlibPartitionId -PartitionHandle $h
            Handle     = "0x$($h.ToString('X'))"
            KernelBase = "0x$((Get-HvlibData2 -PartitionHandle $h -InformationClass $IC::HvddKernelBase).ToString('X'))"
            CPUs       = Get-HvlibData2 -PartitionHandle $h -InformationClass $IC::HvddNumberOfCPU
        }
    }

    $report | Format-Table -AutoSize
    Close-HvlibPartitions
    return $report
}

function Workflow-MemoryAnalysis {
    <#
    .SYNOPSIS
    Analyze VM memory layout and key structures.
    .DESCRIPTION
    Reads kernel base, max physical page count, validates the kernel PE header (MZ signature),
    and checks KUSER_SHARED_DATA accessibility via Get-HvlibData2 and Get-HvlibVmVirtualMemory.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-MemoryAnalysis -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: Memory Analysis" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $IC = [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddKernelBase
    $maxPage    = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddMmMaximumPhysicalPage

    $totalMB = [Math]::Round($maxPage * 0x1000 / 1MB)
    Write-Host "  Kernel Base:       0x$($kernelBase.ToString('X'))"
    Write-Host "  Max Physical Page: 0x$($maxPage.ToString('X'))"
    Write-Host "  Total Memory:      ~${totalMB} MB"

    # Check kernel PE header
    $pe = Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $kernelBase -size 0x200
    if ($pe -and $pe[0] -eq 0x4D -and $pe[1] -eq 0x5A) {
        Write-Host "  Kernel PE Header:  Valid (MZ)" -ForegroundColor Green
    }

    # Check KUSER_SHARED_DATA
    $kuserAddr = [System.Convert]::ToUInt64("FFFFF78000000000", 16)
    $kuser = Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $kuserAddr -size 0x100
    if ($kuser) {
        Write-Host "  KUSER_SHARED_DATA: Accessible" -ForegroundColor Green
    }

    Close-HvlibPartition -handle $handle
}

function Workflow-ProcessIntrospection {
    <#
    .SYNOPSIS
    Analyze guest OS processes and their CR3 values.
    .DESCRIPTION
    Retrieves the kernel CR3 (PID 4) and enumerates guest processes via
    Get-HvlibCr3 and Get-HvlibProcessesList.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-ProcessIntrospection -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: Process Introspection" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $kernelCr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId 4
    Write-Host "  Kernel CR3 (PID 4): 0x$($kernelCr3.ToString('X'))" -ForegroundColor Green

    $processes = Get-HvlibProcessesList -PartitionHandle $handle
    if ($processes) {
        Write-Host "  Processes: $($processes.Length - 1)" -ForegroundColor Green
    }

    Close-HvlibPartition -handle $handle
}

function Workflow-SafeMemoryDump {
    <#
    .SYNOPSIS
    Dump first N physical memory pages to individual files.
    .DESCRIPTION
    Reads sequential 4 KB physical pages from the VM and writes each as a .bin file.
    Uses Get-HvlibVmPhysicalMemory for each page.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER OutputPath
    Directory to write dump files to. Created if it does not exist.
    .PARAMETER PageCount
    Number of physical pages (4 KB each) to dump.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-SafeMemoryDump -VmName "Windows Server 2025" -PageCount 5
    #>
    param(
        [string]$VmName = $script:VmName,
        [string]$OutputPath = "$env:TEMP\hvlib_memdump",
        [int]$PageCount = 10
    )

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: Safe Memory Dump" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    Write-Host "  Dumping $PageCount pages to: $OutputPath"

    for ($page = 0; $page -lt $PageCount; $page++) {
        $address = $page * 0x1000
        $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
            -start_position $address -size 0x1000

        if ($data) {
            $fileName = "page_{0:X4}.bin" -f $page
            $filePath = Join-Path $OutputPath $fileName
            [System.IO.File]::WriteAllBytes($filePath, $data)
            Write-Host "    Dumped page $page to $fileName" -ForegroundColor Green
        }
    }

    Write-Host "  Done: $OutputPath" -ForegroundColor Green
    Close-HvlibPartition -handle $handle
}

function Workflow-DebugSession {
    <#
    .SYNOPSIS
    Run a complete debug session on a target VM.
    .DESCRIPTION
    Multi-step workflow that detects architecture, checks VBS status, reads CPU registers
    (RIP, CR3) while suspended, translates kernel VA to PA, and reads physical memory.
    .PARAMETER VmName
    Target virtual machine name.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-DebugSession -VmName "Windows Server 2025"
    #>
    param([string]$VmName = $script:VmName)

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: Debug Session" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $IC = [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]

    # Step 1: Architecture
    Write-Host "`n  Step 1: Architecture" -ForegroundColor Cyan
    $machineType = Get-HvlibMachineType -PartitionHandle $handle
    Write-Host "    Type: $machineType"

    # Step 2: VBS check
    Write-Host "`n  Step 2: VBS Check" -ForegroundColor Cyan
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddKernelBase
    $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $kernelBase
    Write-Host "    Kernel VTL: $vtl"

    # Step 3: CPU context (requires suspend)
    Write-Host "`n  Step 3: CPU Context" -ForegroundColor Cyan
    $suspended = Suspend-HvlibVm -PartitionHandle $handle
    if ($suspended) {
        try {
            $rip = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000).Reg64
            $cr3 = (Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020014).Reg64
            Write-Host "    RIP: 0x$($rip.ToString('X16'))"
            Write-Host "    CR3: 0x$($cr3.ToString('X16'))"

            # Step 4: Address translation
            Write-Host "`n  Step 4: Address Translation" -ForegroundColor Cyan
            $pa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $kernelBase
            Write-Host "    Kernel VA: 0x$($kernelBase.ToString('X'))"
            Write-Host "    Kernel PA: 0x$($pa.ToString('X'))"

            # Step 5: Memory read
            Write-Host "`n  Step 5: Memory Read" -ForegroundColor Cyan
            $memData = Get-HvlibVmPhysicalMemory -prtnHandle $handle -start_position $pa -size 0x100
            Write-Host "    Read $($memData.Length) bytes from PA"
        } finally {
            Resume-HvlibVm -PartitionHandle $handle | Out-Null
        }
    }

    Close-HvlibPartition -handle $handle
    Write-Host "`n  Session complete." -ForegroundColor Green
}

function Workflow-MultiVmReport {
    <#
    .SYNOPSIS
    Generate architecture and VBS report for all running VMs.
    .DESCRIPTION
    Enumerates all Hyper-V partitions and reports each VM's architecture (x64/x86),
    VTL level, and kernel base address. Uses Get-HvlibMachineType and Get-HvlibCurrentVtl.
    .OUTPUTS
    [PSCustomObject[]] Array of objects with VMName, Arch, VTL, KernelBase properties.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-MultiVmReport
    #>

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: Multi-VM Analysis Report" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    $vms = Get-HvlibAllPartitions
    if (-not $vms -or $vms.Count -eq 0) { Write-Warning "No VMs found"; return $null }

    $IC = [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]

    Write-Host ("  {0,-25} {1,-12} {2,-10} {3}" -f "VM Name", "Arch", "VTL", "Kernel Base") -ForegroundColor Cyan
    Write-Host ("  " + '-' * 70)

    $report = foreach ($vm in $vms) {
        $h = $vm.VmHandle
        Select-HvlibPartition -PartitionHandle $h | Out-Null

        $type = Get-HvlibMachineType -PartitionHandle $h
        $arch = if ($type -eq 'MACHINE_AMD64') { "x64" } else { "x86" }

        $kb = Get-HvlibData2 -PartitionHandle $h -InformationClass $IC::HvddKernelBase
        $vtl = Get-HvlibCurrentVtl -PartitionHandle $h -VirtualAddress $kb

        Write-Host ("  {0,-25} {1,-12} {2,-10} 0x{3:X}" -f $vm.VMName, $arch, $vtl, $kb)
        Close-HvlibPartition -handle $h

        [PSCustomObject]@{ VMName=$vm.VMName; Arch=$arch; VTL=$vtl; KernelBase="0x$($kb.ToString('X'))" }
    }

    return $report
}

function Workflow-SymbolAnalysis {
    <#
    .SYNOPSIS
    Perform comprehensive symbol analysis for specified drivers.
    .DESCRIPTION
    Multi-step workflow: queries symbol table sizes, resolves key symbols via direct SDK lookup
    (SdkSymGetSymbolAddress2), and performs full enumeration for a small driver module.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER DriverNames
    Array of driver module names to analyze.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Workflow-SymbolAnalysis -VmName "Windows Server 2025" -DriverNames @('ntoskrnl','winhv')
    #>
    param(
        [string]$VmName = $script:VmName,
        [string[]]$DriverNames = @('ntoskrnl', 'winhv', 'securekernel')
    )

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "WORKFLOW: Symbol Analysis" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    # Step 1: Symbol table sizes
    Write-Host "`n  Step 1: Symbol counts" -ForegroundColor Cyan
    foreach ($drv in $DriverNames) {
        $count = Get-HvlibSymbolTableLength $handle $drv
        $str = if ($count -gt 0) { $count } else { "N/A" }
        Write-Host "    ${drv}: $str"
    }

    # Step 2: Resolve key symbols via direct lookup
    Write-Host "`n  Step 2: Key symbol resolution (direct)" -ForegroundColor Cyan
    $keySymbols = @("nt!MmCopyVirtualMemory", "nt!KeBugCheckEx", "winhv!WinHvAllocateOverlayPages")
    foreach ($sym in $keySymbols) {
        $addr = Get-HvlibSymbolAddressDirect $handle $sym
        $str = if ($addr -ne 0) { "0x$($addr.ToString('X'))" } else { "N/A" }
        Write-Host "    $sym = $str"
    }

    # Step 3: Full enumeration for first small driver
    $smallDriver = $DriverNames | Where-Object { $_ -ne 'ntoskrnl' } | Select-Object -First 1
    if ($smallDriver) {
        Write-Host "`n  Step 3: Full enumeration ($smallDriver)" -ForegroundColor Cyan
        $symbols = Get-HvlibAllSymbols $handle $smallDriver
        if ($symbols) {
            Write-Host "    Total: $($symbols.Count) symbols"
            Write-Host "    First: $($symbols[0].Name)"
            Write-Host "    Last:  $($symbols[$symbols.Count - 1].Name)"
        }
    }

    Close-HvlibPartition -handle $handle
    Write-Host "`n  Done." -ForegroundColor Green
}

#endregion

# ==============================================================================
#region Entry Point
# ==============================================================================

function Invoke-AllExamples {
    <#
    .SYNOPSIS
    Run all Hvlib example functions sequentially.
    .DESCRIPTION
    Initializes the Hvlib module, then executes every example and workflow function in order.
    Memory-write examples can be skipped with -SkipMemoryWrites.
    .PARAMETER VmName
    Target virtual machine name.
    .PARAMETER DllPath
    Path to hvlibdotnet.dll.
    .PARAMETER SkipMemoryWrites
    If set, skips examples that write to VM memory.
    .EXAMPLE
    . .\Hvlib-Examples.ps1
    Invoke-AllExamples -VmName "Windows Server 2025" -DllPath "C:\path\hvlibdotnet.dll"
    #>
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$DllPath,

        [switch]$SkipMemoryWrites
    )

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "Hvlib PowerShell Module - Examples v$script:SCRIPT_VERSION" -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta

    if (-not (Initialize-HvlibExamples -DllPath $DllPath)) { return }

    # Section 1: Library and Configuration
    Example-GetHvlib -DllPath $DllPath | Out-Null
    Example-GetHvlibPreferredSettings | Out-Null

    # Section 2: Partition Enumeration
    Example-GetHvlibAllPartitions | Out-Null
    Example-GetHvlibPartition -VmName $VmName | Out-Null

    # Section 3: Partition Information
    Example-GetHvlibPartitionName -VmName $VmName | Out-Null
    Example-GetHvlibPartitionGuid -VmName $VmName | Out-Null
    Example-GetHvlibPartitionId -VmName $VmName | Out-Null
    Example-GetHvlibData2-KernelBase -VmName $VmName | Out-Null
    Example-GetHvlibData2-CpuCount -VmName $VmName | Out-Null
    Example-GetHvlibData2-MultipleProperties -VmName $VmName | Out-Null

    # Section 4: Physical Memory
    Example-GetHvlibVmPhysicalMemory-Basic -VmName $VmName | Out-Null
    Example-GetHvlibVmPhysicalMemory-Address -VmName $VmName | Out-Null
    if (-not $SkipMemoryWrites) {
        Write-Host "`n  WARNING: Memory write examples will be executed" -ForegroundColor Red
        Example-SetHvlibVmPhysicalMemoryBytes -VmName $VmName | Out-Null
    }

    # Section 5: Virtual Memory
    Example-GetHvlibVmVirtualMemory-KUserSharedData -VmName $VmName | Out-Null
    Example-GetHvlibVmVirtualMemory-KernelAddress -VmName $VmName | Out-Null

    # Section 6: Process Information
    Example-GetHvlibProcessesList -VmName $VmName | Out-Null
    Example-GetHvlibCr3-Kernel -VmName $VmName | Out-Null

    # Section 8: Utilities
    Example-GetHexValue | Out-Null

    # Section 7: Cleanup
    Example-CloseHvlibPartition -VmName $VmName | Out-Null

    # Workflows
    Workflow-VmInformationReport | Out-Null
    Workflow-MemoryAnalysis -VmName $VmName | Out-Null
    Workflow-ProcessIntrospection -VmName $VmName | Out-Null

    # Section 13: Symbol Operations
    Example-GetHvlibSymbolAddressDirect -VmName $VmName | Out-Null
    Example-GetHvlibSymbolAddress -VmName $VmName | Out-Null
    Example-GetHvlibSymbolAddress-Multiple -VmName $VmName | Out-Null
    Example-GetHvlibAllSymbols -VmName $VmName | Out-Null
    Example-GetHvlibSymbolTableLength -VmName $VmName | Out-Null

    # Symbol Workflow
    Workflow-SymbolAnalysis -VmName $VmName | Out-Null

    # Final cleanup
    Example-CloseHvlibPartitions | Out-Null

    Write-Host "`n$('=' * 70)" -ForegroundColor Magenta
    Write-Host "All examples completed." -ForegroundColor Magenta
    Write-Host "$('=' * 70)" -ForegroundColor Magenta
}

# --- Load configuration and run ---

$script:_config = Get-HvlibConfig
$script:DllPath = if ($script:_config.DllPath) { $script:_config.DllPath } else { $script:DEFAULT_DLL_PATH }
$script:VmName  = if ($script:_config.VmName)  { $script:_config.VmName }  else { $script:DEFAULT_VM_NAME }

Invoke-AllExamples -DllPath $script:DllPath -VmName $script:VmName

#endregion
