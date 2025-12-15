# ==============================================================================
# Module:      Hvlib.psm1
# Version:     1.3.0
# Description: PowerShell wrapper for hvlib.dll - Hyper-V Memory Manager Plugin
# Author:      Arthur Khudyaev (@gerhart_x)
# ==============================================================================
# Change Log:
# 1.3.0 - Major feature release
#       - ADDED: Set-HvlibPartitionData (SdkSetData)
#       - ADDED: Suspend-HvlibVm / Resume-HvlibVm (SdkControlVmState)
#       - ADDED: Get-HvlibPhysicalAddress (SdkGetPhysicalAddress)
#       - ADDED: Get-HvlibMachineType (SdkGetMachineType)
#       - ADDED: Get-HvlibCurrentVtl (SdkGetCurrentVtl)
#       - ADDED: Get-HvlibVpRegister (SdkReadVpRegister)
#       - ADDED: Set-HvlibVpRegister (SdkWriteVpRegister)
#       - Total: 28 public functions (21 + 7 new)
# 1.1.1 - Bug fix release
#       - FIXED: Removed hard-coded DEFAULT_DLL_PATH constant
#       - FIXED: Export-ModuleMember errors in dot-sourced files
#       - CHANGED: Get-Hvlib requires -path_to_dll parameter (mandatory)
#       - IMPROVED: DLL path saved and reused automatically
# 1.1.0 - Refactored version with improved code quality and readability
# 1.0.1 - Added missing API functions from hvlibdotnet.cs
# 1.0.0 - Initial release
# ==============================================================================

# Module initialization
$Script:is_lib_loaded = $false
$Script:dll_path = $null

# Import supporting modules
. $PSScriptRoot\Hvlib.Constants.ps1
. $PSScriptRoot\Hvlib.Helpers.ps1

function Get-HexValue2 {
    <#
    .SYNOPSIS
    Convert values to HEX format
    .PARAMETER decimal_number
    Decimal number
    .EXAMPLE
    Get-HexValue 1234567890
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$number
    )

    $varType = $number.GetType().Name

    if ($varType -eq "String")
    {
        return [System.String]::Format("{0:X}",[System.Convert]::ToUInt64($number))
    }
    if (($varType -eq "Int32") -or ($varType -eq "Int64") -or ($varType -eq "UInt64") -or ($varType -eq "UInt32"))
    {
        return [System.String]::Format("{0:X}",$number)
    }   

    Write-Host "Error in type: $varType"

    return "0"
}

# ==============================================================================
# SECTION 1: Library and Configuration Management
# ==============================================================================

function Get-Hvlib {
    <#
    .SYNOPSIS
    Load Hvlib library if not already loaded
    .PARAMETER path_to_dll
    Path to hvlibdotnet.dll (required)
    .EXAMPLE
    Get-Hvlib -path_to_dll "C:\hvlib\hvlibdotnet.dll"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$path_to_dll
    )

    # Save DLL path for subsequent calls
    $Script:dll_path = $path_to_dll
    
    return Initialize-Hvlib -DllPath $path_to_dll
}

function Get-HvlibPreferredSettings {
    <#
    .SYNOPSIS
    Get default plugin configuration
    .DESCRIPTION
    Retrieves the default VM_OPERATIONS_CONFIG structure with recommended settings
    .EXAMPLE
    $cfg = Get-HvlibPreferredSettings
    #>
    [CmdletBinding()]
    param()

    if (-not (Initialize-Hvlib)) { return $null }

    $cfg = New-Object Hvlibdotnet.Hvlib+VM_OPERATIONS_CONFIG
    $result = [Hvlibdotnet.Hvlib]::GetPreferredSettings([ref]$cfg)

    if (-not $result) {
        Write-Warning $Script:MSG_OPERATION_FAILED
        return $null
    }

    Write-Host $Script:MSG_OPERATION_SUCCESS -ForegroundColor $Script:COLOR_SUCCESS
    return $cfg
}

# ==============================================================================
# SECTION 2: Partition Enumeration and Selection
# ==============================================================================

function Get-HvlibAllPartitions {
    <#
    .SYNOPSIS
    Enumerate all active Hyper-V partitions
    .DESCRIPTION
    Returns list of all virtual machines with their handles and names
    .EXAMPLE
    $vms = Get-HvlibAllPartitions
    $vms | Format-Table VMName, VmHandle
    #>
    [CmdletBinding()]
    param()

    if (-not (Initialize-Hvlib)) { return $null }

    $partitions = [Hvlibdotnet.Hvlib]::EnumAllPartitions()

    if ($null -eq $partitions -or $partitions.Count -eq 0) {
        Write-Warning $Script:MSG_NULL_RESULT
        return $null
    }

    Write-Host ($Script:MSG_VM_COUNT -f $partitions.Count) -ForegroundColor $Script:COLOR_INFO
    return $partitions
}

function Get-HvlibPartition {
    <#
    .SYNOPSIS
    Select partition by VM name
    .PARAMETER VmName
    Name of the virtual machine
    .EXAMPLE
    $handle = Get-HvlibPartition -VmName "Windows 11"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )

    if (-not (Initialize-Hvlib)) { return $null }

    # Enumerate all partitions and find by name
    $allPartitions = [Hvlibdotnet.Hvlib]::EnumAllPartitions()
    
    if ($null -eq $allPartitions) {
        Write-Warning "Failed to enumerate partitions"
        return $null
    }
    
    $partition = $allPartitions | Where-Object { $_.VMName -eq $VmName } | Select-Object -First 1
    
    if ($null -eq $partition) {
        Write-Warning ($Script:MSG_VM_NOT_FOUND -f $VmName)
        return $null
    }

    $result = [Hvlibdotnet.Hvlib]::SelectPartition($partition.VmHandle)
    
    if (-not $result) {
        Write-Warning $Script:MSG_OPERATION_FAILED
        return $null
    }

    Write-Host ($Script:MSG_VM_FOUND -f $VmName, $partition.VmHandle) -ForegroundColor $Script:COLOR_SUCCESS
    return $partition.VmHandle
}

function Select-HvlibPartition {
    <#
    .SYNOPSIS
    Select partition by handle
    .PARAMETER PartitionHandle
    Handle to partition
    .EXAMPLE
    Select-HvlibPartition -PartitionHandle 0x100000000000
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [uint64]$PartitionHandle
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $false }

    $result = [Hvlibdotnet.Hvlib]::SelectPartition($PartitionHandle)
    
    if (-not $result) {
        Write-Warning $Script:MSG_OPERATION_FAILED
        return $false
    }

    Write-Host ($Script:MSG_PARTITION_SELECTED -f $PartitionHandle) -ForegroundColor $Script:COLOR_SUCCESS
    return $true
}

# ==============================================================================
# SECTION 3: Partition Information Retrieval
# ==============================================================================

function Get-HvlibPartitionName {
    <#
    .SYNOPSIS
    Get partition friendly name
    .PARAMETER PartitionHandle
    Handle to partition
    .EXAMPLE
    $name = Get-HvlibPartitionName -PartitionHandle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    $namePtrValue = [Hvlibdotnet.Hvlib]::GetPartitionData2(
        $PartitionHandle,
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddPartitionFriendlyName
    )
    
    $namePtr = [IntPtr]::new([Int64]$namePtrValue)

    return ConvertFrom-UnmanagedString -Pointer $namePtr
}

function Get-HvlibPartitionGuid {
    <#
    .SYNOPSIS
    Get partition GUID string
    .PARAMETER PartitionHandle
    Handle to partition
    .EXAMPLE
    $guid = Get-HvlibPartitionGuid -PartitionHandle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    $guidPtrValue = [Hvlibdotnet.Hvlib]::GetPartitionData2(
        $PartitionHandle,
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddVmGuidString
    )
    
    $guidPtr = [IntPtr]::new([Int64]$guidPtrValue)

    return ConvertFrom-UnmanagedString -Pointer $guidPtr
}

function Get-HvlibPartitionId {
    <#
    .SYNOPSIS
    Get partition ID
    .PARAMETER PartitionHandle
    Handle to partition
    .EXAMPLE
    $id = Get-HvlibPartitionId -PartitionHandle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    return [Hvlibdotnet.Hvlib]::GetPartitionData2(
        $PartitionHandle,
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddPartitionId
    )
}

function Get-HvlibData {
    <#
    .SYNOPSIS
    Get partition data (out parameter version)
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER InformationClass
    Type of information to retrieve
    .PARAMETER Information
    Output variable for information
    .EXAMPLE
    $info = $null
    Get-HvlibData -PartitionHandle $handle -InformationClass HvddKernelBase -Information ([ref]$info)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]$InformationClass,
        
        [Parameter(Mandatory)]
        [ref]$Information
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $false }

    $outPtr = [UIntPtr]::Zero
    $result = [Hvlibdotnet.Hvlib]::GetPartitionData($PartitionHandle, $InformationClass, [ref]$outPtr)
    
    if ($result) {
        $Information.Value = $outPtr
        Write-Host ($Script:MSG_DATA_RETRIEVED -f $InformationClass) -ForegroundColor $Script:COLOR_SUCCESS
    }
    
    return $result
}

function Get-HvlibData2 {
    <#
    .SYNOPSIS
    Get partition data (return value version)
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER InformationClass
    Type of information to retrieve
    .EXAMPLE
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle -InformationClass HvddKernelBase
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]$InformationClass
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return 0 }

    $result = [Hvlibdotnet.Hvlib]::GetPartitionData2($PartitionHandle, $InformationClass)
    
    if ($result -ne 0) {
        Write-Host ($Script:MSG_DATA_RETRIEVED -f $InformationClass) -ForegroundColor $Script:COLOR_SUCCESS
    }
    
    return $result
}

# ==============================================================================
# SECTION 4: Physical Memory Operations
# ==============================================================================

function Get-HvlibVmPhysicalMemory {
    <#
    .SYNOPSIS
    Read physical memory from VM
    .PARAMETER prtnHandle
    Partition handle
    .PARAMETER start_position
    Starting physical address
    .PARAMETER size
    Number of bytes to read
    .EXAMPLE
    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle -start_position 0x1000 -size 0x1000
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$prtnHandle,
        
        [Parameter(Mandatory)]
        [uint64]$start_position,
        
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [uint64]$size
    )

    return Read-PhysicalMemoryInternal -PartitionHandle $prtnHandle -Address $start_position -Size $size
}

function Set-HvlibVmPhysicalMemory {
    <#
    .SYNOPSIS
    Write physical memory from file
    .PARAMETER filename
    Path to input file
    .PARAMETER prtnHandle
    Partition handle
    .EXAMPLE
    Set-HvlibVmPhysicalMemory -filename "data.bin" -prtnHandle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$filename,
        
        [Parameter(Mandatory)]
        [uint64]$prtnHandle
    )

    if (-not (Test-FileExists -Path $filename)) { return $false }
    if (-not (Test-PartitionHandle -Handle $prtnHandle)) { return $false }

    $bytes = [System.IO.File]::ReadAllBytes($filename)
    return Write-PhysicalMemoryInternal -PartitionHandle $prtnHandle -Address 0 -Data $bytes
}

function Set-HvlibVmPhysicalMemoryBytes {
    <#
    .SYNOPSIS
    Write byte array to physical memory
    .PARAMETER PartitionHandle
    Partition handle
    .PARAMETER StartPosition
    Starting physical address
    .PARAMETER Data
    Byte array to write
    .EXAMPLE
    $data = [byte[]]@(0x90, 0x90, 0xC3)
    Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $handle -StartPosition 0x1000 -Data $data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$StartPosition,
        
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [byte[]]$Data
    )

    return Write-PhysicalMemoryInternal -PartitionHandle $PartitionHandle -Address $StartPosition -Data $Data
}

# ==============================================================================
# SECTION 5: Virtual Memory Operations
# ==============================================================================

function Get-HvlibVmVirtualMemory {
    <#
    .SYNOPSIS
    Read virtual memory from VM
    .PARAMETER prtnHandle
    Partition handle
    .PARAMETER start_position
    Starting virtual address
    .PARAMETER size
    Number of bytes to read
    .EXAMPLE
    $data = Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position 0xFFFFF80000000000 -size 0x1000
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$prtnHandle,
        
        [Parameter(Mandatory)]
        $start_position,
        
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [uint64]$size
    )

    $varType = $start_position.GetType().Name
    $start_position_uint64 = 0

    if ($varType -eq "String")
    {
        $start_position_uint64 = [System.Convert]::ToUInt64($start_position, 16)
    }
    elseif (($varType -eq "Int32") -or ($varType -eq "Int64") -or ($varType -eq "UInt64") -or ($varType -eq "UInt32"))
    {
        $bytes = [BitConverter]::GetBytes($start_position)
        $start_position_uint64 = [BitConverter]::ToUInt64($bytes, 0)
    } 
    else 
    {
        Write-Warning $varType "is not handled"
        return $null
    } 

    return Read-VirtualMemoryInternal -PartitionHandle $prtnHandle -Address $start_position_uint64 -Size $size
}

function Set-HvlibVmVirtualMemory {
    <#
    .SYNOPSIS
    Write virtual memory from file
    .PARAMETER filename
    Path to input file
    .PARAMETER prtnHandle
    Partition handle
    .EXAMPLE
    Set-HvlibVmVirtualMemory -filename "patch.bin" -prtnHandle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$filename,
        
        [Parameter(Mandatory)]
        [uint64]$prtnHandle
    )

    if (-not (Test-FileExists -Path $filename)) { return $false }
    if (-not (Test-PartitionHandle -Handle $prtnHandle)) { return $false }

    $bytes = [System.IO.File]::ReadAllBytes($filename)
    return Write-VirtualMemoryInternal -PartitionHandle $prtnHandle -Address 0 -Data $bytes
}

function Set-HvlibVmVirtualMemoryBytes {
    <#
    .SYNOPSIS
    Write byte array to virtual memory
    .PARAMETER PartitionHandle
    Partition handle
    .PARAMETER StartPosition
    Starting virtual address
    .PARAMETER Data
    Byte array to write
    .EXAMPLE
    $patch = [byte[]]@(0x90, 0x90, 0xC3)
    Set-HvlibVmVirtualMemoryBytes -PartitionHandle $handle -StartPosition 0xFFFFF80000001000 -Data $patch
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$StartPosition,
        
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [byte[]]$Data
    )

    return Write-VirtualMemoryInternal -PartitionHandle $PartitionHandle -Address $StartPosition -Data $Data
}

# ==============================================================================
# SECTION 6: Process and System Information
# ==============================================================================

function Get-HvlibProcessesList {
    <#
    .SYNOPSIS
    Get list of process IDs in VM
    .PARAMETER PartitionHandle
    Handle to partition
    .EXAMPLE
    $processes = Get-HvlibProcessesList -PartitionHandle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    $processListPtrValue = [Hvlibdotnet.Hvlib]::GetPartitionData2(
        $PartitionHandle,
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddGetProcessesIds
    )
    
    $processListPtr = [IntPtr]::new([Int64]$processListPtrValue)

    if ($processListPtr -eq [IntPtr]::Zero) {
        Write-Warning $Script:MSG_NULL_RESULT
        return $null
    }

    $count = [System.Runtime.InteropServices.Marshal]::ReadInt64($processListPtr)
    $processes = @($count)
    
    for ($i = 1; $i -le $count; $i++) {
        $offset = $processListPtr.ToInt64() + ($i * 8)
        $ProcessId = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$offset)
        $processes += $ProcessId
    }

    Write-Host ($Script:MSG_PROCESSES_FOUND -f $count) -ForegroundColor $Script:COLOR_SUCCESS
    return $processes
}

function Get-HvlibCr3 {
    <#
    .SYNOPSIS
    Get CR3 register value for process
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER Pid
    Process ID
    .EXAMPLE
    $cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId 0xFFFFFFFE
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$ProcessId
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return 0 }

    $cr3 = [Hvlibdotnet.Hvlib]::GetCr3FromPid($PartitionHandle, $ProcessId)
    
    if ($cr3 -ne 0) {
        Write-Host ($Script:MSG_CR3_RETRIEVED -f $cr3,$ProcessId) -ForegroundColor $Script:COLOR_SUCCESS
    }
    
    return $cr3
}

# ==============================================================================
# SECTION 7: NEW FUNCTIONS - VM State Control
# ==============================================================================

function Suspend-HvlibVm {
    <#
    .SYNOPSIS
    Suspend virtual machine
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER Method
    Suspend method (default: PowerShell)
    .PARAMETER ManageWorkerProcess
    Manage worker process (default: false)
    .EXAMPLE
    Suspend-HvlibVm -PartitionHandle $handle
    .EXAMPLE
    Suspend-HvlibVm -PartitionHandle $handle -Method SuspendResumeWriteSpecRegister
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Hvlibdotnet.Hvlib+SUSPEND_RESUME_METHOD]$Method = [Hvlibdotnet.Hvlib+SUSPEND_RESUME_METHOD]::SuspendResumePowershell,
        
        [bool]$ManageWorkerProcess = $false
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $false }

    $result = [Hvlibdotnet.Hvlib]::SuspendVm($PartitionHandle, $Method, $ManageWorkerProcess)
    
    if ($result) {
        Write-Host "VM suspended successfully" -ForegroundColor $Script:COLOR_SUCCESS
    } else {
        Write-Warning "Failed to suspend VM"
    }
    
    return $result
}

function Resume-HvlibVm {
    <#
    .SYNOPSIS
    Resume virtual machine
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER Method
    Resume method (default: PowerShell)
    .PARAMETER ManageWorkerProcess
    Manage worker process (default: false)
    .EXAMPLE
    Resume-HvlibVm -PartitionHandle $handle
    .EXAMPLE
    Resume-HvlibVm -PartitionHandle $handle -Method SuspendResumeWriteSpecRegister
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Hvlibdotnet.Hvlib+SUSPEND_RESUME_METHOD]$Method = [Hvlibdotnet.Hvlib+SUSPEND_RESUME_METHOD]::SuspendResumePowershell,
        
        [bool]$ManageWorkerProcess = $false
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $false }

    $result = [Hvlibdotnet.Hvlib]::ResumeVm($PartitionHandle, $Method, $ManageWorkerProcess)
    
    if ($result) {
        Write-Host "VM resumed successfully" -ForegroundColor $Script:COLOR_SUCCESS
    } else {
        Write-Warning "Failed to resume VM"
    }
    
    return $result
}

# ==============================================================================
# SECTION 8: NEW FUNCTIONS - Advanced Memory Operations
# ==============================================================================

function Get-HvlibPhysicalAddress {
    <#
    .SYNOPSIS
    Translate virtual address to physical address (GVA to GPA)
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER VirtualAddress
    Virtual address to translate
    .PARAMETER AccessType
    Memory access type (default: Virtual)
    .EXAMPLE
    $gpa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress 0xFFFFF80000000000
    Write-Host "Physical address: 0x$($gpa.ToString('X16'))"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$VirtualAddress,
        
        [Hvlibdotnet.Hvlib+MEMORY_ACCESS_TYPE]$AccessType = [Hvlibdotnet.Hvlib+MEMORY_ACCESS_TYPE]::MmVirtualMemory
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return 0 }

    $physicalAddress = [Hvlibdotnet.Hvlib]::GetPhysicalAddress($PartitionHandle, $VirtualAddress, $AccessType)
    
    if ($physicalAddress -eq 0) {
        Write-Warning "Address translation failed for 0x$($VirtualAddress.ToString('X16'))"
    } else {
        Write-Host "GVA 0x$($VirtualAddress.ToString('X16')) -> GPA 0x$($physicalAddress.ToString('X16'))" -ForegroundColor $Script:COLOR_SUCCESS
    }
    
    return $physicalAddress
}

function Set-HvlibPartitionData {
    <#
    .SYNOPSIS
    Set partition data
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER InformationClass
    Type of information to set
    .PARAMETER Information
    Information value
    .EXAMPLE
    Set-HvlibPartitionData -PartitionHandle $handle -InformationClass HvddSetMemoryBlock -Information 1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]$InformationClass,
        
        [Parameter(Mandatory)]
        [uint64]$Information
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return 0 }

    $result = [Hvlibdotnet.Hvlib]::SetPartitionData($PartitionHandle, $InformationClass, $Information)
    
    if ($result -ne 0) {
        Write-Host "Partition data set successfully" -ForegroundColor $Script:COLOR_SUCCESS
    } else {
        Write-Warning "Failed to set partition data"
    }
    
    return $result
}

# ==============================================================================
# SECTION 9: NEW FUNCTIONS - VM Introspection
# ==============================================================================

function Get-HvlibMachineType {
    <#
    .SYNOPSIS
    Get VM machine type (architecture)
    .PARAMETER PartitionHandle
    Handle to partition
    .EXAMPLE
    $machineType = Get-HvlibMachineType -PartitionHandle $handle
    switch ($machineType) {
        'MACHINE_AMD64' { Write-Host "64-bit VM" }
        'MACHINE_X86' { Write-Host "32-bit VM" }
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    $machineType = [Hvlibdotnet.Hvlib]::GetMachineType($PartitionHandle)
    
    Write-Host "Machine Type: $machineType" -ForegroundColor $Script:COLOR_INFO
    
    return $machineType
}

function Get-HvlibCurrentVtl {
    <#
    .SYNOPSIS
    Get current Virtual Trust Level for address
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER VirtualAddress
    Virtual address to check
    .EXAMPLE
    $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress 0xFFFFF80000000000
    if ($vtl -eq 'Vtl1') { Write-Host "Address is in secure kernel (VTL1)" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$VirtualAddress
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    $vtl = [Hvlibdotnet.Hvlib]::GetCurrentVtl($PartitionHandle, $VirtualAddress)
    
    Write-Host "VTL Level for 0x$($VirtualAddress.ToString('X16')): $vtl" -ForegroundColor $Script:COLOR_INFO
    
    return $vtl
}

# ==============================================================================
# SECTION 10: NEW FUNCTIONS - CPU Register Access
# ==============================================================================

function Get-HvlibVpRegister {
    <#
    .SYNOPSIS
    Read virtual processor register
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER VpIndex
    Virtual processor index (0 for first CPU)
    .PARAMETER RegisterCode
    Register code (e.g., 0x00020000 for RIP)
    .PARAMETER Vtl
    Virtual Trust Level (default: Vtl0)
    .EXAMPLE
    # Read RIP (instruction pointer)
    $rip = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000
    Write-Host "RIP: 0x$($rip.Reg64.ToString('X16'))"
    .EXAMPLE
    # Read RAX
    $rax = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020003
    Write-Host "RAX: 0x$($rax.Reg64.ToString('X16'))"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [ValidateRange(0, 64)]
        [uint32]$VpIndex,
        
        [Parameter(Mandatory)]
        [uint32]$RegisterCode,
        
        [Hvlibdotnet.Hvlib+VTL_LEVEL]$Vtl = [Hvlibdotnet.Hvlib+VTL_LEVEL]::Vtl0
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    $registerValue = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
    $result = [Hvlibdotnet.Hvlib]::ReadVpRegister($PartitionHandle, $VpIndex, $Vtl, $RegisterCode, [ref]$registerValue)
    
    if ($result) {
        Write-Host "Register read successfully: 0x$($registerValue.Reg64.ToString('X16'))" -ForegroundColor $Script:COLOR_SUCCESS
        return $registerValue
    } else {
        Write-Warning "Failed to read register 0x$($RegisterCode.ToString('X8'))"
        return $null
    }
}

function Set-HvlibVpRegister {
    <#
    .SYNOPSIS
    Write virtual processor register
    .PARAMETER PartitionHandle
    Handle to partition
    .PARAMETER VpIndex
    Virtual processor index (0 for first CPU)
    .PARAMETER RegisterCode
    Register code (e.g., 0x00020000 for RIP)
    .PARAMETER RegisterValue
    Register value structure to write
    .PARAMETER Vtl
    Virtual Trust Level (default: Vtl0)
    .EXAMPLE
    # Set RIP to new value
    $newRip = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
    $newRip.Reg64 = 0xFFFFF80000001000
    Set-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000 -RegisterValue $newRip
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [ValidateRange(0, 64)]
        [uint32]$VpIndex,
        
        [Parameter(Mandatory)]
        [uint32]$RegisterCode,
        
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $RegisterValue,
        
        [Hvlibdotnet.Hvlib+VTL_LEVEL]$Vtl = [Hvlibdotnet.Hvlib+VTL_LEVEL]::Vtl0
    )

    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $false }

    $result = [Hvlibdotnet.Hvlib]::WriteVpRegister($PartitionHandle, $VpIndex, $Vtl, $RegisterCode, $RegisterValue)
    
    if ($result) {
        Write-Host "Register written successfully" -ForegroundColor $Script:COLOR_SUCCESS
    } else {
        Write-Warning "Failed to write register 0x$($RegisterCode.ToString('X8'))"
    }
    
    return $result
}

# ==============================================================================
# SECTION 11: Resource Management
# ==============================================================================

function Close-HvlibPartitions {
    <#
    .SYNOPSIS
    Close all open partitions
    .EXAMPLE
    Close-HvlibPartitions
    #>
    [CmdletBinding()]
    param()

    if (-not (Initialize-Hvlib)) { return }

    [Hvlibdotnet.Hvlib]::CloseAllPartitions()
    Write-Host $Script:MSG_ALL_PARTITIONS_CLOSED -ForegroundColor $Script:COLOR_SUCCESS
}

function Close-HvlibPartition {
    <#
    .SYNOPSIS
    Close specific partition
    .PARAMETER handle
    Partition handle to close
    .EXAMPLE
    Close-HvlibPartition -handle $handle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$handle
    )

    if (-not (Test-PartitionHandle -Handle $handle)) { return }

    [Hvlibdotnet.Hvlib]::ClosePartition($handle)
    Write-Host ($Script:MSG_PARTITION_CLOSED -f $handle) -ForegroundColor $Script:COLOR_SUCCESS
}

# ==============================================================================
# SECTION 12: Utility Functions
# ==============================================================================

function Get-HexValue {
    <#
    .SYNOPSIS
    Convert number to hex string
    .PARAMETER num
    Number to convert
    .EXAMPLE
    Get-HexValue -num 65536
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $num
    )

    #return ConvertTo-HexString -Number $num
    return Get-HexValue2 $num
}

# ==============================================================================
# Module Export
# ==============================================================================

Export-ModuleMember -Function @(
    # Configuration (2)
    'Get-Hvlib',
    'Get-HvlibPreferredSettings',
    
    # Partition Management (3)
    'Get-HvlibAllPartitions',
    'Get-HvlibPartition',
    'Select-HvlibPartition',
    
    # Information Retrieval (5)
    'Get-HvlibPartitionName',
    'Get-HvlibPartitionGuid',
    'Get-HvlibPartitionId',
    'Get-HvlibData',
    'Get-HvlibData2',
    
    # Physical Memory (3)
    'Get-HvlibVmPhysicalMemory',
    'Set-HvlibVmPhysicalMemory',
    'Set-HvlibVmPhysicalMemoryBytes',
    
    # Virtual Memory (3)
    'Get-HvlibVmVirtualMemory',
    'Set-HvlibVmVirtualMemory',
    'Set-HvlibVmVirtualMemoryBytes',
    
    # Process Information (2)
    'Get-HvlibProcessesList',
    'Get-HvlibCr3',
    
    # VM State Control (2) - NEW
    'Suspend-HvlibVm',
    'Resume-HvlibVm',
    
    # Advanced Memory (2) - NEW
    'Get-HvlibPhysicalAddress',
    'Set-HvlibPartitionData',
    
    # VM Introspection (2) - NEW
    'Get-HvlibMachineType',
    'Get-HvlibCurrentVtl',
    
    # CPU Registers (2) - NEW
    'Get-HvlibVpRegister',
    'Set-HvlibVpRegister',
    
    # Resource Management (2)
    'Close-HvlibPartitions',
    'Close-HvlibPartition',
    
    # Utilities (1)
    'Get-HexValue'
)

# Total: 28 exported functions (21 original + 7 new)
