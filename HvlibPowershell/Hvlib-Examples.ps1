# ==============================================================================
# Hvlib-Examples.ps1
# Version: 1.5.0
# Description: Complete usage examples for Hvlib PowerShell Module
# ==============================================================================

#requires -Version 7.0

#region Constants and Configuration

# Module Settings
$script:MODULE_NAME = 'Hvlib'
$script:MODULE_VERSION = '1.5.0'

# Memory Constants
$script:PAGE_SIZE = 0x1000
$script:KB_SIZE = 1KB
$script:MB_SIZE = 1MB
$script:ADDR_KUCER_SHARED_DATA = "0xFFFFF78000000000"  # String for conversion
$script:ADDR_TEST_PHYSICAL = 0x1000
$script:ADDR_SAFE_TEST = 0x50000

# Special Process IDs (as strings for proper UInt64 conversion)
$script:PID_KERNEL = "0xFFFFFFFE"
$script:PID_HYPERVISOR = "0xFFFFFFFF"

# Register Codes - Special
$script:REG_RIP = 0x00020000
$script:REG_RFLAGS = 0x00020001
$script:REG_RSP = 0x00020002

# Register Codes - General Purpose
$script:REG_RAX = 0x00020003
$script:REG_RCX = 0x00020004
$script:REG_RDX = 0x00020005
$script:REG_RBX = 0x00020006
$script:REG_RBP = 0x00020007
$script:REG_RSI = 0x00020008
$script:REG_RDI = 0x00020009

# Register Codes - Control
$script:REG_CR0 = 0x00020012
$script:REG_CR2 = 0x00020013
$script:REG_CR3 = 0x00020014
$script:REG_CR4 = 0x00020015
$script:REG_DR0 = 0x00020017

# Register Sets
$script:GPR_REGISTERS = @(
    @{Name='RAX'; Code=$script:REG_RAX}
    @{Name='RCX'; Code=$script:REG_RCX}
    @{Name='RDX'; Code=$script:REG_RDX}
    @{Name='RBX'; Code=$script:REG_RBX}
    @{Name='RSP'; Code=$script:REG_RSP}
    @{Name='RBP'; Code=$script:REG_RBP}
    @{Name='RSI'; Code=$script:REG_RSI}
    @{Name='RDI'; Code=$script:REG_RDI}
)

$script:CONTROL_REGISTERS = @(
    @{Name='CR0'; Code=$script:REG_CR0; Desc='Control Register 0 (system flags)'}
    @{Name='CR2'; Code=$script:REG_CR2; Desc='Page Fault Linear Address'}
    @{Name='CR3'; Code=$script:REG_CR3; Desc='Page Directory Base'}
    @{Name='CR4'; Code=$script:REG_CR4; Desc='Control Register 4 (extensions)'}
)

# Display Colors
$script:COLOR_HEADER = 'Magenta'
$script:COLOR_SECTION = 'Cyan'
$script:COLOR_SUCCESS = 'Green'
$script:COLOR_WARNING = 'Yellow'
$script:COLOR_ERROR = 'Red'
$script:COLOR_INFO = 'Gray'

# Success Messages
$script:MSG_MODULE_LOADED = "Hvlib module loaded: Version {0}"
$script:MSG_LIBRARY_LOADED = "Library loaded successfully from: {0}"
$script:MSG_VM_SELECTED = "VM '{0}' selected successfully"
$script:MSG_VM_SUSPENDED = "VM suspended successfully"
$script:MSG_VM_RESUMED = "VM resumed successfully"
$script:MSG_FOUND_VMS = "Found {0} virtual machine(s):"
$script:MSG_FOUND_PROCESSES = "Found {0} process(es)"
$script:MSG_READ_SUCCESS = "Read {0} bytes from {1}"
$script:MSG_VALID_PE = "Valid PE header found (MZ signature)"
$script:MSG_PARTITION_CLOSED = "Partition closed successfully"
$script:MSG_ALL_CLOSED = "All partitions closed successfully"
$script:MSG_WRITE_SUCCESS = "Write operation successful"
$script:MSG_TRANSLATION_SUCCESS = "Translation successful: GVA → GPA"

# Error Messages
$script:ERR_DLL_NOT_FOUND = "DLL not found: {0}"
$script:ERR_MODULE_FAILED = "Failed to load Hvlib module"
$script:ERR_LIBRARY_FAILED = "Failed to load library from: {0}"
$script:ERR_VM_NOT_FOUND = "VM '{0}' not found or selection failed"
$script:ERR_NO_PARTITIONS = "No partitions found"
$script:ERR_SUSPEND_FAILED = "Failed to suspend VM"
$script:ERR_RESUME_FAILED = "Failed to resume VM"
$script:ERR_INVALID_HANDLE = "Invalid partition handle"

#endregion

#region Helper Functions

function ConvertTo-SafeUInt64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HexString
    )

    $varType = $HexString.GetType().Name

    if ($varType -eq "String")
    {
        return [System.String]::Format("{0:X}",[System.Convert]::ToUInt64($number))
    }
    if (($varType -eq "Int32") -or ($varType -eq "Int64") -or ($varType -eq "UInt64") -or ($varType -eq "UInt32"))
    {
        return [System.String]::Format("{0:X}",$number)
    }   
    
    return [System.Convert]::ToUInt64($HexString, 16)
}

function Write-SectionHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,
        
        [string]$Color = $script:COLOR_SECTION
    )
    
    Write-Host "`n=== $Title ===" -ForegroundColor $Color
}

function Write-MainHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title
    )
    
    $separator = '=' * 80
    Write-Host "`n$separator" -ForegroundColor $script:COLOR_HEADER
    Write-Host $Title -ForegroundColor $script:COLOR_HEADER
    Write-Host "$separator`n" -ForegroundColor $script:COLOR_HEADER
}

function Write-PropertyLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        $Value,
        
        [int]$Indent = 2
    )
    
    $prefix = ' ' * $Indent
    Write-Host "${prefix}${Name}: $Value"
}

function ConvertTo-HexString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint64]$Value
    )
    
    return "0x{0:X16}" -f $Value
}

function Test-ValidHandle {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [uint64]$Handle
    )
    
    return ($null -ne $Handle -and $Handle -ne 0)
}

function Get-SafeHandle {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        
        [string]$VmName = ''
    )
    
    if (Test-ValidHandle -Handle $Handle) {
        return $Handle
    }
    
    if ($VmName) {
        return Get-HvlibPartition -VmName $VmName
    }
    
    return $null
}

function Test-PESignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [byte[]]$Data
    )
    
    return ($Data.Length -ge 2 -and $Data[0] -eq 0x4D -and $Data[1] -eq 0x5A)
}

function Invoke-WithSuspend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({Test-ValidHandle -Handle $_})]
        [uint64]$Handle,
        
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )
    
    $suspended = Suspend-HvlibVm -PartitionHandle $Handle
    
    if (-not $suspended) {
        Write-Warning $script:ERR_SUSPEND_FAILED
        return $null
    }
    
    $result = & $ScriptBlock $Handle
    
    $resumed = Resume-HvlibVm -PartitionHandle $Handle
    if (-not $resumed) {
        Write-Warning $script:ERR_RESUME_FAILED
    }
    
    return $result
}

function Read-CpuRegister {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({Test-ValidHandle -Handle $_})]
        [uint64]$Handle,
        
        [Parameter(Mandatory)]
        [uint32]$RegisterCode,
        
        [uint32]$VpIndex = 0
    )
    
    $value = Get-HvlibVpRegister -PartitionHandle $Handle -VpIndex $VpIndex -RegisterCode $RegisterCode
    return if ($value) { $value.Reg64 } else { 0 }
}

function Show-RegisterSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({Test-ValidHandle -Handle $_})]
        [uint64]$Handle,
        
        [Parameter(Mandatory)]
        [string]$SetName,
        
        [Parameter(Mandatory)]
        [array]$Registers,
        
        [uint32]$VpIndex = 0
    )
    
    Write-Host "`n[ $SetName ]" -ForegroundColor $script:COLOR_SECTION
    
    foreach ($reg in $Registers) {
        $value = Read-CpuRegister -Handle $Handle -RegisterCode $reg.Code -VpIndex $VpIndex
        $label = "{0}:" -f $reg.Name
        Write-Host ("{0,-4} 0x{1:X16}" -f $label, $value)
    }
}

#endregion

#region Section 1: Library and Configuration Management

function Example-GetHvlib {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({Test-Path $_})]
        [string]$DllPath
    )
    
    Write-SectionHeader "Example 1.1: Get-Hvlib - Load Library"
    
    $result = Get-Hvlib -path_to_dll $DllPath
    
    if ($result) {
        Write-Host ($script:MSG_LIBRARY_LOADED -f $DllPath) -ForegroundColor $script:COLOR_SUCCESS
    } else {
        Write-Warning ($script:ERR_LIBRARY_FAILED -f $DllPath)
    }
    
    return $result
}

function Example-GetHvlibPreferredSettings {
    [CmdletBinding()]
    param()
    
    Write-SectionHeader "Example 1.2: Get-HvlibPreferredSettings"
    
    $config = Get-HvlibPreferredSettings
    
    if (-not $config) {
        Write-Warning "Failed to retrieve configuration"
        return $null
    }
    
    Write-Host "Configuration retrieved successfully:" -ForegroundColor $script:COLOR_SUCCESS
    Write-PropertyLine -Name "ReadMethod" -Value $config.ReadMethod
    Write-PropertyLine -Name "WriteMethod" -Value $config.WriteMethod
    Write-PropertyLine -Name "SuspendMethod" -Value $config.SuspendMethod
    Write-PropertyLine -Name "LogLevel" -Value $config.LogLevel
    Write-PropertyLine -Name "ForceFreezeCPU" -Value $config.ForceFreezeCPU
    Write-PropertyLine -Name "PausePartition" -Value $config.PausePartition
    Write-PropertyLine -Name "SimpleMemory" -Value $config.SimpleMemory
    
    return $config
}

#endregion

#region Section 2: Partition Enumeration and Selection

function Example-GetHvlibAllPartitions {
    [CmdletBinding()]
    param()
    
    Write-SectionHeader "Example 2.1: Get-HvlibAllPartitions"
    
    $partitions = Get-HvlibAllPartitions
    
    if (-not $partitions -or $partitions.Count -eq 0) {
        Write-Warning $script:ERR_NO_PARTITIONS
        return $null
    }
    
    Write-Host ($script:MSG_FOUND_VMS -f $partitions.Count) -ForegroundColor $script:COLOR_SUCCESS
    
    $partitions | Format-Table @{
        Label = "VM Name"
        Expression = { $_.VMName }
    }, @{
        Label = "Handle (Hex)"
        Expression = { ConvertTo-HexString -Value $_.VmHandle }
    } -AutoSize
    
    return $partitions
}

function Example-GetHvlibPartition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 2.2: Get-HvlibPartition"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    Write-Host ($script:MSG_VM_SELECTED -f $VmName) -ForegroundColor $script:COLOR_SUCCESS
    Write-PropertyLine -Name "Handle" -Value (ConvertTo-HexString -Value $handle)
    
    return $handle
}

function Example-SelectHvlibPartition {
    [CmdletBinding()]
    param()
    
    Write-SectionHeader "Example 2.3: Select-HvlibPartition"
    
    $partitions = Get-HvlibAllPartitions
    
    if (-not $partitions -or $partitions.Count -eq 0) {
        Write-Warning $script:ERR_NO_PARTITIONS
        return $null
    }
    
    $handle = $partitions[0].VmHandle
    $result = Select-HvlibPartition -PartitionHandle $handle
    
    if ($result) {
        Write-Host "Partition selected by handle:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "Handle" -Value (ConvertTo-HexString -Value $handle)
    }
    
    return $handle
}

#endregion

#region Section 3: Partition Information Retrieval

function Example-GetHvlibPartitionName {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 3.1: Get-HvlibPartitionName"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $name = Get-HvlibPartitionName -PartitionHandle $handle
    
    if ($name) {
        Write-Host "VM Name: $name" -ForegroundColor $script:COLOR_SUCCESS
    }
    
    return $name
}

function Example-GetHvlibPartitionGuid {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 3.2: Get-HvlibPartitionGuid"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $guid = Get-HvlibPartitionGuid -PartitionHandle $handle
    
    if ($guid) {
        Write-Host "VM GUID: $guid" -ForegroundColor $script:COLOR_SUCCESS
    }
    
    return $guid
}

function Example-GetHvlibPartitionId {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 3.3: Get-HvlibPartitionId"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $partitionId = Get-HvlibPartitionId -PartitionHandle $handle
    
    if ($partitionId) {
        Write-Host "Partition ID: $partitionId" -ForegroundColor $script:COLOR_SUCCESS
    }
    
    return $partitionId
}

function Example-GetHvlibData2-KernelBase {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 3.4: Get-HvlibData2 - Kernel Base"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    if ($kernelBase) {
        Write-Host "Kernel Base Address:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $kernelBase)
    }
    
    return $kernelBase
}

function Example-GetHvlibData2-CpuCount {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 3.5: Get-HvlibData2 - CPU Count"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $cpuCount = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddNumberOfCPU)
    
    if ($cpuCount) {
        Write-Host "Number of CPUs: $cpuCount" -ForegroundColor $script:COLOR_SUCCESS
    }
    
    return $cpuCount
}

function Example-GetHvlibData2-MultipleProperties {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 3.6: Get-HvlibData2 - Multiple Properties"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    $dtb = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddDirectoryTableBase)
    
    $maxPage = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddMmMaximumPhysicalPage)
    
    $cpuCount = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddNumberOfCPU)
    
    Write-Host "VM Properties:" -ForegroundColor $script:COLOR_SUCCESS
    Write-PropertyLine -Name "Kernel Base" -Value (ConvertTo-HexString -Value $kernelBase)
    Write-PropertyLine -Name "Directory Table Base" -Value (ConvertTo-HexString -Value $dtb)
    Write-PropertyLine -Name "Max Physical Page" -Value (ConvertTo-HexString -Value $maxPage)
    Write-PropertyLine -Name "CPU Count" -Value $cpuCount
    
    return @{
        KernelBase = $kernelBase
        DTB = $dtb
        MaxPage = $maxPage
        CpuCount = $cpuCount
    }
}

#endregion

#region Section 4: Physical Memory Operations

function Example-GetHvlibVmPhysicalMemory-Basic {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 4.1: Get-HvlibVmPhysicalMemory - Basic"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
        -start_position $script:ADDR_TEST_PHYSICAL -size $script:PAGE_SIZE
    
    if ($data) {
        $hexAddr = ConvertTo-HexString -Value $script:ADDR_TEST_PHYSICAL
        Write-Host ($script:MSG_READ_SUCCESS -f $data.Length, $hexAddr) -ForegroundColor $script:COLOR_SUCCESS
        Write-Host "First 64 bytes:" -ForegroundColor $script:COLOR_INFO
        $data[0..63] | Format-Hex
    }
    
    return $data
}

function Example-GetHvlibVmPhysicalMemory-Address {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = '',
        [uint64]$PhysicalAddress = 0x10000
    )
    
    Write-SectionHeader "Example 4.2: Get-HvlibVmPhysicalMemory - Specific Address"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
        -start_position $PhysicalAddress -size 0x100
    
    if ($data) {
        $hexAddr = ConvertTo-HexString -Value $PhysicalAddress
        Write-Host ($script:MSG_READ_SUCCESS -f $data.Length, $hexAddr) -ForegroundColor $script:COLOR_SUCCESS
        $data | Format-Hex
    }
    
    return $data
}

function Example-SetHvlibVmPhysicalMemoryBytes {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 4.3: Set-HvlibVmPhysicalMemoryBytes"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $testData = [byte[]]@(0x90, 0x90, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00)
    
    Write-Host "Writing $($testData.Length) bytes to physical address:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $script:ADDR_SAFE_TEST)
    Write-PropertyLine -Name "Data" -Value ($testData -join ', ')
    
    $result = Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $handle `
        -StartPosition $script:ADDR_SAFE_TEST -Data $testData
    
    if ($result) {
        Write-Host $script:MSG_WRITE_SUCCESS -ForegroundColor $script:COLOR_SUCCESS
        
        $verify = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
            -start_position $script:ADDR_SAFE_TEST -size $testData.Length
        
        Write-Host "Verification read:" -ForegroundColor $script:COLOR_INFO
        $verify | Format-Hex
    }
    
    return $result
}

function Example-SetHvlibVmPhysicalMemory-FromFile {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = '',
        [string]$FilePath = "$env:TEMP\hvlib_test_data.bin"
    )
    
    Write-SectionHeader "Example 4.4: Set-HvlibVmPhysicalMemory - From File"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "Creating test file: $FilePath" -ForegroundColor $script:COLOR_INFO
        $testData = [byte[]]@(0x4D, 0x5A, 0x90, 0x00)
        [System.IO.File]::WriteAllBytes($FilePath, $testData)
    }
    
    if (Test-Path $FilePath) {
        Write-Host "Writing data from file: $FilePath" -ForegroundColor $script:COLOR_INFO
        Set-HvlibVmPhysicalMemory -filename $FilePath -prtnHandle $handle
    }
}

#endregion

#region Section 5: Virtual Memory Operations

function Example-GetHvlibVmVirtualMemory-KUserSharedData {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 5.1: Get-HvlibVmVirtualMemory - KUSER_SHARED_DATA"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    # Convert hex string to UInt64
    $kuserAddress = ConvertTo-SafeUInt64 -HexString $script:ADDR_KUCER_SHARED_DATA
    
    $data = Get-HvlibVmVirtualMemory -prtnHandle $handle `
        -start_position $kuserAddress -size 0x100
    
    if ($data) {
        Write-Host ($script:MSG_READ_SUCCESS -f $data.Length, $script:ADDR_KUCER_SHARED_DATA) `
            -ForegroundColor $script:COLOR_SUCCESS
        Write-Host "First 64 bytes:" -ForegroundColor $script:COLOR_INFO
        $data[0..63] | Format-Hex
    }
    
    return $data
}

function Example-GetHvlibVmVirtualMemory-KernelAddress {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 5.2: Get-HvlibVmVirtualMemory - Kernel Address"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    if (-not $kernelBase) {
        Write-Warning "Failed to get kernel base address"
        return $null
    }
    
    Write-Host "Kernel Base:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $kernelBase)
    
    $data = Get-HvlibVmVirtualMemory -prtnHandle $handle `
        -start_position $kernelBase -size 0x200
    
    if ($data) {
        Write-Host "Read PE header ($($data.Length) bytes)" -ForegroundColor $script:COLOR_SUCCESS
        $data[0..63] | Format-Hex
        
        if (Test-PESignature -Data $data) {
            Write-Host $script:MSG_VALID_PE -ForegroundColor $script:COLOR_SUCCESS
        }
    }
    
    return $data
}

function Example-SetHvlibVmVirtualMemoryBytes {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 5.3: Set-HvlibVmVirtualMemoryBytes"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $targetAddress = 0xFFFFF80000100000
    $patch = [byte[]]@(0x90, 0x90, 0x90)
    
    Write-Host "WARNING: This is a demonstration only!" -ForegroundColor $script:COLOR_ERROR
    Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $targetAddress)
    Write-PropertyLine -Name "Patch data" -Value ($patch -join ', ')
    Write-Host "Skipped actual write for safety" -ForegroundColor $script:COLOR_WARNING
}

function Example-SetHvlibVmVirtualMemory-FromFile {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = '',
        [string]$FilePath = "$env:TEMP\hvlib_patch.bin"
    )
    
    Write-SectionHeader "Example 5.4: Set-HvlibVmVirtualMemory - From File"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "Creating test patch file: $FilePath" -ForegroundColor $script:COLOR_INFO
        $testData = [byte[]]@(0x90, 0x90, 0xC3)
        [System.IO.File]::WriteAllBytes($FilePath, $testData)
    }
    
    if (Test-Path $FilePath) {
        Write-Host "File prepared: $FilePath" -ForegroundColor $script:COLOR_INFO
        Write-Host "Skipped actual write for safety" -ForegroundColor $script:COLOR_WARNING
    }
}

#endregion

#region Section 6: Process and System Information

function Example-GetHvlibProcessesList {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 6.1: Get-HvlibProcessesList"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $processes = Get-HvlibProcessesList -PartitionHandle $handle
    
    if (-not $processes) {
        Write-Warning "Failed to get process list"
        return $null
    }
    
    $count = $processes.Length - 1
    Write-Host ($script:MSG_FOUND_PROCESSES -f $count) -ForegroundColor $script:COLOR_SUCCESS
    
    Write-Host "First 5 process entries:" -ForegroundColor $script:COLOR_INFO
    for ($i = 1; $i -lt [Math]::Min(6, $processes.Length); $i++) {
        Write-PropertyLine -Name "Process[$i]" -Value (ConvertTo-HexString -Value $processes[$i])
    }
    
    return $processes
}

function Example-GetHvlibCr3-Kernel {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 6.2: Get-HvlibCr3 - Kernel"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    # Convert hex string to UInt64
    $kernelPid = 4
    
    $cr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $kernelPid
    
    if ($cr3) {
        Write-Host "Kernel CR3:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $cr3)
    }
    
    return $cr3
}

function Example-GetHvlibCr3-Process {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = '',
        [uint64]$ProcessId = 1234
    )
    
    Write-SectionHeader "Example 6.4: Get-HvlibCr3 - Process"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return $null
    }
    
    $cr3 = Get-HvlibCr3 -PartitionHandle $handle -Pid $ProcessId
    
    if ($cr3) {
        Write-Host "Process $ProcessId CR3:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $cr3)
    } else {
        Write-Warning "Process $ProcessId not found or invalid"
    }
    
    return $cr3
}

#endregion

#region Section 7: Resource Management

function Example-CloseHvlibPartition {
    [CmdletBinding()]
    param(
        [uint64]$Handle = 0,
        [string]$VmName = ''
    )
    
    Write-SectionHeader "Example 7.1: Close-HvlibPartition"
    
    $handle = Get-SafeHandle -Handle $Handle -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning $script:ERR_INVALID_HANDLE
        return
    }
    
    Write-Host "Closing partition:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "Handle" -Value (ConvertTo-HexString -Value $handle)
    
    Close-HvlibPartition -handle $handle
    Write-Host $script:MSG_PARTITION_CLOSED -ForegroundColor $script:COLOR_SUCCESS
}

function Example-CloseHvlibPartitions {
    [CmdletBinding()]
    param()
    
    Write-SectionHeader "Example 7.2: Close-HvlibPartitions"
    
    Write-Host "Closing all partitions..." -ForegroundColor $script:COLOR_INFO
    Close-HvlibPartitions
    Write-Host $script:MSG_ALL_CLOSED -ForegroundColor $script:COLOR_SUCCESS
}

#endregion

#region Section 8: Utility Functions

function Example-GetHexValue {
    [CmdletBinding()]
    param()
    
    Write-SectionHeader "Example 8.1: Get-HexValue"
    
    $numbers = @(
        0x1000,
        65536,
        (ConvertTo-SafeUInt64 -HexString $script:ADDR_KUCER_SHARED_DATA),
        [uint64]::MaxValue
    )
    
    foreach ($num in $numbers) {
        $hex = Get-HexValue -num $num
        Write-Host "Decimal: $num => Hex: 0x$hex" -ForegroundColor $script:COLOR_SUCCESS
    }
}

#endregion

#region Section 9: VM State Control (v1.3.0)

function Example-SuspendHvlibVm-PowerShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 9.1: Suspend-HvlibVm - PowerShell Method"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    Write-Host "Suspending VM '$VmName'..." -ForegroundColor $script:COLOR_INFO
    
    $result = Suspend-HvlibVm -PartitionHandle $handle
    
    if ($result) {
        Write-Host $script:MSG_VM_SUSPENDED -ForegroundColor $script:COLOR_SUCCESS
        Write-Host "VM is now paused and ready for analysis" -ForegroundColor $script:COLOR_INFO
    } else {
        Write-Warning $script:ERR_SUSPEND_FAILED
    }
    
    Close-HvlibPartition -handle $handle
    return $result
}

function Example-SuspendHvlibVm-RegisterWrite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 9.2: Suspend-HvlibVm - Register Write Method"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $method = [Hvlibdotnet.Hvlib+SUSPEND_RESUME_METHOD]::SuspendResumeWriteSpecRegister
    
    $result = Suspend-HvlibVm -PartitionHandle $handle -Method $method
    
    if ($result) {
        Write-Host "VM suspended using register write method" -ForegroundColor $script:COLOR_SUCCESS
    }
    
    Close-HvlibPartition -handle $handle
    return $result
}

function Example-ResumeHvlibVm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 9.3: Resume-HvlibVm"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    Write-Host "Resuming VM '$VmName'..." -ForegroundColor $script:COLOR_INFO
    
    $result = Resume-HvlibVm -PartitionHandle $handle
    
    if ($result) {
        Write-Host $script:MSG_VM_RESUMED -ForegroundColor $script:COLOR_SUCCESS
        Write-Host "VM is now running normally" -ForegroundColor $script:COLOR_INFO
    } else {
        Write-Warning $script:ERR_RESUME_FAILED
    }
    
    Close-HvlibPartition -handle $handle
    return $result
}

function Example-SafeMemoryAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 9.4: Safe Memory Analysis with Suspend/Resume"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $result = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        Write-Host "1. Reading kernel base address..." -ForegroundColor $script:COLOR_INFO
        $kernelBase = Get-HvlibData2 -PartitionHandle $h `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
        
        Write-PropertyLine -Name "Kernel Base" -Value (ConvertTo-HexString -Value $kernelBase) -Indent 3
        
        Write-Host "2. Reading PE header..." -ForegroundColor $script:COLOR_INFO
        $peHeader = Get-HvlibVmVirtualMemory -prtnHandle $h `
            -start_position $kernelBase -size $script:PAGE_SIZE
        
        if ($peHeader -and (Test-PESignature -Data $peHeader)) {
            $mz = [System.Text.Encoding]::ASCII.GetString($peHeader[0..1])
            Write-PropertyLine -Name "PE Signature" -Value $mz -Indent 3
            
            Write-Host "3. First 64 bytes of PE header:" -ForegroundColor $script:COLOR_INFO
            $peHeader[0..63] | Format-Hex | Select-Object -First 4
        }
        
        return $peHeader
    }
    
    Close-HvlibPartition -handle $handle
    return $result
}

#endregion

#region Section 10: Advanced Memory Operations (v1.2.0)

function Example-GetHvlibPhysicalAddress-KernelVA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 10.1: Get-HvlibPhysicalAddress - Kernel VA"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $kernelVa = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    Write-Host "Kernel Virtual Address:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "VA" -Value (ConvertTo-HexString -Value $kernelVa)
    
    $kernelPa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $kernelVa
    
    if ($kernelPa -ne 0) {
        Write-Host "Kernel Physical Address:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "PA" -Value (ConvertTo-HexString -Value $kernelPa)
        Write-Host $script:MSG_TRANSLATION_SUCCESS -ForegroundColor $script:COLOR_INFO
        
        Write-Host "`nReading from physical address..." -ForegroundColor $script:COLOR_INFO
        $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
            -start_position $kernelPa -size 0x100
        
        if ($data) {
            Write-Host "Successfully read $($data.Length) bytes" -ForegroundColor $script:COLOR_SUCCESS
            $data[0..15] | Format-Hex
        }
    }
    
    Close-HvlibPartition -handle $handle
    return $kernelPa
}

function Example-GetHvlibPhysicalAddress-UserVA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName,
        
        [uint64]$UserVirtualAddress = 0x00007FF000000000
    )
    
    Write-SectionHeader "Example 10.2: Get-HvlibPhysicalAddress - User VA"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    Write-Host "User Virtual Address:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "VA" -Value (ConvertTo-HexString -Value $UserVirtualAddress)
    
    $userPa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $UserVirtualAddress
    
    if ($userPa -ne 0) {
        Write-Host "User Physical Address:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "PA" -Value (ConvertTo-HexString -Value $userPa)
    } else {
        Write-Host "Address translation failed (page may not be present)" -ForegroundColor $script:COLOR_INFO
    }
    
    Close-HvlibPartition -handle $handle
    return $userPa
}

function Example-GetHvlibPhysicalAddress-Batch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 10.3: Get-HvlibPhysicalAddress - Batch Translation"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    $addresses = @(
        @{Name = "Kernel Base"; VA = $kernelBase}
        @{Name = "Kernel +0x1000"; VA = $kernelBase + $script:PAGE_SIZE}
        @{Name = "Kernel +0x10000"; VA = $kernelBase + 0x10000}
    )
    
    Write-Host "Translating multiple addresses..." -ForegroundColor $script:COLOR_INFO
    Write-Host ("{0,-20} {1,-18} {2,-18}" -f "Name", "Virtual Address", "Physical Address") `
        -ForegroundColor $script:COLOR_SECTION
    Write-Host ('-' * 60) -ForegroundColor $script:COLOR_INFO
    
    foreach ($addr in $addresses) {
        $pa = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $addr.VA
        
        $vaStr = ConvertTo-HexString -Value $addr.VA
        $paStr = if ($pa -ne 0) { ConvertTo-HexString -Value $pa } else { "Failed" }
        
        Write-Host ("{0,-20} {1,-18} {2,-18}" -f $addr.Name, $vaStr, $paStr)
    }
    
    Close-HvlibPartition -handle $handle
}

function Example-SetHvlibPartitionData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 10.4: Set-HvlibPartitionData"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    Write-Host "Setting partition data..." -ForegroundColor $script:COLOR_INFO
    Write-Warning "This is an advanced operation - use with caution!"
    
    $result = Set-HvlibPartitionData `
        -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddSetMemoryBlock) `
        -Information 1
    
    if ($result -ne 0) {
        Write-Host "Partition data set successfully: $result" -ForegroundColor $script:COLOR_SUCCESS
    } else {
        Write-Warning "Failed to set partition data"
    }
    
    Close-HvlibPartition -handle $handle
    return $result
}

#endregion

#region Section 11: VM Introspection (v1.2.0)

function Example-GetHvlibMachineType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 11.1: Get-HvlibMachineType"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $machineType = Get-HvlibMachineType -PartitionHandle $handle
    
    Write-Host "VM Name: $VmName" -ForegroundColor $script:COLOR_INFO
    Write-Host "Machine Type: $machineType" -ForegroundColor $script:COLOR_SUCCESS
    
    switch ($machineType) {
        'MACHINE_AMD64' {
            Write-PropertyLine -Name "Architecture" -Value "64-bit Virtual Machine"
            Write-PropertyLine -Name "Tools" -Value "Use x64 analysis tools"
        }
        'MACHINE_X86' {
            Write-PropertyLine -Name "Architecture" -Value "32-bit Virtual Machine"
            Write-PropertyLine -Name "Tools" -Value "Use x86 analysis tools"
        }
        'MACHINE_UNKNOWN' {
            Write-PropertyLine -Name "Architecture" -Value "Unknown architecture"
        }
        'MACHINE_UNSUPPORTED' {
            Write-PropertyLine -Name "Architecture" -Value "Unsupported architecture"
        }
    }
    
    Close-HvlibPartition -handle $handle
    return $machineType
}

function Example-GetHvlibMachineType-Report {
    [CmdletBinding()]
    param()
    
    Write-SectionHeader "Example 11.2: Get-HvlibMachineType - All VMs Report"
    
    $vms = Get-HvlibAllPartitions
    
    if (-not $vms -or $vms.Count -eq 0) {
        Write-Warning $script:ERR_NO_PARTITIONS
        return $null
    }
    
    Write-Host "`nVM Architecture Report:" -ForegroundColor $script:COLOR_INFO
    Write-Host ("{0,-30} {1,-20}" -f "VM Name", "Architecture") -ForegroundColor $script:COLOR_SECTION
    Write-Host ('-' * 50) -ForegroundColor $script:COLOR_INFO
    
    foreach ($vm in $vms) {
        Select-HvlibPartition -PartitionHandle $vm.VmHandle | Out-Null
        $machineType = Get-HvlibMachineType -PartitionHandle $vm.VmHandle
        
        $arch = switch ($machineType) {
            'MACHINE_AMD64' { "64-bit (x64)" }
            'MACHINE_X86' { "32-bit (x86)" }
            default { "Unknown" }
        }
        
        Write-Host ("{0,-30} {1,-20}" -f $vm.VMName, $arch)
        Close-HvlibPartition -handle $vm.VmHandle
    }
}

function Example-GetHvlibCurrentVtl-KernelBase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 11.3: Get-HvlibCurrentVtl - Kernel Base"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    Write-Host "Kernel Base:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $kernelBase)
    
    $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $kernelBase
    
    Write-Host "VTL Level: $vtl" -ForegroundColor $script:COLOR_SUCCESS
    
    switch ($vtl) {
        'Vtl0' {
            Write-PropertyLine -Name "Location" -Value "VTL0 (Normal Kernel)"
            Write-PropertyLine -Name "Description" -Value "Standard Windows kernel space"
        }
        'Vtl1' {
            Write-PropertyLine -Name "Location" -Value "VTL1 (Secure Kernel)"
            Write-PropertyLine -Name "Description" -Value "Virtual Secure Mode (VBS/VSM) is active"
            Write-Host "  → This VM has security features enabled" -ForegroundColor $script:COLOR_WARNING
        }
        'BadVtl' {
            Write-PropertyLine -Name "Status" -Value "Invalid VTL or address not accessible"
        }
    }
    
    Close-HvlibPartition -handle $handle
    return $vtl
}

function Example-GetHvlibCurrentVtl-VBSDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 11.4: Get-HvlibCurrentVtl - VBS Detection"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    $addresses = @(
        @{Name = "Kernel Base"; Addr = $kernelBase}
        @{Name = "Kernel +0x100000"; Addr = $kernelBase + 0x100000}
    )
    
    Write-Host "Checking VTL levels for VBS detection..." -ForegroundColor $script:COLOR_INFO
    
    $hasVtl1 = $false
    foreach ($addr in $addresses) {
        $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $addr.Addr
        Write-PropertyLine -Name $addr.Name -Value $vtl
        
        if ($vtl -eq 'Vtl1') {
            $hasVtl1 = $true
        }
    }
    
    Write-Host "`nVBS Status:" -ForegroundColor $script:COLOR_INFO
    if ($hasVtl1) {
        Write-Host "  ✓ Virtual Based Security (VBS) is ENABLED" -ForegroundColor $script:COLOR_SUCCESS
        Write-Host "  ✓ Secure kernel (VTL1) detected" -ForegroundColor $script:COLOR_SUCCESS
    } else {
        Write-Host "  ✗ Virtual Based Security (VBS) is NOT detected" -ForegroundColor $script:COLOR_INFO
        Write-Host "  ✗ Running in standard mode (VTL0 only)" -ForegroundColor $script:COLOR_INFO
    }
    
    Close-HvlibPartition -handle $handle
    return $hasVtl1
}

#endregion

#region Section 12: CPU Register Access (v1.2.0)

function Example-GetHvlibVpRegister-RIP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 12.1: Get-HvlibVpRegister - RIP"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $rip = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        $ripValue = Read-CpuRegister -Handle $h -RegisterCode $script:REG_RIP -VpIndex 0
        
        Write-Host "RIP (Instruction Pointer):" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $ripValue)
        Write-PropertyLine -Name "Description" -Value "Current execution address on CPU #0"
        
        return $ripValue
    }
    
    Close-HvlibPartition -handle $handle
    return $rip
}

function Example-GetHvlibVpRegister-GPRs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 12.2: Get-HvlibVpRegister - General Purpose Registers"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $registers = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        Write-Host "General Purpose Registers (CPU #0):" -ForegroundColor $script:COLOR_INFO
        Write-Host ("{0,-6} {1,-18}" -f "Reg", "Value") -ForegroundColor $script:COLOR_SECTION
        Write-Host ('-' * 26) -ForegroundColor $script:COLOR_INFO
        
        $result = @{}
        foreach ($reg in $script:GPR_REGISTERS | Sort-Object Name) {
            $value = Read-CpuRegister -Handle $h -RegisterCode $reg.Code -VpIndex 0
            $result[$reg.Name] = $value
            Write-Host ("{0,-6} 0x{1:X16}" -f $reg.Name, $value)
        }
        
        return $result
    }
    
    Close-HvlibPartition -handle $handle
    return $registers
}

function Example-GetHvlibVpRegister-ControlRegisters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 12.3: Get-HvlibVpRegister - Control Registers"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $registers = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        Write-Host "Control Registers (CPU #0):" -ForegroundColor $script:COLOR_INFO
        Write-Host ("{0,-6} {1,-18} {2}" -f "Reg", "Value", "Description") `
            -ForegroundColor $script:COLOR_SECTION
        Write-Host ('-' * 60) -ForegroundColor $script:COLOR_INFO
        
        $result = @{}
        foreach ($reg in $script:CONTROL_REGISTERS | Sort-Object Name) {
            $value = Read-CpuRegister -Handle $h -RegisterCode $reg.Code -VpIndex 0
            $result[$reg.Name] = $value
            Write-Host ("{0,-6} 0x{1:X16} {2}" -f $reg.Name, $value, $reg.Desc)
        }
        
        return $result
    }
    
    Close-HvlibPartition -handle $handle
    return $registers
}

function Example-GetHvlibVpRegister-FullContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 12.4: Get-HvlibVpRegister - Full CPU Context"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $context = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        Write-MainHeader "CPU Context for VP0"
        
        # Special registers
        Write-Host "`n[ Special Registers ]" -ForegroundColor $script:COLOR_SECTION
        $rip = Read-CpuRegister -Handle $h -RegisterCode $script:REG_RIP -VpIndex 0
        $rflags = Read-CpuRegister -Handle $h -RegisterCode $script:REG_RFLAGS -VpIndex 0
        Write-Host ("RIP:    0x{0:X16}" -f $rip)
        Write-Host ("RFLAGS: 0x{0:X16}" -f $rflags)
        
        # General purpose registers
        Show-RegisterSet -Handle $h -SetName "General Purpose Registers" `
            -Registers $script:GPR_REGISTERS -VpIndex 0
        
        # Control registers
        Show-RegisterSet -Handle $h -SetName "Control Registers" `
            -Registers $script:CONTROL_REGISTERS -VpIndex 0
        
        return @{
            RIP = $rip
            RFLAGS = $rflags
        }
    }
    
    Close-HvlibPartition -handle $handle
    return $context
}

function Example-SetHvlibVpRegister-RIP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 12.5: Set-HvlibVpRegister - RIP (Demonstration)"
    
    Write-Warning "This is a DANGEROUS operation - modifying RIP will change execution flow!"
    Write-Host "This example is for demonstration only" -ForegroundColor $script:COLOR_WARNING
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        $currentRip = Read-CpuRegister -Handle $h -RegisterCode $script:REG_RIP -VpIndex 0
        Write-Host "Current RIP:" -ForegroundColor $script:COLOR_INFO
        Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $currentRip)
        
        $newRipValue = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
        $newRipValue.Reg64 = $currentRip + 0x10
        
        Write-Host "New RIP would be:" -ForegroundColor $script:COLOR_INFO
        Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $newRipValue.Reg64)
        Write-Host "NOT actually writing (demonstration only)" -ForegroundColor $script:COLOR_ERROR
    }
    
    Close-HvlibPartition -handle $handle
}

function Example-SetHvlibVpRegister-Breakpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Example 12.6: Set-HvlibVpRegister - Hardware Breakpoint"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $result = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        $kernelBase = Get-HvlibData2 -PartitionHandle $h `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
        
        $breakpointAddr = $kernelBase + $script:PAGE_SIZE
        
        Write-Host "Setting hardware breakpoint at:" -ForegroundColor $script:COLOR_INFO
        Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $breakpointAddr)
        
        $dr0 = New-Object Hvlibdotnet.Hvlib+HV_REGISTER_VALUE
        $dr0.Reg64 = $breakpointAddr
        
        $setResult = Set-HvlibVpRegister -PartitionHandle $h -VpIndex 0 `
            -RegisterCode $script:REG_DR0 -RegisterValue $dr0
        
        if ($setResult) {
            Write-Host "Hardware breakpoint set in DR0" -ForegroundColor $script:COLOR_SUCCESS
            Write-Host "Note: DR7 must also be configured to enable the breakpoint" -ForegroundColor $script:COLOR_INFO
        }
        
        return $setResult
    }
    
    Close-HvlibPartition -handle $handle
    return $result
}

#endregion

#region Section 13: Symbol Operations (v1.5.0)

function Example-GetHvlibSymbolAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName,

        [string]$SymbolFullName = "nt!MmCopyVirtualMemory"
    )

    Write-SectionHeader "Example 13.1: Get-HvlibSymbolAddress"

    $handle = Get-HvlibPartition -VmName $VmName

    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }

    Write-Host "Resolving symbol: $SymbolFullName" -ForegroundColor $script:COLOR_INFO

    $address = Get-HvlibSymbolAddress $handle $SymbolFullName

    if ($address -and $address -ne 0) {
        Write-Host "Symbol resolved successfully:" -ForegroundColor $script:COLOR_SUCCESS
        Write-PropertyLine -Name "Symbol"  -Value $SymbolFullName
        Write-PropertyLine -Name "Address" -Value (ConvertTo-HexString -Value $address)
    } else {
        Write-Warning "Symbol '$SymbolFullName' not found"
    }

    Close-HvlibPartition -handle $handle
    return $address
}

function Example-GetHvlibSymbolAddress-Multiple {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )

    Write-SectionHeader "Example 13.2: Get-HvlibSymbolAddress - Multiple Symbols"

    $handle = Get-HvlibPartition -VmName $VmName

    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }

    $symbolNames = @(
        "winhv!WinHvAllocateOverlayPages"
        "winhv!WinHvpDllLoadSuccessful"
        "nt!MmCopyVirtualMemory"
        "nt!PsGetProcessPeb"
    )

    Write-Host ("{0,-45} {1}" -f "Symbol", "Address") -ForegroundColor $script:COLOR_SECTION
    Write-Host ('-' * 65) -ForegroundColor $script:COLOR_INFO

    $resolved = @{}
    foreach ($sym in $symbolNames) {
        $addr = Get-HvlibSymbolAddress $handle $sym
        $addrStr = if ($addr -and $addr -ne 0) { ConvertTo-HexString -Value $addr } else { "Not found" }
        Write-Host ("{0,-45} {1}" -f $sym, $addrStr)
        $resolved[$sym] = $addr
    }

    Close-HvlibPartition -handle $handle
    return $resolved
}

function Example-GetHvlibAllSymbols {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName,

        [string]$DriverName = "winhv"
    )

    Write-SectionHeader "Example 13.3: Get-HvlibAllSymbols"

    $handle = Get-HvlibPartition -VmName $VmName

    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }

    Write-Host "Enumerating symbols for: $DriverName" -ForegroundColor $script:COLOR_INFO

    $symbols = Get-HvlibAllSymbols $handle $DriverName

    if ($symbols -and $symbols.Count -gt 0) {
        Write-Host "Total symbols: $($symbols.Count)" -ForegroundColor $script:COLOR_SUCCESS

        Write-Host "`nFirst 10 symbols:" -ForegroundColor $script:COLOR_INFO
        Write-Host ("{0,-50} {1,-18} {2}" -f "Name", "Address", "Size") -ForegroundColor $script:COLOR_SECTION
        Write-Host ('-' * 80) -ForegroundColor $script:COLOR_INFO

        $symbols | Select-Object -First 10 | ForEach-Object {
            Write-Host ("{0,-50} {1,-18} {2}" -f $_.Name, $_.Address, $_.Size)
        }
    } else {
        Write-Warning "No symbols found for '$DriverName'"
    }

    Close-HvlibPartition -handle $handle
    return $symbols
}

function Example-GetHvlibSymbolTableLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )

    Write-SectionHeader "Example 13.4: Get-HvlibSymbolTableLength"

    $handle = Get-HvlibPartition -VmName $VmName

    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }

    $drivers = @('ntoskrnl', 'winhv', 'kdcom', 'mcupdate', 'securekernel')

    Write-Host ("{0,-20} {1}" -f "Driver", "Symbol Count") -ForegroundColor $script:COLOR_SECTION
    Write-Host ('-' * 35) -ForegroundColor $script:COLOR_INFO

    $counts = @{}
    foreach ($drv in $drivers) {
        $count = Get-HvlibSymbolTableLength $handle $drv
        $counts[$drv] = $count
        if ($count -gt 0) {
            Write-Host ("{0,-20} {1}" -f $drv, $count) -ForegroundColor $script:COLOR_SUCCESS
        } else {
            Write-Host ("{0,-20} {1}" -f $drv, "N/A") -ForegroundColor $script:COLOR_WARNING
        }
    }

    Close-HvlibPartition -handle $handle
    return $counts
}

#endregion

#region Advanced Workflows

function Workflow-SymbolAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName,

        [string[]]$DriverNames = @('ntoskrnl', 'winhv', 'kdcom')
    )

    Write-MainHeader "WORKFLOW: Symbol Analysis (v1.5.0)"

    $handle = Get-HvlibPartition -VmName $VmName

    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }

    # Step 1: Symbol counts
    Write-Host "Step 1: Symbol table sizes..." -ForegroundColor $script:COLOR_SECTION
    Write-Host ("{0,-20} {1}" -f "Driver", "Symbols") -ForegroundColor $script:COLOR_INFO
    Write-Host ('-' * 35) -ForegroundColor $script:COLOR_INFO

    foreach ($drv in $DriverNames) {
        $count = Get-HvlibSymbolTableLength $handle $drv
        $countStr = if ($count -gt 0) { $count.ToString() } else { "N/A" }
        Write-Host ("{0,-20} {1}" -f $drv, $countStr)
    }

    # Step 2: Key symbol resolution
    Write-Host "`nStep 2: Resolving key symbols..." -ForegroundColor $script:COLOR_SECTION

    $keySymbols = @(
        "winhv!WinHvAllocateOverlayPages"
        "winhv!WinHvpDllLoadSuccessful"
        "nt!MmCopyVirtualMemory"
        "nt!KeBugCheckEx"
    )

    $resolved = @{}
    foreach ($sym in $keySymbols) {
        $addr = Get-HvlibSymbolAddress $handle $sym
        if ($addr -and $addr -ne 0) {
            $resolved[$sym] = $addr
        }
    }

    # Step 3: Full enum for first driver with symbols
    Write-Host "`nStep 3: Full symbol enumeration for '$($DriverNames[0])'..." -ForegroundColor $script:COLOR_SECTION
    $symbols = Get-HvlibAllSymbols $handle $DriverNames[0]

    if ($symbols -and $symbols.Count -gt 0) {
        Write-PropertyLine -Name "Total symbols" -Value $symbols.Count
        Write-PropertyLine -Name "First symbol"  -Value $symbols[0].Name
        Write-PropertyLine -Name "Last symbol"   -Value $symbols[$symbols.Count - 1].Name
    }

    Close-HvlibPartition -handle $handle

    Write-Host "`nSymbol analysis completed." -ForegroundColor $script:COLOR_SUCCESS
    return @{
        Counts   = $counts
        Resolved = $resolved
        Symbols  = $symbols
    }
}

function Workflow-DebugSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-MainHeader "WORKFLOW: Complete VM Debugging Session (v1.2.0)"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    # Step 1: Architecture detection
    Write-Host "Step 1: Detecting VM architecture..." -ForegroundColor $script:COLOR_SECTION
    $machineType = Get-HvlibMachineType -PartitionHandle $handle
    Write-PropertyLine -Name "Architecture" -Value $machineType -Indent 0
    
    # Step 2: VBS check
    Write-Host "`nStep 2: Checking for Virtual Based Security..." -ForegroundColor $script:COLOR_SECTION
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    $vtl = Get-HvlibCurrentVtl -PartitionHandle $handle -VirtualAddress $kernelBase
    Write-PropertyLine -Name "VTL Level" -Value $vtl -Indent 0
    
    # Steps 3-7: With suspend
    $result = Invoke-WithSuspend -Handle $handle -ScriptBlock {
        param($h)
        
        # Step 4: CPU context
        Write-Host "`nStep 4: Reading CPU context..." -ForegroundColor $script:COLOR_SECTION
        $rip = Read-CpuRegister -Handle $h -RegisterCode $script:REG_RIP -VpIndex 0
        $cr3 = Read-CpuRegister -Handle $h -RegisterCode $script:REG_CR3 -VpIndex 0
        Write-PropertyLine -Name "RIP" -Value (ConvertTo-HexString -Value $rip) -Indent 0
        Write-PropertyLine -Name "CR3" -Value (ConvertTo-HexString -Value $cr3) -Indent 0
        
        # Step 5: Address translation
        Write-Host "`nStep 5: Translating virtual to physical addresses..." -ForegroundColor $script:COLOR_SECTION
        $kernelPa = Get-HvlibPhysicalAddress -PartitionHandle $h -VirtualAddress $kernelBase
        Write-PropertyLine -Name "Kernel VA" -Value (ConvertTo-HexString -Value $kernelBase) -Indent 0
        Write-PropertyLine -Name "Kernel PA" -Value (ConvertTo-HexString -Value $kernelPa) -Indent 0
        
        # Step 6: Memory read
        Write-Host "`nStep 6: Reading memory from physical address..." -ForegroundColor $script:COLOR_SECTION
        $memData = Get-HvlibVmPhysicalMemory -prtnHandle $h -start_position $kernelPa -size 0x100
        Write-PropertyLine -Name "Bytes read" -Value $memData.Length -Indent 0
        
        return @{
            RIP = $rip
            CR3 = $cr3
            KernelPA = $kernelPa
        }
    }
    
    Close-HvlibPartition -handle $handle
    Write-Host "`nDebug session completed successfully!" -ForegroundColor $script:COLOR_SUCCESS
    
    return $result
}

function Workflow-MultiVmReport {
    [CmdletBinding()]
    param()
    
    Write-MainHeader "WORKFLOW: Multi-VM Analysis Report (v1.3.0)"
    
    $vms = Get-HvlibAllPartitions
    
    if (-not $vms -or $vms.Count -eq 0) {
        Write-Warning $script:ERR_NO_PARTITIONS
        return $null
    }
    
    Write-Host ("{0,-25} {1,-12} {2,-10} {3}" -f "VM Name", "Architecture", "VTL", "Kernel Base") `
        -ForegroundColor $script:COLOR_SECTION
    Write-Host ('-' * 75) -ForegroundColor $script:COLOR_INFO
    
    $report = foreach ($vm in $vms) {
        Select-HvlibPartition -PartitionHandle $vm.VmHandle | Out-Null
        
        $machineType = Get-HvlibMachineType -PartitionHandle $vm.VmHandle
        $arch = if ($machineType -eq 'MACHINE_AMD64') { "x64" } else { "x86" }
        
        $kernelBase = Get-HvlibData2 -PartitionHandle $vm.VmHandle `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
        
        $vtl = Get-HvlibCurrentVtl -PartitionHandle $vm.VmHandle -VirtualAddress $kernelBase
        
        $kernelStr = ConvertTo-HexString -Value $kernelBase
        Write-Host ("{0,-25} {1,-12} {2,-10} {3}" -f $vm.VMName, $arch, $vtl, $kernelStr)
        
        Close-HvlibPartition -handle $vm.VmHandle
        
        [PSCustomObject]@{
            VMName = $vm.VMName
            Architecture = $arch
            VTL = $vtl
            KernelBase = $kernelStr
        }
    }
    
    return $report
}

function Workflow-VmInformationReport {
    [CmdletBinding()]
    param()
    
    Write-MainHeader "WORKFLOW: VM Information Report"
    
    $vms = Get-HvlibAllPartitions
    
    if (-not $vms -or $vms.Count -eq 0) {
        Write-Warning $script:ERR_NO_PARTITIONS
        return $null
    }
    
    $report = foreach ($vm in $vms) {
        $handle = $vm.VmHandle
        
        $name = Get-HvlibPartitionName -PartitionHandle $handle
        $guid = Get-HvlibPartitionGuid -PartitionHandle $handle
        $partitionId = Get-HvlibPartitionId -PartitionHandle $handle
        
        $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
        
        $cpuCount = Get-HvlibData2 -PartitionHandle $handle `
            -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddNumberOfCPU)
        
        [PSCustomObject]@{
            Name = $name
            GUID = $guid
            PartitionID = $partitionId
            Handle = ConvertTo-HexString -Value $handle
            KernelBase = ConvertTo-HexString -Value $kernelBase
            CPUs = $cpuCount
        }
    }
    
    Write-Host "`nVM Information Report:" -ForegroundColor $script:COLOR_SUCCESS
    $report | Format-Table -AutoSize
    
    Close-HvlibPartitions
    return $report
}

function Workflow-MemoryAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-MainHeader "WORKFLOW: Memory Analysis"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $kernelBase = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddKernelBase)
    
    $maxPage = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddMmMaximumPhysicalPage)
    
    Write-Host "`nMemory Layout:" -ForegroundColor $script:COLOR_SUCCESS
    Write-PropertyLine -Name "Kernel Base" -Value (ConvertTo-HexString -Value $kernelBase)
    Write-PropertyLine -Name "Max Physical Page" -Value (ConvertTo-HexString -Value $maxPage)
    
    $totalMemoryMB = [Math]::Round(($maxPage * $script:PAGE_SIZE) / $script:MB_SIZE, 2)
    Write-PropertyLine -Name "Total Physical Memory" -Value "~$totalMemoryMB MB"
    
    $peHeader = Get-HvlibVmVirtualMemory -prtnHandle $handle `
        -start_position $kernelBase -size 0x200
    
    if ($peHeader -and (Test-PESignature -Data $peHeader)) {
        Write-PropertyLine -Name "Kernel PE Header" -Value "Valid (MZ signature found)"
    }
    
    $kuserAddress = ConvertTo-SafeUInt64 -HexString $script:ADDR_KUCER_SHARED_DATA
    $kuserData = Get-HvlibVmVirtualMemory -prtnHandle $handle `
        -start_position $kuserAddress -size 0x100
    
    if ($kuserData) {
        Write-PropertyLine -Name "KUSER_SHARED_DATA" -Value "Accessible"
    }
    
    Close-HvlibPartition -handle $handle
}

function Workflow-ProcessIntrospection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-MainHeader "WORKFLOW: Process Introspection"
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $kernelPid = ConvertTo-SafeUInt64 -HexString $script:PID_KERNEL
    $kernelCr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $kernelPid
    Write-Host "Kernel CR3:" -ForegroundColor $script:COLOR_SUCCESS
    Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $kernelCr3)
    
    $hypervisorPid = ConvertTo-SafeUInt64 -HexString $script:PID_HYPERVISOR
    $hvCr3 = Get-HvlibCr3 -PartitionHandle $handle -ProcessId $hypervisorPid
    Write-Host "Hypervisor CR3:" -ForegroundColor $script:COLOR_SUCCESS
    Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $hvCr3)
    
    $processes = Get-HvlibProcessesList -PartitionHandle $handle
    
    if ($processes) {
        $count = $processes.Length - 1
        Write-Host "`n$($script:MSG_FOUND_PROCESSES -f $count)" -ForegroundColor $script:COLOR_SUCCESS
    }
    
    Close-HvlibPartition -handle $handle
}

function Workflow-SafeMemoryDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName,
        
        [string]$OutputPath = "$env:TEMP\hvlib_memdump",
        
        [int]$PageCount = 10
    )
    
    Write-MainHeader "WORKFLOW: Safe Memory Dump"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return $null
    }
    
    $maxPage = Get-HvlibData2 -PartitionHandle $handle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddMmMaximumPhysicalPage)
    
    Write-Host "Max physical page:" -ForegroundColor $script:COLOR_INFO
    Write-PropertyLine -Name "Value" -Value (ConvertTo-HexString -Value $maxPage)
    
    $pagesToDump = [Math]::Min($PageCount, $maxPage)
    
    Write-Host "Dumping first $pagesToDump pages..." -ForegroundColor $script:COLOR_INFO
    
    for ($page = 0; $page -lt $pagesToDump; $page++) {
        $address = $page * $script:PAGE_SIZE
        $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
            -start_position $address -size $script:PAGE_SIZE
        
        if ($data) {
            $fileName = "page_{0:X4}.bin" -f $page
            $filePath = Join-Path $OutputPath $fileName
            [System.IO.File]::WriteAllBytes($filePath, $data)
            
            Write-Host "  Dumped page $page to $fileName" -ForegroundColor $script:COLOR_SUCCESS
        }
    }
    
    Write-Host "`nMemory dump completed: $OutputPath" -ForegroundColor $script:COLOR_SUCCESS
    Close-HvlibPartition -handle $handle
}

#endregion

#region Main Execution Functions

function Import-HvlibModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({Test-Path $_})]
        [string]$DllPath
    )
    
    if (-not (Test-Path $DllPath)) {
        Write-Warning ($script:ERR_DLL_NOT_FOUND -f $DllPath)
        return $false
    }
    
    $module = Import-Module -FullyQualifiedName @{
        ModuleName = $script:MODULE_NAME
        ModuleVersion = $script:MODULE_VERSION
    } -PassThru
    
    if (-not $module) {
        Write-Warning $script:ERR_MODULE_FAILED
        return $false
    }
    
    Write-Host ($script:MSG_MODULE_LOADED -f $module.Version) -ForegroundColor $script:COLOR_SUCCESS
    
    $result = Get-Hvlib -path_to_dll $DllPath
    
    if (-not $result) {
        Write-Warning ($script:ERR_LIBRARY_FAILED -f $DllPath)
        return $false
    }
    
    Write-Host ($script:MSG_LIBRARY_LOADED -f $DllPath) -ForegroundColor $script:COLOR_SUCCESS
    return $true
}

function Invoke-AllExamples {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName,
        
        [Parameter(Mandatory)]
        [ValidateScript({Test-Path $_})]
        [string]$DllPath,
        
        [switch]$SkipMemoryWrites
    )
    
    Write-MainHeader "Hvlib PowerShell Module - Complete Examples Demonstration v$script:MODULE_VERSION"
    
    if (-not (Import-HvlibModule -DllPath $DllPath)) {
        Write-Error "Failed to import Hvlib module. Aborting."
        return
    }
    
    # Section 1: Library and Configuration
    Example-GetHvlib -DllPath $DllPath
    Example-GetHvlibPreferredSettings
    
    # Section 2: Partition Enumeration
    $partitions = Example-GetHvlibAllPartitions
    
    if (-not $partitions -or $partitions.Count -eq 0) {
        Write-Warning "No VMs found. Cannot continue with examples."
        return
    }
    
    $testHandle = Example-GetHvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $testHandle)) {
        Write-Warning "Failed to get VM handle. Cannot continue with examples."
        return
    }
    
    # Section 3: Information Retrieval
    Example-GetHvlibPartitionName -Handle $testHandle
    Example-GetHvlibPartitionGuid -Handle $testHandle
    Example-GetHvlibPartitionId -Handle $testHandle
    Example-GetHvlibData2-KernelBase -Handle $testHandle
    Example-GetHvlibData2-CpuCount -Handle $testHandle
    Example-GetHvlibData2-MultipleProperties -Handle $testHandle
    
    # Section 4: Physical Memory Operations
    $data = Example-GetHvlibVmPhysicalMemory-Basic -Handle $testHandle
    $data = Example-GetHvlibVmPhysicalMemory-Address -Handle $testHandle
    
    if (-not $SkipMemoryWrites) {
        Write-Host "`nWARNING: Memory write examples will be executed" -ForegroundColor $script:COLOR_ERROR
        Example-SetHvlibVmPhysicalMemoryBytes -Handle $testHandle
    }
    
    # Section 5: Virtual Memory Operations
    $data = Example-GetHvlibVmVirtualMemory-KUserSharedData -Handle $testHandle
    $data = Example-GetHvlibVmVirtualMemory-KernelAddress -Handle $testHandle
    
    # Section 6: Process Information
    Example-GetHvlibProcessesList -Handle $testHandle
    Example-GetHvlibCr3-Kernel -Handle $testHandle
    
    # Section 8: Utilities
    Example-GetHexValue
    
    # Cleanup
    Example-CloseHvlibPartition -Handle $testHandle
    
    # Workflows
    Workflow-VmInformationReport
    Workflow-MemoryAnalysis -VmName $VmName
    Workflow-ProcessIntrospection -VmName $VmName

    # Section 13: Symbol Operations
    Example-GetHvlibSymbolAddress -VmName $VmName
    Example-GetHvlibSymbolAddress-Multiple -VmName $VmName
    Example-GetHvlibAllSymbols -VmName $VmName
    Example-GetHvlibSymbolTableLength -VmName $VmName

    # Symbol Workflow
    Workflow-SymbolAnalysis -VmName $VmName

    # Final cleanup
    Example-CloseHvlibPartitions
    
    Write-MainHeader "All examples completed successfully!"
}

function Invoke-QuickStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({Test-Path $_})]
        [string]$DllPath,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VmName
    )
    
    Write-SectionHeader "Quick Start Example"
    
    if (-not (Import-HvlibModule -DllPath $DllPath)) {
        return
    }
    
    $handle = Get-HvlibPartition -VmName $VmName
    
    if (-not (Test-ValidHandle -Handle $handle)) {
        Write-Warning ($script:ERR_VM_NOT_FOUND -f $VmName)
        return
    }
    
    $data = Get-HvlibVmPhysicalMemory -prtnHandle $handle `
        -start_position 0x10000 -size $script:PAGE_SIZE
    
    if ($data) {
        Write-Host "Successfully read $($data.Length) bytes" -ForegroundColor $script:COLOR_SUCCESS
        $data | Format-Hex | Select-Object -First 5
    }
    
    Close-HvlibPartition -handle $handle
}

#endregion

#region Configuration and Entry Point

# Default Configuration - Update these values for your environment
$script:DEFAULT_DLL_PATH = "C:\Distr\LiveCloudKd_public\hvlibdotnet.dll"
$script:DEFAULT_VM_NAME = "Windows Server 2025"

# Display Usage Information
function Show-UsageHelp {
    Write-Host @"

═══════════════════════════════════════════════════════════════════════════════
Hvlib Examples Script v$script:MODULE_VERSION Loaded!
═══════════════════════════════════════════════════════════════════════════════

⚠️  IMPORTANT: Configure your environment settings!
   Update `$script:DEFAULT_DLL_PATH and `$script:DEFAULT_VM_NAME

📁 Current Configuration:
   DLL Path: $script:DEFAULT_DLL_PATH
   VM Name:  $script:DEFAULT_VM_NAME

🚀 Quick Start:
   1. Update configuration variables
   2. Run: Invoke-QuickStart -DllPath <path> -VmName <vm>
   3. Run: Invoke-AllExamples -DllPath <path> -VmName <vm>

📖 Available Commands:

   Basic Operations:
   • Import-HvlibModule -DllPath <path>
   • Invoke-QuickStart -DllPath <path> -VmName <vm>
   • Invoke-AllExamples -DllPath <path> -VmName <vm>

   Example Functions (51 total):
   • Example-GetHvlib -DllPath <path>
   • Example-GetHvlibAllPartitions
   • Example-GetHvlibPartition -VmName <vm>
   • Example-SuspendHvlibVm-PowerShell -VmName <vm>
   • Example-GetHvlibMachineType -VmName <vm>
   • Example-GetHvlibVpRegister-FullContext -VmName <vm>
   ... and 45 more examples

   Workflows (7):
   • Workflow-VmInformationReport
   • Workflow-MemoryAnalysis -VmName <vm>
   • Workflow-ProcessIntrospection -VmName <vm>
   • Workflow-SafeMemoryDump -VmName <vm>
   • Workflow-DebugSession -VmName <vm>
   • Workflow-MultiVmReport
   • Workflow-SymbolAnalysis -VmName <vm> ⭐ NEW

📊 Example Sections:
   Section 1:  Library and Configuration (2)
   Section 2:  Partition Enumeration (3)
   Section 3:  Partition Information (6)
   Section 4:  Physical Memory (4)
   Section 5:  Virtual Memory (4)
   Section 6:  Process Information (4)
   Section 7:  Resource Management (2)
   Section 8:  Utilities (1)
   Section 9:  VM State Control (4) - v1.3.0
   Section 10: Advanced Memory (4) - v1.3.0
   Section 11: VM Introspection (4) - v1.3.0
   Section 12: CPU Registers (6) - v1.3.0
   Section 13: ⭐ Symbol Operations (4) - NEW v1.5.0

💡 Usage Example:
   Invoke-QuickStart -DllPath $script:DEFAULT_DLL_PATH -VmName $script:DEFAULT_VM_NAME

📝 For detailed help on any function:
   Get-Help <FunctionName> -Detailed

═══════════════════════════════════════════════════════════════════════════════
"@ -ForegroundColor $script:COLOR_WARNING
}

# Display usage help
# Show-UsageHelp

Invoke-QuickStart -DllPath $script:DEFAULT_DLL_PATH -VmName $script:DEFAULT_VM_NAME
Invoke-AllExamples -DllPath $script:DEFAULT_DLL_PATH -VmName $script:DEFAULT_VM_NAME

#endregion