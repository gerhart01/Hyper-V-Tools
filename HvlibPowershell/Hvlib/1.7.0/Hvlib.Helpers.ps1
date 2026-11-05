# ==============================================================================
# Module:      Hvlib.Helpers.ps1
# Version:     1.2.0
# Description: Helper functions for Hvlib PowerShell module
# ==============================================================================
# Change Log:
# 1.1.1 - Bug fix: Updated Initialize-Hvlib, removed Export-ModuleMember
# 1.1.0 - Initial refactored version with helper functions
# License GPL3
# ==============================================================================

# Import constants
. $PSScriptRoot\Hvlib.Constants.ps1

# ==============================================================================
# Library Management
# ==============================================================================

function Test-HvlibLoaded {
    <#
    .SYNOPSIS
    Check if Hvlib library is loaded
    #>
    return $Script:is_lib_loaded -eq $true
}

function Initialize-Hvlib {
    <#
    .SYNOPSIS
    Initialize and load Hvlib library
    .PARAMETER DllPath
    Path to hvlibdotnet.dll (optional if already initialized)
    #>
    param(
        [string]$DllPath
    )

    if (Test-HvlibLoaded) {
        return $true
    }

    # Use saved DLL path if not provided
    if ([string]::IsNullOrEmpty($DllPath)) {
        if ([string]::IsNullOrEmpty($Script:dll_path)) {
            Write-Warning "DLL path not provided. Please call Get-Hvlib first with the DLL path."
            return $false
        }
        $DllPath = $Script:dll_path
    }

    if (-not (Test-Path $DllPath)) {
        Write-Warning ($Script:MSG_LIBRARY_NOT_FOUND -f $DllPath)
        return $false
    }

    Add-Type -Path $DllPath
    Write-Host ($Script:MSG_LIBRARY_LOADED -f $DllPath) -ForegroundColor $Script:COLOR_SUCCESS

    $Script:is_lib_loaded = $true
    return $true
}

function Remove-Hvlib {
    <#
    .SYNOPSIS
    Counterpart to Initialize-Hvlib / Get-Hvlib. Releases native resources
    (closes all open partitions) and resets the module's "loaded" state.

    .DESCRIPTION
    What this DOES:
      - Calls [Hvlibdotnet.Hvlib]::CloseAllPartitions() to release any open
        VM partition handles (real native cleanup via SdkCloseAllPartitions).
      - Sets $Script:is_lib_loaded = $false so the next Get-Hvlib / Initialize
        call will re-run Add-Type.
      - Optionally clears the cached $Script:dll_path (use -ClearDllPath).

    What this does NOT do (and cannot, without re-architecting the module):
      - It does NOT unload hvlibdotnet.dll or its native dependency hvlib.dll
        from the PowerShell process. Add-Type loads assemblies into the
        default AssemblyLoadContext, which .NET does not allow to unload.
        The [Hvlibdotnet.Hvlib] type and the pinned native DLL stay in the
        process until pwsh exits.
      - Consequence: if you rebuild hvlibdotnet.dll and want the new build
        loaded, you MUST start a fresh pwsh session. Re-calling Get-Hvlib
        in the current session will not replace the already-loaded types.

    .PARAMETER ClearDllPath
    Also clear the cached $Script:dll_path so the next Get-Hvlib call
    requires an explicit -path_to_dll argument again.

    .PARAMETER SkipPartitionClose
    Skip the CloseAllPartitions step. Use if partitions were already closed
    individually or the SDK is in an inconsistent state and the close call
    would fault.

    .EXAMPLE
    # Normal teardown: closes partitions, resets state, keeps DLL path
    Remove-Hvlib

    .EXAMPLE
    # Full teardown: also forget the DLL path
    Remove-Hvlib -ClearDllPath

    .OUTPUTS
    [bool] $true on success (state reset), $false if nothing to do.
    #>
    [CmdletBinding()]
    param(
        [switch]$ClearDllPath,
        [switch]$SkipPartitionClose
    )

    if (-not (Test-HvlibLoaded)) {
        Write-Verbose "Hvlib is not marked as loaded — nothing to release."
        if ($ClearDllPath) { $Script:dll_path = $null }
        return $false
    }

    # Real resource cleanup: close any partitions the SDK is still holding.
    # Guarded by both the switch and a type-presence check, so we never throw
    # MethodNotFoundException if the assembly somehow isn't there.
    if (-not $SkipPartitionClose) {
        $hvlibType = [System.Management.Automation.PSTypeName]'Hvlibdotnet.Hvlib'
        if ($hvlibType.Type) {
            try {
                [Hvlibdotnet.Hvlib]::CloseAllPartitions()
                Write-Verbose "CloseAllPartitions() called successfully."
            } catch {
                Write-Warning "CloseAllPartitions() failed: $($_.Exception.Message)"
            }
        }
    }

    $Script:is_lib_loaded = $false
    if ($ClearDllPath) { $Script:dll_path = $null }

    # Write-Warning instead of Write-Host -ForegroundColor: when Close-Hvlib (module-
    # scope) calls Remove-Hvlib (session-scope from ScriptsToProcess), $Script:COLOR_*
    # may not be resolvable, which produced "Cannot bind parameter 'ForegroundColor'".
    Write-Warning "Hvlib state reset. NOTE: .NET assembly hvlibdotnet.dll remains loaded in this process - a fresh pwsh session is required to pick up a newly-built DLL."
    return $true
}

# ==============================================================================
# Validation Functions
# ==============================================================================

function Test-PartitionHandle {
    <#
    .SYNOPSIS
    Validate partition handle
    #>
    param([object]$Handle)

    if ($null -eq $Handle -or $Handle -eq 0) {
        Write-Warning ($Script:MSG_INVALID_HANDLE -f $Handle)
        return $false
    }
    return $true
}

function Test-FileExists {
    <#
    .SYNOPSIS
    Validate file existence
    #>
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Warning ($Script:MSG_FILE_NOT_FOUND -f $Path)
        return $false
    }
    return $true
}

function Test-MemorySize {
    <#
    .SYNOPSIS
    Validate memory size parameter
    #>
    param([int]$Size)

    if ($Size -le 0) {
        Write-Warning "Invalid memory size: $Size"
        return $false
    }
    return $true
}

# ==============================================================================
# Conversion Functions
# ==============================================================================

function ConvertTo-HexString {
    <#
    .SYNOPSIS
    Convert number to hexadecimal string
    #>
    param([object]$Number)

    if ($null -eq $Number) {
        return "0"
    }
    return [System.Convert]::ToString([uint64]$Number, 16).ToUpper()
}

function ConvertTo-ManagedBuffer {
    <#
    .SYNOPSIS
    Convert byte array to unmanaged memory buffer
    #>
    param([byte[]]$Data)

    $size = $Data.Length
    $memPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    [System.Runtime.InteropServices.Marshal]::Copy($Data, 0, $memPtr, $size)
    
    return $memPtr
}

function ConvertFrom-ManagedBuffer {
    <#
    .SYNOPSIS
    Convert unmanaged memory buffer to byte array
    #>
    param(
        [IntPtr]$Buffer,
        [int]$Size
    )

    $bytes = [byte[]]::new($Size)
    [System.Runtime.InteropServices.Marshal]::Copy($Buffer, $bytes, 0, $Size)
    
    return $bytes
}

# ==============================================================================
# String Marshaling
# ==============================================================================

function ConvertFrom-UnmanagedString {
    <#
    .SYNOPSIS
    Convert unmanaged Unicode string pointer to managed string
    #>
    param([IntPtr]$Pointer)

    if ($Pointer -eq [IntPtr]::Zero) {
        return $null
    }
    return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Pointer)
}

# ==============================================================================
# Memory Operation Helpers
# ==============================================================================

function Read-PhysicalMemoryInternal {
    <#
    .SYNOPSIS
    Internal helper for reading physical memory
    .PARAMETER PartitionHandle
    Partition handle
    .PARAMETER Address
    Physical address
    .PARAMETER Size
    Number of bytes to read
    #>
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$Address,
        
        [Parameter(Mandatory)]
        [int]$Size
    )

    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
    $result = [hvlibdotnet.hvlib]::ReadPhysicalMemory($PartitionHandle, $Address, $Size, $buffer)

    if (-not $result) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        Write-Warning ($Script:MSG_MEMORY_OPERATION_FAILED + " (ReadPhysical @ 0x$($Address.ToString('X')))")
        return $null
    }

    $data = ConvertFrom-ManagedBuffer -Buffer $buffer -Size $Size
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

    return $data
}

function Write-PhysicalMemoryInternal {
    <#
    .SYNOPSIS
    Internal helper for writing physical memory
    .PARAMETER PartitionHandle
    Partition handle
    .PARAMETER Address
    Physical address
    .PARAMETER Data
    Byte array to write
    #>
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$Address,
        
        [Parameter(Mandatory)]
        [byte[]]$Data
    )

    $buffer = ConvertTo-ManagedBuffer -Data $Data
    $result = [hvlibdotnet.hvlib]::WritePhysicalMemory($PartitionHandle, $Address, $Data.Length, $buffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

    if (-not $result) {
        Write-Warning ($Script:MSG_MEMORY_OPERATION_FAILED + " (WritePhysical @ 0x$($Address.ToString('X')))")
    }
    return $result
}

function Read-VirtualMemoryInternal {
    <#
    .SYNOPSIS
    Internal helper for reading virtual memory
    .PARAMETER PartitionHandle
    Partition handle
    .PARAMETER Address
    Virtual address
    .PARAMETER Size
    Number of bytes to read
    #>
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        $Address,
        
        [Parameter(Mandatory)]
        [int]$Size
    )

    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
    $result = [hvlibdotnet.hvlib]::ReadVirtualMemory($PartitionHandle, $Address, $Size, $buffer)

    if (-not $result) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        Write-Warning ($Script:MSG_MEMORY_OPERATION_FAILED + " (ReadVirtual @ 0x$($Address.ToString('X')))")
        return $null
    }

    $data = ConvertFrom-ManagedBuffer -Buffer $buffer -Size $Size
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

    return $data
}

function Write-VirtualMemoryInternal {
    <#
    .SYNOPSIS
    Internal helper for writing virtual memory
    .PARAMETER PartitionHandle
    Partition handle
    .PARAMETER Address
    Virtual address
    .PARAMETER Data
    Byte array to write
    #>
    param(
        [Parameter(Mandatory)]
        [uint64]$PartitionHandle,
        
        [Parameter(Mandatory)]
        [uint64]$Address,
        
        [Parameter(Mandatory)]
        [byte[]]$Data
    )

    $buffer = ConvertTo-ManagedBuffer -Data $Data
    $result = [hvlibdotnet.hvlib]::WriteVirtualMemory($PartitionHandle, $Address, $Data.Length, $buffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    
    return $result
}
