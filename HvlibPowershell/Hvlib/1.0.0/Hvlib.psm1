#
# C:\Program Files\WindowsPowerShell\Modules\Hvlib\1.0.<version_number>
#

$global:is_lib_loaded = $false
$path_to_dll = "C:\Distr\hvlib\hvlibdotnet.dll"
function Get-Hvlib([string]$path_to_dll)
{
    if ($global:is_lib_loaded -eq $false){
        
        if ((Test-Path $path_to_dll) -eq $false){
            Write-Host "library $path_to_dll was not found" -ForegroundColor DarkMagenta
            return $false
        }

        Add-Type -Path $path_to_dll
        Write-Host "library $path_to_dll was loaded" -ForegroundColor DarkMagenta
        $global:is_lib_loaded = $true
    }
}

function Get-HexValue($num)
{
    $hex = [System.Convert]::ToString($num, 16)
    return $hex
}
function Get-HvlibPartition()
{
    param(
        [string]$VmName
    )

    if (Get-Hvlib -eq $false)
    {
        return $false
    }

    $HandleList = [hvlibdotnet.hvlib]::EnumAllPartitions()

    $count = $HandleList.Count
    if ($count -eq 0)
    {
        Write-Warning "Get-HvlibPartition. VM count is zero"
        return $null
    }
    Write-Host "Get-HvlibPartition. VM count is $count" -ForegroundColor DarkMagenta

    $CurrentHandle = 0;

    for ($i = 0; $i -lt $count; $i++)
    {
        $vm_name_in_cycle = $HandleList[$i].Vmname
        Write-Host "Get-HvlibPartition. VM name is $vm_name_in_cycle" -ForegroundColor DarkMagenta
        if ($HandleList[$i].Vmname -eq $VmName){
            $CurrentHandle = $HandleList[$i].VmHandle
            Write-Host "Get-HvlibPartition. VM $vm_name_in_cycle found. Current handle:$CurrentHandle" -ForegroundColor DarkMagenta
        }
    }

    if ($CurrentHandle -eq 0)
    {
        Write-Warning "Get-HvlibPartition. VM with name $VmName is not presented. CurrentHandle is zero"
        return $null
    }

    $bResult = [hvlibdotnet.hvlib]::SelectPartition($CurrentHandle)

    if ($bResult -eq $false)
    {
        Write-Warning "Get-HvlibPartition. Partition Handle is $null"
        return $null
    }

    Write-Host "Get-HvlibPartition. SelectPartition is successfull" -ForegroundColor DarkMagenta

    return $CurrentHandle
}

function Set-HvlibVmPhysicalMemory
{
    param(
        [string]$filename,
        $prtnHandle
    )
    Get-Hvlib

    if ((Test-Path $filename) -eq $False)
    {
        Write-Warning "$filename is not present"
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($filename)

    $start_position = 0
    $file_size = $bytes.Length

    $memPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($file_size)

    # copy byte array to allocated unmanaged memory from previous step
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $memPtr, $file_size)

    $result = [hvlibdotnet.hvlib]::WritePhysicalMemory($prtnHandle, $start_position, $file_size, $memPtr)

    if ($result -eq $True)
    {
        Write-Host "Operation finished"	
    } 
    else
    {
        Write-Warning "Result is false. Try repeat it"
    }
}

function Get-HvlibVmPhysicalMemory
{
    param(
        $prtnHandle,
        $start_position,
        $size
    )
    Get-Hvlib
    $memPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    $result = [hvlibdotnet.hvlib]::ReadPhysicalMemory($prtnHandle, $start_position, $size, $memPtr)

    if ($result -eq $False)
    {
        Write-Warning "Memory reading error"
        return $null
    }

    # https://github.com/FuzzySecurity/PSKernel-Primitives
    $bytes = [byte[]]::new($size)
    [System.Runtime.InteropServices.Marshal]::Copy($memPtr, $bytes, 0, $size) # IntPtr, bytes, start position in memPtr, size

    return $bytes
}

function Close-HvlibPartitions
{
    Get-Hvlib
    [hvlibdotnet.hvlib]::CloseAllPartitions()
}

function Close-HvlibPartition($handle)
{
    Get-Hvlib
    [hvlibdotnet.hvlib]::ClosePartition($handle)
}

function Get-HvlibVmVirtualMemory
{
    param(
        $prtnHandle,
        $start_position,
        $size
    )

    Get-Hvlib
    $memPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    $result = [hvlibdotnet.hvlib]::ReadVirtualMemory($prtnHandle, $start_position, $size, $memPtr)

    if ($result -eq $False)
    {
        Write-Warning "Memory reading error"
        return $null
    }

    # https://github.com/FuzzySecurity/PSKernel-Primitives
    $bytes = [byte[]]::new($size)
    [System.Runtime.InteropServices.Marshal]::Copy($memPtr, $bytes, 0, $size) # IntPtr, bytes, start position in memPtr, size

    return $bytes # $bytes | Format-Hex
}

function Set-HvlibVmVirtualMemory
{
    param(
        [string]$filename,
        $prtnHandle
    )
    Get-Hvlib
    if ((Test-Path $filename) -eq $False)
    {
        Write-Warning "$filename is not present"
        return
    }


    $bytes = [System.IO.File]::ReadAllBytes($filename)

    $start_position = 0
    $file_size = $bytes.Length

    $memPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($file_size)

    # copy byte array to allocated unmanaged memory from previous step
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $memPtr, $file_size)

    $result = [hvlibdotnet.hvlib]::WriteVirtualMemory($prtnHandle, $start_position, $file_size, $memPtr)

    if ($result -eq $True)
    {
        Write-Host "Operation finished"	
    } 
    else
    {
        Write-Warning "Result is false"
    }
}

Export-ModuleMember -Function Get-Hvlib, Get-HvlibPartition, Close-HvlibPartitions, Get-HvlibVmPhysicalMemory, Set-HvlibVmPhysicalMemory, Get-HvlibVmVirtualMemory, Set-HvlibVmVirtualMemory