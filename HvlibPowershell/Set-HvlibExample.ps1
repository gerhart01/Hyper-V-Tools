function Import-VMCloud($dll_path)
{
    Import-Module -FullyQualifiedName @{ModuleName = 'VMCloud'; ModuleVersion = '1.1.0' }
    Set-HvLibPath $dll_path
}

function Close-AllPartitions
{
    Close-HvlibPartitions
}

function Convert-ToHex {
    param ([object]$InputObject)

    # Loop through each property and convert numbers to hex
    $InputObject | Select-Object -Property * | ForEach-Object {
        $props = @{}
        $_.PSObject.Properties | ForEach-Object {
            if ($_ -and $_.Value -match '^\d+$') { # Check if it's a number
                $props[$_.Name] = "0x{0:X}" -f [int]$_.Value
            } else {
                $props[$_.Name] = $_.Value
            }
        }
        [PSCustomObject]$props
    }
}

function Test()
{
    Get-CloudVmList
    $a = Get-CloudPartition "Windows 11 (Secure Boot)"
    #$symbolName = "nt!MmCopyVirtualMemory"
    
    $symbolName = "winhv!WinHvAllocateOverlayPages"
    $MmCopyVirtualMemoryAddress = Get-HvlibSymbolAddress $a $symbolName
    $hex = $MmCopyVirtualMemoryAddress.ToString("X")
    Write-Host $symbolName ("address: 0x"+$MmCopyVirtualMemoryAddress.ToString("X"))
    
    $symbolName = "winhv!WinHvpDllLoadSuccessful"
    $MmCopyVirtualMemoryAddress = Get-HvlibSymbolAddress $a $symbolName
    $hex = $MmCopyVirtualMemoryAddress.ToString("X")
    Write-Host $symbolName ("address: 0x"+$MmCopyVirtualMemoryAddress.ToString("X"))
    
    $ModuleName = "winhv"
    $TableOfSymbols = Get-HvlibAllSymbols $a $ModuleName
    $TableOfSymbols | select * | Out-GridView

    $ModuleName = "kdcom"
    $TableOfSymbols = Get-HvlibAllSymbols $a $ModuleName
    $TableOfSymbols | select * | Out-GridView

    $ModuleName = "mcupdate"
    $TableOfSymbols = Get-HvlibAllSymbols $a $ModuleName
    $TableOfSymbols | select * | Out-GridView

    $ModuleName = "securekernel"
    $TableOfSymbols = Get-HvlibAllSymbols $a $ModuleName
    $TableOfSymbols | select * | Out-GridView
}

    $DllPath = "C:\Distr\LiveCloudKd_sdk_test\hvlibdotnet.dll"
    $VmName = "Windows Server 2025"

    Import-VMCloud $DllPath
    Get-CloudVmList
    $a = Get-CloudPartition $VmName

    $ModuleName = "ntoskrnl"
    $TableOfSymbols = Get-HvlibAllSymbols $a $ModuleName
    $TableOfSymbols | select * | Out-GridView

    # $modules = Get-VmKernelModulesCount $a
    # $modules | select * | Out-GridView

    # $allData = @()

    # $modules | ForEach-Object {
    #     $ModuleName = $_.ImageName.Replace(".sys","").Replace(".dll","").Replace(".exe","").Replace(".SYS","").Replace(".DLL","").Replace(".","")
    #     $TableOfSymbols = Get-HvlibAllSymbols $a $ModuleName
    #     $allData += $TableOfSymbols
    # }
 