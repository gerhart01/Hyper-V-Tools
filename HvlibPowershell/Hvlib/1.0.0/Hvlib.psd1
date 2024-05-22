@{
    RootModule = 'Hvlib.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'BD2EDFC0-C293-4B01-AC0B-3065DF025AB1'
    Author = 'Arthur "gerhart_x" Khudyaev'
    CompanyName = ''
    Copyright = '(c) All rights reserved'
    Description = 'This module works with Hyper-V Memory Manager plugin'
    PowerShellVersion = '5.0'
    DotNetFrameworkVersion = '4.6.1'
    CLRVersion = '4.0.0'
    AliasesToExport = @()
    FunctionsToExport = 'Get-Hvlib', 'Get-HvlibPartition', 'Close-HvlibPartitions', 'Get-HvlibVmPhysicalMemory', 'Set-HvlibVmPhysicalMemory','Get-HvlibVmVirtualMemory', 'Set-HvlibVmVirtualMemory'
        
    CmdletsToExport = ''
    HelpInfoURI = 'https://github.com/gerhart01/Hyper-V-Tools/HvlibPowershell'
}
    