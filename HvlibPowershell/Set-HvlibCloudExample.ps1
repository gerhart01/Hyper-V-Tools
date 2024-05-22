function Import-Hvlib()
{
    Import-Module -FullyQualifiedName @{ModuleName = 'Hvlib'; ModuleVersion = '1.0.0' }
}

function Close-AllPartitions
{
    Close-HvlibPartitions
}

Import-Hvlib()
$a = Get-HvlibPartition()
$b = Get-HvlibVmPhysicalMemory $a 0x10000 0x1000
