# ==============================================================================
# Module Manifest: Hvlib.psd1
# Version:         1.4.0
# Description:     PowerShell Module Manifest for Hvlib
# ==============================================================================

@{
    # Script module or binary module file associated with this manifest
    RootModule = 'Hvlib.psm1'

    # Version number of this module
    ModuleVersion = '1.4.0'
    
    # ID used to uniquely identify this module
    GUID = 'BD2EDFC0-C293-4B01-AC0B-3065DF025AB1'
    
    # Author of this module
    Author = 'Arthur Khudyaev (@gerhart_x)'
    
    # Company or vendor of this module
    CompanyName = ''
    
    # Copyright statement for this module
    Copyright = '(c) All rights reserved'
    
    # Description of the functionality provided by this module
    Description = 'PowerShell wrapper for hvlib.dll - Hyper-V Memory Manager Plugin. Provides comprehensive API for VM memory operations, partition management, and process introspection.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'
    
    # Minimum version of the .NET Framework required by this module
    DotNetFrameworkVersion = '4.6.1'
    
    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0.0'
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()
    
    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @(
        'Hvlib.Constants.ps1',
        'Hvlib.Helpers.ps1'
    )
    
    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @()
    
    # Functions to export from this module
    FunctionsToExport = @(
        # Library Management (2)
        'Get-Hvlib',
        'Get-HvlibPreferredSettings',
        
        # Partition Enumeration and Selection (3)
        'Get-HvlibAllPartitions',
        'Get-HvlibPartition',
        'Select-HvlibPartition',
        
        # Partition Information (5)
        'Get-HvlibData',
        'Get-HvlibData2',
        'Get-HvlibPartitionName',
        'Get-HvlibPartitionGuid',
        'Get-HvlibPartitionId',
        
        # Physical Memory Operations (3)
        'Get-HvlibVmPhysicalMemory',
        'Set-HvlibVmPhysicalMemory',
        'Set-HvlibVmPhysicalMemoryBytes',
        
        # Virtual Memory Operations (3)
        'Get-HvlibVmVirtualMemory',
        'Set-HvlibVmVirtualMemory',
        'Set-HvlibVmVirtualMemoryBytes',
        
        # Process and System Information (2)
        'Get-HvlibProcessesList',
        'Get-HvlibCr3',
        
        # VM State Control (2) - NEW in v1.2.0
        'Suspend-HvlibVm',
        'Resume-HvlibVm',
        
        # Advanced Memory Operations (2) - NEW in v1.2.0
        'Get-HvlibPhysicalAddress',
        'Set-HvlibPartitionData',
        
        # VM Introspection (2) - NEW in v1.2.0
        'Get-HvlibMachineType',
        'Get-HvlibCurrentVtl',
        
        # CPU Register Access (2) - NEW in v1.2.0
        'Get-HvlibVpRegister',
        'Set-HvlibVpRegister',

        # Symbol Operations (3) - NEW in v1.4.0
        'Get-HvlibSymbolAddress',
        'Get-HvlibAllSymbols',
        'Get-HvlibSymbolTableLength',

        # Resource Management (2)
        'Close-HvlibPartitions',
        'Close-HvlibPartition',

        # Utilities (1)
        'Get-HexValue'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # List of all modules packaged with this module
    ModuleList = @()
    
    # List of all files packaged with this module
    FileList = @(
        'Hvlib.psm1',
        'Hvlib.psd1',
        'Hvlib.Constants.ps1',
        'Hvlib.Helpers.ps1'
    )
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Hyper-V', 'Memory', 'VM', 'Virtualization', 'Debugging', 'Introspection')
            
            # A URL to the license for this module
            LicenseUri = ''
            
            # A URL to the main website for this project
            ProjectUri = 'https://github.com/gerhart01/Hyper-V-Tools'
            
            # A URL to an icon representing this module
            IconUri = ''
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 1.4.0 (Symbol Operations)
- ADDED: Get-HvlibSymbolAddress - Resolve symbol address via "module!SymbolName" notation
- ADDED: Get-HvlibAllSymbols - Enumerate all symbols for a driver module
- ADDED: Get-HvlibSymbolTableLength - Get symbol count without loading full table
- TOTAL: 31 public functions (28 + 3 new)
- Wraps: SdkSymGetSymbolAddress, SdkSymEnumAllSymbols, SdkSymEnumAllSymbolsGetTableLength

Version 1.3.0 (Major Feature Release)
- ADDED: Set-HvlibPartitionData - Set partition configuration data
- ADDED: Suspend-HvlibVm / Resume-HvlibVm - VM state control
- ADDED: Get-HvlibPhysicalAddress - Virtual to physical address translation (GVA→GPA)
- ADDED: Get-HvlibMachineType - VM architecture detection (x86/AMD64)
- ADDED: Get-HvlibCurrentVtl - Get Virtual Trust Level (VTL0/VTL1)
- ADDED: Get-HvlibVpRegister - Read CPU registers (RIP, RAX, CR3, etc.)
- ADDED: Set-HvlibVpRegister - Write CPU registers
- TOTAL: 28 public functions (21 + 7 new)
- Coverage: 95% of HvlibHandle.h API (19/20 functions)

Version 1.1.1 (Bug Fix Release)
- FIXED: Removed hard-coded DEFAULT_DLL_PATH constant
- FIXED: Export-ModuleMember errors in dot-sourced files (Constants, Helpers)
- CHANGED: Get-Hvlib now requires -path_to_dll parameter (mandatory)
- IMPROVED: DLL path is saved and reused automatically for subsequent calls
- UPDATED: All examples to include DLL path parameter
- UPDATED: Documentation to reflect changes

Version 1.1.0 (Refactored Release)
- Complete code refactoring for improved readability and maintainability
- Extracted constants to separate module (Hvlib.Constants.ps1)
- Added helper functions module (Hvlib.Helpers.ps1)
- Improved parameter validation with PowerShell attributes
- Removed try-catch blocks in favor of explicit validation
- Split large functions into smaller, focused helper functions
- Enhanced error handling and user messaging
- Added comprehensive inline documentation
- Improved code organization with logical sections
- All functions now under 50 lines for better readability

Version 1.0.1
- Added missing API functions from hvlibdotnet.cs
- Added Get-HvlibPreferredSettings
- Added Get-HvlibAllPartitions
- Added Get-HvlibData and Get-HvlibData2
- Added partition information retrieval functions
- Added process list and CR3 retrieval functions
- Added byte array write functions for memory operations

Version 1.0.0
- Initial release
- Basic VM enumeration and selection
- Physical and virtual memory read/write operations
- Partition management functions
'@
        }
    }
    
    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/gerhart01/Hyper-V-Tools/HvlibPowershell'
}
