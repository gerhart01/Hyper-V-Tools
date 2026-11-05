# ==============================================================================
# Module Manifest: Hvlib_aux.psd1
# Version:         1.7.0
# Description:     Auxiliary tools for Hvlib — Capstone x64 disassembly
# ==============================================================================

@{
    RootModule        = 'Hvlib_aux.psm1'
    ModuleVersion     = '1.7.0'
    GUID              = 'A7F3B2C1-9D4E-4A8F-B6C2-1E5D7F9A3B4C'
    Author            = 'Arthur Khudyaev (@gerhart_x)'
    CompanyName       = ''
    Copyright         = '(c) All rights reserved'

    Description       = 'Auxiliary tools for Hvlib module: Capstone x64 disassembly engine wrapper and instruction analysis helpers. Provides PowerShell functions for disassembling x64 machine code, extracting branch targets, and analyzing RIP-relative addressing.'

    PowerShellVersion = '7.0'

    # Hvlib_aux can be used independently (no hard dependency on Hvlib),
    # but is designed to complement it.
    RequiredModules   = @()

    FunctionsToExport = @(
        'Initialize-Capstone',
        'Invoke-CapstoneDisasm',
        'Get-CapstoneBranchTarget',
        'Get-CapstoneLeaRipTarget',
        'Test-CapstoneBranchMnemonic',
        'Format-CapstoneDisassembly'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    FileList = @(
        'Hvlib_aux.psm1',
        'Hvlib_aux.psd1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('Capstone', 'Disassembly', 'x64', 'Reverse-Engineering', 'Hyper-V')
            ProjectUri   = 'https://github.com/gerhart01/Hyper-V-Tools'
            ReleaseNotes = @'
Version 1.7.0 (Version alignment)
- No functional changes. Bumped to 1.7.0 to align with main Hvlib module
  (new active working version; 1.6.0 archived).

Version 1.6.0 (Version alignment)
- No functional changes. Module version bumped to 1.6.0 to align with the
  main Hvlib module and hvlibdotnet.dll v1.6.0.

Version 1.0.0 (Initial Release)
- Extracted from Hvlib.psm1 v1.5.0 into standalone auxiliary module
- Initialize-Capstone: load capstone.dll with auto-detection from Python site-packages
- Invoke-CapstoneDisasm: disassemble x64 bytes, return instruction objects
- Get-CapstoneBranchTarget: extract absolute jmp/call target address
- Get-CapstoneLeaRipTarget: compute LEA [rip+disp] effective address
- Test-CapstoneBranchMnemonic: check if mnemonic is a branch instruction
- Format-CapstoneDisassembly: pretty-print disassembly listing
- Supports Capstone v5.x and v6.x (auto-detect struct layout)
'@
        }
    }
}
