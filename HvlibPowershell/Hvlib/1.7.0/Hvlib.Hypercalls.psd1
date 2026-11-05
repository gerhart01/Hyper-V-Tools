# ==============================================================================
# Module Manifest: Hvlib.Hypercalls.psd1
# Version:         1.7.0
# Description:     Generic Hyper-V hypercall interface (DSL + raw)
# ==============================================================================

@{
    RootModule        = 'Hvlib.Hypercalls.psm1'
    ModuleVersion     = '1.7.0'
    GUID              = 'D4E8F1A2-7B3C-4D9E-A5F6-2C8E1D3B5A7F'
    Author            = 'Arthur Khudyaev (@gerhart_x)'
    CompanyName       = ''
    Copyright         = '(c) All rights reserved'

    Description       = 'Generic Hyper-V hypercall interface based on the Top Level Functional Specification (TLFS). Exposes Invoke-Hypercall (DSL by name + -Field Value pairs) and Invoke-HypercallRaw (low-level by code + byte[]/[ordered]@{}), plus the $HvCallCode table of 261 hypercall codes. Per-hypercall typed wrappers ship as user-editable examples in Hvlib-HvExamples.ps1.'

    PowerShellVersion = '7.0'

    # Requires Hvlib module (for [Hvlibdotnet.Hvlib]::InvokeHypercallBytes)
    RequiredModules   = @('Hvlib')

    FunctionsToExport = @(
        # Generic hypercall interface (DSL: by name + -Field Value pairs)
        'Invoke-Hypercall',
        # Low-level interface (by code + byte[]/ordered/@{})
        'Invoke-HypercallRaw'
    )

    CmdletsToExport    = @()
    # $HvCallCode is the ordered table of all 261 hypercall name -> code mappings.
    # Consumers reference it as $HvCallCode.HvCallReadGpa etc. — must be exported.
    VariablesToExport  = @('HvCallCode')
    AliasesToExport    = @()

    FileList = @(
        'Hvlib.Hypercalls.psm1',
        'Hvlib.Hypercalls.psd1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('Hyper-V', 'Hypercall', 'TLFS', 'Virtualization', 'Memory')
            ProjectUri   = 'https://github.com/gerhart01/Hyper-V-Tools'
            ReleaseNotes = @'
Version 1.7.0 (Version alignment)
- No functional changes. Bumped to 1.7.0 to align with main Hvlib module
  (new active working version; 1.6.0 archived).

Version 1.6.0 (Version alignment)
- No functional changes. Module version bumped to 1.6.0 to align with the
  main Hvlib module and hvlibdotnet.dll v1.6.0.

Version 1.1.0
- BREAKING: Removed per-hypercall typed wrappers (Invoke-HvCallReadGpa,
  Invoke-HvCallWriteGpa, Invoke-HvCallGetPartitionId,
  Invoke-HvCallGetVpRegisters, Invoke-HvCallSetVpRegisters,
  Invoke-HvCallTranslateVirtualAddress, Invoke-HvCallPostMessage,
  Invoke-HvCallSignalEvent). They were moved to Hvlib-HvExamples.ps1
  as user-editable examples (load the file with the dot operator -
  `. .\Hvlib-HvExamples.ps1` - to bring them into the current scope).
- Module now exposes only the generic interface: Invoke-Hypercall,
  Invoke-HypercallRaw, $HvCallCode.

Version 1.0.0
- Invoke-Hypercall: generic hypercall with auto-serialization ([ordered]@{}, array, byte[])
- Invoke-HypercallRaw: low-level byte[]-based invocation
- $HvCallCode: ordered table of 261 hypercall name -> code mappings
- All input/output structures based on Microsoft TLFS
- References: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
'@
        }
    }
}
