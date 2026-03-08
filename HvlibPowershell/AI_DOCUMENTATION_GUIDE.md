---
manifest_version: 1.0
project_name: Hvlib PowerShell Module
language: PowerShell
framework: Hvlib (.NET interop via hvlibdotnet.dll)
last_updated: 2026-03-08
maintained_by: gerhart01
ai_target: [Claude, GPT-4, Copilot]
---

# AI Documentation Guide for Hvlib Module

> **Purpose**: This guide helps AI assistants (Claude, ChatGPT, etc.) understand the Hvlib PowerShell module to generate high-quality, safe code for Hyper-V virtual machine introspection.
> Paste this document into your AI query when generating PowerShell code with Hvlib.

---

## 1. Project Overview

**Hvlib** is a PowerShell module for live introspection of Hyper-V virtual machines via the Windows Hypervisor Platform. It provides cmdlets for reading VM memory, accessing CPU registers, enumerating processes, and resolving debug symbols — all without an agent inside the guest OS.

### Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Runtime | PowerShell 7.x (compatible with 5.1) | 7.4+ |
| Platform | Windows Server 2025 / Windows 11 | x64 |
| .NET Interop | hvlibdotnet.dll (C# wrapper) | — |
| Native SDK | hvlib.dll (C/C++) | — |
| Module | Hvlib.psm1 + Hvlib.psd1 | 1.4.0 |

### Key Dependencies

- **hvlibdotnet.dll** — C# managed wrapper around the native SDK; must be loaded first via `Get-Hvlib`
- **Symbol server access** — PDB symbols are downloaded from Microsoft symbol servers for `Get-HvlibSymbolAddress`, `Get-HvlibAllSymbols`, etc.
- **Administrator privileges** — required for hypervisor partition access
- **Running Hyper-V VMs** — target VM must be in Running state

---

## 2. Codebase Structure

```
C:\Program Files\WindowsPowerShell\Modules\Hvlib\
├── Hvlib.psd1                  # Module manifest (exports 32 cmdlets)
├── Hvlib.psm1                  # Main module file — all cmdlet definitions
├── Hvlib.Constants.ps1         # Constants (register codes, memory sizes, info classes)
└── Hvlib.Helpers.ps1           # Internal helpers (Test-PartitionHandle, Get-HexValue2)

C:\Projects\powershell_tests\
├── Hvlib-Examples.ps1           # v2.0.0 — 58 example/demo functions, all sections 1-13
├── Hvlib-Config.json            # JSON config (DllPath, VmName)
├── Hvlib_Functions_Reference.md # Full function reference (32 cmdlets)
└── AI_DOCUMENTATION_GUIDE.md    # This file
```

### Entry Points

- **Module import**: `Import-Module Hvlib` or `Get-Hvlib -path_to_dll "..."` (loads DLL + module)
- **Examples script**: `. .\Hvlib-Examples.ps1` then `Invoke-AllExamples` or individual `Example-*` functions
- **Config loading**: `Get-HvlibConfig` reads from `Hvlib-Config.json` → Registry → fallback defaults

### Key Modules

| File | Role | Functions |
|------|------|-----------|
| `Hvlib.psm1` | All 32 exported cmdlets | `Get-Hvlib`, `Get-HvlibPartition`, `Get-HvlibVmVirtualMemory`, etc. |
| `Hvlib.Constants.ps1` | Named constants | Register codes, info classes, color constants |
| `Hvlib.Helpers.ps1` | Internal utilities | `Test-PartitionHandle`, `Get-HexValue2` |
| `Hvlib-Examples.ps1` | Demo/test script | 58 functions across 13 sections + 7 workflows |

---

## 3. Architecture

### Layer Diagram

```
┌──────────────────────────────────┐
│  PowerShell Scripts / User Code  │  ← Hvlib-Examples.ps1, user scripts
└──────────────┬───────────────────┘
               │ Cmdlet calls (Get-HvlibPartition, etc.)
┌──────────────▼───────────────────┐
│  Hvlib.psm1 (PowerShell Module)  │  ← Parameter validation, error handling
└──────────────┬───────────────────┘
               │ [Hvlibdotnet.Hvlib]::MethodName()
┌──────────────▼───────────────────┐
│  hvlibdotnet.dll (C# Wrapper)   │  ← Managed .NET, P/Invoke to native
└──────────────┬───────────────────┘
               │ Native P/Invoke calls
┌──────────────▼───────────────────┐
│  hvlib.dll (Native C/C++ SDK)    │  ← Direct hypervisor API (WHvPartition*)
└──────────────┬───────────────────┘
               │
┌──────────────▼───────────────────┐
│  Windows Hypervisor Platform     │  ← Kernel-mode, partition handles
└──────────────────────────────────┘
```

### Data Flow

1. User calls a cmdlet: `$handle = Get-HvlibPartition -VmName "MyVM"`
2. `Hvlib.psm1` validates parameters via `Test-PartitionHandle` / null checks
3. Calls C# static method: `[Hvlibdotnet.Hvlib]::GetPartitionFriendlyName($vmName)`
4. C# wrapper calls native `hvlib.dll` via P/Invoke
5. Returns result (handle, byte array, struct) back up the stack

### Component Boundaries

- **Module ↔ Script**: Cmdlets accept typed parameters; scripts should always validate return values
- **PowerShell ↔ C#**: Type marshaling happens automatically; large addresses use `[UInt64]`, handles use `[IntPtr]`
- **C# ↔ Native**: Managed by P/Invoke attributes in `hvlibdotnet.cs`

---

## 4. Code Conventions

### PowerShell Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Cmdlets | `Verb-HvlibNoun` (approved verbs) | `Get-HvlibPartition`, `Suspend-HvlibVm` |
| Example functions | `Example-PascalCase` | `Example-GetHvlibPartition` |
| Parameters | `$PascalCase` | `$PartitionHandle`, `$VmName` |
| Script-scope vars | `$script:UPPER_SNAKE_CASE` | `$script:DEFAULT_DLL_PATH` |
| Local vars | `$camelCase` or `$PascalCase` | `$handle`, `$regValue` |

### Comment-Based Help

All public functions must have help blocks:

```powershell
function Example-Something {
    <#
    .SYNOPSIS
    Brief description (one line).
    .DESCRIPTION
    Detailed description of what the function does.
    .PARAMETER ParamName
    Description of the parameter.
    .OUTPUTS
    [type] Description of return value.
    .EXAMPLE
    Example-Something -ParamName "value"
    #>
    param(...)
}
```

### Function Structure

```powershell
function Verb-HvlibNoun {
    param(
        [Parameter(Mandatory)]
        [IntPtr]$PartitionHandle,

        [int]$OptionalParam = 0
    )

    # 1. Validate handle
    if (-not (Test-PartitionHandle -Handle $PartitionHandle)) { return $null }

    # 2. Call C# method
    try {
        $result = [Hvlibdotnet.Hvlib]::MethodName($PartitionHandle, $OptionalParam)
        return $result
    }
    catch {
        Write-Error "Operation failed: $_"
        return $null
    }
}
```

---

## 5. Common Patterns

### Handle Lifecycle (CRITICAL)

Every script that works with a VM must follow this pattern:

```powershell
# 1. Initialize
Get-Hvlib -path_to_dll "C:\path\to\hvlibdotnet.dll"

# 2. Get handle + validate
$handle = Get-HvlibPartition -VmName "VM Name"
if ($null -eq $handle -or $handle -eq 0) {
    Write-Error "Failed to get VM handle"
    return
}

# 3. Operations in try block
try {
    # ... work with $handle ...
}
finally {
    # 4. ALWAYS close handle
    Close-HvlibPartition -handle $handle
}
```

### Suspend/Resume for Register Access

```powershell
Suspend-HvlibVm -PartitionHandle $handle
try {
    $reg = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000
    $rip = $reg.Reg64
}
finally {
    Resume-HvlibVm -PartitionHandle $handle  # MUST use same method as Suspend
}
```

### Memory Read with Validation

```powershell
$data = Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $addr -size 0x1000
if ($null -eq $data) {
    Write-Warning "Memory read failed at 0x$($addr.ToString('X16'))"
    return
}
# Safe to use $data
```

### Configuration Loading (JSON → Registry → Fallback)

```powershell
$config = Get-HvlibConfig    # Returns @{ DllPath; VmName; Source }
# Priority: Hvlib-Config.json > HKLM:\SOFTWARE\LiveCloudKd\params > hardcoded defaults
```

### Output Suppression in Demo Scripts

```powershell
# Functions that return byte arrays/handles must be piped to Out-Null
# when called for side effects only (prevents massive stdout output)
Example-GetHvlibVmMemory -Handle $handle | Out-Null
```

---

## 6. Critical Requirements

### VM Safety

| Requirement | Details |
|------------|---------|
| Always resume after suspend | A forgotten `Resume-HvlibVm` leaves the VM frozen |
| Match suspend/resume methods | Use `Suspend-HvlibVm`/`Resume-HvlibVm` pair (not mixing with debug methods) |
| Close handles in finally | Leaked handles may prevent future operations |
| Validate all return values | Memory reads and handle operations can return `$null` |

### Performance

| Concern | Guidance |
|---------|----------|
| Symbol enumeration | `Get-HvlibAllSymbols` for ntoskrnl returns 46000+ symbols — can take minutes |
| Prefer direct lookup | Use `Get-HvlibSymbolAddressDirect` instead of `Get-HvlibSymbolAddress` for single symbol lookups |
| Large memory reads | Keep `$size` reasonable; read in chunks if needed |
| Handle caching | Get the handle once, reuse it across operations |

### Security

- Requires Administrator privileges
- Operates at hypervisor level — incorrect memory writes can crash the VM
- Never expose partition handles or memory contents to untrusted code
- DLL path should be validated (load only from trusted locations)

---

## 7. Document Structure (Hvlib_Functions_Reference.md)

The main documentation file (`Hvlib_Functions_Reference.md`) is organized to support AI code generation:

### Section Map

| Section | Line | Content |
|---------|------|---------|
| Quick Start | ~52 | Initialization flow, minimal working example |
| AI Code Generation Guidelines | ~120 | **CRITICAL** — mandatory patterns, type rules, templates, anti-patterns |
| Function Reference | ~900 | All 32 functions with syntax, parameters, returns, examples |
| Special Constants | ~1100 | Memory constants, info classes, register codes |
| Workflow Scenarios | ~1400 | 7 complete multi-function workflows |
| Best Practices | ~1650 | Safe operations, performance, common pitfalls |
| AI Quick Reference | ~2400 | Fast lookup: signatures, types, templates, rules |

### How AI Should Use the Reference

**First time:**
1. Read "AI Code Generation Guidelines" section completely
2. Review "AI Assistant Quick Reference" section

**When generating code:**
1. Check "AI Quick Reference" for function signatures
2. Use templates from "Common Operation Templates"
3. Follow "Required Code Structure" template
4. Verify against "Anti-Patterns" section

---

## 8. AI Checklist

### Before Generating Code

- [ ] `Get-Hvlib` called if library not yet loaded
- [ ] Handle validation present after `Get-HvlibPartition`
- [ ] `try-finally` with `Close-HvlibPartition`
- [ ] Memory read results validated before use
- [ ] `Suspend-HvlibVm` / `Resume-HvlibVm` paired for register access
- [ ] Same suspend/resume method used (don't mix)
- [ ] All parameter types correct (`[IntPtr]`, `[UInt64]`, `[string]`)
- [ ] Error messages are specific and actionable

### Anti-Patterns (NEVER Generate)

```powershell
# ❌ Missing handle validation
$handle = Get-HvlibPartition -VmName "VM"
$data = Get-HvlibVmVirtualMemory -prtnHandle $handle ...  # $handle could be null!

# ❌ Missing finally block
$handle = Get-HvlibPartition -VmName "VM"
# ... operations ...
Close-HvlibPartition -handle $handle  # Never reached if exception occurs

# ❌ Suspend without resume
Suspend-HvlibVm -PartitionHandle $handle
$reg = Get-HvlibVpRegister ...
# Forgot Resume-HvlibVm → VM stays frozen!

# ❌ Using memory without null check
$data = Get-HvlibVmVirtualMemory ...
[BitConverter]::ToUInt64($data, 0)  # Crashes if $data is null

# ❌ Generic error messages
Write-Error "Operation failed"  # Not helpful — what operation? What to do?
```

### Correct Patterns

```powershell
# ✅ Full safe pattern
Get-Hvlib -path_to_dll $DllPath
$handle = Get-HvlibPartition -VmName $VmName
if ($null -eq $handle -or $handle -eq 0) {
    Write-Error "Failed to get handle for '$VmName'. Is the VM running?"
    return
}
try {
    Suspend-HvlibVm -PartitionHandle $handle
    try {
        $reg = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000
        Write-Host ("RIP = 0x{0:X16}" -f $reg.Reg64)
    }
    finally {
        Resume-HvlibVm -PartitionHandle $handle
    }
}
finally {
    Close-HvlibPartition -handle $handle
}
```

---

## 9. Common User Request Patterns

| User Says | AI Should Generate |
|-----------|-------------------|
| "Get RIP register" | Suspend → Get-HvlibVpRegister (0x00020000) → Resume |
| "List all VMs" | Get-HvlibAllPartitions with foreach loop |
| "Dump memory" | Physical memory read → WriteAllBytes |
| "Check if VBS enabled" | Get-HvlibCurrentVtl and check for Vtl1 |
| "Get process list" | Get-HvlibProcessesList with array iteration |
| "Find symbol address" | Get-HvlibSymbolAddressDirect (fast) or Get-HvlibSymbolAddress (full enum) |
| "List all symbols" | Get-HvlibAllSymbols with driver name |
| "How many symbols?" | Get-HvlibSymbolTableLength with driver name |
| "Read kernel memory at X" | Get-HvlibVmVirtualMemory with address + validation |

---

## 10. Error Messages AI Should Generate

```powershell
# Good: specific and actionable
Write-Error "Failed to get VM handle for '$VmName'. Ensure VM name is correct and VM is running."
Write-Warning "Memory read failed at 0x$($addr.ToString('X16')). Address may not be mapped."
Write-Error "Failed to suspend VM. Check VM state and permissions."
Write-Warning "Symbol '$symbolName' not found in module '$moduleName'."

# Bad: vague (avoid)
Write-Error "Operation failed"
Write-Warning "Error"
```

---

## 11. Version History

| Version | Changes |
|---------|---------|
| **1.4.0** | Symbol operations: `Get-HvlibSymbolAddress`, `Get-HvlibSymbolAddressDirect`, `Get-HvlibAllSymbols`, `Get-HvlibSymbolTableLength` |
| **1.3.0** | VM state control, advanced memory ops, VM introspection, CPU register access |
| **Breaking Changes** | None (backward compatible) |

---

**For questions or issues**: https://github.com/gerhart01/Hyper-V-Tools/tree/main/HvlibPowershell

**Last Updated**: March 2026
