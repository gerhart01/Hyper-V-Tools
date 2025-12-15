# AI Documentation Guide for Hvlib Module

> **Purpose**: This guide helps AI assistants (Claude, ChatGPT, etc.) understand how to use the Hvlib Powershell documentation to generate high-quality, safe code.
Paste that document to AI query, when you use it for powershell code generation.

## Document Structure

The main documentation file (`Hvlib_Functions_Reference.md`) is organized specifically to support AI code generation:

### 1. Quick Start Section (Line ~52)
- **For AI**: Read this first to understand basic initialization flow
- Contains minimal working example
- Shows proper initialization sequence

### 2. AI Code Generation Guidelines (Line ~120)
**CRITICAL SECTION** - AI assistants MUST read this before generating any code

Contains:
- **Mandatory Patterns**: Required code structures for all generated code
- **Type Conversion Rules**: How to handle large addresses and special values
- **Function Call Patterns**: Standard calling conventions for each function category
- **Required Validations**: Checks that must be in every generated function
- **Operation Templates**: Copy-paste templates for common operations
- **Anti-Patterns**: Code patterns AI must NEVER generate
- **AI Request Handling Examples**: How to interpret common user requests

### 3. Function Reference (Line ~900)
Detailed documentation for all 28 functions organized by category:
- Syntax with exact parameter types
- Parameter descriptions with constraints
- Return value types
- Working code examples

### 4. Special Constants and Values (Line ~1100)
- Memory constants
- Information class enumeration
- Register codes reference table

### 5. Workflow Scenarios (Line ~1400)
7 complete workflow examples combining multiple functions:
- Multi-VM analysis
- Memory analysis
- Process introspection
- Safe memory dump
- CPU context snapshot
- VBS detection

### 6. Best Practices (Line ~1650)
- Safe VM operations patterns
- Performance optimization tips
- Common pitfalls with corrections

### 7. AI Assistant Quick Reference (Line ~2400)
**Fast lookup section** for AI generating code in real-time:
- Function call signatures in one place
- Type conversion rules summary
- Required code structure template
- Common constants
- Critical rules summary table
- AI request handling patterns

## How AI Should Use This Documentation

### Step 1: First Time Using Module
1. Read "🤖 For AI Assistants" section (top of document)
2. Read "AI Code Generation Guidelines" section completely
3. Review "AI Assistant Quick Reference" section

### Step 2: Generating Code
1. Check "AI Assistant Quick Reference" for function signatures
2. Use provided templates from "Common Operation Templates"
3. Follow "Required Code Structure" template
4. Apply all validations from checklist
5. Verify against "Anti-Patterns" section

### Step 3: Handling User Requests
1. Identify request type (memory read, register access, VM info, etc.)
2. Look up corresponding example in "AI Request Handling Examples"
3. Adapt template to user's specific needs
4. Always include error handling and cleanup

## Critical Rules Summary

These rules are **MANDATORY** for all AI-generated code:

| Rule # | Rule | Consequence of Violation |
|--------|------|-------------------------|
| 1 | Always validate handle after `Get-HvlibPartition` | Null reference exception |
| 2 | Always close partition in `finally` block | Resource leak, future operations may fail |
| 3 | Always suspend before register access | Race conditions, unstable reads |
| 4 | Always validate memory read results | Null reference when processing data |
| 5 | Always resume after suspend | VM remains frozen |
| 6 | Use same method for Suspend/Resume | Undefined behavior |
| 7 | Initialize with `Get-Hvlib` first | All operations will fail |

## Code Generation Checklist

Before returning code to user, verify:

- [ ] `Get-Hvlib` called if needed
- [ ] Handle validation present
- [ ] Try-finally with Close-HvlibPartition
- [ ] Memory reads validated before use
- [ ] Suspend/Resume if accessing registers
- [ ] Same method for Suspend and Resume
- [ ] All function parameters have correct types

## Quick Lookup: Most Common Operations

### Initialize Module
```powershell
Get-Hvlib -path_to_dll "C:\path\to\hvlibdotnet.dll"
```

### Get VM Handle (with validation)
```powershell
$handle = Get-HvlibPartition -VmName "VM Name"
if ($null -eq $handle -or $handle -eq 0) {
    Write-Error "Failed to get VM handle"
    return
}
```

### Read Kernel Memory (large address)
```powershell
$data = Get-HvlibVmVirtualMemory -prtnHandle $handle -start_position $addr -size 0x1000
```

### Access Register (with suspend/resume)
```powershell
Suspend-HvlibVm -PartitionHandle $handle
try {
    $reg = Get-HvlibVpRegister -PartitionHandle $handle -VpIndex 0 -RegisterCode 0x00020000
    $value = $reg.Reg64
}
finally {
    Resume-HvlibVm -PartitionHandle $handle
}
```

### Cleanup (always in finally)
```powershell
try {
    # operations
}
finally {
    Close-HvlibPartition -handle $handle
}
```

## Common User Request Patterns

| User Says | AI Should Generate |
|-----------|-------------------|
| "Get RIP register" | Suspend → Get-HvlibVpRegister → Resume |
| "List all VMs" | Get-HvlibAllPartitions with foreach loop |
| "Dump memory" | Physical memory read → WriteAllBytes |
| "Check if VBS enabled" | Get-HvlibCurrentVtl and check for Vtl1 |
| "Get process list" | Get-HvlibProcessesList with array iteration |

## Error Messages AI Should Generate

When operations fail, use clear, actionable error messages:

```powershell
# Good error messages
Write-Error "Failed to get VM handle for '$VmName'. Ensure VM name is correct and VM is running."
Write-Warning "Memory read failed at 0x$($addr.ToString('X16')). Address may not be mapped."
Write-Error "Failed to suspend VM. Check VM state and permissions."

# Not helpful (avoid these)
Write-Error "Operation failed"
Write-Warning "Error"
```

## Version Compatibility

- **Current Version**: 1.3.0
- **New in v1.3.0**: VM state control, advanced memory ops, VM introspection, CPU register access
- **Breaking Changes**: None (backward compatible)

---

**For questions or issues**: https://github.com/gerhart01/Hyper-V-Tools/tree/main/HvlibPowershell

**Last Updated**: December 2025
