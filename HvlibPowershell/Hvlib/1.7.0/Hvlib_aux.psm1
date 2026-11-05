# ==============================================================================
# Module:      Hvlib_aux.psm1
# Version:     1.7.0
# Description: Auxiliary tools for Hvlib — Capstone x64 disassembly engine
#              wrapper and instruction analysis helpers.
# Author:      Arthur Khudyaev (www.x.com/gerhart_x)
# License      GPL3
# ==============================================================================
# Change Log:
# 1.0.0 - Initial release (extracted from Hvlib.psm1 v1.5.0)
#       - Initialize-Capstone     — load capstone.dll with auto-detection
#       - Invoke-CapstoneDisasm   — disassemble x64 code, return instruction objects
#       - Get-CapstoneBranchTarget    — extract jmp/call absolute target
#       - Get-CapstoneLeaRipTarget    — compute LEA [rip+disp] effective address
#       - Test-CapstoneBranchMnemonic — check if mnemonic is a branch
#       - Format-CapstoneDisassembly  — pretty-print disassembly listing
#       - Total: 6 public functions
# ==============================================================================


# ==============================================================================
# Module state
# ==============================================================================

$Script:CapstoneLoaded = $false


# ==============================================================================
# C# P/Invoke wrapper for Capstone Engine
# ==============================================================================
# Supports both Capstone v5.x and v6.x (different struct layouts).
# The CapstoneX64 class auto-detects the version via cs_version()
# and adjusts field offsets accordingly.
# ==============================================================================

$Script:CapstoneWrapperSource = @'
using System;
using System.Runtime.InteropServices;

/// <summary>
/// Minimal x64 disassembler backed by capstone.dll (v5 or v6).
/// Implements IDisposable — always wrap in try/finally or 'using'.
/// </summary>
public class CapstoneX64 : IDisposable
{
    const int CS_MODE_64 = 1 << 3;

    // --- Capstone C API imports ---

    [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern int cs_version(ref int major, ref int minor);

    [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern int cs_open(int arch, int mode, out IntPtr handle);

    [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern int cs_close(ref IntPtr handle);

    [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern ulong cs_disasm(IntPtr handle, byte[] code, ulong code_size,
                                   ulong address, ulong count, out IntPtr insn);

    [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void cs_free(IntPtr insn, ulong count);

    // --- cs_insn struct layout (version-dependent) ---

    int _insnSize, _offAddress, _offSize, _offMnemonic, _offOpStr;
    IntPtr _handle;

    /// <summary>Capstone major version (5 or 6)</summary>
    public int MajorVersion { get; private set; }

    public CapstoneX64()
    {
        int major = 0, minor = 0;
        cs_version(ref major, ref minor);
        MajorVersion = major;

        // Capstone v6 changed the architecture enum and cs_insn layout
        int archX86 = (major >= 6) ? 4 : 3;

        if (major >= 6)
        {
            // cs_insn v6: size=256, address@16, size@24, mnemonic@50, op_str@82
            _offAddress  = 16;
            _offSize     = 24;
            _offMnemonic = 50;
            _offOpStr    = 82;
            _insnSize    = 256;
        }
        else
        {
            // cs_insn v5: size=248, address@8, size@16, mnemonic@42, op_str@74
            _offAddress  = 8;
            _offSize     = 16;
            _offMnemonic = 42;
            _offOpStr    = 74;
            _insnSize    = 248;
        }

        int err = cs_open(archX86, CS_MODE_64, out _handle);
        if (err != 0)
            throw new Exception("cs_open failed with error code: " + err);
    }

    /// <summary>
    /// Disassemble a byte array starting at the given base address.
    /// Returns all instructions found (greedy disassembly).
    /// </summary>
    public CsInsn[] Disassemble(byte[] code, ulong baseAddress)
    {
        IntPtr insnPtr;
        ulong count = cs_disasm(_handle, code, (ulong)code.Length,
                                baseAddress, 0, out insnPtr);
        if (count == 0)
            return new CsInsn[0];

        var result = new CsInsn[count];
        try
        {
            for (ulong i = 0; i < count; i++)
            {
                IntPtr p = IntPtr.Add(insnPtr, (int)(i * (uint)_insnSize));
                result[i] = new CsInsn
                {
                    Address  = (ulong)Marshal.ReadInt64(p, _offAddress),
                    Size     = (ushort)Marshal.ReadInt16(p, _offSize),
                    Mnemonic = Marshal.PtrToStringAnsi(IntPtr.Add(p, _offMnemonic)) ?? "",
                    OpStr    = Marshal.PtrToStringAnsi(IntPtr.Add(p, _offOpStr)) ?? ""
                };
            }
        }
        finally
        {
            cs_free(insnPtr, count);
        }
        return result;
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            cs_close(ref _handle);
            _handle = IntPtr.Zero;
        }
    }
}

/// <summary>
/// Single disassembled instruction.
/// </summary>
public class CsInsn
{
    public ulong  Address;
    public ushort Size;
    public string Mnemonic;
    public string OpStr;

    public override string ToString()
    {
        return string.IsNullOrEmpty(OpStr) ? Mnemonic : Mnemonic + " " + OpStr;
    }
}
'@


# ==============================================================================
# PUBLIC FUNCTIONS
# ==============================================================================

function Initialize-Capstone {
    <#
    .SYNOPSIS
    Load capstone.dll and compile the C# P/Invoke wrapper.

    .DESCRIPTION
    Searches for capstone.dll in the following order:
      1. Explicit -DllPath parameter
      2. Common Python site-packages paths (Python 3.11–3.14)
      3. Auto-detect via 'py -c "import capstone"'
    Once found, adds capstone.dll directory to PATH, compiles the
    C# wrapper via Add-Type, and verifies it works.

    .PARAMETER DllPath
    Explicit path to capstone.dll (optional).

    .EXAMPLE
    Initialize-Capstone
    .EXAMPLE
    Initialize-Capstone -DllPath "C:\tools\capstone\capstone.dll"
    #>
    [CmdletBinding()]
    param(
        [string]$DllPath
    )

    # Already loaded? Skip.
    if ($Script:CapstoneLoaded -or ([System.Management.Automation.PSTypeName]'CapstoneX64').Type) {
        $Script:CapstoneLoaded = $true
        return $true
    }

    # --- Search for capstone.dll ---

    $modulePath = Split-Path $PSCommandPath -Parent
    $candidates = @(
        $DllPath,
        # 1. Same directory as the Hvlib module
        (Join-Path $modulePath "capstone.dll"),
        # 2. LiveCloudKd distribution folder
        # 3. Common standalone install locations
        "C:\Tools\capstone\capstone.dll",
        "C:\capstone\capstone.dll",
        "$env:ProgramFiles\capstone\capstone.dll",
        "${env:ProgramFiles(x86)}\capstone\capstone.dll",
        # 4. NuGet global packages cache
        (Join-Path $env:USERPROFILE ".nuget\packages\capstone.net\*\runtimes\win-x64\native\capstone.dll")
    )

    # Expand wildcards (for NuGet path) and find first existing file
    $capstoneDll = $candidates |
        Where-Object { $_ } |
        ForEach-Object { if ($_ -match '\*') { Resolve-Path $_ -ErrorAction SilentlyContinue | Select-Object -Last 1 -ExpandProperty Path } else { $_ } } |
        Where-Object { $_ -and (Test-Path $_) } |
        Select-Object -First 1

    # 5. Search in system PATH
    if (-not $capstoneDll) {
        $pathDirs = $env:PATH -split ';'
        foreach ($dir in $pathDirs) {
            $p = Join-Path $dir "capstone.dll"
            if (Test-Path $p) { $capstoneDll = $p; break }
        }
    }

    # 6. Last resort: Python site-packages
    if (-not $capstoneDll) {
        $pyCandidates = @(
            "C:\Python315\Lib\site-packages\capstone\lib\capstone.dll",
            "C:\Python314\Lib\site-packages\capstone\lib\capstone.dll",
            "C:\Python313\Lib\site-packages\capstone\lib\capstone.dll",
            "C:\Python312\Lib\site-packages\capstone\lib\capstone.dll",
            "C:\Python311\Lib\site-packages\capstone\lib\capstone.dll"
        )
        $capstoneDll = $pyCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $capstoneDll) {
            try {
                $pyDir = & py -c "import capstone,os;print(os.path.dirname(capstone.__file__))" 2>$null
                if ($pyDir) {
                    $capstoneDll = Join-Path $pyDir "lib\capstone.dll"
                }
            } catch {}
        }
    }

    if (-not $capstoneDll -or -not (Test-Path $capstoneDll)) {
        Write-Error @"
capstone.dll not found. Install it via ONE of the following:

  A) Easiest - via Python (the auto-detector picks it up from site-packages):
       py -m pip install capstone
     (or: pip install capstone)
     Then re-run the script.

  B) Standalone - no Python required:
     1. Download the Windows x64 'core engine' zip from
        https://www.capstone-engine.org/download.html
        (or build from https://github.com/capstone-engine/capstone)
     2. Extract capstone.dll into one of:
        - $modulePath
        - C:\Distr\LiveCloudKd_public\
        - C:\Tools\capstone\  or  C:\capstone\
        - any directory in your PATH

  C) Explicit path - if capstone.dll is already on disk somewhere else:
       Initialize-Capstone -DllPath 'C:\path\to\capstone.dll'
     Or pass -CapstoneDllPath '<path>' to the calling script.

Searched paths (in order): module dir, LiveCloudKd_public, C:\Tools\capstone,
C:\capstone, Program Files\capstone, NuGet capstone.net, %PATH%, Python
site-packages (3.11-3.14).
"@
        return $false
    }

    # --- Load and compile ---

    $env:PATH = "$(Split-Path $capstoneDll -Parent);$env:PATH"
    Add-Type -TypeDefinition $Script:CapstoneWrapperSource -ErrorAction Stop

    # Verify: create a temporary instance to check the version
    $testInstance = New-Object CapstoneX64
    Write-Host ("Capstone v{0} loaded from: {1}" -f $testInstance.MajorVersion, $capstoneDll) -ForegroundColor Cyan
    $testInstance.Dispose()

    $Script:CapstoneLoaded = $true
    return $true
}


function Invoke-CapstoneDisasm {
    <#
    .SYNOPSIS
    Disassemble x64 machine code using Capstone.

    .DESCRIPTION
    Takes a byte array and returns an array of instruction objects, each with:
      - Address  : absolute virtual address of the instruction
      - Offset   : offset from BaseAddress (Address - BaseAddress)
      - Size     : instruction length in bytes
      - Mnemonic : instruction mnemonic (e.g. "mov", "jmp", "lea")
      - OpStr    : operand string (e.g. "rax, [rip + 0x1234]")
      - Text     : full text (Mnemonic + OpStr)

    Automatically calls Initialize-Capstone if not yet loaded.

    .PARAMETER Bytes
    Byte array of x64 machine code to disassemble.

    .PARAMETER BaseAddress
    Virtual address of the first byte (used for address calculation).
    Default: 0.

    .EXAMPLE
    $code = [byte[]]@(0x48, 0x89, 0xE5, 0xC3)
    $insns = Invoke-CapstoneDisasm -Bytes $code -BaseAddress 0x1000
    $insns | ForEach-Object { "  {0:X8}: {1}" -f $_.Address, $_.Text }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [uint64]$BaseAddress = 0
    )

    # Auto-initialize if needed
    if (-not $Script:CapstoneLoaded) {
        if (-not (Initialize-Capstone)) {
            Write-Error "Capstone engine not available"
            return @()
        }
    }

    $disasm = New-Object CapstoneX64
    try {
        $insns  = $disasm.Disassemble($Bytes, $BaseAddress)
        $result = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($insn in $insns) {
            $result.Add([PSCustomObject]@{
                Address  = $insn.Address
                Offset   = $insn.Address - $BaseAddress
                Size     = [int]$insn.Size
                Mnemonic = $insn.Mnemonic
                OpStr    = $insn.OpStr
                Text     = $insn.ToString()
            })
        }

        return $result.ToArray()
    }
    finally {
        $disasm.Dispose()
    }
}


function Get-CapstoneBranchTarget {
    <#
    .SYNOPSIS
    Extract the absolute target address from a branch instruction.

    .DESCRIPTION
    For jmp/jcc/call instructions with an immediate operand (e.g. "jmp 0x12345"),
    parses the operand and returns the target address as UInt64.
    Returns 0 if the operand is not an immediate address (e.g. "jmp rax").

    .PARAMETER Insn
    Instruction object from Invoke-CapstoneDisasm.

    .EXAMPLE
    $target = Get-CapstoneBranchTarget -Insn $insn
    if ($target -ne 0) { Write-Host "Jumps to 0x$($target.ToString('X'))" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Insn
    )

    if ($Insn.OpStr -match '^0x([0-9a-fA-F]+)$') {
        return [uint64]"0x$($Matches[1])"
    }

    return [uint64]0
}


function Get-CapstoneLeaRipTarget {
    <#
    .SYNOPSIS
    Compute the effective address from a LEA reg, [rip +/- displacement] instruction.

    .DESCRIPTION
    Parses the operand string for RIP-relative addressing (e.g. "[rip + 0x1234]"
    or "[rip - 0x56]"), and computes:
      EffectiveAddress = InstructionAddress + InstructionSize + Displacement

    Returns 0 if the operand is not a RIP-relative LEA.

    Note: the result is masked to 32 bits (RVA context). For full 64-bit VA
    computation, the caller should add the module base.

    .PARAMETER Insn
    Instruction object from Invoke-CapstoneDisasm.

    .EXAMPLE
    $addr = Get-CapstoneLeaRipTarget -Insn $insn
    if ($addr -ne 0) { Write-Host "LEA target RVA: 0x$($addr.ToString('X'))" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Insn
    )

    if ($Insn.OpStr -match '\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]') {
        $disp = [int64]"0x$($Matches[2])"
        if ($Matches[1] -eq '-') { $disp = -$disp }

        # Effective address = instruction end (Address + Size) + signed displacement
        return [uint64](([int64]$Insn.Address + [int64]$Insn.Size + $disp) -band 0xFFFFFFFF)
    }

    return [uint64]0
}


function Test-CapstoneBranchMnemonic {
    <#
    .SYNOPSIS
    Check if a mnemonic represents a branch instruction.

    .DESCRIPTION
    Returns $true for: call, jmp, jcc (je, jne, jg, jl, ...), loop, loope, loopne.
    Returns $false for everything else.

    .PARAMETER Mnemonic
    Instruction mnemonic string (e.g. "jmp", "call", "mov").

    .EXAMPLE
    foreach ($insn in $instructions) {
        if (Test-CapstoneBranchMnemonic -Mnemonic $insn.Mnemonic) {
            Write-Host "Branch at 0x$($insn.Address.ToString('X')): $($insn.Text)"
        }
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Mnemonic
    )

    return ($Mnemonic -eq 'call' -or $Mnemonic -like 'j*' -or $Mnemonic -like 'loop*')
}


function Format-CapstoneDisassembly {
    <#
    .SYNOPSIS
    Pretty-print a disassembly listing from Invoke-CapstoneDisasm output.

    .DESCRIPTION
    Formats each instruction as:
      ADDR: MNEMONIC OPERANDS
    with optional raw bytes display.

    .PARAMETER Instructions
    Array of instruction objects from Invoke-CapstoneDisasm.

    .PARAMETER ShowOffset
    Show file offset instead of absolute address. Default: $false.

    .PARAMETER MaxCount
    Maximum number of instructions to display. Default: unlimited (0).

    .EXAMPLE
    $insns = Invoke-CapstoneDisasm -Bytes $code -BaseAddress 0x1000
    Format-CapstoneDisassembly -Instructions $insns -MaxCount 20
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Instructions,

        [switch]$ShowOffset,

        [int]$MaxCount = 0
    )

    $count = 0

    foreach ($insn in $Instructions) {
        if ($MaxCount -gt 0 -and $count -ge $MaxCount) { break }

        $addrValue = if ($ShowOffset) { $insn.Offset } else { $insn.Address }
        $line = "  {0:X8}:  {1,-8} {2}" -f $addrValue, $insn.Mnemonic, $insn.OpStr

        Write-Host $line
        $count++
    }

    if ($MaxCount -gt 0 -and $Instructions.Count -gt $MaxCount) {
        Write-Host ("  ... ({0} more instructions)" -f ($Instructions.Count - $MaxCount)) -ForegroundColor DarkGray
    }
}


# ==============================================================================
# Module Export
# ==============================================================================

Export-ModuleMember -Function @(
    'Initialize-Capstone',
    'Invoke-CapstoneDisasm',
    'Get-CapstoneBranchTarget',
    'Get-CapstoneLeaRipTarget',
    'Test-CapstoneBranchMnemonic',
    'Format-CapstoneDisassembly'
)
