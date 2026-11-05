# ==============================================================================
# Module:      Hvlib.Hypercalls.psm1
# Version:     1.7.0
# Description: Generic Hyper-V hypercall interface based on TLFS (Top Level
#              Functional Specification).
# Author:      Arthur Khudyaev (www.x.com/gerhart_x)
# ==============================================================================
#
# What this module exports:
#   - Invoke-Hypercall       — DSL by name: -Code HvCallReadGpa -Field Value ...
#   - Invoke-HypercallRaw    — low-level: by uint16 code + byte[]/[ordered]@{}
#   - $HvCallCode            — ordered table of all 261 hypercall name -> code mappings
#
# Per-hypercall typed wrappers (Invoke-HvCallReadGpa, Invoke-HvCallWriteGpa,
# Invoke-HvCallGetPartitionId, Invoke-HvCallGetVpRegisters,
# Invoke-HvCallSetVpRegisters, Invoke-HvCallTranslateVirtualAddress,
# Invoke-HvCallPostMessage, Invoke-HvCallSignalEvent) are NOT shipped from
# this module since 1.1.0. They live as user-editable examples in
# Hvlib-HvExamples.ps1 — load that file with the dot (.) operator
# (`. .\Hvlib-HvExamples.ps1`, runs it in your current scope) to get them.
#
# Hypercall codes — complete table from hvgdk.h, hvgdk_mini.h, and TLFS.
# Key naming follows hvgdk.h convention: HvCall<Name>
#
# Sources:
#   [hvgdk.h]      LiveCloudKd SDK / Alex Ionescu HDK (https://github.com/ionescu007/hdk)
#   [hvgdk_mini.h] Linux kernel / mshv headers
#   [mu_msvm]      microsoft/mu_msvm HvGuestHypercall.h
#   [TLFS]         Microsoft Hypervisor Top Level Functional Specification
#
# References:
#   [TLFS] Microsoft Hypervisor Top Level Functional Specification
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
#
#   [TLFS-Hypercalls] Hypercall interface
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
#
#   [TLFS-MemoryAccess] HvCallReadGpa / HvCallWriteGpa
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallReadGpa
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallWriteGpa
#
#   [TLFS-VpRegisters] HvCallGetVpRegisters / HvCallSetVpRegisters
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetVpRegisters
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSetVpRegisters
#
#   [TLFS-VA] HvCallTranslateVirtualAddress
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallTranslateVirtualAddress
#
#   [TLFS-SynIC] HvCallPostMessage / HvCallSignalEvent
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallPostMessage
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSignalEvent
#
#   [TLFS-PartitionId] HvCallGetPartitionId
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetPartitionId
#
#   [TLFS-Appendix] Register names, hypercall codes, status codes
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv-register-name
#
#   [hvlib SDK] LiveCloudKd / hvlib — SdkInvokeHypercall
#          https://github.com/gerhart01/LiveCloudKd
#
# Architecture:
#   PowerShell (this module)         C# (hvlibdotnet.dll)          Driver (hvmm.sys)
#   +--------------------------+     +----------------------+      +-------------------+
#   | Invoke-Hypercall  (DSL)  |     | InvokeHypercallBytes |      | SdkInvokeHypercall|
#   | Invoke-HypercallRaw      | --> |  byte[] -> byte[]    | -->  | AllocPages, vmcall|
#   | $HvCallCode (lookup)     |     |  (buffer mgmt)       |      |  (kernel mode)    |
#   +--------------------------+     +----------------------+      +-------------------+
#   ConvertTo-HypercallBytes is an internal serializer used by Invoke-Hypercall
#   to flatten [ordered]@{} / arrays / byte[] into the buffer the SDK expects.
#
# Change Log:
# 1.6.0 - Version alignment (no functional changes)
#       - Bumped to 1.6.0 alongside Hvlib (Close-Hvlib added there) and
#         Hvlib_aux (capstone install hints), to keep the suite in lockstep.
#
# 1.1.0 - Generic-only API (BREAKING)
#       - REMOVED from this module: per-hypercall typed wrappers
#         Invoke-HvCallReadGpa, Invoke-HvCallWriteGpa, Invoke-HvCallGetPartitionId,
#         Invoke-HvCallGetVpRegisters, Invoke-HvCallSetVpRegisters,
#         Invoke-HvCallTranslateVirtualAddress, Invoke-HvCallPostMessage,
#         Invoke-HvCallSignalEvent.
#       - They were moved to Hvlib-HvExamples.ps1 as user-editable examples;
#         load that file with the dot (.) operator to get them in scope.
#       - Module now exposes ONLY the generic interface:
#         Invoke-Hypercall, Invoke-HypercallRaw, $HvCallCode.
#
# 1.0.0 - Initial release
#       - Invoke-HypercallRaw                  — any hypercall via code + byte[]/ordered/array
#       - Invoke-HvCallReadGpa                 — 0x0053: read up to 16 bytes from GPA
#       - Invoke-HvCallWriteGpa                — 0x0054: write up to 16 bytes to GPA
#       - Invoke-HvCallGetPartitionId          — 0x0046: get calling partition ID
#       - Invoke-HvCallGetVpRegisters          — 0x0050: read VP registers (rep)
#       - Invoke-HvCallSetVpRegisters          — 0x0051: write VP registers (rep)
#       - Invoke-HvCallTranslateVirtualAddress — 0x0052: GVA → GPA translation
#       - Invoke-HvCallPostMessage             — 0x005C: post SynIC message
#       - Invoke-HvCallSignalEvent             — 0x005D: signal SynIC event
#       - Total: 9 public functions
# ==============================================================================

#region Hypercall code constants
# ==============================================================================


$Script:HvCallCode = [ordered]@{

    # ── V1 core / fast hypercalls (0x0000 – 0x0007) ──────────────────────────

    HvCallReserved0000                      = [uint16]0x0000
    HvCallSwitchVirtualAddressSpace         = [uint16]0x0001
    HvCallFlushVirtualAddressSpace          = [uint16]0x0002
    HvCallFlushVirtualAddressList           = [uint16]0x0003
    HvCallGetLogicalProcessorRunTime        = [uint16]0x0004
    HvCallUpdateHvProcessorFeatures         = [uint16]0x0005   # hvgdk.h: SetLogicalProcessorRunTimeGroup
    HvCallSwitchAliasMap                    = [uint16]0x0006   # hvgdk.h: ClearLogicalProcessorRunTimeGroup
    HvCallUpdateMicrocode                   = [uint16]0x0007   # hvgdk.h: NotifyLogicalProcessorPowerState

    # ── VTL / IPI / flush-ex / patching (0x0008 – 0x001F) ────────────────────

    HvCallNotifyLongSpinWait                = [uint16]0x0008
    HvCallParkedVirtualProcessors           = [uint16]0x0009
    HvCallInvokeHypervisorDebugger          = [uint16]0x000A
    HvCallSendSyntheticClusterIpi           = [uint16]0x000B
    HvCallModifyVtlProtectionMask           = [uint16]0x000C
    HvCallEnablePartitionVtl                = [uint16]0x000D
    HvCallDisablePartitionVtl               = [uint16]0x000E
    HvCallEnableVpVtl                       = [uint16]0x000F
    HvCallDisableVpVtl                      = [uint16]0x0010
    HvCallVtlCall                           = [uint16]0x0011
    HvCallVtlReturn                         = [uint16]0x0012
    HvCallFlushVirtualAddressSpaceEx        = [uint16]0x0013
    HvCallFlushVirtualAddressListEx         = [uint16]0x0014
    HvCallSendSyntheticClusterIpiEx         = [uint16]0x0015
    HvCallQueryImageInfo                    = [uint16]0x0016
    HvCallMapImagePages                     = [uint16]0x0017
    HvCallCommitPatch                       = [uint16]0x0018
    HvCallSyncContext                       = [uint16]0x0019
    HvCallSyncContextEx                     = [uint16]0x001A
    HvCallSetPerfRegister                   = [uint16]0x001B
    HvCallGetPerfRegister                   = [uint16]0x001C
    HvCallReserved001d                      = [uint16]0x001D
    HvCallReserved001e                      = [uint16]0x001E
    HvCallReserved001f                      = [uint16]0x001F

    # ── Reserved block (0x0020 – 0x003F) ─────────────────────────────────────

    HvCallReserved0020                      = [uint16]0x0020
    HvCallReserved0021                      = [uint16]0x0021
    HvCallReserved0022                      = [uint16]0x0022
    HvCallReserved0023                      = [uint16]0x0023
    HvCallReserved0024                      = [uint16]0x0024
    HvCallReserved0025                      = [uint16]0x0025
    HvCallReserved0026                      = [uint16]0x0026
    HvCallReserved0027                      = [uint16]0x0027
    HvCallReserved0028                      = [uint16]0x0028
    HvCallReserved0029                      = [uint16]0x0029
    HvCallReserved002a                      = [uint16]0x002A
    HvCallReserved002b                      = [uint16]0x002B
    HvCallReserved002c                      = [uint16]0x002C
    HvCallReserved002d                      = [uint16]0x002D
    HvCallReserved002e                      = [uint16]0x002E
    HvCallReserved002f                      = [uint16]0x002F
    HvCallReserved0030                      = [uint16]0x0030
    HvCallReserved0031                      = [uint16]0x0031
    HvCallReserved0032                      = [uint16]0x0032
    HvCallReserved0033                      = [uint16]0x0033
    HvCallReserved0034                      = [uint16]0x0034
    HvCallReserved0035                      = [uint16]0x0035
    HvCallReserved0036                      = [uint16]0x0036
    HvCallReserved0037                      = [uint16]0x0037
    HvCallReserved0038                      = [uint16]0x0038
    HvCallReserved0039                      = [uint16]0x0039
    HvCallReserved003a                      = [uint16]0x003A
    HvCallReserved003b                      = [uint16]0x003B
    HvCallReserved003c                      = [uint16]0x003C
    HvCallReserved003d                      = [uint16]0x003D
    HvCallReserved003e                      = [uint16]0x003E
    HvCallReserved003f                      = [uint16]0x003F

    # ── Partition management (0x0040 – 0x0047) ───────────────────────────────

    HvCallCreatePartition                   = [uint16]0x0040
    HvCallInitializePartition               = [uint16]0x0041
    HvCallFinalizePartition                 = [uint16]0x0042
    HvCallDeletePartition                   = [uint16]0x0043
    HvCallGetPartitionProperty              = [uint16]0x0044
    HvCallSetPartitionProperty              = [uint16]0x0045
    HvCallGetPartitionId                    = [uint16]0x0046
    HvCallGetNextChildPartition             = [uint16]0x0047

    # ── Memory management (0x0048 – 0x004A) ──────────────────────────────────

    HvCallDepositMemory                     = [uint16]0x0048
    HvCallWithdrawMemory                    = [uint16]0x0049
    HvCallGetMemoryBalance                  = [uint16]0x004A

    # ── GPA management (0x004B – 0x004C) ─────────────────────────────────────

    HvCallMapGpaPages                       = [uint16]0x004B
    HvCallUnmapGpaPages                     = [uint16]0x004C

    # ── Intercept (0x004D) ───────────────────────────────────────────────────

    HvCallInstallIntercept                  = [uint16]0x004D

    # ── Virtual processor (0x004E – 0x0051) ──────────────────────────────────

    HvCallCreateVp                          = [uint16]0x004E
    HvCallDeleteVp                          = [uint16]0x004F
    HvCallGetVpRegisters                    = [uint16]0x0050
    HvCallSetVpRegisters                    = [uint16]0x0051

    # ── Virtual TLB / GPA read-write (0x0052 – 0x0054) ───────────────────────

    HvCallTranslateVirtualAddress           = [uint16]0x0052
    HvCallReadGpa                           = [uint16]0x0053
    HvCallWriteGpa                          = [uint16]0x0054

    # ── Interrupts (0x0055 – 0x0056) ─────────────────────────────────────────

    HvCallAssertVirtualInterruptDeprecated  = [uint16]0x0055
    HvCallClearVirtualInterrupt             = [uint16]0x0056

    # ── Ports / messaging (0x0057 – 0x005D) ──────────────────────────────────

    HvCallCreatePortDeprecated              = [uint16]0x0057
    HvCallDeletePort                        = [uint16]0x0058
    HvCallConnectPortDeprecated             = [uint16]0x0059
    HvCallGetPortProperty                   = [uint16]0x005A
    HvCallDisconnectPort                    = [uint16]0x005B
    HvCallPostMessage                       = [uint16]0x005C
    HvCallSignalEvent                       = [uint16]0x005D

    # ── Partition state (0x005E – 0x005F) ────────────────────────────────────

    HvCallSavePartitionState                = [uint16]0x005E
    HvCallRestorePartitionState             = [uint16]0x005F

    # ── Event logging (0x0060 – 0x0068) ──────────────────────────────────────

    HvCallInitializeEventLogBufferGroup     = [uint16]0x0060
    HvCallFinalizeEventLogBufferGroup       = [uint16]0x0061
    HvCallCreateEventLogBuffer              = [uint16]0x0062
    HvCallDeleteEventLogBuffer              = [uint16]0x0063
    HvCallMapEventLogBuffer                 = [uint16]0x0064
    HvCallUnmapEventLogBuffer               = [uint16]0x0065
    HvCallSetEventLogGroupSources           = [uint16]0x0066
    HvCallReleaseEventLogBuffer             = [uint16]0x0067
    HvCallFlushEventLogBuffer               = [uint16]0x0068

    # ── Debugging (0x0069 – 0x006B) ──────────────────────────────────────────

    HvCallPostDebugData                     = [uint16]0x0069
    HvCallRetrieveDebugData                 = [uint16]0x006A
    HvCallResetDebugSession                 = [uint16]0x006B

    # ── Statistics (0x006C – 0x006D) ─────────────────────────────────────────

    HvCallMapStatsPage                      = [uint16]0x006C
    HvCallUnmapStatsPage                    = [uint16]0x006D

    # ── V1 extended / test (0x006E – 0x0075) ─────────────────────────────────

    HvCallMapSparseGpaPages                 = [uint16]0x006E
    HvCallSetSystemProperty                 = [uint16]0x006F
    HvCallSetPortProperty                   = [uint16]0x0070
    HvCallOutputDebugCharacter              = [uint16]0x0071
    HvCallEchoIncrement                     = [uint16]0x0072
    HvCallPerfNop                           = [uint16]0x0073
    HvCallPerfNopInput                      = [uint16]0x0074
    HvCallPerfNopOutput                     = [uint16]0x0075

    # ── V2 logical processor / NUMA (0x0076 – 0x007B) ────────────────────────

    HvCallAddLogicalProcessor               = [uint16]0x0076
    HvCallRemoveLogicalProcessor            = [uint16]0x0077
    HvCallQueryNumaDistance                  = [uint16]0x0078
    HvCallSetLogicalProcessorProperty       = [uint16]0x0079
    HvCallGetLogicalProcessorProperty       = [uint16]0x007A
    HvCallGetSystemProperty                 = [uint16]0x007B

    # ── Device interrupts (0x007C – 0x0080) ──────────────────────────────────

    HvCallMapDeviceInterrupt                = [uint16]0x007C
    HvCallUnmapDeviceInterrupt              = [uint16]0x007D
    HvCallRetargetDeviceInterrupt           = [uint16]0x007E
    HvCallRetargetRootDeviceInterrupt       = [uint16]0x007F
    HvCallAssertDeviceInterrupt             = [uint16]0x0080

    # ── Device attach / power / MCA (0x0081 – 0x008F) ────────────────────────

    HvCallReserved0081                      = [uint16]0x0081
    HvCallAttachDevice                      = [uint16]0x0082
    HvCallDetachDevice                      = [uint16]0x0083
    HvCallEnterSleepState                   = [uint16]0x0084
    HvCallNotifyStandbyTransition           = [uint16]0x0085
    HvCallPrepareForHibernate               = [uint16]0x0086
    HvCallNotifyPartitionEvent              = [uint16]0x0087
    HvCallGetLogicalProcessorRegisters      = [uint16]0x0088
    HvCallSetLogicalProcessorRegisters      = [uint16]0x0089
    HvCallQueryAssociatedLpsForMca          = [uint16]0x008A
    HvCallNotifyPortRingEmpty               = [uint16]0x008B
    HvCallInjectSyntheticMachineCheck       = [uint16]0x008C
    HvCallScrubPartition                    = [uint16]0x008D
    HvCallCollectLivedump                   = [uint16]0x008E
    HvCallDisableHypervisor                 = [uint16]0x008F

    # ── Sparse GPA / intercept result / assert (0x0090 – 0x009C) ─────────────

    HvCallModifySparseGpaPages              = [uint16]0x0090
    HvCallRegisterInterceptResult           = [uint16]0x0091
    HvCallUnregisterInterceptResult         = [uint16]0x0092
    HvCallGetCoverageData                   = [uint16]0x0093
    HvCallAssertVirtualInterrupt            = [uint16]0x0094
    HvCallCreatePort                        = [uint16]0x0095
    HvCallConnectPort                       = [uint16]0x0096
    HvCallGetSpaPageList                    = [uint16]0x0097
    HvCallReserved0098                      = [uint16]0x0098
    HvCallStartVirtualProcessor             = [uint16]0x0099
    HvCallGetVpIndexFromApicId              = [uint16]0x009A
    HvCallGetPowerProperty                  = [uint16]0x009B
    HvCallSetPowerProperty                  = [uint16]0x009C

    # ── PASID (0x009D – 0x00A9) ──────────────────────────────────────────────

    HvCallCreatePasidSpace                  = [uint16]0x009D
    HvCallDeletePasidSpace                  = [uint16]0x009E
    HvCallSetPasidAddressSpace              = [uint16]0x009F
    HvCallFlushPasidAddressSpace            = [uint16]0x00A0
    HvCallFlushPasidAddressList             = [uint16]0x00A1
    HvCallAttachPasidSpace                  = [uint16]0x00A2
    HvCallDetachPasidSpace                  = [uint16]0x00A3
    HvCallEnablePasid                       = [uint16]0x00A4
    HvCallDisablePasid                      = [uint16]0x00A5
    HvCallAcknowledgeDevicePageRequest      = [uint16]0x00A6
    HvCallCreateDevicePrQueue               = [uint16]0x00A7
    HvCallDeleteDevicePrQueue               = [uint16]0x00A8
    HvCallSetDevicePrqProperty              = [uint16]0x00A9

    # ── Physical device / translate-ex / GPA attributes (0x00AA – 0x00B0) ────

    HvCallGetPhysicalDeviceProperty         = [uint16]0x00AA
    HvCallSetPhysicalDeviceProperty         = [uint16]0x00AB
    HvCallTranslateVirtualAddressEx         = [uint16]0x00AC
    HvCallCheckForIoIntercept               = [uint16]0x00AD
    HvCallSetGpaPageAttributes              = [uint16]0x00AE
    HvCallFlushGuestPhysicalAddressSpace    = [uint16]0x00AF
    HvCallFlushGuestPhysicalAddressList     = [uint16]0x00B0

    # ── Device domain (0x00B1 – 0x00B4) ──────────────────────────────────────

    HvCallCreateDeviceDomain                = [uint16]0x00B1
    HvCallAttachDeviceDomain                = [uint16]0x00B2
    HvCallMapDeviceGpaPages                 = [uint16]0x00B3
    HvCallUnmapDeviceGpaPages               = [uint16]0x00B4

    # ── CPU groups (0x00B5 – 0x00BB) ─────────────────────────────────────────

    HvCallCreateCpuGroup                    = [uint16]0x00B5
    HvCallDeleteCpuGroup                    = [uint16]0x00B6
    HvCallGetCpuGroupProperty               = [uint16]0x00B7
    HvCallSetCpuGroupProperty               = [uint16]0x00B8
    HvCallGetCpuGroupAffinity               = [uint16]0x00B9
    HvCallGetNextCpuGroup                   = [uint16]0x00BA
    HvCallGetNextCpuGroupPartition          = [uint16]0x00BB

    # ── Memory / intercept / GPA commit (0x00BC – 0x00BF) ────────────────────

    HvCallAddPhysicalMemory                 = [uint16]0x00BC
    HvCallCompleteIntercept                 = [uint16]0x00BD
    HvCallPrecommitGpaPages                 = [uint16]0x00BE
    HvCallUncommitGpaPages                  = [uint16]0x00BF

    # ── Direct messaging / dispatch / IOMMU (0x00C0 – 0x00CB) ────────────────

    HvCallSignalEventDirect                 = [uint16]0x00C0
    HvCallPostMessageDirect                 = [uint16]0x00C1
    HvCallDispatchVp                        = [uint16]0x00C2
    HvCallProcessIommuPrq                   = [uint16]0x00C3
    HvCallDetachDeviceDomain                = [uint16]0x00C4
    HvCallDeleteDeviceDomain                = [uint16]0x00C5
    HvCallQueryDeviceDomain                 = [uint16]0x00C6
    HvCallMapSparseDeviceGpaPages           = [uint16]0x00C7
    HvCallUnmapSparseDeviceGpaPages         = [uint16]0x00C8
    HvCallGetGpaPagesAccessState            = [uint16]0x00C9
    HvCallGetSparseGpaPagesAccessState      = [uint16]0x00CA
    HvCallInvokeTestFramework               = [uint16]0x00CB

    # ── VTL protection range / device domain config (0x00CC – 0x00D1) ────────

    HvCallQueryVtlProtectionMaskRange       = [uint16]0x00CC
    HvCallModifyVtlProtectionMaskRange      = [uint16]0x00CD
    HvCallConfigureDeviceDomain             = [uint16]0x00CE
    HvCallQueryDeviceDomainProperties       = [uint16]0x00CF
    HvCallFlushDeviceDomain                 = [uint16]0x00D0
    HvCallFlushDeviceDomainList             = [uint16]0x00D1

    # ── Sparse GPA host access / VTL check (0x00D2 – 0x00D8) ────────────────

    HvCallAcquireSparseGpaPageHostAccess    = [uint16]0x00D2
    HvCallReleaseSparseGpaPageHostAccess    = [uint16]0x00D3
    HvCallCheckSparseGpaPageVtlAccess       = [uint16]0x00D4
    HvCallEnableDeviceInterrupt             = [uint16]0x00D5
    HvCallFlushTlb                          = [uint16]0x00D6
    HvCallAcquireSparseSpaPageHostAccess    = [uint16]0x00D7
    HvCallReleaseSparseSpaPageHostAccess    = [uint16]0x00D8

    # ── Isolation / GPA accept (0x00D9 – 0x00DF) ────────────────────────────

    HvCallAcceptGpaPages                    = [uint16]0x00D9
    HvCallUnacceptGpaPages                  = [uint16]0x00DA
    HvCallModifySparseGpaPageHostVisibility = [uint16]0x00DB
    HvCallLockSparseGpaPageMapping          = [uint16]0x00DC
    HvCallUnlockSparseGpaPageMapping        = [uint16]0x00DD
    HvCallRequestProcessorHalt              = [uint16]0x00DE
    HvCallGetInterceptData                  = [uint16]0x00DF

    # ── VP state / IPT / persistence (0x00E0 – 0x00EE) ──────────────────────

    HvCallQueryDeviceInterruptTarget        = [uint16]0x00E0
    HvCallMapVpStatePage                    = [uint16]0x00E1
    HvCallUnmapVpStatePage                  = [uint16]0x00E2
    HvCallGetVpState                        = [uint16]0x00E3
    HvCallSetVpState                        = [uint16]0x00E4
    HvCallGetVpSetFromMda                   = [uint16]0x00E5
    HvCallReserved00e6                      = [uint16]0x00E6
    HvCallCreateIptBuffers                  = [uint16]0x00E7
    HvCallDeleteIptBuffers                  = [uint16]0x00E8
    HvCallControlHypervisorIptTrace         = [uint16]0x00E9
    HvCallReserveDeviceInterrupt            = [uint16]0x00EA
    HvCallPersistDevice                     = [uint16]0x00EB
    HvCallUnpersistDevice                   = [uint16]0x00EC
    HvCallPersistDeviceInterrupt            = [uint16]0x00ED
    HvCallRefreshPerformanceCounters        = [uint16]0x00EE

    # ── SNP / isolated import (0x00EF – 0x00FD) ─────────────────────────────

    HvCallImportIsolatedPages               = [uint16]0x00EF
    HvCallCompletePendingIsolatedPagesImport = [uint16]0x00F0
    HvCallCompleteIsolatedImport            = [uint16]0x00F1
    HvCallIssueSnpPspGuestRequest           = [uint16]0x00F2
    HvCallRootSignalEvent                   = [uint16]0x00F3
    HvCallGetVpCpuidValues                  = [uint16]0x00F4
    HvCallReadSystemMemory                  = [uint16]0x00F5
    HvCallSetHwWatchdogConfig               = [uint16]0x00F6
    HvCallRemovePhysicalMemory              = [uint16]0x00F7
    HvCallLogHypervisorSystemConfig         = [uint16]0x00F8
    HvCallIssueNestedSnpPspRequests         = [uint16]0x00F9
    HvCallCompleteSnpPspRequests            = [uint16]0x00FA
    HvCallSubsumeInitializedMemory          = [uint16]0x00FB
    HvCallSubsumeVp                         = [uint16]0x00FC
    HvCallDestroySubsumedContext            = [uint16]0x00FD

    # ── Extended partition property (0x0101) ─────────────────────────────────

    HvCallGetPartitionPropertyEx            = [uint16]0x0101

    # ── Extended hypercalls (0x8001 – 0x8006) ────────────────────────────────

    HvExtCallQueryCapabilities              = [uint16]0x8001
    HvExtCallGetBootZeroedMemory            = [uint16]0x8002
    HvExtCallMemoryHeatHint                 = [uint16]0x8003
    HvExtCallEpfSetup                       = [uint16]0x8004
    HvExtCallSchedulerAssistSetup           = [uint16]0x8005
    HvExtCallMemoryHeatHintAsync            = [uint16]0x8006
}

#endregion

# ==============================================================================
# region Internal helpers
# ==============================================================================

function ConvertTo-HypercallBytes {
    <#
    .SYNOPSIS
    Serialize a single typed value to its little-endian byte representation.
    .DESCRIPTION
    Internal helper for Invoke-HypercallRaw. Converts PowerShell typed values
    to byte arrays matching their C struct layout (little-endian).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)

    switch ($Value) {
        { $_ -is [byte] }   { return ,[byte[]]@($Value) }
        { $_ -is [uint16] } { return ,[BitConverter]::GetBytes([uint16]$Value) }
        { $_ -is [int16] }  { return ,[BitConverter]::GetBytes([int16]$Value) }
        { $_ -is [uint32] } { return ,[BitConverter]::GetBytes([uint32]$Value) }
        { $_ -is [int32] }  { return ,[BitConverter]::GetBytes([int32]$Value) }
        { $_ -is [uint64] } { return ,[BitConverter]::GetBytes([uint64]$Value) }
        { $_ -is [int64] }  { return ,[BitConverter]::GetBytes([int64]$Value) }
        { $_ -is [byte[]] } { return ,$Value }
        default { throw "Unsupported type [$($Value.GetType().Name)]" }
    }
}

#endregion


# ==============================================================================
# region Generic hypercall interface
# ==============================================================================

function Invoke-HypercallRaw {
    <#
    .SYNOPSIS
    Generic hypercall invocation with automatic serialization.
    .DESCRIPTION
    Universal entry point for ANY Hyper-V hypercall. Accepts input as:
      - [ordered]@{} hashtable  — field names + typed values, serialized in order
      - [object[]] array        — typed values serialized sequentially
      - [byte[]] raw bytes      — copied as-is

    All buffer management (AllocHGlobal/FreeHGlobal, copy in/out) is handled
    by the C# method [Hvlibdotnet.Hvlib]::InvokeHypercallBytes.

    For known hypercalls, prefer the typed wrappers (Invoke-HvCallReadGpa, etc.)
    which provide named parameters and parsed output.

    Type-to-size mapping for automatic serialization:
      [byte]   -> 1    [uint16]/[int16] -> 2    [uint32]/[int32] -> 4
      [uint64]/[int64] -> 8    [byte[]] -> length of array

    .PARAMETER CallCode
    Hypercall code (e.g. 0x0053 for HvCallReadGpa).
    See [TLFS] https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface

    .PARAMETER InputData
    Input data: [ordered]@{...}, typed array, or [byte[]].

    .PARAMETER OutputSize
    Expected output size in bytes (default 4096, max 4096).

    .PARAMETER IsFast
    Use fast hypercall (register-only, no input/output pages).

    .PARAMETER CountOfElements
    Rep count for rep hypercalls (e.g. number of registers for HvCallGetVpRegisters).

    .PARAMETER RepStartIndex
    Rep start index for rep hypercalls.

    .PARAMETER IsNested
    Nested hypercall flag.

    .EXAMPLE
    # HvCallReadGpa — read 16 bytes from GPA 0x1000, partition 3
    $r = Invoke-HypercallRaw -CallCode 0x0053 -InputData ([ordered]@{
        PartitionId  = [uint64]3
        VpIndex      = [uint32]0
        ByteCount    = [uint32]16
        BaseGpa      = [uint64]0x1000
        ControlFlags = [uint64]0
    }) -OutputSize 24

    .EXAMPLE
    # Same call, compact array form
    $r = Invoke-HypercallRaw 0x0053 -InputData ([uint64]3, [uint32]0, [uint32]16, [uint64]0x1000, [uint64]0) -OutputSize 24

    .EXAMPLE
    # Raw byte array form
    $bytes = [byte[]]::new(32)
    [BitConverter]::GetBytes([uint64]3).CopyTo($bytes, 0)
    $r = Invoke-HypercallRaw 0x0053 -InputData $bytes -OutputSize 24

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uint32]$CallCode,

        [Parameter(Position = 1)]
        [object]$InputData,

        [uint32]$OutputSize = 0x1000,

        [switch]$IsFast,
        [uint32]$CountOfElements = 0,
        [uint32]$RepStartIndex = 0,
        [switch]$IsNested
    )

    # --- Serialize input to [byte[]] ---
    $inputBytes = if ($null -eq $InputData) {
        [byte[]]::new(0)
    }
    elseif ($InputData -is [byte[]]) {
        $InputData
    }
    elseif ($InputData -is [System.Collections.Specialized.OrderedDictionary] -or
            $InputData -is [object[]]) {
        $items = if ($InputData -is [System.Collections.Specialized.OrderedDictionary]) {
            $InputData.Values
        } else { $InputData }
        $buf = [System.IO.MemoryStream]::new()
        foreach ($val in $items) {
            $b = ConvertTo-HypercallBytes $val
            $buf.Write($b, 0, $b.Length)
        }
        $buf.ToArray()
    }
    else {
        throw "InputData must be [ordered]@{}, typed array, or [byte[]]"
    }

    # --- Call C# (all buffer management is in InvokeHypercallBytes) ---
    $r = [Hvlibdotnet.Hvlib]::InvokeHypercallBytes(
        $CallCode, $inputBytes, $OutputSize,
        [bool]$IsFast, $CountOfElements, $RepStartIndex, [bool]$IsNested)

    [PSCustomObject]@{
        Ok          = $r.Ok
        OutputBytes = $r.OutputData
    }
}


function Invoke-Hypercall {
    <#
    .SYNOPSIS
    Invoke any Hyper-V hypercall by name with named parameters.

    .DESCRIPTION
    Looks up the hypercall code by name, parses -Field Value pairs from remaining
    arguments, serializes them (native value types determine byte width), and
    delegates to Invoke-HypercallRaw.

    Name lookup order:
      1. Exact match              "HvCallEnableVpVtl"
      2. "HvCall" + Name         "EnableVpVtl"
      3. Insert "Call" after Hv  "HvEnableVpVtl" -> "HvCallEnableVpVtl"

    Fields are serialized in the order given. Native value type determines width:
      [uint64] / [int64]  -> 8 bytes    [uint32] / [int32] -> 4 bytes
      [uint16] / [int16]  -> 2 bytes    [byte]              -> 1 byte
      [byte[]]            -> raw

    Variables that are already typed (e.g. $ctx.PartitionId as [uint64]) need no cast.
    Bare integer literals (1, 0xFF) are [int32] = 4 bytes — cast when 8 bytes needed.

    .PARAMETER Name
    Hypercall name: "HvCallEnableVpVtl", "EnableVpVtl", or "HvEnableVpVtl".

    .PARAMETER Out
    Output buffer size in bytes (default 0 = 4096 via Invoke-HypercallRaw).

    .PARAMETER Rep
    Rep count for rep hypercalls (CountOfElements).

    .PARAMETER Rest
    -Field Value pairs for the input struct, in struct field order.

    .EXAMPLE
    Invoke-Hypercall HvCallEnableVpVtl -PartitionId $ctx.PartitionId -VpIndex ([uint32]0) -TargetVtl ([uint32]1)

    .EXAMPLE
    Invoke-Hypercall EnableVpVtl -PartitionId $ctx.PartitionId -VpIndex ([uint32]0) -TargetVtl ([uint32]1)

    .EXAMPLE
    Invoke-Hypercall HvCallModifyVtlProtectionMask `
        -PartitionId ([uint64]$ctx.PartitionId) -MapFlags ([uint32]7) `
        -TargetVtl ([uint32]0) -GpaPageNumber ([uint64]$gpa) -Rep 1

    .EXAMPLE
    Invoke-Hypercall HvCallGetLogicalProcessorRunTime -Out 32

    .EXAMPLE
    Invoke-Hypercall HvCallPerfNop

    .EXAMPLE
    Invoke-Hypercall HvCallSomethingNew -Field1 ([uint64]$val) -Field2 ([uint32]1)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Name,

        [int]$Out = 0,
        [int]$Rep = 0,

        [Parameter(ValueFromRemainingArguments)]
        [object[]]$Rest
    )

    # ── 1. Resolve call code ──────────────────────────────────────────────────
    $code = $Script:HvCallCode[$Name]
    if (-not $code) { $code = $Script:HvCallCode["HvCall$Name"] }
    if (-not $code -and $Name -match '^Hv(.+)') {
        $code = $Script:HvCallCode["HvCall$($Matches[1])"]
    }
    if (-not $code) {
        Write-Error "Unknown hypercall: '$Name'"
        return $null
    }

    # ── 2. Parse -Key Value pairs from $Rest ─────────────────────────────────
    $fields = [ordered]@{}
    $i = 0
    while ($i -lt $Rest.Count) {
        $token = $Rest[$i]
        if ($token -is [string] -and $token.StartsWith('-')) {
            $key = $token.TrimStart('-')
            $isNextValue = ($i + 1) -lt $Rest.Count -and
                           -not ($Rest[$i + 1] -is [string] -and $Rest[$i + 1].StartsWith('-'))
            if ($isNextValue) {
                $fields[$key] = $Rest[$i + 1]
                $i += 2
            } else {
                $fields[$key] = [uint64]0
                $i++
            }
        } else { $i++ }
    }

    # ── 3. No fields — simple call ────────────────────────────────────────────
    if ($fields.Count -eq 0) {
        return Invoke-HypercallRaw $code -OutputSize $Out -CountOfElements $Rep
    }

    # ── 4. Serialize — native value types determine byte width ───────────────
    $buf = [System.IO.MemoryStream]::new()
    foreach ($v in $fields.Values) {
        $b = ConvertTo-HypercallBytes $v
        $buf.Write($b, 0, $b.Length)
    }

    Invoke-HypercallRaw $code $buf.ToArray() -OutputSize $Out -CountOfElements $Rep
}

#endregion


# Note: Typed wrappers (Invoke-HvCallReadGpa, Invoke-HvCallWriteGpa,
# Invoke-HvCallGetPartitionId, Invoke-HvCallGetVpRegisters,
# Invoke-HvCallSetVpRegisters, Invoke-HvCallTranslateVirtualAddress,
# Invoke-HvCallPostMessage, Invoke-HvCallSignalEvent) were moved to
# C:\Hvlib-HvExamples.ps1 as user-editable
# examples. This module now exposes only the generic interface:
# Invoke-Hypercall, Invoke-HypercallRaw, $HvCallCode.


# ==============================================================================
# Module Export
# ==============================================================================

Export-ModuleMember -Function @(
    'Invoke-Hypercall',
    'Invoke-HypercallRaw'
) -Variable @(
    'HvCallCode'
)
