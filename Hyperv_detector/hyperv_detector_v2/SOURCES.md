# Hyper-V Detection - Documentation Sources

## Microsoft Official Documentation

### Hypervisor Top-Level Functional Specification (TLFS)
Main reference for Hyper-V internals and hypercall interface.

- **TLFS Main Page**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
- **Feature Discovery (CPUID)**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
- **Partition Properties**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/partition-properties
- **Hypercall Interface**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
- **Hypercall Reference**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/overview

### Data Types and Structures
- **HV_PARTITION_PRIVILEGE_MASK**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask

### Hypercalls (Individual)
- HvCallEnablePartitionVtl: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallenablepartitionvtl
- HvCallEnableVpVtl: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallenablevpvtl
- HvExtCallQueryCapabilities: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvextcallquerycapabilities

### Performance Counters
- **Hyper-V Performance Counters**: https://learn.microsoft.com/en-us/archive/blogs/tvoellm/hyper-v-performance-counters-part-four-of-many-hyper-v-hypervisor-virtual-processor-and-hyper-v-hypervisor-root-virtual-processor-counter-set
- **Monitoring Hyper-V Performance**: https://learn.microsoft.com/en-us/archive/blogs/tvoellm/monitoring-hyper-v-performance
- **Hyper-V Configuration**: https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/hyper-v-server/configuration
- **Detecting Bottlenecks**: https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/hyper-v-server/detecting-virtualized-environment-bottlenecks

### Root Partition / Host CPU Management
- **Hyper-V Host CPU Resource Management**: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-minroot-2016

---

## Microsoft Blogs and Articles

### Root Partition Detection
- **"Is this real? The Metaphysics of Hardware Virtualization"** (SQL Server Team Blog)
  https://learn.microsoft.com/en-us/archive/blogs/sqlosteam/is-this-real-the-metaphysics-of-hardware-virtualization
  
  Key quote: "Bit 0 of the EBX register will then be set to 1 if running in a root partition, 
  and 0 if running in a child partition."

### CPUID Clarification
- **Hyper-V CPUID Clarification Request** (Microsoft Q&A)
  https://learn.microsoft.com/en-us/answers/questions/992351/hyper-v-cpuid-clarification-request
  
  Discusses:
  - Bit 12 (CPU Management Permissions) of 0x40000003 EBX
  - Undocumented leaf 0x40000007 with ReservedIdentityBit 31 in EAX

---

## Linux Kernel Sources

### Hyper-V Support in Linux
- **Linux Kernel Hyper-V TLFS Header**: 
  https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/hyperv-tlfs.h

- **Root Partition Detection Patch**:
  https://lore.kernel.org/linux-hyperv/1622241819-21155-7-git-send-email-nunodasneves@linux.microsoft.com/
  https://www.spinics.net/lists/linux-hyperv/msg04248.html

Key definitions from Linux kernel:
```c
#define HYPERV_CPUID_FEATURES           0x40000003
#define HYPERV_CPUID_CPU_MANAGEMENT_FEATURES 0x40000007

#define HV_CPU_MANAGEMENT               BIT(12)  // EBX bit 12

// Root partition detection:
if (cpuid_ebx(HYPERV_CPUID_FEATURES) & HV_CPU_MANAGEMENT) {
    hv_root_partition = true;
}
```

---

## Third-Party Research and Analysis

### Hypervisor Detection
- **Hypervisor Detection with SystemHypervisorDetailInformation** (Matt Hand, Medium)
  https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e

### VBS and Hyper-V Internals
- **"A virtual journey: From hardware virtualization to Hyper-V's Virtual Trust Levels"** (Quarkslab)
  https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html
  
  Contains analysis of partition privilege masks:
  - Root partition: 0x002bb9ff00003fff
  - Child partition: 0x0038803000002e7f

- **"From firmware to VBS enclave: bootkitting Hyper-V"** (Samuel Tulach)
  https://tulach.cc/from-firmware-to-vbs-enclave-bootkitting-hyper-v/

### Hypercall Fuzzing Research
- **"Ventures into Hyper-V - Fuzzing hypercalls"** (WithSecure Labs)
  https://labs.withsecure.com/publications/ventures-into-hyper-v-part-1-fuzzing-hypercalls

---

## Source Code References

### VirtualBox Hyper-V Header
Contains comprehensive hypercall definitions:
https://www.virtualbox.org/svn/vbox/trunk/include/iprt/nt/hyperv.h

### Windows Internals (Geoff Chappell)
- **HV_PARTITION_PRIVILEGE_MASK**:
  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/hvgdk_mini/hv_partition_privilege_mask.htm

### Vergilius Project (Windows Structures)
- **_HV_PARTITION_PRIVILEGE_MASK**:
  https://www.vergiliusproject.com/kernels/x86/Windows%2010/1507%20Threshold%201/_HV_PARTITION_PRIVILEGE_MASK

### Intel PT Driver (Hyper-V Structures)
https://github.com/intelpt/WindowsIntelPT/blob/master/WindowsPtDriver/hv.h

### Xen Viridian Implementation
https://github.com/Xilinx/xen/blob/master/xen/arch/x86/hvm/viridian/viridian.c

---

## CPUID References

### General CPUID Documentation
- **OSDev Wiki - CPUID**: http://wiki.osdev.org/CPUID
- **Intel CPUID Reference**: https://www.felixcloutier.com/x86/cpuid
- **KVM CPUID Bits**: https://docs.kernel.org/virt/kvm/x86/cpuid.html

---

## Key CPUID Leaves for Hyper-V Detection

| Leaf | Register | Description |
|------|----------|-------------|
| 0x00000001 | ECX[31] | Hypervisor Present Bit |
| 0x40000000 | EBX,ECX,EDX | Vendor ID ("Microsoft Hv") |
| 0x40000000 | EAX | Max Hypervisor CPUID Leaf |
| 0x40000001 | EAX | Interface ID ("Hv#1") |
| 0x40000002 | EAX,EBX,ECX,EDX | Version Information |
| 0x40000003 | EAX | Partition Privileges (MSR access) |
| 0x40000003 | EBX | Partition Privileges (Hypercalls) |
| 0x40000003 | ECX | Power Management Features |
| 0x40000003 | EDX | Misc Features |
| 0x40000004 | EAX,EBX,ECX | Implementation Recommendations |
| 0x40000005 | EAX,EBX | Implementation Limits |
| 0x40000006 | EAX | Hardware Features |
| 0x40000007 | EAX | CPU Management Features (undocumented) |
| 0x4000000A | EAX | Nested Virtualization Features |

---

## HV_PARTITION_PRIVILEGE_MASK Structure

### EAX (bits 0-31) - Access to Virtual MSRs
| Bit | Name | Description |
|-----|------|-------------|
| 0 | AccessVpRunTimeReg | VP runtime MSR |
| 1 | AccessPartitionReferenceCounter | Partition reference counter |
| 2 | AccessSynicRegs | Synthetic interrupt controller |
| 3 | AccessSyntheticTimerRegs | Synthetic timers |
| 4 | AccessIntrCtrlRegs | APIC MSRs |
| 5 | AccessHypercallMsrs | Hypercall MSRs |
| 6 | AccessVpIndex | VP index MSR |
| 7 | AccessResetReg | Reset MSR |
| 8 | AccessStatsReg | Statistics MSRs |
| 9 | AccessPartitionReferenceTsc | Reference TSC |
| 10 | AccessGuestIdleReg | Guest idle MSR |
| 11 | AccessFrequencyRegs | Frequency MSRs |
| 12 | AccessDebugRegs | Debug MSRs |
| 13 | AccessReenlightenmentControls | Reenlightenment |
| 14-31 | Reserved | - |

### EBX (bits 32-63) - Access to Hypercalls
| Bit | Name | Description | Root Only? |
|-----|------|-------------|------------|
| 0 (32) | CreatePartitions | Create child partitions | **YES** |
| 1 (33) | AccessPartitionId | Get partition ID | No |
| 2 (34) | AccessMemoryPool | Deposit/withdraw memory | **YES** |
| 3 (35) | AdjustMessageBuffers | Message buffers | No |
| 4 (36) | PostMessages | Post messages | No |
| 5 (37) | SignalEvents | Signal events | No |
| 6 (38) | CreatePort | Create ports | **YES** |
| 7 (39) | ConnectPort | Connect to ports | No |
| 8 (40) | AccessStats | Statistics pages | No |
| 9-10 | Reserved | - | - |
| 11 (43) | Debugging | Debug hypercalls | **YES** |
| 12 (44) | CpuManagement | CPU management | **YES** |
| 13-15 | Reserved | - | - |
| 16 (48) | AccessVSM | VSM hypercalls | Partial |
| 17 (49) | AccessVpRegisters | VP registers | No |
| 18-19 | Reserved | - | - |
| 20 (52) | EnableExtendedHypercalls | Extended hypercalls | No |
| 21 (53) | StartVirtualProcessor | Start VP | **YES** |

---

## Hypercall Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0x0000 | HV_STATUS_SUCCESS | Success |
| 0x0002 | HV_STATUS_INVALID_HYPERCALL_CODE | Unknown hypercall |
| 0x0003 | HV_STATUS_INVALID_HYPERCALL_INPUT | Invalid input |
| 0x0004 | HV_STATUS_INVALID_ALIGNMENT | Alignment error |
| 0x0005 | HV_STATUS_INVALID_PARAMETER | Invalid parameter |
| 0x0006 | HV_STATUS_ACCESS_DENIED | **Insufficient privileges** |
| 0x0007 | HV_STATUS_INVALID_PARTITION_STATE | Invalid partition state |
| 0x0008 | HV_STATUS_OPERATION_DENIED | Operation denied |
| 0x000B | HV_STATUS_INSUFFICIENT_MEMORY | Out of memory |
| 0x000D | HV_STATUS_INVALID_PARTITION_ID | Invalid partition ID |
| 0x000E | HV_STATUS_INVALID_VP_INDEX | Invalid VP index |

---

## Notes

1. **CPUID 0x40000007** is not officially documented in TLFS but is used by Linux kernel
   for root partition detection via the ReservedIdentityBit (EAX bit 31).

2. **CreatePartitions privilege** (EBX bit 0) is the most reliable indicator of root partition,
   as it's required to create child VMs.

3. **CpuManagement privilege** (EBX bit 12) is another strong indicator, used by Linux kernel.

4. Performance counters like "Hyper-V Hypervisor Root Virtual Processor" only exist on
   root partition and provide an OS-level detection method.

5. WMI "Win32_ComputerSystem.Model" returns "Virtual Machine" for guest VMs but the actual
   hardware model for root partition.

---

## VMBus Detection

### VMBus vs VMBusr

| Driver | Location | Present In | Description |
|--------|----------|------------|-------------|
| vmbus.sys | \Device\VmBus | Guest partitions | Virtual Machine Bus driver for guest VMs |
| vmbusr.sys | \Device\VmBusr | Root partition only | VMBus Root driver for Hyper-V host |

**Detection Method:**

1. **Registry Check:**
   - `HKLM\SYSTEM\CurrentControlSet\Services\vmbus` - Guest partition
   - `HKLM\SYSTEM\CurrentControlSet\Services\vmbusr` - Root partition

2. **Driver Files:**
   - `%SystemRoot%\System32\drivers\vmbus.sys` - Guest
   - `%SystemRoot%\System32\drivers\vmbusr.sys` - Root only

3. **Kernel Mode:**
   - `IoGetDeviceObjectPointer(L"\\Device\\VmBus", ...)` - Guest
   - `IoGetDeviceObjectPointer(L"\\Device\\VmBusr", ...)` - Root only

**Logic:**
- VMBusr present → Root partition (Hyper-V host)
- VMBus present + no VMBusr → Guest partition (VM)
- Neither present → Bare metal or non-Hyper-V hypervisor

---

## Hyper-V Enlightenments and MSRs

### QEMU/KVM Hyper-V Enlightenments Documentation
- **QEMU Hyper-V Documentation**: https://www.qemu.org/docs/master/system/i386/hyperv.html
- **QEMU GitHub**: https://github.com/qemu/qemu/blob/master/docs/system/i386/hyperv.rst
- **FOSDEM 2019 Presentation**: https://archive.fosdem.org/2019/schedule/event/vai_enlightening_kvm/

### Key MSR Addresses
| MSR | Address | Description |
|-----|---------|-------------|
| HV_X64_MSR_GUEST_OS_ID | 0x40000000 | Guest OS identification |
| HV_X64_MSR_HYPERCALL | 0x40000001 | Hypercall page setup |
| HV_X64_MSR_VP_INDEX | 0x40000002 | Virtual processor index |
| HV_X64_MSR_VP_RUNTIME | 0x40000010 | VP runtime (100ns units) |
| HV_X64_MSR_TIME_REF_COUNT | 0x40000020 | Reference time counter |
| HV_X64_MSR_REFERENCE_TSC | 0x40000021 | Reference TSC page |
| HV_X64_MSR_TSC_FREQUENCY | 0x40000022 | TSC frequency |
| HV_X64_MSR_APIC_FREQUENCY | 0x40000023 | APIC frequency |
| HV_X64_MSR_VP_ASSIST_PAGE | 0x40000073 | VP Assist page |
| HV_X64_MSR_SCONTROL | 0x40000080 | SynIC control |
| HV_X64_MSR_STIMER0_CONFIG | 0x400000B0 | Synthetic timer 0 |
| HV_X64_MSR_CRASH_CTL | 0x40000105 | Crash control |

### Enlightenment Flags (CPUID 0x40000004 EAX)
| Bit | Name | Description |
|-----|------|-------------|
| 0 | HypercallAddressSwitch | Use hypercall for CR3 switch |
| 1 | LocalTLBFlush | Use hypercall for local TLB flush |
| 2 | RemoteTLBFlush | Use hypercall for remote TLB flush |
| 3 | MSRAPICAccess | Use MSR for APIC access |
| 4 | MSRReset | Use MSR for system reset |
| 5 | RelaxedTiming | Relaxed timing (hv-relaxed) |
| 10 | SyntheticClusterIPI | Use hypercall for cluster IPI |
| 12 | NestedHyperV | Nested Hyper-V support |

---

## Integration Services

### Microsoft Documentation
- **Integration Services Overview**: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/integration-services
- **Managing Integration Services**: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services

### Service Names
| Service | Display Name | Purpose |
|---------|--------------|---------|
| vmicheartbeat | Hyper-V Heartbeat Service | Monitors VM state |
| vmicshutdown | Hyper-V Guest Shutdown Service | Graceful shutdown |
| vmictimesync | Hyper-V Time Synchronization | Clock sync |
| vmickvpexchange | Hyper-V Data Exchange Service | KVP exchange |
| vmicguestinterface | Hyper-V Guest Service Interface | File copy |
| vmicrdv | Hyper-V Remote Desktop Virtualization | Enhanced RDP |
| vmicvss | Hyper-V Volume Shadow Copy Requestor | Backup |
| vmicvmsession | Hyper-V PowerShell Direct Service | PS Direct |

---

## ACPI Tables

### WAET (Windows ACPI Emulated Devices Table)
- **OSDev Wiki**: https://wiki.osdev.org/WAET
- **Microsoft Specification**: https://download.microsoft.com/download/7/E/7/7E7662CF-CBEA-470B-A97E-CE7CE0D98DC2/WAET.docx
- **QEMU WAET Patch**: https://mail.gnu.org/archive/html/qemu-devel/2020-03/msg04045.html
- **Evading ACPI Checks**: https://revers.engineering/evading-trivial-acpi-checks/

### WAET Flags
| Bit | Name | Description |
|-----|------|-------------|
| 0 | RTC_GOOD | RTC doesn't lose time |
| 1 | PM_TIMER_GOOD | ACPI PM timer reliable |

### Known VM OEM IDs in ACPI Tables
| OEM ID | Hypervisor |
|--------|------------|
| VRTUAL | Hyper-V |
| MSFT | Hyper-V |
| MSHYPR | Hyper-V |
| VMWARE | VMware |
| VBOX | VirtualBox |
| QEMU | QEMU |
| AMAZON | AWS |
| Google | GCP |

---

## Synthetic Devices and VMBus

### Linux Kernel Documentation
- **VMBus Documentation**: https://docs.kernel.org/virt/hyperv/vmbus.html
- **GitHub VMBus RST**: https://github.com/torvalds/linux/blob/master/Documentation/virt/hyperv/vmbus.rst

### Synthetic Device GUIDs
| GUID | Device |
|------|--------|
| f8615163-df3e-46c5-913f-f2d2f965ed0e | Synthetic Network (netvsc) |
| ba6163d9-04a1-4d29-b605-72e2ffb1dc7f | Synthetic SCSI (storvsc) |
| 0e0b6031-5213-4934-818b-38d90ced39db | Shutdown |
| 9527e630-d0ae-497b-adce-e80ab0175caf | Time Sync |
| 57164f39-9115-4e78-ab55-382f3bd5422d | Heartbeat |
| a9a0f4e7-5a45-4d96-b827-8a841e8c03e6 | KVP Exchange |
| 35fa2e29-ea23-4236-96ae-3a6ebacba440 | Dynamic Memory |
| 34d14be3-dee4-41c8-9ae7-6b174977c192 | VSS |

### VSP/VSC Architecture
- **VSP** (Virtual Service Provider): Runs in root partition
- **VSC** (Virtual Service Consumer): Runs in guest partition
- Communication via VMBus ring buffers

---

## VM Generation Detection

### Microsoft Documentation
- **Generation 1 vs 2**: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v
- **Gen2 Security**: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/generation-2-virtual-machine-security-settings-for-hyper-v

### Generation Characteristics
| Feature | Gen1 | Gen2 |
|---------|------|------|
| Firmware | BIOS | UEFI |
| Boot Disk | IDE | SCSI |
| Secure Boot | No | Yes |
| Virtual TPM | No | Yes |
| Max Boot Disk | 2TB | 64TB |
| COM Ports | Yes | No |
| Floppy | Yes | No |

---

## NtQuerySystemInformation Detection

### Documentation
- **Matt Hand Article**: https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e
- **Geoff Chappell**: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_hypervisor_detail_information.htm
- **Microsoft SDK**: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation

### SystemHypervisorDetailInformation (0x9F)

This undocumented information class returns CPUID results for hypervisor leaves:

| Offset | CPUID Leaf | Description |
|--------|------------|-------------|
| 0x00 | 0x40000000 | Vendor and Max Function |
| 0x10 | 0x40000001 | Interface ID |
| 0x20 | 0x40000002 | Version Information |
| 0x30 | 0x40000003 | Features and Privileges |
| 0x40 | 0x40000004 | Enlightenments/Recommendations |
| 0x50 | 0x40000005 | Implementation Limits |
| 0x60 | 0x40000006 | Hardware Features |

### SYSTEM_HYPERVISOR_DETAIL_INFORMATION Structure (0x70 bytes)
```c
typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION {
    HV_DETAILS HvVendorAndMaxFunction;  /* 0x40000000 */
    HV_DETAILS HvInterface;             /* 0x40000001 */
    HV_DETAILS HvVersion;               /* 0x40000002 */
    HV_DETAILS HvFeatures;              /* 0x40000003 */
    HV_DETAILS HvEnlightenments;        /* 0x40000004 */
    HV_DETAILS HvImplementationLimits;  /* 0x40000005 */
    HV_DETAILS HvHardwareFeatures;      /* 0x40000006 */
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION;
```

---

## WMI Hyper-V Namespace Detection

### Documentation
- **WMI v2 Namespace**: https://learn.microsoft.com/en-us/archive/blogs/virtual_pc_guy/the-v2-wmi-namespace-in-hyper-v-on-windows-8
- **Programming Hyper-V with WMI**: https://learn.microsoft.com/en-us/archive/blogs/richard_macdonald/programming-hyper-v-with-wmi-and-c-getting-started
- **WMI Undocumented Changes**: https://virtualizationdojo.com/hyper-v/undocumented-changes-hyper-v-2016-wmi/

### Key WMI Namespaces
| Namespace | Windows Version | Description |
|-----------|-----------------|-------------|
| root\virtualization\v2 | Server 2012+ / Windows 8+ | Current namespace |
| root\virtualization | Server 2008/2008R2 | Legacy namespace |

### Key WMI Classes
| Class | Description |
|-------|-------------|
| Msvm_ComputerSystem | Virtual machines and host |
| Msvm_VirtualSystemManagementService | VM management service (host only) |
| Msvm_VirtualEthernetSwitch | Virtual switches |
| Msvm_SummaryInformation | VM summary info |

### Host Detection Logic
- Presence of `root\virtualization\v2` namespace
- Presence of `Msvm_VirtualSystemManagementService` class
- Both indicate Hyper-V HOST (root partition)
- Guest VMs do NOT have these namespaces

---

## Nested Virtualization Detection

### Documentation
- **TLFS Nested Virtualization**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/nested-virtualization
- **QEMU Hyper-V Enlightenments**: https://www.qemu.org/docs/master/system/i386/hyperv.html
- **CoCo VMs Documentation**: https://docs.kernel.org/virt/hyperv/coco.html
- **Linux kernel hyperv-tlfs.h**: arch/x86/include/asm/hyperv-tlfs.h

### CPUID 0x4000000A - Nested Features
| Bit | Name | Description |
|-----|------|-------------|
| 17 | DirectFlush | Direct virtual flush support |
| 18 | GuestMappingFlush | Guest mapping flush |
| 19 | MsrBitmap | Enlightened MSR bitmap |
| 20 | EVMCS | Enlightened VMCS (Intel) |
| 22 | EnlightenedTLB | Enlightened TLB (AMD) |
| 23 | ExceptionCombining | Exception combining |

### CPUID 0x4000000C - Isolation Config
| Bits | Field | Values |
|------|-------|--------|
| 0 | Paravisor | 0=No, 1=Present |
| 1-4 | IsolationType | 0=None, 1=VBS, 2=SEV-SNP, 3=TDX |

### Confidential Computing (CoCo) VM Types
| Type | Hardware | Description |
|------|----------|-------------|
| VBS | Software | Virtualization-Based Security |
| SEV-SNP | AMD | Secure Encrypted Virtualization |
| TDX | Intel | Trust Domain Extensions |


## Virtual Secure Mode (VSM) Detection

### Documentation
- **TLFS VSM**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm
- **Quarkslab VTL Research**: https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html
- **Microsoft Press Virtualization**: https://www.microsoftpressstore.com/articles/article.aspx?p=3145750

### VSM MSRs
| MSR | Address | Description |
|-----|---------|-------------|
| HV_X64_MSR_VSM_CAPABILITIES | 0x4009001C | VSM capabilities |
| HV_X64_MSR_VSM_PARTITION_STATUS | 0x4009001D | Partition VSM status |
| HV_X64_MSR_VSM_VP_STATUS | 0x4009001E | VP VTL status |

### Privilege Flags for VSM (CPUID 0x40000003)
| Privilege | Bit | Required for VSM |
|-----------|-----|------------------|
| AccessVsm | 48 | Yes |
| AccessVpRegisters | 49 | Yes |
| AccessSynicRegs | 2 | Yes |

### VTL Hypercalls
| Hypercall | Description |
|-----------|-------------|
| HvCallEnablePartitionVtl | Enable VTL for partition |
| HvCallEnableVpVtl | Enable VTL for VP |
| HvCallVtlCall | Switch to higher VTL |
| HvCallVtlReturn | Return to lower VTL |

### Registry Keys for VSM Detection
```
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
  - EnableVirtualizationBasedSecurity
  - HypervisorEnforcedCodeIntegrity

HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  - LsaCfgFlags (Credential Guard)
```

---

## Partition Properties Detection

### Documentation
- **TLFS Partition**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/partition-properties
- **HV_PARTITION_PRIVILEGE_MASK**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask
- **Hypercall Interface**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
- **MSRC Hyper-V Research**: https://msrc-blog.microsoft.com/2018/12/10/first-steps-in-hyper-v-research/

### CPUID 0x40000003 - Partition Privilege Mask
#### EAX - MSR Access Privileges
| Bit | Privilege | Description |
|-----|-----------|-------------|
| 0 | AccessVpRunTimeReg | VP runtime register |
| 1 | AccessPartitionReferenceCounter | Reference counter |
| 2 | AccessSynicRegs | SynIC registers |
| 3 | AccessSyntheticTimerRegs | Synthetic timers |
| 5 | AccessHypercallMsrs | Hypercall MSRs |
| 6 | AccessVpIndex | VP index |
| 9 | AccessPartitionReferenceTsc | Reference TSC |

#### EBX - Hypercall Privileges
| Bit | Privilege | Description |
|-----|-----------|-------------|
| 0 (32) | CreatePartitions | ROOT ONLY |
| 1 (33) | AccessPartitionId | Partition ID |
| 4 (36) | PostMessages | Message posting |
| 5 (37) | SignalEvents | Event signaling |
| 12 (44) | CpuManagement | ROOT ONLY |
| 16 (48) | AccessVSM | VSM access |

### Root Partition Indicators
- CreatePartitions privilege (bit 32)
- CpuManagement privilege (bit 44)
- Both must be present for root partition

---

## Synthetic MSR Detection

### Documentation
- **QEMU Hyper-V Enlightenments**: https://www.qemu.org/docs/master/system/i386/hyperv.html
- **FOSDEM 2019 KVM Enlightenments**: https://archive.fosdem.org/2019/schedule/event/vai_enlightening_kvm/

### Synthetic MSR Categories
| Category | MSR Range | Description |
|----------|-----------|-------------|
| Core | 0x40000000-03 | Guest OS ID, Hypercall, VP Index, Reset |
| Timing | 0x40000010-23 | VP Runtime, Time Ref, TSC, Frequencies |
| SynIC | 0x40000080-9F | Synthetic Interrupt Controller |
| Timers | 0x400000B0-B7 | Synthetic Timers (4 per VP) |
| Crash | 0x40000100-05 | Crash Parameters and Control |
| Re-enlight | 0x40000106-08 | Re-enlightenment Control |

### Key MSRs
| MSR | Address | Purpose |
|-----|---------|---------|
| HV_X64_MSR_GUEST_OS_ID | 0x40000000 | Guest OS identification |
| HV_X64_MSR_HYPERCALL | 0x40000001 | Hypercall page setup |
| HV_X64_MSR_VP_INDEX | 0x40000002 | Virtual processor index |
| HV_X64_MSR_TIME_REF_COUNT | 0x40000020 | Reference time counter |
| HV_X64_MSR_REFERENCE_TSC | 0x40000021 | Reference TSC page |
| HV_X64_MSR_CRASH_CTL | 0x40000105 | Crash control |

---

## Hypervisor Recommendations Detection

### Documentation
- **TLFS Feature Discovery**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
- **Matt Hand Article**: https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e

### CPUID 0x40000004 - Recommendations (EAX)
| Bit | Recommendation | Description |
|-----|----------------|-------------|
| 0 | HypercallForSwitch | Use hypercall for address space switch |
| 1 | HypercallForLocalTlb | Use hypercall for local TLB flush |
| 2 | HypercallForRemoteTlb | Use hypercall for remote TLB flush |
| 3 | MsrForApicAccess | Use MSRs for APIC access |
| 5 | RelaxedTiming | Use relaxed timing |
| 10 | HypercallForIpi | Use hypercall for IPI |
| 13 | Nested | Nested hypervisor indicator |
| 15 | EnlightenedVmcs | Use enlightened VMCS |

### EBX - Spinlock Retries
- Value: Number of retry attempts before notifying hypervisor
- 0xFFFFFFFF: Never notify (default)
- Other: Retry count for paravirtualized spinlocks

---

## Implementation Limits Detection

### Documentation
- **TLFS Feature Discovery**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
- **Windows Driver Docs (MSDN)**: Virtual Processor Data Types

### CPUID 0x40000005 - Implementation Limits
| Register | Value | Description |
|----------|-------|-------------|
| EAX | Max VPs | Maximum virtual processors per partition |
| EBX | Max LPs | Maximum logical processors |
| ECX | Max Vectors | Maximum physical interrupt vectors |
| EDX | Reserved | Reserved |

### Typical Values
- Windows Server 2012 R2: Up to 320 LPs, 2048 VPs
- Windows Server 2016+: Up to 512 LPs, 2048 VPs per partition

---

## Hardware Features Detection

### Documentation
- **TLFS Feature Discovery**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
- **Alex Ionescu hdv**: Hyper-V Development Kit

### CPUID 0x40000006 EAX - Hardware Features
| Bit | Feature | Description |
|-----|---------|-------------|
| 0 | APIC Overlay | APIC overlay assist |
| 1 | MSR Bitmaps | MSR bitmap support |
| 2 | Arch Perf Counters | Architectural performance counters |
| 3 | SLAT | EPT (Intel) / NPT (AMD) enabled |
| 4 | DMA Remapping | VT-d / AMD-Vi IOMMU |
| 5 | Interrupt Remapping | Interrupt remapping enabled |
| 6 | Memory Patrol | Memory patrol scrubber |
| 7 | DMA Protection | DMA protection in use |
| 8 | HPET Requested | HPET requested |
| 9 | Synth Timers Volatile | Synthetic timers are volatile |

### Note on SLAT
SLAT (Second Level Address Translation) bit is expected to be set on virtually 
every modern hypervisor. Intel calls this EPT (Extended Page Tables), AMD calls 
it NPT (Nested Page Tables).

---

## Hypervisor Version Detection

### Documentation
- **Behrooz Abbassi HypervCpuidInfo**: https://gist.github.com/BehroozAbbassi/8e07bae41b0b037a55259c19d00aa458
- **Alex Ionescu HDK**: https://github.com/ionescu007/hdk
- **Matt Hand SystemHypervisorDetailInformation**: https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e

### CPUID 0x40000002 - Version Information
| Register | Content |
|----------|---------|
| EAX | Build number |
| EBX | Major (high word) + Minor (low word) |
| ECX | Service Pack |
| EDX | Service branch (bits 0-23) + Service number (bits 24-31) |

### Known Build Numbers
| Build | Windows Version | Hyper-V |
|-------|-----------------|---------|
| 14393 | Server 2016 / Win10 1607 | Hyper-V 2016 |
| 17763 | Server 2019 / Win10 1809 | Hyper-V 2019 |
| 20348 | Server 2022 | Hyper-V 2022 |
| 22621 | Windows 11 22H2 | Hyper-V (Win11) |
| 26100 | Server 2025 / Win11 24H2 | Hyper-V 2025 |

---

## Hyper-V Socket Detection

### Documentation
- **Arthur Khudyaev**: https://hvinternals.blogspot.com/2017/09/hyperv-socket-internals.html
- **VMBusPipe**: https://github.com/awakecoding/VMBusPipe
- **Microsoft Learn**: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service

### AF_HYPERV Constants
- Address Family: 34 (AF_HYPERV)
- Protocol: 1 (HV_PROTOCOL_RAW)

### Well-Known VM GUIDs
| GUID | Purpose |
|------|---------|
| HV_GUID_PARENT | Parent partition |
| HV_GUID_CHILDREN | All child partitions |
| HV_GUID_LOOPBACK | Loopback |
| HV_GUID_WILDCARD | Any partition |

---

## Windows Hypervisor Platform (WHP) Detection

### Documentation
- **Microsoft WHP API**: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform
- **Simpleator**: https://github.com/ionescu007/Simpleator
- **pywinhv**: https://github.com/0vercl0k/pywinhv
- **libwhp (Rust)**: https://crates.io/crates/libwhp
- **whpexp**: https://github.com/epakskape/whpexp

### WHP DLL
- Library: WinHvPlatform.dll
- Available since: Windows 10 1803 (Build 17134)

### WHP Capability Codes
| Code | Description |
|------|-------------|
| 0x00000000 | Hypervisor Present |
| 0x00000001 | Features |
| 0x00001000 | Processor Vendor |
| 0x00001001 | Processor Features |

---

## Host Compute System (HCS) Detection

### Documentation
- **Microsoft HCS API**: https://learn.microsoft.com/en-us/virtualization/api/hcs/overview
- **NanaBox**: https://github.com/M2Team/NanaBox
- **Kenji Mouri Notes**: https://github.com/MouriNaruto/MouriDocs/tree/main/docs/4
- **Windows Sandbox**: https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Windows-Sandbox/ba-p/301849
- **Hyper-V API Overview (Benjamin Armstrong)**: MSFT internal presentation

### HCS DLLs
| DLL | Description |
|-----|-------------|
| computecore.dll | Core HCS API (newer) |
| vmcompute.dll | Alternative API |
| compute.dll | Legacy API |

### HCS Services
| Service | Purpose |
|---------|---------|
| vmcompute | Host Compute Service |
| vmms | Virtual Machine Management Service |

---

## Research History References

### Key Researchers
- **Arthur Khudyaev** (@gerhart_x) - Hyper-V internals, memory, sockets
- **Alex Ionescu** (@aionescu) - HDK, Simpleator, Hyper-V IPC
- **Behrooz Abbassi** (@BehroozAbbassi) - CPUID info, research scripts
- **Matt Hand** (@matterpreter) - SystemHypervisorDetailInformation
- **Saar Amar** (@AmarSaar) - Hyper-V research, VSM
- **Kenji Mouri** (@MouriNaruto) - Mile.HyperV, NanaBox

### Research Papers & Tools
- https://github.com/gerhart01/Hyper-V-Internals
- https://github.com/BehroozAbbassi/hyperv-research-scripts
- https://github.com/ProjectMile/Mile.HyperV
- https://github.com/ionescu007/hdk


---

## GPU Paravirtualization (GPU-PV) Detection

### Documentation
- **DirectX: The New Hyper-V Attack Surface** (Zhenhao Hon, Ziming Zhang): https://i.blackhat.com/USA-22/Thursday/US-22-Hong-DirectX-The-New-Hyper-V-Attack-Surface.pdf
- **Microsoft GPU Partitioning**: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/gpu-partitioning

### Detection Methods
| Method | Description |
|--------|-------------|
| Display Adapter | Check for "Microsoft Hyper-V Video" |
| VMBus DX Device | GPU exposed via VMBus |
| dxgkrnl.sys | DirectX Graphics Kernel |
| vmrdvcore | Remote Desktop Video Core |

---

## VBS Enclave / IUM Detection

### Documentation
- **Battle of SKM and IUM** (Alex Ionescu): https://web.archive.org/web/20190728160948/http://www.alex-ionescu.com/blackhat2015.pdf
- **Debugging Windows IUM Processes** (Francisco Falcon): https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html
- **Abusing VBS Enclaves** (Ori David): https://www.akamai.com/blog/security-research/2025-february-abusing-vbs-enclaves-evasive-malware
- **VBS Internals** (Saar Amar): BlueHat IL 2018

### Enclave Types
| Type | Value | Description |
|------|-------|-------------|
| SGX | 0x00000001 | Intel Software Guard Extensions |
| VBS | 0x00000010 | Virtualization-Based Security |

### IUM Processes
- LsaIso.exe - Credential Guard
- securekernel.exe - Secure Kernel

---

## VM Worker Process (VMWP) Detection

### Documentation
- **Attacking the VM Worker Process** (Saar Amar): https://msrc.microsoft.com/blog/2019/09/attacking-the-vm-worker-process/
- **VmwpMonitor** (Behrooz Abbassi): https://github.com/BehroozAbbassi/VmwpMonitor
- **First Steps in Hyper-V Research** (Saar Amar): https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/
- **A Dive in to Hyper-V Architecture** (Joly, Bialek): BlackHat 2018

### Host Processes
| Process | Description |
|---------|-------------|
| vmwp.exe | VM Worker Process (one per VM) |
| vmms.exe | Virtual Machine Management Service |
| vmcompute.exe | VM Compute Process |
| vmsvc.exe | VM Service |

### Key DLLs
- vid.dll - Virtualization Infrastructure Driver
- winhvplatform.dll - Windows Hypervisor Platform

---

## Hypercall Interface Detection

### Documentation
- **Writing a Hyper-V Bridge for Fuzzing** (Alex Ionescu): https://www.alex-ionescu.com/?p=471
- **Fuzzing para-virtualized devices in Hyper-V** (MSRC): https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/
- **Ventures into Hyper-V - Fuzzing hypercalls** (Amardeep Chana): https://labs.withsecure.com/publications/ventures-into-hyper-v-part-1-fuzzing-hypercalls
- **Growing Hypervisor 0day with Hyperseed** (Daniel King, Shawn Denbow): OffensiveCon 2019
- **HyperDeceit** (Aryan Xyrem): https://github.com/Xyrem/HyperDeceit
- **Hvcalls GUI** (Arthur Khudyaev): https://github.com/gerhart01/Hyper-V-Tools/tree/main/Extract.Hvcalls

### CPUID 0x40000003 Privileges
| Bit | EAX/EBX | Description |
|-----|---------|-------------|
| EBX:0 | CreatePartitions | Root partition indicator |
| EBX:2 | AccessHypercallMsrs | MSR access |
| EBX:4 | AccessVpIndex | VP Index access |
| EBX:5 | PostMessages | Message posting |
| EBX:6 | SignalEvents | Event signaling |

### Key Hypercalls
| Code | Name |
|------|------|
| 0x005C | HVCALL_POST_MESSAGE |
| 0x005D | HVCALL_SIGNAL_EVENT |
| 0x0050 | HVCALL_GET_VP_REGISTERS |
| 0x0051 | HVCALL_SET_VP_REGISTERS |

---

## VM Saved State Detection

### Documentation
- **vmsavedstatedump API**: https://learn.microsoft.com/en-us/windows/win32/api/vmsavedstatedump/
- **LiveCloudKd**: https://github.com/gerhart01/LiveCloudKd
- **MemProcFS Hyper-V Plugin**: https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd

### Saved State Files
| Extension | Description |
|-----------|-------------|
| .vmrs | Runtime saved state (Gen2) |
| .bin | Memory snapshot |
| .vsav | Legacy saved state (Gen1) |

### Key DLL
- vmsavedstatedumpprovider.dll

---

## HVCI Detection

### Documentation
- **Living The Age of VBS, HVCI, and Kernel CFG** (Connor McGarr): https://connormcgarr.github.io/hvci/
- **CVE-2024-21305** (Satoshi Tanda): https://tandasat.github.io/blog/2024/01/15/CVE-2024-21305.html
- **Code Execution against Windows HVCI** (Worawit Wang): https://datafarm-cybersecurity.medium.com/code-execution-against-windows-hvci-f617570e9df0
- **Kernel Data Protection** (Andrea Allievi): https://www.microsoft.com/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- **KCFG and KCET** (Connor McGarr): BlackHat 2025

### Registry Keys
| Path | Value |
|------|-------|
| DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity | Enabled, Running |
| DeviceGuard | EnableVirtualizationBasedSecurity |
| CI\Config | VirtualizationBasedSecurityStatus |

### Code Integrity Features
- HVCI - Hypervisor-enforced Code Integrity
- KCFG - Kernel Control Flow Guard
- KCET - Kernel Control Flow Enforcement Technology (Shadow Stacks)
- KDP - Kernel Data Protection

---

## VMBus Channel Detection

### Documentation
- **Linux Integration Services**: https://github.com/LIS
- **Hyper-V LIS description** (Alisa Shevchenko): https://re.alisa.sh/notes/Hyper-V-LIS.html
- **VMBusPipe** (Marc-André Moreau): https://github.com/awakecoding/VMBusPipe
- **hcsshim** (Microsoft): https://github.com/microsoft/hcsshim
- **CHIPSEC VMBus fuzzing** (Yuriy Bulygin): https://github.com/chipsec/chipsec/tree/master/chipsec/modules/tools/vmm/hv

### VMBus Drivers
| Driver | Environment |
|--------|-------------|
| vmbus | Guest VM |
| vmbusr | Root partition |

### Integration Channels
| Channel | GUID | Purpose |
|---------|------|---------|
| KVP | cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a | Key-Value Pair |
| Shutdown | 0e0b6031-5213-4934-818b-38d90ced39db | Shutdown IC |
| Heartbeat | 57164f39-9115-4e78-ab55-382f3bd5422d | Heartbeat IC |
| Time Sync | 9527e630-d0ae-497b-adce-e80ab0175caf | Time Synchronization |
| VSS | 35fa2e29-ea23-4236-96ae-3a6ebacba440 | Volume Shadow Copy |

---

## HyperGuard / SKPG Detection

### Documentation
- **HyperGuard Part 1** (Yarden Shafir): https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-1-skpg-initialization/
- **HyperGuard Part 2** (Yarden Shafir): https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-2-skpg-extents/
- **HyperGuard Part 3** (Yarden Shafir): https://windows-internals.com/hyperguard-part-3-more-skpg-extents/
- **Secure Pool Internals** (Yarden Shafir): https://windows-internals.com/secure-pool
- **Breaking VSM by Attacking Secure Kernel** (Saar Amar, Daniel King): MSRC BlackHat 2020

### Components
| Component | Description |
|-----------|-------------|
| securekernel.exe | Secure Kernel binary |
| skci.dll | Secure Kernel Code Integrity |
| Secure Pool | KDP-protected pool allocations |

---

## System Guard Runtime Attestation Detection

### Documentation
- **Inside the Octagon** (Alex Ionescu, David Weston): OPCDE 2018
- **Redefining Security Boundaries** (Connor McGarr): SANS Hackfest 2024
- **Microsoft System Guard**: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/

### Root of Trust Types
| Type | Description |
|------|-------------|
| SRTM | Static Root of Trust Measurement (firmware) |
| DRTM | Dynamic Root of Trust Measurement (Secure Launch) |
| SMM Protection | System Management Mode protection |

---

## Windows Container Detection

### Documentation
- **Windows SDK**: wmcontainer.h, isolatedapplauncher.h
- **HCN (Host Compute Network)**: https://github.com/microsoft/hcsshim
- **Windows Sandbox** (Hari Pulapaka): https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Windows-Sandbox/ba-p/301849
- **WDAG** (Yunhai Zhang): https://www.powerofcommunity.net/poc2018/yunhai.pdf

### Container Features
| Feature | Description |
|---------|-------------|
| Windows Containers | Docker/Kubernetes support |
| Windows Sandbox | Disposable desktop environment |
| WDAG | Windows Defender Application Guard |
| Hyper-V Isolation | VM-based container isolation |

---

## Hyper-V Emulation API Detection

### Documentation
- **Windows SDK**: WinHvEmulation.h
- **QEMU WHPX module**: https://github.com/qemu/qemu/tree/master/hw/hyperv
- **VirtualBox NEM**: https://www.virtualbox.org/browser/vbox/trunk/src/VBox/VMM/VMMR3/NEMR3Native-win.cpp
- **Hyntrospect** (Diane Dubois): https://github.com/googleprojectzero/Hyntrospect
- **Fuzzing para-virtualized devices** (MSRC): https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/

### Emulation DLLs
| DLL | Description |
|-----|-------------|
| WinHvEmulation.dll | Device emulation API |
| WinHvPlatform.dll | Hypervisor platform API |

### Third-party Hypervisors Using WHPX
- QEMU (qemu-system-x86_64.exe with -accel whpx)
- VirtualBox (NEM backend)
- Android Emulator

---

## Secure Calls / SkBridge Detection

### Description
Detects Secure Calls infrastructure - the communication bridge between the NT Kernel (VTL0)
and Secure Kernel (VTL1). This mechanism enables protected operations like Credential Guard
and other Virtualization-Based Security features.

### Documentation
- **Windows Internals: Secure Calls** (Connor McGarr): https://connormcgarr.github.io/secure-calls-and-skbridge
- **SkBridge** (Connor McGarr): https://github.com/connormcgarr/SkBridge
- **Vtl1Mon** (Connor McGarr): https://github.com/connormcgarr/Vtl1Mon
- **Breaking VSM by Attacking SecureKernel** (Saar Amar, Daniel King): MSRC 2020
- **VBS Internals** (Saar Amar): BlueHat IL 2018

### Components
| Component | Description |
|-----------|-------------|
| securekernel.exe | Secure Kernel binary |
| CI.dll | Code Integrity |
| SKCI.dll | Secure Kernel Code Integrity |
| LsaIso.exe | Credential Guard IUM process |

---

## EXO Partition / Memory Access Detection

### Description
Detects EXO (External) Partition memory access capabilities. EXO partitions allow
the Hyper-V host to access guest VM memory for debugging and forensics purposes.
Tools like LiveCloudKd and MemProcFS use these APIs for live memory analysis.

### Documentation
- **Hyper-V memory internals. EXO partition** (Arthur Khudyaev): https://hvinternals.blogspot.com/2020/06/hyper-v-memory-internals-exo-partition.html
- **Hyper-V memory internals. Guest OS memory** (Arthur Khudyaev): https://hvinternals.blogspot.com/2019/09/hyper-v-memory-internals-guest-os-memory-access.html
- **LiveCloudKd** (Arthur Khudyaev): https://github.com/gerhart01/LiveCloudKd
- **MemProcFS Hyper-V plugin**: https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd
- **hvlib SDK**: https://gitlab.com/hvlib/sdk

### Key Components
| Component | Description |
|-----------|-------------|
| vid.sys | Virtualization Infrastructure Driver |
| vid.dll | VID user-mode API |
| hvmm.sys | Hyper-V Memory Manager (custom) |

---

## Hyper-V Debugging Interface Detection

### Description
Detects Hyper-V debugging interfaces and configuration. Includes BCD debug settings,
kernel debugger presence, and specialized debugging tools like EXDi plugins and
WinDbg extensions for hypervisor analysis.

### Documentation
- **Hyper-V debugging for beginners** (Arthur Khudyaev): https://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html
- **Hyper-V debugging Part 2** (Arthur Khudyaev): https://hvinternals.blogspot.com/2017/10/hyper-v-debugging-for-beginners-part-2.html
- **LiveCloudKd EXDi plugin**: https://github.com/gerhart01/LiveCloudKd/tree/master/ExdiKdSample
- **hvext** (Satoshi Tanda): https://github.com/tandasat/hvext
- **SecurekernelIUMDebug** (cbwang505): https://github.com/cbwang505/SecurekernelIUMDebug

### Debug Settings
| Setting | Registry/BCD |
|---------|--------------|
| Kernel Debug | BCD 0x16000010 |
| Hypervisor Debug | BCD 0x250000f4 |
| VM Debugging | Virtualization\GuestDebuggingEnabled |

---

## VMCS / EPT Detection

### Description
Detects Intel VT-x virtualization structures (VMCS - Virtual Machine Control Structure) 
and EPT (Extended Page Tables) support indicators. These are fundamental hardware 
virtualization features used by Hyper-V for efficient VM execution and memory management.

### Documentation
- **hvext** (Satoshi Tanda): https://github.com/tandasat/hvext
  - WinDbg extension for Hyper-V debugging
  - Commands: !dump_ept, !dump_vmcs, !dump_msr
  - Primary tool for EPT and VMCS structure analysis
- **Some notes on exit handlers** (Bruce Dang): https://gracefulbits.wordpress.com/2019/03/25/some-notes-on-identifying-exit-and-hypercall-handlers-in-hyperv/
- **A Dive in to Hyper-V Architecture** (Nicolas Joly, Joe Bialek): BlackHat USA 2018
- **Intel SDM**: Volume 3, Chapter 24-28 (VMX)
- **Hyper-V TLFS**: VMCS enlightenments

### CPUID Indicators
| Leaf | Description |
|------|-------------|
| 0x40000004 | Implementation recommendations (nested virt) |
| 0x40000006 | Hardware features (EPT indicators) |
| 0x4000000A | Nested enlightenments |
