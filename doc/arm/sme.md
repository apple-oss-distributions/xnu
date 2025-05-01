ARM Scalable Matrix Extension
=============================

Managing hardware resources related to SME state.

Introduction
------------

This document describes how xnu manages the hardware resources associated with
ARM's Scalable Matrix Extension (SME).

SME is an ARMv9 extension intended to accelerate matrix math operations.  SME
builds on top of ARM's previous Scalable Vector Extension (SVE), which extends
the length of the FPSIMD register files and adds new 1D vector-math
instructions.  SME extends SVE by adding a matrix register file and associated
2D matrix-math instructions.  SME2 further extends SME with additional
instructions and register state.

This document summarizes SVE, SME, and SME2 hardware features that are relevant
to xnu.  It is not intended as a full programming guide for SVE or SME: readers
may find a full description of these ISAs in the
[SVE supplement to the ARM ARM](https://developer.arm.com/documentation/ddi0584/latest/)
and [SME supplement to the ARM ARM](https://developer.arm.com/documentation/ddi0616/latest/),
respectively.



Hardware overview
-----------------

### EL0-accessible state

SVE, SME, and SME2 introduce four new EL0-accessible register
files<sup>[1](#feat_sve_footnote)</sup>:

- vector registers `Z0`-`Z31`
- predicate registers `P0`-`P15`
- matrix data `ZA` (SME/SME2 only)
- look-up table `ZT0` (SME2 only)

These register files are unbanked, i.e., their contents are shared across all
exception levels.  Data can be copied between these registers and system memory
using specialized `ldr` and `str` variants.  SME also adds `mov` variants that
can directly copy data between the vector and matrix register files.

Most of these register files supplement, rather than replace, the existing ARM
register files.  However the `Z` register file effectively extends the length of
the existing FPSIMD `V` register file.  Instructions targeting the `V` register
file will now access the lower 128 bits of the corresponding `Z` register.

The size of most of these files is defined by the *streaming vector length*
(SVL), a power-of-two between 128 and 2048 inclusive.  Each `Z` register is SVL
bits in size; each `P` register is SVL / 8 bits in size; and `ZA` is SVL x SVL
bits in size.  The value of SVL is determined by both hardware and software.
Hardware places an implementation-defined cap on SVL, and privileged software
can further reduce SVL for itself and lower exception levels.

In contrast, `ZT0` is fixed at 512 bits, independent of SVL.

SME also adds a single EL0-accessible system register `TPIDR2_EL0`.  Like
`TPIDR_EL0`, `TPIDR2_EL0` is officially reserved for ABI use, but its contents
have no particular meaning to hardware.

### `PSTATE` changes

SME adds two orthogonal states to `PSTATE`.

`PSTATE.SM` moves the CPU in and out of a special execution mode called
*streaming SVE mode*.  Software must enter streaming SVE mode to execute most
SME instructions.  However software must then exit streaming SVE mode to execute
many legacy SIMD instructions<sup>[2](#feat_sme_fa64_footnote)</sup>.  To make
things even more complicated, these transitions cause the CPU to zero out the
`V`/`Z` and `P` register files, and to set all `FPSR` flags.  When software
needs to retain this state across `PSTATE.SM` transitions, it must manually
stash the state in memory.

`PSTATE.ZA` independently controls whether the contents of `ZA` and `ZT0` are
valid.  Setting `PSTATE.ZA` zeroes out both register files, and enables
instructions that access them.  Clearing `PSTATE.ZA` causes `ZA` and `ZT0`
accesses to trap.

Most SME instructions require both `PSTATE.SM` and `PSTATE.ZA` to be
set, so software usually toggles both bits at the same time.  However setting
these bits independently can be useful when software needs to interleave SME and
FPSIMD instructions.  If software needs to temporarily exit streaming SVE mode
to execute FPSIMD instructions, setting `PSTATE.{SM,ZA} = {0,1}` will do so
without clobbering the `ZA` or `ZT0` array.

`PSTATE.{SM,ZA} = {0,0}` acts as a hint to the CPU that it may power down
SME-related hardware.  Hence software should clear these bits as soon as
SME state can be discarded.

These `PSTATE` bits are accessible to software in several ways:

- Reads or writes to the `SVCR` system register, which packs both bits into
  a single register
- Writes to the `SVCRSM`, `SVCRZA`, or `SVCRSMZA` system registers with the
  immediate values `0` or `1`, which directly modify the specified bit(s)
- `sm{start,stop} (sm|za)` pseudo-instructions, which are assembler aliases for
  the above `msr` instructions

Regardless of which method is used to access these bits, software generally does
not need explicit barriers.  Specifically, ARM guarantees that all direct and
indirect reads from these bits will appear in program order relative to any
direct writes.

### Other hardware resources

An implementation may share SME compute resources across multiple CPUs.  In this
case, the per-CPU `SMPRI_EL1` controls the relative priority of the SME
instructions issued by that CPU.  ARM guarantees that higher `SMPRI_EL1` values
indicate higher priorities, and that setting `SMPRI_EL1 = 0` on all CPUs is a
safe way to disable SME prioritization.  Otherwise the exact meaning of
`SMPRI_EL1` is implementation-defined.

EL2 may trap guest reads and writes to `SMPRI_EL1` using the fine-grained trap
controls `HFGRTR_EL2.nSMPRI_EL1` and `HFGWTR_EL2.nSMPRI_EL1`, respectively.
Alternatively, EL2 may adjust the effective SME priority at EL0 and EL1 without
trapping, by populating the lookup table register `SMPRIMAP_EL2` and setting the
control bit `HCRX_EL2.SMPME`.  When `HCRX_EL2.SMPME` is set, SME instructions
executed at EL0 and EL1 will interpret `SMPRI_EL1` as an index into
`SMPRIMAP_EL2` rather than as a raw priority value.

`SMIDR_EL1` advertises hardware properties about the SME implementation,
including whether SME execution priority is implemented.

`CPACR_EL1` and `CPTR_ELx` have controls that can trap SVE and SME operations.
Two of these are relevant to Apple's SME
implementation<sup>[3](#cpacr_zen_footnote)</sup>:

- `SMEN`: trap SME instructions and register accesses, including SVE
  instructions executed during streaming SVE mode.
- `FPEN`: trap FPSIMD, SME, and SVE instructions and most register accesses, but
  *not* `SVCR` accesses.  Lower priority than `SMEN`.

Several SME registers aren't affected by these controls, since they have their
own trapping mechanisms.  `SMPRI_EL1` has fine-grained hypervisor trap controls
as described above.  `SMIDR_EL1` accesses can trap to the hypervisor using the
existing `HCR_EL2.TID1` control bit.  Finally `TPIDR2_EL0` has a dedicated
control bit `SCTLR_ELx.EnTP2` along with fine-grained trap controls
`HFG{R,W}TR_EL2.TPIDR2_EL0`.


Software usage
--------------

### SME `PSTATE` management

xnu has in-kernel SIMD instructions<sup>[4](#xnu_simd_footnote)</sup> which
become illegal while the CPU is in streaming SVE mode.  This poses a problem if
xnu interrupts EL0 while it is in the middle of executing SME-accelerated code.

Hence, anytime xnu enters the kernel with `PSTATE.SM` set, it saves the current
`Z`, `P`, and `SVCR` values and then clears `PSTATE.SM`.  xnu later restores
these values during kernel exit.  These operations occur in an assembly-only
module (`locore.s`) where we have strict control over code generation, and can
guarantee that no problematic SIMD instructions are executed while `PSTATE.SM`
is set.

Since the kernel may interrupt *itself*, kernel code is forbidden from entering
streaming SVE mode.  This policy means that xnu does not need to preserve
`TPIDR2_EL0`, `ZA`, or `ZT0` during kernel entry and exit, since there are no
in-kernel SME operations that could clobber them.

### Context switching

xnu saves and restores `TPIDR2_EL0`, `ZA`, and `ZT0` inside the ARM64
implementation of `machine_switch_context()`, specifically as the routines
`machine_{save,restore}_sme_context()` in `osfmk/arm64/pcb.c`.  These in turn
build on lower-level routines to save and load SME register state, located in
`osfmk/arm64/sme.c`.  The low-level routines are built on top of the SME `str`
and `ldr` instructions, which can be executed outside of streaming SVE mode.

`machine_{save,restore}_sme_context()` unconditionally save and restore
`TPIDR2_EL0`, since its contents are valid even when EL0 isn't actually using
SME.  However `ZA`'s and `ZT0`'s contents are often invalid and hence do not
require context-switching.  `machine_save_sme_context()` reads `SVCR.ZA`
to determine if the `ZA` and `ZT0` arrays were actually valid at context-switch
time.  If not, it skips saving the invalid `ZA` and `ZT0` contents.

Likewise, when context-switching back to a thread where the saved-state
`SVCR.ZA` is cleared, `machine_restore_sme_context()` simply ensures that the
CPU's `PSTATE.ZA` bit is cleared (executing `smstop za` if necessary).  xnu does
not need to manually invalidate any `ZA` or `ZT0` state left by a previous
thread: the next time `PSTATE.ZA` is enabled, the CPU is architecturally
guaranteed to zero out both register files.

As noted above, xnu saves `SVCR` on kernel entry and uses it to restore
`PSTATE.SM` on kernel exit.  Hence `machine_restore_sme_context()` updates
`PSTATE.ZA` to match the new process's saved state, but doesn't update
`PSTATE.SM`.  Likewise `machine_restore_sme_context()` doesn't manipulate the `Z`
or `P` register files, since these will be updated on kernel exit.

Since SME thread state (`thread->machine.usme`) is large, and won't be used by
most threads, xnu lazily allocates the backing memory the first time a thread
encounters an SME instruction.  This is implemented by clearing `SCTLR_EL1.SMEN`
inside `machine_restore_sme_context()`, then performing the allocation during
the subsequent SME trap.

### Execution priority

xnu does not currently have an API for changing SME execution priority.
Accordingly xnu resets `SMPRI_EL1` to `0` during CPU initialization, and
otherwise does not modify it at runtime.

### Power management

xnu updates `PSTATE.ZA` during `machine_switch_sme_context()` using the `SVCR`
value stashed in the new thread's SME state.  If the new process has never used
SME, and hence doesn't have saved `ZA` state, xnu unconditionally clears
`PSTATE.ZA`.  This policy means that xnu issues the power-down hint
`PSTATE.{SM,ZA} = {0,0}` on every context-switch, unless the new thread has live
`ZA` state.  (Recall that `PSTATE.SM` was previously cleared on kernel entry.)

By extension, xnu will always issue this hint before entering WFI.  In order to
reach `arm64_retention_wfi()`, xnu must first context-switch to the idle thread,
which never has `ZA` state.

### Virtualizing SME

SME introduces a number of new registers that the hypervisor needs to manage.
`SMCR_ELx` is the only one of these that's banked between EL1 and EL2.  The
`SVCR`, `SMPRI_EL1`, and `TPIDR2_EL0` system registers are all shared between
the host and guest, and must be managed by the host hypervisor accordingly.

More critically, the `Z`, `P`, `ZA`, and `ZT0` register files are also shared
across all exception levels.  To minimize the cost of managing this unbanked SME
register state, xnu tries to keep the guest matrix state resident in the CPU as
long as possible, even when the guest traps to EL2.  xnu will only spill the `ZA`
and `ZT0` state back to memory when one of two things happens:

(1) The `hv_vcpu_run` trap handler returns control all the way back to the VMM
    thread at host EL0

(2) xnu needs to context-switch the host VMM thread that owns the vCPU

In these cases xnu will spill the guest `ZA` and `ZT0` state back to memory,
then replace them with the VMM thread's or new thread's state (respectively).

Unfortunately since xnu has to disable streaming SVE mode to handle traps, it's
still forced to spill `Z` and `P` state to memory anytime the guest traps to EL2
with `PSTATE.SM` set.


Since xnu doesn't currently support SME prioritization, it sets `HCRX_EL2.SMPME`
and populates all `SMPRIMAP_EL2` entries with a value of `0`.  Guest OSes are
still allowed to write to `SMPRI_EL1`, but currently this has no effect on
the actual hardware priority.


Appendix: Mach thread-state APIs
--------------------------------

Low-level tools (e.g., debuggers) may access thread SVE and SME state through
the standard Mach APIs `thread_{get,set}_state`.  But because SVE and SME
register state are large and have implementation-defined size, accessing this
state can be more complicated than other thread state flavors.

xnu splits the SVE and SME thread state into several flavors:

| Flavor                                       | C thread-state type   | Description               |
|----------------------------------------------|-----------------------|---------------------------|
| `ARM_SME_STATE`                              | `arm_sme_state_t`     | SVCR, TPIDR2_EL0, and SVL |
| `ARM_SVE_Z_STATE1`, `ARM_SME_Z_STATE2`       | `arm_sve_z_state_t`   | Z register file           |
| `ARM_SVE_P_STATE`                            | `arm_sve_p_state_t`   | P register file           |
| `ARM_SME_ZA_STATE1` ... `ARM_SME_ZA_STATE16` | `arm_sme_za_state_t`  | ZA register file          |
| `ARM_SME2_STATE`                             | `arm_sme2_state_t`    | ZT0 register file         |

`arm_sve_z_state_t`, `arm_sve_p_state_t`, and `arm_sme_za_state_t` are
statically sized for a vector length of 2048 bits, the largest vector length
allowed by the ARM architecture.  In practice, all Apple CPUs currently use a
smaller vector length.  In this case `thread_get_state` will pad the unused
upper bits of each `z`, `p`, and `za` field with zeroes.  Likewise,
`thread_set_state` will ignore any unused upper bits.

`Z` can architecturally be up to 8 kilobytes in size.  Since this is too large
to fit in a single Mach message, xnu's Mach thread-state APIs divide the `Z`
register space into two different thread-state flavors.  Thread-state flavor
`ARM_SME_ZA_STATE1` accesses Z0-Z15, and thread-state flavor `ARM_SME_ZA_STATE2`
accesses Z16-Z31.

xnu likewise divides `ZA` into 4-kilobyte windows.  Thread-state flavor
`ARM_SME_ZA_STATE1` accesses the first 4 kilobytes of ZA space,
`ARM_SME_ZA_STATE2` accesses the next 4 kilobytes of ZA space, and so on up to
`ARM_SME_ZA_STATE16`.  When `ZA` is smaller than 4 kilobytes, `thread_get_state`
will pad the unused upper bytes of `arm_sme_za_state_t::za` with zeroes, and
`thread_set_state` will ignore any unused upper bytes.

`thread_{get,set}_state` will return `KERN_INVALID_ARGUMENT` if software tries
to do any of the following:

* Access SME or SME2 state on a CPU that doesn't implement FEAT_SME or FEAT_SME2
  (respectively)
* Access `Z` or `P` state when the target thread's `SVCR.SM` bit is cleared
* Access `ZA` or `ZT0` state when the target thread's `SVCR.ZA` bit is cleared
* Change the current `svl` value while setting `ARM_SME_STATE`

xnu does not currently support sending SME or SVE thread state with Mach
exception messages.  Mach APIs that set exception ports, such as
`thread_set_exception_ports`, will return `KERN_INVALID_ARGUMENT` if the
requested `flavor` is one of the values described in this appendix.

### Sample code

The following C code illustrates how to interpret SME and SME2 state returned by
`thread_get_state`.  (To keep the code as simple as possible, it ignores all of
the possible error cases listed above.)

```c
arm_sme_state_t sme_state; mach_msg_type_number_t sme_state_count = ARM_SME_STATE_COUNT;
// Read SVL_B and SVCR
thread_get_state(thread, ARM_SME_STATE, &sme_state, &sme_state_count);

const uint64_t SVCR_SM = (1 << 0);
// Are Z and P valid?
if (sme_state.__svcr & SVCR_SM) {
    size_t z_element_size = sme_state.__svl_b;
    char z[32][z_element_size];
    size_t p_element_size = sme_state.__svl_b / 8;
    char p[16][p_element_size];

    arm_sve_z_state_t z_state; mach_msg_type_number_t z_state_count = ARM_SVE_Z_STATE_COUNT;
    // Read Z0-Z15 and copy active bits
    thread_get_state(thread, ARM_SVE_Z_STATE1, &z_state, &z_state_count);
    for (int i = 0; i < 16; i++) {
       memcpy(z[i], z_state.__z[i], z_element_size);
    }
    // Read Z16-Z32 and copy active bits
    thread_get_state(thread, ARM_SVE_Z_STATE2, &z_state, &z_state_count);
    for (int i = 0; i < 16; i++) {
       memcpy(z[i + 16], z_state.__z[i], z_element_size);
    }

    arm_sve_p_state_t p_state; mach_msg_type_number_t p_state_count = ARM_SVE_P_STATE_COUNT;
    // Read P0-P15 and copy active bits
    thread_get_state(thread, ARM_SVE_P_STATE, &p_state, &p_state_count);
    for (int i = 0; i < 16; i++) {
       memcpy(p[i], p_state.__p[i], p_element_size);
    }
}

const uint64_t SVCR_ZA = (1 << 1);
// Are ZA and ZT0 valid?
if (sme_state.__svcr & SVCR_ZA) {
    size_t za_size = sme_state.__svl_b * sme_state.__svl_b;
    char za[za_size];
    const size_t zt0_size = 64;
    char zt0[zt0_size];

    const size_t max_chunk_size = 4096;
    int n_chunks; size_t chunk_size;
    if (za_size <= max_chunk_size) {
        n_chunks = 1;
        chunk_size = za_size;
    } else {
        n_chunks = za_size / max_chunk_size;
        chunk_size = max_chunk_size;
    }

    for (int i = 0; i < n_chunks; i++) {
        arm_sme_za_state_t za_state; mach_msg_type_number_t za_state_count = ARM_SME_ZA_STATE_COUNT;
        // Read next chunk of ZA
        thread_get_state(thread, ARM_SME_ZA_STATE1 + i, &za_state, &za_state_count);
        memcpy(&za[chunk_size * i], za_state.__za, chunk_size);
    }

    arm_sme2_state_t sme2_state; mach_msg_type_number_t sme2_state_count = ARM_SME2_STATE;
    thread_get_state(thread, ARM_SME2_STATE, &sme2_state, &sme2_state_count);
    memcpy(zt0, sme2_state.__zt0, zt0_size);
}
```


Footnotes
---------

<a name="feat_sve_footnote"></a>1. For simplicity, this section describes the
behavior on Apple CPUs.  Details like register length and accessibility may
depend on whether the CPU is in streaming SVE mode (described later in the
document).  Apple's current SME implementation simply makes SVE features
inaccessible outside this mode.

<a name="feat_sme_fa64_footnote"></a>2. The optional CPU feature FEAT_SME_FA64
allows full use of the SIMD instruction set inside streaming SVE mode.
However xnu does not currently support any CPUs which implement FEAT_SME_FA64.

<a name="cpacr_zen_footnote"></a>3. `CPACR_EL1` and `CPTR_ELx` also have a
discrete trap control `ZEN` for SVE instruction and register accesses performed
outside streaming SVE mode.  This trap control isn't currently relevant to Apple
CPUs, since Apple's current SME implementation only allows SVE accesses inside
streaming SVE mode.

<a name="xnu_simd_footnote"></a>4. LLVM is surprisingly aggressive about
emitting SIMD instructions unless explicitly inhibited by compiler flags.  Even
if the xnu build started inhibiting these instructions for targets that support
SME, they could still appear in existing kext binaries.

