export MakeInc_cmd=$(SRCROOT)/makedefs/MakeInc.cmd
export MakeInc_def=$(SRCROOT)/makedefs/MakeInc.def
export MakeInc_rule=$(SRCROOT)/makedefs/MakeInc.rule
export MakeInc_dir=$(SRCROOT)/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)


ARM_HEADER_FILES = \
	machine_cpuid.h		\
	machine_machdep.h	\

# Headers installed into Kernel.framework/Headers (public and internal SDKs).
INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = \
	hv_hvc.h \
	lowglobals.h \
	machine_kpc.h \
	machine_remote_time.h \
	monotonic.h \
	proc_reg.h \
	tlb.h \
	$(ARM_HEADER_FILES)

# Headers installed into System.framework/PrivateHeaders
INSTALL_SF_MD_LCL_LIST = \
	$(ARM_PRIVATE_HEADERS)

# TODO: Is there a reason that machine_machdep.h is not in this list? If not, these lists can be consolidated.
# Headers used to compile xnu
EXPORT_MD_LIST = \
	hv_hvc.h \
	lowglobals.h \
	machine_cpuid.h \
	machine_kpc.h \
	machine_remote_time.h \
	monotonic.h \
	perfmon_arm64_regs.h \
	proc_reg.h \
	asm.h \
	tlb.h \
	pal_hibernate.h

# These headers will be available with #include <arm64/header_file.h>
EXPORT_MD_DIR = arm64

INSTALL_MD_DIR = arm64

include $(MakeInc_rule)
include $(MakeInc_dir)
