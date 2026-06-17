export MakeInc_cmd=$(SRCROOT)/makedefs/MakeInc.cmd
export MakeInc_def=$(SRCROOT)/makedefs/MakeInc.def
export MakeInc_rule=$(SRCROOT)/makedefs/MakeInc.rule
export MakeInc_dir=$(SRCROOT)/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# proc_reg.h is exported into the userspace internal SDK for usage by SPTM's
# userspace testing system.
ARM_PRIVATE_HEADERS = \
	proc_reg.h


INSTINC_SUBDIRS_ARM64 += \
	sptm

EXPINC_SUBDIRS_ARM64 += \
	sptm

ARM_HEADER_FILES = \
	machine_cpuid.h		\
	machine_machdep.h	\
	mte.h			\

INSTALL_MD_LIST = \
	mte.h \

# Headers installed into Kernel.framework/Headers (public and internal SDKs).
INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = \
	hv_hvc.h \
	lowglobals.h \
	machine_remote_time.h \
	monotonic.h \
	proc_reg.h \
	tlb.h \
	x86_64_compat.h \
	$(ARM_HEADER_FILES)

# Headers installed into System.framework/PrivateHeaders
INSTALL_SF_MD_LCL_LIST = \
	$(ARM_PRIVATE_HEADERS)

# Headers used to compile xnu
EXPORT_MD_LIST = \
	cpc_arm64.h \
	hv_hvc.h \
	lowglobals.h \
	machine_cpuid.h \
	machine_remote_time.h \
	monotonic.h \
	proc_reg.h \
	asm.h \
	speculation.h \
	static_if.h \
	tlb.h \
	pal_hibernate.h \
	mte.h \
	mte_xnu.h \
	x86_64_compat.h \
	sop.h

# These headers will be available with #include <arm64/header_file.h>
EXPORT_MD_DIR = arm64

INSTALL_MD_DIR = arm64

include $(MakeInc_rule)
include $(MakeInc_dir)
