export MakeInc_cmd=$(SRCROOT)/makedefs/MakeInc.cmd
export MakeInc_def=$(SRCROOT)/makedefs/MakeInc.def
export MakeInc_rule=$(SRCROOT)/makedefs/MakeInc.rule
export MakeInc_dir=$(SRCROOT)/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

PRIVATE_DATAFILES = boot.h

PRIVATE_KERNELFILES = \
	AIC.h \
	apple_arm64_common.h \
	apple_arm64_regs.h \
	vhe_disable.h \
	board_config.h \
	boot.h \
	H13.h \
	VMAPPLE.h \
	BCM2837.h


# Headers installed into System.framework/PrivateHeaders (userspace internal SDK only).
INSTALL_SF_MD_LCL_LIST = $(PRIVATE_DATAFILES)

# The userspace headers can be located in System.framework/PrivateHeaders/pexpert/arm64
INSTALL_MD_DIR = pexpert/arm64

# Ensure these files don't get auto-included into the public Kernel.framework/Headers.
INSTALL_KF_MD_LIST = $(EMPTY)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = $(PRIVATE_KERNELFILES)

EXPORT_ONLY_FILES =	\
			platform.h

# Headers used to compile xnu
EXPORT_MD_LIST = $(PRIVATE_KERNELFILES) $(EXPORT_ONLY_FILES)

# These headers will be available with #include <pexpert/arm64/header_file.h>
EXPORT_MD_DIR = pexpert/arm64

include $(MakeInc_rule)
include $(MakeInc_dir)
