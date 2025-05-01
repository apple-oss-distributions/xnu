export MakeInc_cmd=$(SRCROOT)/makedefs/MakeInc.cmd
export MakeInc_def=$(SRCROOT)/makedefs/MakeInc.def
export MakeInc_rule=$(SRCROOT)/makedefs/MakeInc.rule
export MakeInc_dir=$(SRCROOT)/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

PRIVATE_DATAFILES = boot.h consistent_debug.h protos.h dockchannel.h apple_uart_regs.h

PRIVATE_KERNELFILES = \
	AIC.h \
	board_config.h \
	boot.h \
	consistent_debug.h \
	dockchannel.h \
	PL192_VIC.h \
	protos.h \
	apple_uart_regs.h

# Headers installed into System.framework/PrivateHeaders (userspace internal SDK only).
INSTALL_SF_MD_LCL_LIST = $(PRIVATE_DATAFILES)

# The userspace headers can be located in System.framework/PrivateHeaders/pexpert/arm
INSTALL_MD_DIR = pexpert/arm

# Ensure these files don't get auto-included into the public Kernel.framework/Headers.
INSTALL_KF_MD_LIST = $(EMPTY)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = $(PRIVATE_KERNELFILES)

# Headers used to compile xnu
EXPORT_MD_LIST = $(PRIVATE_KERNELFILES)

# These headers will be available with #include <pexpert/arm/header_file.h>
EXPORT_MD_DIR = pexpert/arm

include $(MakeInc_rule)
include $(MakeInc_dir)
