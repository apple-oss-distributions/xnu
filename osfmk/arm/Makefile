export MakeInc_cmd=$(SRCROOT)/makedefs/MakeInc.cmd
export MakeInc_def=$(SRCROOT)/makedefs/MakeInc.def
export MakeInc_rule=$(SRCROOT)/makedefs/MakeInc.rule
export MakeInc_dir=$(SRCROOT)/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

ARM_HEADER_FILES =	\
		arch.h \
		arm_features.inc \
		atomic.h \
		cpu_number.h \
		cpu_capabilities.h	\
		cpu_capabilities_public.h	\
		cpu_x86_64_capabilities.h	\
		cpuid.h \
		cpuid_internal.h \
		lock.h \
		locks.h \
		machine_cpuid.h \
		machine_routines.h \
		memory_types.h \
		pal_routines.h \
		simple_lock.h \
		thread.h \
		trap.h

INSTALL_MD_DIR = arm

# Headers installed into System.framework/PrivateHeaders (internal SDK only).
INSTALL_SF_MD_LCL_LIST = arch.h cpu_capabilities.h

# Headers installed into /usr/include (public and internal SDKs).
# These are covered by ../../bsd/machine/machine.modulemap.
INSTALL_MD_LIST = \
		arch.h \
		cpu_capabilities_public.h

# Headers installed into /usr/local/include (internal SDK only).
# These are covered by ../../bsd/machine/machine_private.modulemap.
INSTALL_MD_LCL_LIST = cpu_capabilities.h

# Headers installed in the public/internal SDKs for userspace DriverKit drivers.
INSTALL_DRIVERKIT_MD_LIST = arch.h

# Headers installed into Kernel.framework/Headers (public and internal SDKs).
INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = \
		cpu_topology.h \
		dbgwrap.h \
		machine_kpc.h \
		pmap_public.h \
		proc_reg.h \
		smp.h \
		$(ARM_HEADER_FILES)

# TODO: consolidate INSTALL_KF_MD_LCL_LIST and EXPORT_MD_LIST? Only difference is caches_internal.h/machine_cpu.h
# Headers used to compile xnu
EXPORT_MD_LIST = \
		caches_internal.h \
		cpu_topology.h \
		dbgwrap.h \
		machine_cpu.h \
		machine_kpc.h \
		pmap_public.h \
		proc_reg.h \
		smp.h \
		$(ARM_HEADER_FILES)

# These headers will be available with #include <arm/header_file.h>
EXPORT_MD_DIR = arm

include $(MakeInc_rule)
include $(MakeInc_dir)
