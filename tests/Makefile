PROJECT := xnu/darwintests

include disabled.mk

# When building as part of xnu_tests, we get passed a DSTROOT that's got the
# unit test path in it already.  But, BASEDSTROOT doesn't, so use that instead.
ifdef BASEDSTROOT
override DSTROOT = $(BASEDSTROOT)
endif

INVALID_ARCHS = i386 $(filter armv7%,$(ARCH_CONFIGS))
ENABLE_LTE_TESTS=YES

OTHER_LTE_INCLUDE_FILES += \
	/System/Library/PrivateFrameworks/LoggingSupport.framework, \
	/System/Library/PrivateFrameworks/MobileKeyBag.framework, \
	/System/Library/Frameworks/IOSurface.framework, \
	/usr/local/lib/libdarwintest_utils.dylib, \
	/usr/lib/libapple_crypto.dylib,

ENV = /usr/bin/env

DEVELOPER_DIR ?= $(shell xcode-select -p)


ifeq ($(origin TIGHTBEAM_MODULE_DIR),undefined)
	export TIGHTBEAM_MODULE_DIR := $(shell /usr/bin/xcrun --show-sdk-path -sdk $(SDKROOT))/usr/local/lib/kernel/tightbeam
endif

USE_WERROR := 1
ifneq ($(BUILD_WERROR),)
USE_WERROR := $(BUILD_WERROR)
endif

ifeq ($(USE_WERROR),1)
WERROR := -Werror
endif

# the xnu build system will only ever call us with the default target
.DEFAULT_GOAL := install

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.common

OTHER_CFLAGS  = -Wall
OTHER_CFLAGS += -Wno-deprecated-declarations
OTHER_CFLAGS += -Werror=excess-initializers
OTHER_CFLAGS += -Wno-c2x-extensions
OTHER_CFLAGS += -Werror=excess-initializers
OTHER_CFLAGS += --std=gnu17 -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
OTHER_CFLAGS += -UT_NAMESPACE_PREFIX -DT_NAMESPACE_PREFIX=xnu -DT_LEAKS_DISABLE=1
OTHER_CFLAGS += -F $(SDKROOT)/System/Library/PrivateFrameworks


CODESIGN:=$(shell xcrun -sdk "$(TARGETSDK)" -find codesign)
CODESIGN_HARDENED_RUNTIME:=$(CODESIGN) -o runtime
CODESIGN_ALLOCATE:=$(shell xcrun -sdk "$(TARGETSDK)" -find codesign_allocate)

LIPO:=$(shell xcrun -sdk "$(TARGETSDK)" -find lipo)

ifeq ($(PLATFORM),iPhoneOS)
  IOS_TEST_COMPAT = YES
else
  IOS_TEST_COMPAT = NO
endif

# Generate tightbeam header for ExclavesCHelloServer from tbmodule in the SDK
ifneq ($(wildcard $(SDKROOT)/System/Library/PrivateFrameworks/Tightbeam.framework/Headers/tightbeam.h),)
TIGHTBEAM_MODULES := \
	ExclavesCHelloServer.tbmodule

TIGHTBEAM_MODULE_HEADERS := $(patsubst %.tbmodule,%.tightbeam.h,$(TIGHTBEAM_MODULES))
TIGHTBEAM_MODULE_IMPL := $(patsubst %.tbmodule,%.tightbeam.c,$(TIGHTBEAM_MODULES))

# This makes sure to not include any tbmodules which don't exist in the SDK and
# expand the modules listed above to their full path in the SDK. The modules
# should only be needed when actually building with CONFIG_EXCLAVES
# (which can't easily be checked here).
TIGHTBEAM_MODULES := $(patsubst %.tbmodule,$(TIGHTBEAM_MODULE_DIR)/%.tbmodule,$(TIGHTBEAM_MODULES))
TIGHTBEAM_MODULES := $(wildcard $(TIGHTBEAM_MODULES))
TIGHTBEAM_MODULE_IMPL_PATH := $(addprefix $(OBJROOT)/, $(TIGHTBEAM_MODULE_IMPL))

$(TIGHTBEAM_MODULE_IMPL) : \
	%.tightbeam.c : $(TIGHTBEAM_MODULES)
	$(TIGHTBEAMC) build generate-c --output-base $(OBJROOT)/$*.tightbeam.c --codegen-version 2 $<

$(TIGHTBEAM_MODULE_HEADERS) : $(TIGHTBEAM_MODULE_IMPL)
endif

# Subsystems

include containment_vessels/Makefile
include cpu_counters/Makefile
include ipc/Makefile
include ktrace/Makefile
include recount/Makefile
include sched/Makefile
include signals/Makefile
include vfs/Makefile
include vm/Makefile
include vm_stress_tests/Makefile

# Miscellaneous Tests

mach_eventlink: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
mach_eventlink: $(SCHED_UTILS) test_utils.c

handoff_perf: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
handoff_perf: $(SCHED_UTILS) test_utils.c

atm_diagnostic_flag: OTHER_CFLAGS += drop_priv.c

atm_diagnostic_flag_entitled: CODE_SIGN_ENTITLEMENTS = atm_diagnostic_flag.entitlements
atm_diagnostic_flag_entitled: OTHER_CFLAGS += drop_priv.c

avx: INVALID_ARCHS = $(filter arm%,$(ARCH_CONFIGS))
avx: OTHER_CFLAGS += -mavx512f -mavx512bw -mavx512vl
avx: OTHER_CFLAGS += -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
avx: CONFIG_FLAGS := $(filter-out -O%,$(CONFIG_FLAGS))
# Add -mno-implicit-float to prevent the compiler from touching SIMD regs
# unexpectedly
avx: CONFIG_FLAGS += -mno-implicit-float
# Disable vzeroupper insertion to work around rdar://problem/35035096
avx: CONFIG_FLAGS += -mllvm -x86-use-vzeroupper=0
ifneq (osx,$(TARGET_NAME))
EXCLUDED_SOURCES += avx.c
endif

CUSTOM_TARGETS += sr_entitlement_helper

sr_entitlement_helper: sr_entitlement_helper.c
	mkdir -p $(SYMROOT)
	$(CC) -I $(OBJROOT) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) sr_entitlement_helper.c -o $(SYMROOT)/$@
	echo $(CODESIGN) --force --sign - --timestamp=none --entitlements sr_entitlement.entitlements $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements sr_entitlement.entitlements $(SYMROOT)/$@;

install-sr_entitlement_helper: sr_entitlement_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/sr_entitlement_helper $(INSTALLDIR)

sr_entitlement: OTHER_LDFLAGS += -ldarwintest_utils

restrict_jit: CODE_SIGN_ENTITLEMENTS = restrict_jit.entitlements

backtracing_tests: OTHER_LDFLAGS += -framework CoreSymbolication
backtracing_tests: CODE_SIGN_ENTITLEMENTS = kernel_symbolication_entitlements.plist

CUSTOM_TARGETS += corpse_backtrace2

corpse_backtrace2:
		$(MIG) $(CFLAGS) \
		-DMACH_EXC_SERVER_TASKIDTOKEN \
		-DMACH_EXC_SERVER_BACKTRACE \
		-sheader $(OBJROOT)/excserver_backtrace.h \
		-server $(OBJROOT)/excserver_backtrace.c \
		-header /dev/null -user /dev/null \
		excserver_backtrace.defs

install-corpse_backtrace2: ;

corpse_backtrace: corpse_backtrace2 exc_helpers.c
corpse_backtrace: OTHER_CFLAGS += $(OBJROOT)/excserver_backtrace.c
corpse_backtrace: OTHER_CFLAGS += -I $(OBJROOT)
corpse_backtrace: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

# Tests that use exc_guard_helper.h should add all of the build options used by exc_guard_helper_test:
# - additional C files exc_guard_helper.c and exc_helpers.c and test_utils.c
# - additional library darwintest_utils
# - excserver MIG-generated file
# - entitlement to allow thread_set_exception_ports()
exc_guard_helper_test: exc_guard_helper.c exc_helpers.c test_utils.c excserver
exc_guard_helper_test: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
exc_guard_helper_test: OTHER_LDFLAGS += -ldarwintest_utils
exc_guard_helper_test: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

EXCLUDED_SOURCES += exc_guard_helper.c

exc_guard_helper_test_unexpected: exc_guard_helper.c exc_helpers.c test_utils.c excserver
exc_guard_helper_test_unexpected: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
exc_guard_helper_test_unexpected: OTHER_LDFLAGS += -ldarwintest_utils
exc_guard_helper_test_unexpected: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

# Tests that use try_read_write.h should add all of the build options used by try_read_write_test:
# - additional C files try_read_write.c and exc_helpers.c
# - excserver MIG-generated file
# - entitlement to allow thread_set_exception_ports()
try_read_write_test: try_read_write.c exc_helpers.c excserver
try_read_write_test: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
try_read_write_test: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

EXCLUDED_SOURCES += try_read_write.c

try_read_write_test_unexpected: try_read_write.c exc_helpers.c excserver
try_read_write_test_unexpected: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
try_read_write_test_unexpected: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

vm/corpse_owned_vmobjects: excserver_protect_state excserver
vm/corpse_owned_vmobjects: OTHER_CFLAGS += $(OBJROOT)/excserver_protect_state.c -I $(OBJROOT)
vm/corpse_owned_vmobjects: CODE_SIGN_ENTITLEMENTS += vm/corpse_owned_vmobjects.entitlements

vm_test_mach_map: try_read_write.c exc_helpers.c excserver
vm_test_mach_map: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
vm_test_mach_map: CODE_SIGN_ENTITLEMENTS = ./vm_test_mach_map.plist

OTHER_TEST_TARGETS += vm/vm_parameter_validation
vm/vm_parameter_validation: CODE_SIGN_ENTITLEMENTS = vm/vm_parameter_validation.entitlements

# vm_parameter_validation builds each arch as a separate build command
# so we can pass architecture-specific linker flags.
# and generate arch-specific MIG files.

# libdarwintest.a doesn't have an arm64 slice on watchOS
ifeq ($(PLATFORM),WatchOS)
VM_PARAMETER_VALIDATION_INVALID_ARCHS = arm64
vm/vm_parameter_validation: INVALID_ARCHS += arm64
endif

VM_PARAMETER_VALIDATION_ARCHS = $(filter-out $(VM_PARAMETER_VALIDATION_INVALID_ARCHS),$(ARCH_CONFIGS))

# Some tests map-overwrite wildly at addresses near 0.
# Use a large PAGEZERO so our executable and other data do not land there.
# (This is 32-bit only. 64-bit uses 4GB PAGEZERO by default which is fine.)
VM_PARAMETER_VALIDATION_LDFLAGS_i386     = -Xlinker -pagezero_size -Xlinker 0x1000000
VM_PARAMETER_VALIDATION_LDFLAGS_armv7    = -Xlinker -pagezero_size -Xlinker 0x1000000
VM_PARAMETER_VALIDATION_LDFLAGS_armv7s   = -Xlinker -pagezero_size -Xlinker 0x1000000
VM_PARAMETER_VALIDATION_LDFLAGS_armv7k   = -Xlinker -pagezero_size -Xlinker 0x1000000
VM_PARAMETER_VALIDATION_LDFLAGS_arm64_32 = -Xlinker -pagezero_size -Xlinker 0x1000000

VM_PARAMETER_VALIDATION_SLICES=$(addprefix $(SYMROOT)/vm/vm_parameter_validation_,$(VM_PARAMETER_VALIDATION_ARCHS))

vm/vm_parameter_validation: assets $(VM_PARAMETER_VALIDATION_SLICES)
	$(LIPO) -create $(VM_PARAMETER_VALIDATION_SLICES) -output $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@

$(SYMROOT)/vm/vm_parameter_validation_%: ../osfmk/tests/vm_parameter_validation.h \
                                         $(OBJROOT)/vm_parameter_validation_%_vm32_map_user.c \
                                         $(OBJROOT)/vm_parameter_validation_%_mach_vm_user.c \
                                         $(OBJROOT)/vm_parameter_validation_%_replacement_mach_host.c \
                                         $(OBJROOT)/vm_parameter_validation_%_replacement_host_priv.c \
                                         vm/vm_parameter_validation.c
	mkdir -p $(SYMROOT)/vm
	$(CC) -I $(OBJROOT) \
	    $(DT_CFLAGS) $(OTHER_CFLAGS) $(filter-out $(ARCH_FLAGS),$(CFLAGS)) -arch $* \
	    $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $(VM_PARAMETER_VALIDATION_LDFLAGS_$*) \
	    -DVM32_SUPPORT=1 -DKERNEL_VM_TEST=1 \
	    $(OBJROOT)/vm_parameter_validation_$*_vm32_map_user.c \
	    $(OBJROOT)/vm_parameter_validation_$*_mach_vm_user.c \
	    $(OBJROOT)/vm_parameter_validation_$*_replacement_mach_host.c \
	    $(OBJROOT)/vm_parameter_validation_$*_replacement_host_priv.c \
	    vm/vm_parameter_validation.c -o $@

# xnu/libsyscall/mach/mach_vm.c intercepts some VM calls from userspace,
# sometimes doing something other than the expected MIG call.
# And on 64-bit platforms libsystem has no interface to reach the 32-bit entrypoints.
# We generate our own MIG userspace call sites to call the kernel entrypoints directly.
$(OBJROOT)/vm_parameter_validation_%_vm32_map_user.c: ../osfmk/mach/vm32_map.defs
	$(MIG) $(filter-out $(ARCH_FLAGS),$(CFLAGS)) -arch $* \
	 -I../osfmk -novouchers -DKERNEL_USER=1 -DKOBJECT_SERVER -DKERNEL_VM_TEST=1 \
	 -user $@ -header $(subst _$*_,_,$(@:.c=.h)) \
	 -server /dev/null -sheader /dev/null \
	 $<
$(OBJROOT)/vm_parameter_validation_%_mach_vm_user.c: ../osfmk/mach/mach_vm.defs
	$(MIG) $(filter-out $(ARCH_FLAGS),$(CFLAGS)) -arch $* \
	 -I../osfmk -novouchers -DKERNEL_USER=1 -DKOBJECT_SERVER -DKERNEL_VM_TEST=1 \
	 -user $@ -header $(subst _$*_,_,$(@:.c=.h)) \
	 -server /dev/null -sheader /dev/null \
	 $<
# The declaration of mach_memory_object_memory_entry is buggy on U32.
# We compile in our own MIG user stub for it with a "replacement_" prefix.
# rdar://117927965
$(OBJROOT)/vm_parameter_validation_%_replacement_mach_host.c: vm/vm_parameter_validation_replacement_mach_host.defs
	$(MIG) $(filter-out $(ARCH_FLAGS),$(CFLAGS)) -arch $* \
	 -I../osfmk -novouchers -DKERNEL_USER=1 -DKOBJECT_SERVER -DKERNEL_VM_TEST=1 \
	 -user $@ -header $(subst _$*_,_,$(@:.c=.h)) \
	 -server /dev/null -sheader /dev/null \
	 $<
# The declaration of vm_wire is buggy on U32.
# We compile in our own MIG user stub for it with a "replacement_" prefix.
# rdar://118258929
$(OBJROOT)/vm_parameter_validation_%_replacement_host_priv.c: vm/vm_parameter_validation_replacement_host_priv.defs
	$(MIG) $(filter-out $(ARCH_FLAGS),$(CFLAGS)) -arch $* \
	 -I../osfmk -novouchers -DKERNEL_USER=1 -DKOBJECT_SERVER -DKERNEL_VM_TEST=1 \
	 -user $@ -header $(subst _$*_,_,$(@:.c=.h)) \
	 -server /dev/null -sheader /dev/null \
	 $<


CUSTOM_TARGETS += vm_spawn_tool port_exhaustion_client port_table_limits_client fd_table_limits_client posix_spawnattr_set_crash_behavior_np_child kqworkloop_limits_client

locks: OTHER_LDFLAGS += -ldarwintest_utils

CUSTOM_TARGETS += locks_throughput

install-locks_throughput: locks_throughput
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/manual_wq_cooperative $(INSTALLDIR)


EXCLUDED_SOURCES += posix_sem_namespace_helper.c
CUSTOM_TARGETS   += posix_sem_namespace_helper_team0 posix_sem_namespace_helper_team1
posix_sem_namespace_helper_team0: posix_sem_namespace_helper.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --timestamp=none --team-identifier "PSXSEMT0" $(SYMROOT)/$@
posix_sem_namespace_helper_team1: posix_sem_namespace_helper.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --timestamp=none --team-identifier "PSXSEMT1" $(SYMROOT)/$@

install-posix_sem_namespace_helper_team0: posix_sem_namespace_helper_team0
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/posix_sem_namespace_helper_team0 $(INSTALLDIR)/
install-posix_sem_namespace_helper_team1: posix_sem_namespace_helper_team1
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/posix_sem_namespace_helper_team1 $(INSTALLDIR)/

posix_sem: posix_sem_namespace_helper_team0 posix_sem_namespace_helper_team1
posix_sem: OTHER_LDFLAGS += -ldarwintest_utils


posix_spawnattr_set_crash_behavior_np: posix_spawnattr_set_crash_behavior_np_child
posix_spawnattr_set_crash_behavior_np: CODE_SIGN_ENTITLEMENTS = posix_spawnattr_set_crash_behavior_np_entitlements.plist

posix_spawnattr_set_crash_behavior_np_child: posix_spawnattr_set_crash_behavior_np_child.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) posix_spawnattr_set_crash_behavior_np_child.c -o $(SYMROOT)/posix_spawnattr_set_crash_behavior_np_child
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

install-posix_spawnattr_set_crash_behavior_np_child: posix_spawnattr_set_crash_behavior_np_child
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/posix_spawnattr_set_crash_behavior_np_child $(INSTALLDIR)/

posix_spawnattr_set_launch_type_np: posix_spawnattr_set_launch_type_test
posix_spawnattr_set_launch_type_np: OTHER_CFLAGS += -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

posix_spawn_launch_type: CODE_SIGN_ENTITLEMENTS = posix_spawn_launch_type-entitlements.plist

port_exhaustion: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
port_exhaustion: port_exhaustion_client

port_exhaustion_client: port_exhaustion_client.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) port_exhaustion_client.c -o $(SYMROOT)/port_exhaustion_client

install-port_exhaustion_client: port_exhaustion_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/port_exhaustion_client $(INSTALLDIR)/

port_table_limits: rnserver
port_table_limits: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist
port_table_limits: OTHER_CFLAGS += $(OBJROOT)/rnServer.c -I $(OBJROOT)
port_table_limits: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
port_table_limits: port_table_limits_client

port_table_limits_client: port_table_limits_client.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) port_table_limits_client.c -o $(SYMROOT)/port_table_limits_client
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

install-port_table_limits_client: port_table_limits_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/port_table_limits_client $(INSTALLDIR)/

CUSTOM_TARGETS += kqwl_rnserver

kqwl_rnserver:
	$(MIG) $(CFLAGS) \
		-DKQWORKLOOPS_VIOLATION_SUPPORTED \
		-user /dev/null \
		-header $(OBJROOT)/kqwl_rn.h \
		-sheader $(OBJROOT)/kqwl_rnServer.h \
		-server $(OBJROOT)/kqwl_rnServer.c \
		rnserver.defs
install-kqwl_rnserver: ;

kqworkloop_limits: kqwl_rnserver
kqworkloop_limits: OTHER_CFLAGS += $(OBJROOT)/kqwl_rnServer.c -I $(OBJROOT)
kqworkloop_limits: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
kqworkloop_limits: kqworkloop_limits_client

kqworkloop_limits_client: kqworkloop_limits_client.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) kqworkloop_limits_client.c -o $(SYMROOT)/kqworkloop_limits_client
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

install-kqworkloop_limits_client: kqworkloop_limits_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/kqworkloop_limits_client $(INSTALLDIR)/

fd_table_limits: rnserver
fd_table_limits: OTHER_CFLAGS += $(OBJROOT)/rnServer.c -I $(OBJROOT)
fd_table_limits: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
fd_table_limits: fd_table_limits_client

fd_table_limits_client: fd_table_limits_client.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) fd_table_limits_client.c -o $(SYMROOT)/fd_table_limits_client
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

install-fd_table_limits_client: fd_table_limits_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/fd_table_limits_client $(INSTALLDIR)/

vm_spawn_tool: INVALID_ARCHS = i386
vm_spawn_tool: vm_spawn_tool.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) vm_spawn_tool.c -o $(SYMROOT)/vm_spawn_tool

install-vm_spawn_tool: vm_spawn_tool
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/vm_spawn_tool $(INSTALLDIR)/tools/

kas_info: OTHER_LDFLAGS += -framework CoreSymbolication
kas_info: CODE_SIGN_ENTITLEMENTS = kernel_symbolication_entitlements.plist

# TODO: Migrate to the new -fbounds-safety bounds checks (rdar://134446436)
net_bounds_safety: OTHER_CFLAGS += -fbounds-safety -fno-bounds-safety-bringup-missing-checks

net_no_bounds_safety: OTHER_CFLAGS += -fno-bounds-safety
net_no_bounds_safety: net_bounds_safety.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
OTHER_TEST_TARGETS += net_no_bounds_safety

host_statistics_rate_limiting: cs_helpers.c host_statistics_rate_limiting.c

EXCLUDED_SOURCES += drop_priv.c xnu_quick_test_helpers.c memorystatus_assertion_helpers.c bpflib.c in_cksum.c test_utils.c inet_transfer.c net_test_lib.c cs_helpers.c vsock_helpers.c


ifneq ($(IOS_TEST_COMPAT),YES)
EXCLUDED_SOURCES += jumbo_va_spaces_28530648.c perf_compressor.c vm/ios13extended_footprint.c vm/entitlement_internal_bands.c
endif

perf_compressor: OTHER_LDFLAGS += -ldarwintest_utils
perf_compressor: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist


vm/memorystatus_freeze_test: CODE_SIGN_ENTITLEMENTS=./task_for_pid_entitlement.plist
vm/memorystatus_freeze_test: OTHER_LDFLAGS += -ldarwintest_utils
vm/memorystatus_freeze_test: memorystatus_assertion_helpers.c test_utils.c vm/memorystatus_freeze_test.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm/memorystatus_freeze_test_entitled: CODE_SIGN_ENTITLEMENTS=./vm/memorystatus_freeze_test_entitled.plist
vm/memorystatus_freeze_test_entitled: OTHER_LDFLAGS += -ldarwintest_utils
vm/memorystatus_freeze_test_entitled: test_utils.c vm/memorystatus_freeze_test_entitled.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm/memorystatus_jetsam_zprint_snapshot: CODE_SIGN_ENTITLEMENTS=./vm/memorystatus_jetsam_zprint_snapshot.entitlements
vm/memorystatus_jetsam_zprint_snapshot: OTHER_LDFLAGS += -ldarwintest_utils

vm/memorystatus_kill_counts: CODE_SIGN_ENTITLEMENTS=./vm/memorystatus_kill_counts.entitlements
vm/memorystatus_kill_counts: OTHER_LDFLAGS += -ldarwintest_utils

vm/neural_footprint: CODE_SIGN_ENTITLEMENTS=./vm/neural_footprint.entitlement
vm/neural_footprint: OTHER_CFLAGS += -I $(OBJROOT)
vm/neural_footprint: OTHER_LDFLAGS += -ldarwintest_utils
vm/neural_footprint: test_utils.c vm/neural_footprint.c ./vm/neural_footprint.entitlement
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm/vm_guard_objects_telemetry: exc_guard_helper.c exc_helpers.c test_utils.c excserver
vm/vm_guard_objects_telemetry: CODE_SIGN_ENTITLEMENTS = entitlements/guard_objects-enabled.plist
vm/vm_guard_objects_telemetry: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
vm/vm_guard_objects_telemetry: OTHER_LDFLAGS += -ldarwintest_utils
vm/vm_guard_objects_telemetry: vm/vm_guard_objects_telemetry.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

memorystatus_is_assertion: OTHER_LDFLAGS += -ldarwintest_utils
memorystatus_is_assertion: OTHER_CFLAGS += memorystatus_assertion_helpers.c

memorystatus_vm_map_fork: OTHER_CFLAGS += test_utils.c
memorystatus_vm_map_fork: OTHER_LDFLAGS += -ldarwintest_utils

shared_cache_tests: OTHER_LDFLAGS += -ldarwintest_utils

vm_entry_lock_stackshot: OTHER_LDFLAGS += -lz

ifeq ($(PLATFORM),BridgeOS)
EXCLUDED_SOURCES += stackshot_tests.m
EXCLUDED_SOURCES += stackshot_accuracy.m
EXCLUDED_SOURCES += stackshot_block_owner_14362384.m
EXCLUDED_SOURCES += stackshot_idle_25570396.m
else
ifneq ($(wildcard $(SDKROOT)/System/Library/PrivateFrameworks/Tightbeam.framework/Headers/tightbeam.h),)
stackshot_tests: OTHER_LDFLAGS += -framework Tightbeam
stackshot_tests: OTHER_CFLAGS += -I$(OBJROOT)
stackshot_tests: OTHER_CFLAGS += $(TIGHTBEAM_MODULE_IMPL_PATH)
stackshot_tests.m: $(TIGHTBEAM_MODULE_HEADERS)
endif
stackshot_tests: ./stackshot-entitlements.plist stackshot_tests.m
stackshot_tests: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_tests: OTHER_CFLAGS += -Wno-objc-messaging-id test_utils.c
stackshot_tests: OTHER_LDFLAGS += -lkdd -lz -ldarwintest_utils -framework Foundation -framework IOKit
stackshot_tests: INVALID_ARCHS = arm64

stackshot_accuracy: ./stackshot-entitlements.plist
stackshot_accuracy: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_accuracy: OTHER_CFLAGS += -ldarwintest_utils -Wno-objc-messaging-id
stackshot_accuracy: OTHER_LDFLAGS += -lkdd -ldarwintest_utils -framework Foundation
stackshot_accuracy: INVALID_ARCHS = i386 arm64

stackshot_block_owner_14362384: ./stackshot-entitlements.plist
stackshot_block_owner_14362384: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_block_owner_14362384: OTHER_LDFLAGS += -framework Foundation -lpthread -lkdd
ifeq ($(PLATFORM),MacOSX)
stackshot_block_owner_14362384: OTHER_LDFLAGS += -lpcre
endif
stackshot_block_owner_14362384: INVALID_ARCHS = arm64

stackshot_idle_25570396: ./stackshot-entitlements.plist
stackshot_idle_25570396: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_idle_25570396: OTHER_LDFLAGS += -lkdd -framework Foundation
stackshot_idle_25570396: INVALID_ARCHS = arm64
endif

stackshot_spawn_exit_stress: ./stackshot-entitlements.plist
stackshot_spawn_exit_stress: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist

ifeq ($(PLATFORM),MacOSX)
CUSTOM_TARGETS += stackshot_translated_child

stackshot_translated_child: INVALID_ARCHS = arm64 arm64e
stackshot_translated_child: stackshot_translated_child.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) stackshot_translated_child.c -o $(SYMROOT)/stackshot_translated_child

install-stackshot_translated_child: stackshot_translated_child
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/stackshot_translated_child $(INSTALLDIR)/
else
EXCLUDED_SOURCES += stackshot_translated_child.c
endif

telemetry_pagein_tests: CODE_SIGN_ENTITLEMENTS=./entitlements/coalition_spawn.plist

microstackshot_tests: ./stackshot-entitlements.plist
microstackshot_tests: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
microstackshot_tests: OTHER_LDFLAGS = -ldarwintest_utils -framework ktrace -framework kperf -framework CoreFoundation

memorystatus_zone_test: ./stackshot-entitlements.plist
memorystatus_zone_test: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
memorystatus_zone_test: OTHER_CFLAGS += -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
memorystatus_zone_test: OTHER_LDFLAGS += -framework ktrace
memorystatus_zone_test: OTHER_LDFLAGS += -ldarwintest_utils

vm_entry_lock_stackshot: ./stackshot-entitlements.plist
vm_entry_lock_stackshot: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist

memcmp_zero: OTHER_CFLAGS += ../osfmk/arm64/memcmp_zero.s

test_strings: OTHER_CFLAGS += -fno-builtin-strlen

text_corruption: OTHER_LDFLAGS += -ldarwintest_utils
CUSTOM_TARGETS += text_corruption_helper

text_corruption_helper:
	$(CC) $(LDFLAGS) $(CFLAGS) text_corruption_helper.c -lm -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-text_corruption_helper: text_corruption_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/text_corruption_helper $(INSTALLDIR)/

codesigntests: CODE_SIGN_ENTITLEMENTS=codesigntests-entitlements.plist
codesigntests: OTHER_CFLAGS += -DTESTNAME=codesigntests
# Adding a custom target and build/install rules since CODE_SIGN_ENTITLEMENTS
# does not take in arguments, and we need to sign this test using a sha256T
# digest

OTHER_TEST_TARGETS += codesigntests_sha256t
codesigntests_sha256t: OTHER_CFLAGS += -DTESTNAME=codesigntests_sha256t

codesigntests_sha256t: codesigntests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(DT_LDFLAGS) $(LDFLAGS) $(CFLAGS) codesigntests.c -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --digest=sha256T -s - --entitlements codesigntests-entitlements.plist $(SYMROOT)/$@;
install-codesigntests_sha256t: codesigntests_sha256t
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/codesigntests_sha256t $(INSTALLDIR)/

OTHER_TEST_TARGETS += cs_installer_clearinstaller
cs_installer_clearinstaller: codesigntests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(DT_LDFLAGS) $(LDFLAGS) $(CFLAGS) codesigntests.c -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) -s - --entitlements codesigntests-entitlements.plist $(SYMROOT)/$@;
install-cs_installer_clearinstaller: cs_installer_clearinstaller
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/cs_installer_clearinstaller $(INSTALLDIR)/


ecc_test: ecc_test.c ecc_test_helper
ecc_test: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
ecc_test: OTHER_LDFLAGS += -ldarwintest_utils

CUSTOM_TARGETS += ecc_test_helper
ecc_test_helper: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
ecc_test_helper: CODE_SIGN_ENTITLEMENTS = entitlements/iscpreboot.entitlements
ecc_test_helper: ecc_test_helper.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) \
		$(LDFLAGS) $^ -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@

install-ecc_test_helper: ecc_test_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/ecc_test_helper $(INSTALLDIR)/

ifeq ($(PLATFORM),BridgeOS)
EXCLUDED_SOURCES += vm/test_vm_no_pager.m
EXCLUDED_SOURCES += vm/test_vm_no_pager_helper.c
else
vm/test_vm_no_pager: excserver
vm/test_vm_no_pager: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -lkdd -framework Foundation
vm/test_vm_no_pager: INVALID_ARCHS = arm64
vm/test_vm_no_pager: OTHER_CFLAGS += -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders $(OBJROOT)/excserver.c -I$(OBJROOT)
vm/test_vm_no_pager: vm/test_vm_no_pager_helper
vm/test_vm_no_pager: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

CUSTOM_TARGETS += vm/test_vm_no_pager_helper

vm/test_vm_no_pager_helper: vm/test_vm_no_pager_helper.c
	mkdir -p $(SYMROOT)/vm
	$(CC) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -lm -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-vm/test_vm_no_pager_helper: vm/test_vm_no_pager_helper
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/test_vm_no_pager_helper $(INSTALLDIR)/vm/
endif

kevent_qos: OTHER_CFLAGS += -Wno-unused-macros
kevent_qos: OTHER_CFLAGS += -I $(OBJROOT)/

test_knote_use_after_free: OTHER_CFLAGS += -Wno-unused-macros
test_knote_use_after_free: OTHER_LDFLAGS += -ldarwintest_utils -lpthread

mach_get_times: OTHER_LDFLAGS += -ldarwintest_utils

monotonic_core: ./stackshot-entitlements.plist
monotonic_core: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
monotonic_core: OTHER_LDFLAGS += -framework ktrace
monotonic_uncore: recount/recount_test_utils.c
monotonic_uncore: OTHER_LDFLAGS += -ldarwintest_utils

perf_exit: perf_exit_proc
perf_exit: ./stackshot-entitlements.plist
perf_exit: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
perf_exit: OTHER_LDFLAGS = -framework ktrace -ldarwintest_utils
perf_exit: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist

CUSTOM_TARGETS += prioritize_process_launch_helper
prioritize_process_launch: prioritize_process_launch_helper

prioritize_process_launch_helper: prioritize_process_launch_helper.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) prioritize_process_launch_helper.c -o $(SYMROOT)/prioritize_process_launch_helper
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-prioritize_process_launch_helper: prioritize_process_launch_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/prioritize_process_launch_helper $(INSTALLDIR)/


perf_spawn_fork: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist

mach_exception_reply: OTHER_CFLAGS += -Wno-cast-align
mach_exception_reply: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

os_thread_self_restrict: os_thread_self_restrict.c os_thread_self_restrict-entitlements.plist test_utils.c
os_thread_self_restrict: CODE_SIGN_ENTITLEMENTS=os_thread_self_restrict-entitlements.plist
os_thread_self_restrict: OTHER_LDFLAGS += -ldarwintest_utils -sectcreate __TEXT __info_plist os_thread_self_restrict-identifier.plist

subsystem_root_path: subsystem_root_path.c subsystem_root_path-entitlements.plist
subsystem_root_path: CODE_SIGN_ENTITLEMENTS=subsystem_root_path-entitlements.plist

EXCLUDED_SOURCES += $(wildcard bounded_ptr_src/*.cpp)
bounded_ptr: OTHER_CXXFLAGS += -Werror=implicit-int-conversion -Werror=shorten-64-to-32 -I$(SRCROOT)/../libkern -std=c++17
bounded_ptr: $(wildcard bounded_ptr_src/*.cpp) bounded_ptr.cpp

EXCLUDED_SOURCES += bounded_ptr_03.cpp
bounded_ptr_03: OTHER_CXXFLAGS += -Werror=implicit-int-conversion -Werror=shorten-64-to-32 -I$(SRCROOT)/../libkern -std=c++03 $(DT_LDFLAGS)
bounded_ptr_03: bounded_ptr_03.cpp

EXCLUDED_SOURCES += $(wildcard bounded_array_src/*.cpp)
bounded_array: OTHER_CXXFLAGS += -Werror=implicit-int-conversion -Werror=shorten-64-to-32 -I$(SRCROOT)/../libkern -std=c++17
bounded_array: $(wildcard bounded_array_src/*.cpp) bounded_array.cpp

EXCLUDED_SOURCES += $(wildcard bounded_array_ref_src/*.cpp)
bounded_array_ref: OTHER_CXXFLAGS += -Werror=implicit-int-conversion -Werror=shorten-64-to-32 -I$(SRCROOT)/../libkern -std=c++17
bounded_array_ref: $(wildcard bounded_array_ref_src/*.cpp) bounded_array_ref.cpp

EXCLUDED_SOURCES += $(wildcard intrusive_shared_ptr_src/*.cpp)
intrusive_shared_ptr: OTHER_CXXFLAGS += -Werror=implicit-int-conversion -Werror=shorten-64-to-32 -I$(SRCROOT)/../libkern -std=c++17
intrusive_shared_ptr: $(wildcard intrusive_shared_ptr_src/*.cpp) intrusive_shared_ptr.cpp

EXCLUDED_SOURCES += $(wildcard safe_allocation_src/*.cpp)
safe_allocation: OTHER_CXXFLAGS += -Werror=implicit-int-conversion -Werror=shorten-64-to-32 -I$(SRCROOT)/../libkern -std=c++17
safe_allocation: $(wildcard safe_allocation_src/*.cpp) safe_allocation.cpp

EXCLUDED_SOURCES += $(wildcard cxx_safe_buffers_src/*.cpp)
cxx_safe_buffers: OTHER_CXXFLAGS += -Werror=unsafe-buffer-usage -I$(SRCROOT)/../libkern -std=c++20
cxx_safe_buffers: $(wildcard cxx_safe_buffers_src/*.cpp) cxx_safe_buffers.cpp

EXCLUDED_SOURCES += osptr_compat.cpp
osptr_98: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++98 -DOSPTR_STD="98"
osptr_98: osptr_compat.cpp
	$(CXX) $(DT_CXXFLAGS) $(OTHER_CXXFLAGS) $(CXXFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
osptr_11: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++11 -DOSPTR_STD="11"
osptr_11: osptr_compat.cpp
	$(CXX) $(DT_CXXFLAGS) $(OTHER_CXXFLAGS) $(CXXFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
osptr_14: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++14 -DOSPTR_STD="14"
osptr_14: osptr_compat.cpp
	$(CXX) $(DT_CXXFLAGS) $(OTHER_CXXFLAGS) $(CXXFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
osptr_17: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++17 -DOSPTR_STD="17"
osptr_17: osptr_compat.cpp
	$(CXX) $(DT_CXXFLAGS) $(OTHER_CXXFLAGS) $(CXXFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

priority_queue: OTHER_CXXFLAGS += -std=c++17
queue: OTHER_CFLAGS += -I$(SRCROOT)/../osfmk

vm/zalloc: OTHER_LDFLAGS += -ldarwintest_utils
vm/zalloc_buddy: OTHER_CFLAGS += -Wno-format-pedantic

os_refcnt: OTHER_CFLAGS += -I$(SRCROOT)/../libkern/ -Wno-gcc-compat -Wno-undef -O3 -flto -ldarwintest_utils

kernel_inspection: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
kernel_inspection: OTHER_CFLAGS += -DENTITLED=1

turnstile_multihop: OTHER_CFLAGS += -Wno-unused-macros
turnstile_multihop: OTHER_CFLAGS += -I $(OBJROOT)/

CUSTOM_TARGETS += perf_exit_proc

perf_exit_proc:
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) perf_exit_proc.c -o $(SYMROOT)/perf_exit_proc

install-perf_exit_proc: perf_exit_proc
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/perf_exit_proc $(INSTALLDIR)/

# Stackshot


all: $(DSTROOT)/usr/local/bin/kcdata

$(DSTROOT)/usr/local/bin/kcdata: $(SRCROOT)/../tools/lldbmacros/kcdata.py
	mkdir -p $(dir $@)
	cp $< $@
	chmod a+x $@

xnu_quick_test: OTHER_CFLAGS += xnu_quick_test_helpers.c

CUSTOM_TARGETS += vm_set_max_addr_helper

vm_set_max_addr_helper: vm_set_max_addr_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) vm_set_max_addr_helper.c -o $(SYMROOT)/vm_set_max_addr_helper; \
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-vm_set_max_addr_helper: vm_set_max_addr_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/vm_set_max_addr_helper $(INSTALLDIR)/

CUSTOM_TARGETS += subsystem_root_path_helper_entitled
CUSTOM_TARGETS += subsystem_root_path_helper

subsystem_root_path_helper_entitled: subsystem_root_path_helper.c subsystem_root_path-entitlements.plist
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) subsystem_root_path_helper.c -o $(SYMROOT)/subsystem_root_path_helper_entitled; \
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements subsystem_root_path-entitlements.plist $(SYMROOT)/$@;

install-subsystem_root_path_helper_entitled: subsystem_root_path_helper_entitled
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/subsystem_root_path_helper_entitled $(INSTALLDIR)/

subsystem_root_path_helper: subsystem_root_path_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) subsystem_root_path_helper.c -o $(SYMROOT)/subsystem_root_path_helper; \
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-subsystem_root_path_helper: subsystem_root_path_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/subsystem_root_path_helper $(INSTALLDIR)/

CUSTOM_TARGETS += vm_test_code_signing_helper

vm_test_code_signing_helper: vm_test_code_signing_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) vm_test_code_signing_helper.c -o $(SYMROOT)/vm_test_code_signing_helper; \
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-vm_test_code_signing_helper: vm_test_code_signing_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/vm_test_code_signing_helper $(INSTALLDIR)/

vm_test_code_signing: OTHER_LDFLAGS += -ldarwintest_utils

INCLUDED_TEST_SOURCE_DIRS += rm workq

big_map_test: CODE_SIGN_ENTITLEMENTS = ./big_map_test_entitlement.plist

task_info_28439149: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist

rm/pthread_setugid: OTHER_LDFLAGS += -ldarwintest_utils
rm/coalition_info_resource_usage: OTHER_LDFLAGS += -ldarwintest_utils

proc_info: recount/recount_test_utils.c
proc_info: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
proc_info: OTHER_LDFLAGS += -ldarwintest_utils

proc_info_list_kthreads: CODE_SIGN_ENTITLEMENTS = ./proc_info_list_kthreads.entitlements

proc_info_44873309: CODE_SIGN_ENTITLEMENTS = ./proc_info_44873309.entitlements

disk_mount_conditioner: disk_mount_conditioner*
disk_mount_conditioner: CODE_SIGN_ENTITLEMENTS=./disk_mount_conditioner-entitlements.plist
disk_mount_conditioner: OTHER_LDFLAGS += -ldarwintest_utils -framework Foundation

disk_mount_conditioner: OTHER_TEST_TARGETS += disk_mount_conditioner_unentitled
disk_mount_conditioner_unentitled: OTHER_CFLAGS += -DTEST_UNENTITLED
disk_mount_conditioner_unentitled: OTHER_LDFLAGS += -ldarwintest_utils -framework Foundation
disk_mount_conditioner_unentitled: disk_mount_conditioner.m
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

work_interval_test: CODE_SIGN_ENTITLEMENTS = work_interval_test.entitlements
work_interval_test: OTHER_CFLAGS += -DENTITLED=1

work_interval_data_test: CODE_SIGN_ENTITLEMENTS = work_interval_test.entitlements
work_interval_data_test: OTHER_CFLAGS += -DENTITLED=1
work_interval_data_test: OTHER_LDFLAGS += -lpthread

game_mode: CODE_SIGN_ENTITLEMENTS = game_mode.entitlements
carplay_mode: CODE_SIGN_ENTITLEMENTS = carplay_mode.entitlements

runaway_mitigation: CODE_SIGN_ENTITLEMENTS = runaway_mitigation.entitlements
runaway_mitigation: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
runaway_mitigation: $(SCHED_UTILS)

coalition_policy: CODE_SIGN_ENTITLEMENTS = coalition_policy.entitlements
coalition_policy: OTHER_LDFLAGS += $(SCHED_UTILS_FLAGS)
coalition_policy: $(SCHED_UTILS)

settimeofday_29193041: OTHER_CFLAGS += drop_priv.c

settimeofday_29193041_entitled: CODE_SIGN_ENTITLEMENTS = settimeofday_29193041.entitlements
settimeofday_29193041_entitled: OTHER_CFLAGS += drop_priv.c

thread_group_set_32261625: ./stackshot-entitlements.plist
thread_group_set_32261625: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
thread_group_set_32261625: OTHER_LDFLAGS = -framework ktrace

task_info: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist
task_info: OTHER_CFLAGS += test_utils.c
task_info: OTHER_LDFLAGS += -ldarwintest_utils

extract_right_soft_fail: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist

ifneq ($(IOS_TEST_COMPAT),YES)
	EXCLUDED_SOURCES += task_vm_info_decompressions.c
endif

ifeq ($(PLATFORM),MacOSX)
	EXCLUDED_SOURCES += vm/compression_sweep.c
endif

unp_sock_release: CODE_SIGN_ENTITLEMENTS = unp_sock_release-entitlements.plist

accept_race: in_cksum.c net_test_lib.c
accept_race: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

flow_div_doubleconnect_55917185: in_cksum.c net_test_lib.c
flow_div_doubleconnect_55917185: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

bpf_write: bpflib.c in_cksum.c net_test_lib.c
bpf_write: OTHER_LDFLAGS += -ldarwintest_utils

bpf_write_batch: bpflib.c in_cksum.c net_test_lib.c
bpf_write_batch: OTHER_LDFLAGS += -ldarwintest_utils

udp_disconnect: in_cksum.c net_test_lib.c
udp_disconnect: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

udp_bind_connect: in_cksum.c net_test_lib.c
udp_bind_connect: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

tcp_bind_connect: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist
tcp_send_implied_connect: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

sockopt_so_statistics_event: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

tcp_cache_test: CODE_SIGN_ENTITLEMENTS = tcp_cache_entitlements.plist

socket_bind_35243417: in_cksum.c net_test_lib.c
socket_bind_35243417: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

socket_bind_35685803: in_cksum.c net_test_lib.c
socket_bind_35685803: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

tcp_input_outputopts_uaf_56155583: in_cksum.c net_test_lib.c
tcp_input_outputopts_uaf_56155583: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

unp_connect_thread_uaf: in_cksum.c net_test_lib.c
unp_connect_thread_uaf: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

icmp_fragmetned_payload: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist
tcp_invalid_address: OTHER_CFLAGS += -Wno-int-conversion
tcp_invalid_address: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_tuntests: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_bridge: inet_transfer.c bpflib.c in_cksum.c net_test_lib.c
net_bridge: OTHER_LDFLAGS += -ldarwintest_utils
net_bridge: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_vlan: inet_transfer.c bpflib.c in_cksum.c net_test_lib.c
net_vlan: OTHER_LDFLAGS += -ldarwintest_utils
net_vlan: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_bond: inet_transfer.c bpflib.c in_cksum.c net_test_lib.c
net_bond: OTHER_LDFLAGS += -ldarwintest_utils
net_bond: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

mcast_ssm: in_cksum.c net_test_lib.c
mcast_ssm: OTHER_LDFLAGS += -ldarwintest_utils

if_generation_id: net_test_lib.c in_cksum.c
if_generation_id: OTHER_LDFLAGS += -ldarwintest_utils

inet6_addr_mode: net_test_lib.c in_cksum.c
inet6_addr_mode: OTHER_LDFLAGS += -ldarwintest_utils

bpf_direction: bpflib.c
bpf_direction: OTHER_LDFLAGS += -ldarwintest_utils
bpf_direction: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

bpf_timestamp: bpflib.c
bpf_timestamp: OTHER_LDFLAGS += -ldarwintest_utils
bpf_timestamp: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

ipv6_bind_race: in_cksum.c net_test_lib.c
ipv6_bind_race: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist


mcast_group_race_82820812: in_cksum.c net_test_lib.c
mcast_group_race_82820812: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

so_bindtodevice: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

recv_link_addr_type: net_test_lib.c in_cksum.c
recv_link_addr_type: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

ip_pktinfo: net_test_lib.c in_cksum.c
ip_pktinfo: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

v4mappedv6_dontfrag: net_test_lib.c in_cksum.c
v4mappedv6_dontfrag: OTHER_LDFLAGS += -ldarwintest_utils
v4mappedv6_dontfrag: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_siocdifaddr: net_test_lib.c in_cksum.c
net_siocdifaddr: OTHER_LDFLAGS += -ldarwintest_utils

sockopt_sol_socket_domain: CODE_SIGN_ENTITLEMENTS = sockopt_entitlements.plist
sockopt_sol_tcp: CODE_SIGN_ENTITLEMENTS = sockopt_entitlements.plist
sockopt_sol_udp: CODE_SIGN_ENTITLEMENTS = sockopt_entitlements.plist
sockopt_sol_ip: CODE_SIGN_ENTITLEMENTS = sockopt_entitlements.plist
sockopt_sol_ipv6: CODE_SIGN_ENTITLEMENTS = sockopt_entitlements.plist
sockopt_sol_mptcp: CODE_SIGN_ENTITLEMENTS = sockopt_entitlements.plist
sockopt_ip: net_test_lib.c in_cksum.c
sockopt_ip: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

vsock: vsock_helpers.c
vsock_entitled: vsock_helpers.c
vsock_entitled: CODE_SIGN_ENTITLEMENTS = vsock_entitlements.plist

sendmsg_test: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

network_elevated_logging: CODE_SIGN_ENTITLEMENTS = entitlements/network_elevated_logging.entitlements

rvi_doublefree: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist


INCLUDED_TEST_SOURCE_DIRS += net

net/icmp6_redirect_raw_socket: bpflib.c in_cksum.c net_test_lib.c
net/icmp6_redirect_raw_socket: OTHER_LDFLAGS += -ldarwintest_utils

net/test_magic_packet: bpflib.c in_cksum.c net_test_lib.c

net/unreach_icmp_34054660: net/unreach_icmp_34054660.c
net/unreach_icmp_34054660: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net/test_connect_race: net_test_lib.c in_cksum.c

net/test_connect_reuseaddr: net_test_lib.c in_cksum.c

net/test_ctl_bind_race: net_test_lib.c in_cksum.c

net/test_mbuf_exhaustion: net_test_lib.c in_cksum.c

net/test_osiocgif: net_test_lib.c in_cksum.c

net/test_sockopts_with_send: net_test_lib.c in_cksum.c

net/test_zero_length_send: net_test_lib.c in_cksum.c

net/cmsg_padding_leak_171110501: CODE_SIGN_ENTITLEMENTS = net/test_sysctl_tcp_info-entitlements.plist

net/test_sysctl_tcp_info: CODE_SIGN_ENTITLEMENTS = net/test_sysctl_tcp_info-entitlements.plist

CUSTOM_TARGETS += net/test_sysctl_tcp_info_entitled

net/test_sysctl_tcp_info_entitled: net/test_sysctl_tcp_info.c
	mkdir -p $(SYMROOT)/net
	$(CC) $(LDFLAGS) $(CFLAGS) net/test_sysctl_tcp_info.c -o $(SYMROOT)/$@ -ldarwintest
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --digest=sha256 -s - --entitlements net/test_sysctl_tcp_info_entitled-entitlements.plist $(SYMROOT)/$@

install-net/test_sysctl_tcp_info_entitled: net/test_sysctl_tcp_info_entitled
	mkdir -p $(INSTALLDIR)/net
	cp $(SYMROOT)/net/test_sysctl_tcp_info_entitled $(INSTALLDIR)/net/

net/test_restricted_port: net/test_restricted_port.c
net/test_restricted_port: CODE_SIGN_ENTITLEMENTS = net/test_restricted_port-entitlements.plist

CUSTOM_TARGETS += net/test_restricted_port_entitled

net/test_restricted_port_entitled: net/test_restricted_port.c
	mkdir -p $(SYMROOT)/net
	$(CC) $(LDFLAGS) $(CFLAGS) net/test_restricted_port.c -o $(SYMROOT)/$@ -ldarwintest_utils -ldarwintest
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --digest=sha256T -s - --entitlements net/test_restricted_port_entitled-entitlements.plist $(SYMROOT)/$@

install-net/test_restricted_port_entitled: net/test_restricted_port_entitled
	mkdir -p $(INSTALLDIR)/net
	cp $(SYMROOT)/net/test_restricted_port_entitled $(INSTALLDIR)/net/

hardened_process_version_tests: hardened_process_version_tests.c \
	hardened_process_version_no_entitlement \
	hardened_process_version_string_entitlement_v1 \
	hardened_process_version_string_entitlement_v2 \
	hardened_process_version_string_entitlement_v255 \
	hardened_process_version_integer_entitlement_v1 \
	hardened_process_version_integer_entitlement_v2 \
	hardened_process_version_integer_entitlement_v255 \
	hardened_process_version_string_integer_entitlement_v2 \
	hardened_process_version_string_integer_entitlement_v1 \
	hardened_process_version_illegal_string_base_entitlement \
	hardened_process_version_illegal_string_type_entitlement


EXCLUDED_SOURCES += hardened_process_version_expect_version_zero.c \
	hardened_process_version_expect_version_v1.c \
	hardened_process_version_expect_version_v2.c

install-hardened_process_version_expect_version_v2: hardened_process_version_expect_version_v2
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_expect_version_v2 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_no_entitlement
hardened_process_version_no_entitlement: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc.entitlements
hardened_process_version_no_entitlement: hardened_process_version_expect_version_v2.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_no_entitlement: hardened_process_version_no_entitlement
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_no_entitlement $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_string_entitlement_v1
hardened_process_version_string_entitlement_v1: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-v1.entitlements
hardened_process_version_string_entitlement_v1: hardened_process_version_expect_version_v1.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_string_entitlement_v1: hardened_process_version_string_entitlement_v1
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_string_entitlement_v1 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_string_entitlement_v2
hardened_process_version_string_entitlement_v2: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-v2.entitlements
hardened_process_version_string_entitlement_v2: hardened_process_version_expect_version_v2.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_string_entitlement_v2: hardened_process_version_string_entitlement_v2
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_string_entitlement_v2 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_string_entitlement_v255
hardened_process_version_string_entitlement_v255: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-v255.entitlements
hardened_process_version_string_entitlement_v255: hardened_process_version_expect_version_v2.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_string_entitlement_v255: hardened_process_version_string_entitlement_v255
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_string_entitlement_v255 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_integer_entitlement_v1
hardened_process_version_integer_entitlement_v1: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-integer-v1.entitlements
hardened_process_version_integer_entitlement_v1: hardened_process_version_expect_version_v1.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_integer_entitlement_v1: hardened_process_version_integer_entitlement_v1
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_integer_entitlement_v1 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_integer_entitlement_v2
hardened_process_version_integer_entitlement_v2: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-integer-v2.entitlements
hardened_process_version_integer_entitlement_v2: hardened_process_version_expect_version_v2.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_integer_entitlement_v2: hardened_process_version_integer_entitlement_v2
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_integer_entitlement_v2 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_integer_entitlement_v255
hardened_process_version_integer_entitlement_v255: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-integer-v255.entitlements
hardened_process_version_integer_entitlement_v255: hardened_process_version_expect_version_v2.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_integer_entitlement_v255: hardened_process_version_integer_entitlement_v255
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_integer_entitlement_v255 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_string_integer_entitlement_v2
hardened_process_version_string_integer_entitlement_v2: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-integer-v2-v1.entitlements
hardened_process_version_string_integer_entitlement_v2: hardened_process_version_expect_version_v2.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_string_integer_entitlement_v2: hardened_process_version_string_integer_entitlement_v2
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_string_integer_entitlement_v2 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_string_integer_entitlement_v1
hardened_process_version_string_integer_entitlement_v1: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-integer-v1-v2.entitlements
hardened_process_version_string_integer_entitlement_v1: hardened_process_version_expect_version_v1.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_string_integer_entitlement_v1: hardened_process_version_string_integer_entitlement_v1
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_string_integer_entitlement_v1 $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_illegal_string_base_entitlement
hardened_process_version_illegal_string_base_entitlement: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-illegal-base.entitlements
hardened_process_version_illegal_string_base_entitlement: hardened_process_version_expect_version_zero.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_illegal_string_base_entitlement: hardened_process_version_illegal_string_base_entitlement
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_illegal_string_base_entitlement $(INSTALLDIR)

CUSTOM_TARGETS += hardened_process_version_illegal_string_type_entitlement
hardened_process_version_illegal_string_type_entitlement: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-string-illegal-type.entitlements
hardened_process_version_illegal_string_type_entitlement: hardened_process_version_expect_version_zero.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

install-hardened_process_version_illegal_string_type_entitlement: hardened_process_version_illegal_string_type_entitlement
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/hardened_process_version_illegal_string_type_entitlement $(INSTALLDIR)

EXCLUDED_SOURCES += posix_spawn_archpref_helper.c

CUSTOM_TARGETS += posix_spawn_archpref_helper

posix_spawn_archpref_helper: CFLAGS += -arch arm64
posix_spawn_archpref_helper: posix_spawn_archpref_helper.c
	$(CC) $(LDFLAGS) $(CFLAGS) posix_spawn_archpref_helper.c -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-posix_spawn_archpref_helper: posix_spawn_archpref_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/posix_spawn_archpref_helper $(INSTALLDIR)/

CUSTOM_TARGETS += posix_spawn_alt_rosetta_helper

posix_spawn_alt_rosetta_helper: posix_spawn_alt_rosetta_helper.c
	$(CC) $(LDFLAGS) $(CFLAGS) posix_spawn_alt_rosetta_helper.c -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-posix_spawn_alt_rosetta_helper: posix_spawn_alt_rosetta_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/posix_spawn_alt_rosetta_helper $(INSTALLDIR)/

MIG:=SDKROOT=$(SDKROOT) $(shell xcrun -sdk "$(TARGETSDK)" -find mig)

CUSTOM_TARGETS += excserver

$(OBJROOT)/excserver.c:
excserver:
	$(MIG) $(CFLAGS) \
		-sheader $(OBJROOT)/excserver.h \
		-server $(OBJROOT)/excserver.c \
		-header /dev/null -user /dev/null \
		excserver.defs
install-excserver: ;

CUSTOM_TARGETS += excserver_protect
$(OBJROOT)/excserver_protect.c:
excserver_protect:
	$(MIG) $(CFLAGS) \
		-DMACH_EXC_SERVER_TASKIDTOKEN \
		-sheader $(OBJROOT)/excserver_protect.h \
		-server $(OBJROOT)/excserver_protect.c \
		-header /dev/null -user /dev/null \
		excserver_protect.defs
install-excserver_protect: ;

CUSTOM_TARGETS += excserver_protect_state
$(OBJROOT)/excserver_protect_state.c:
excserver_protect_state:
	$(MIG) $(CFLAGS) \
		-DMACH_EXC_SERVER_TASKIDTOKEN_STATE \
		-DMACH_EXC_SERVER_TASKIDTOKEN \
		-sheader $(OBJROOT)/excserver_protect_state.h \
		-server $(OBJROOT)/excserver_protect_state.c \
		-header /dev/null -user /dev/null \
		excserver_protect.defs
install-excserver_protect_state: ;

EXCLUDED_SOURCES += exc_helpers.c

CUSTOM_TARGETS += notifyserver

notifyserver:
	$(MIG) $(CFLAGS) \
		-user /dev/null \
		-header $(OBJROOT)/notify.h \
		-sheader $(OBJROOT)/notifyServer.h \
		-server $(OBJROOT)/notifyServer.c \
		notifyserver.defs
install-notifyserver: ;

CUSTOM_TARGETS += rnserver

rnserver:
	$(MIG) $(CFLAGS) \
		-user /dev/null \
		-header $(OBJROOT)/rn.h \
		-sheader $(OBJROOT)/rnServer.h \
		-server $(OBJROOT)/rnServer.c \
		rnserver.defs
install-rnserver: ;

SKYWALK_COMMON_FILES := \
	skywalk/skywalk_test_common.c \
	skywalk/skywalk_test_utils.c
SKYWALK_TEST_FILES := \
	skywalk/skywalk_test_driver.c \
	skywalk/skt_simple.c \
	skywalk/skt_features.c \
	skywalk/skt_oneslot.c \
	skywalk/skt_shutdown.c \
	skywalk/skt_shutdown2.c \
	skywalk/skt_nslots.c \
	skywalk/skt_closecfd.c \
	skywalk/skt_closenfd.c \
	skywalk/skt_badring.c \
	skywalk/skt_kqueue.c \
	skywalk/skt_mangle.c \
	skywalk/skt_features.c \
	skywalk/skt_ringid.c \
	skywalk/skt_closekq.c \
	skywalk/skt_writemem.c \
	skywalk/skt_debug_verify.c \
	skywalk/skt_utun27302538.c \
	skywalk/skt_utunleak.c \
	skywalk/skt_utunloop.c \
	skywalk/skt_flowswitch_ns_reserve.c \
	skywalk/skt_netifcompat.c \
	skywalk/skt_fswloop.c \
	skywalk/skt_teardown.c \
	skywalk/skt_bind.c \
	skywalk/skt_fsw29301703.c \
	skywalk/skt_fswbinds.c \
	skywalk/skt_manyflows.c \
	skywalk/skt_pllupipe.c \
	skywalk/skt_fullupipe.c \
	skywalk/skt_listener.c \
	skywalk/skt_copy_cksum.c \
	skywalk/skt_reass.c \
	skywalk/skt_memory.c \
	skywalk/skt_flow.c \
	skywalk/skt_flowlookup.c \
	skywalk/skt_libcuckoo.c \
	skywalk/skt_restricted_port.c \
	skywalk/skt_steering.c
SKYWALK_MPTEST_FILES := \
	skywalk/skywalk_mptests.c \
	skywalk/skywalk_mptest_driver.c \
	skywalk/skt_mpsimple.c \
	skywalk/skt_mpprotons.c \
	skywalk/skt_xfer.c \
	skywalk/skt_netifdirect.c \
	skywalk/skt_filter.c
EXCLUDED_SOURCES += $(SKYWALK_COMMON_FILES) $(SKYWALK_TEST_FILES) $(SKYWALK_MPTEST_FILES)

skywalk_tests: excserver
skywalk_tests: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
skywalk_tests: CODE_SIGN_ENTITLEMENTS = skywalk_test.entitlements
skywalk_tests: $(SKYWALK_COMMON_FILES) $(SKYWALK_TEST_FILES) $(SKYWALK_MPTEST_FILES) $(SDKROOT)/usr/local/lib/libCrashReporterClient.a

EXCLUDED_SOURCES += arm_matrix_sme.c

arm_matrix: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_matrix: excserver exc_helpers.c arm_matrix_sme.c
arm_matrix: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT) -Wno-language-extension-token -Wno-c++98-compat -mcpu=firestorm+nofp+sme2
arm_matrix: CODE_SIGN_ENTITLEMENTS = arm_matrix.entitlements

MTE_CFLAGS = -march=armv8.5a+memtag -Wno-declaration-after-statement -Wno-format-pedantic -Wno-language-extension-token

arm_mte: arm_mte_spawn_client_with_hardened_process_entitlement arm_mte_spawn_client_without_hardened_process_entitlement arm_mte_utilities.c
arm_mte: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte: OTHER_LDFLAGS += -ldarwintest_utils
arm_mte: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

proc_core_name_mte: proc_core_name_mte.c
proc_core_name_mte: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
proc_core_name_mte: OTHER_CFLAGS += $(MTE_CFLAGS)
proc_core_name_mte: OTHER_LDFLAGS += -ldarwintest_utils
proc_core_name_mte: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements


arm_mte_compress: arm_mte_utilities.c
arm_mte_compress: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_compress: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_compress: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

arm_mte_unentitled: arm_mte_utilities.c arm_mte_debugger_helper
arm_mte_unentitled: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_unentitled: OTHER_CFLAGS += $(MTE_CFLAGS)

arm_mte_stress: arm_mte_utilities.c
arm_mte_stress: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_stress: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_stress: OTHER_LDFLAGS += -ldarwintest_utils
arm_mte_stress: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

EXCLUDED_SOURCES += arm_mte_debugger_helper.c
CUSTOM_TARGETS += arm_mte_debugger_helper
arm_mte_debugger_helper: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_debugger_helper: OTHER_CFLAGS += -march=armv8.5a+memtag
arm_mte_debugger_helper: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements
arm_mte_debugger_helper: arm_mte_debugger_helper.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@

install-arm_mte_debugger_helper: arm_mte_debugger_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

arm_mte_mach_msg: arm_mte_utilities.c
arm_mte_mach_msg: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_mach_msg: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_mach_msg: OTHER_LDFLAGS += -ldarwintest_utils

arm_mte_knobs_policies: arm_mte_utilities.c
arm_mte_knobs_policies: arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out
arm_mte_knobs_policies: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_knobs_policies: OTHER_CFLAGS += -march=armv8.5a+memtag -Wno-declaration-after-statement -Wno-format-pedantic -Wno-language-extension-token -Wno-bad-function-cast
arm_mte_knobs_policies: OTHER_LDFLAGS += -ldarwintest_utils
arm_mte_knobs_policies: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

arm_mte_launchd: arm_mte_launchd.c
arm_mte_launchd: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_launchd: OTHER_CFLAGS += -march=armv8.5a+memtag -Wno-declaration-after-statement -Wno-format-pedantic -Wno-language-extension-token
arm_mte_launchd: OTHER_LDFLAGS += -ldarwintest_utils
arm_mte_launchd: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

arm_mte_spawn_policies: arm_mte_utilities.c
arm_mte_spawn_policies: arm_mte_spawn_client_without_hardened_process_entitlement
arm_mte_spawn_policies: arm_mte_spawn_client_with_hardened_process_entitlement
arm_mte_spawn_policies: arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out
arm_mte_spawn_policies: arm_mte_driverkit_standin
arm_mte_spawn_policies: arm_mte_spawn_client_with_invalid_entitlement_setting
arm_mte_spawn_policies: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_spawn_policies: OTHER_CFLAGS += $(MTE_CFLAGS)

EXCLUDED_SOURCES += arm_mte_spawn_policies_helper.c
EXCLUDED_SOURCES += arm_mte_utilities.c

CUSTOM_TARGETS += arm_mte_spawn_client_without_hardened_process_entitlement
arm_mte_spawn_client_without_hardened_process_entitlement: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_spawn_client_without_hardened_process_entitlement: OTHER_CFLAGS += -march=armv8.5a+memtag
arm_mte_spawn_client_without_hardened_process_entitlement: arm_mte_spawn_policies_helper.c arm_mte_utilities.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(MTE_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

CUSTOM_TARGETS += arm_mte_spawn_client_with_hardened_process_entitlement
arm_mte_spawn_client_with_hardened_process_entitlement: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_spawn_client_with_hardened_process_entitlement: OTHER_CFLAGS += -march=armv8.5a+memtag
arm_mte_spawn_client_with_hardened_process_entitlement: arm_mte_spawn_policies_helper.c arm_mte_utilities.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(MTE_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- --entitlements $(SRCROOT)/entitlements/hardened-proc.entitlements $(SYMROOT)/$@

CUSTOM_TARGETS += arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out
arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out: OTHER_CFLAGS += -march=armv8.5a+memtag
arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out: arm_mte_spawn_policies_helper.c arm_mte_utilities.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(MTE_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) -i com.apple.internal.arm_mte_opt_out_test -s- -f --entitlements $(SRCROOT)/entitlements/hardened-proc.entitlements $(SYMROOT)/$@

CUSTOM_TARGETS += arm_mte_spawn_client_with_invalid_entitlement_setting
arm_mte_spawn_client_with_invalid_entitlement_setting: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_spawn_client_with_invalid_entitlement_setting: OTHER_CFLAGS += -march=armv8.5a+memtag
arm_mte_spawn_client_with_invalid_entitlement_setting: arm_mte_spawn_policies_helper.c arm_mte_utilities.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(MTE_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) -s- -f --entitlements $(SRCROOT)/entitlements/hardened-proc-invalid.entitlements $(SYMROOT)/$@

CUSTOM_TARGETS += mte_posix_spawn_tool
mte_posix_spawn_tool: INVALID_ARCHS = i386
mte_posix_spawn_tool: mte_posix_spawn_tool.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) mte_posix_spawn_tool.c -o $(SYMROOT)/mte_posix_spawn_tool -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

install-mte_posix_spawn_tool: mte_posix_spawn_tool
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/mte_posix_spawn_tool $(INSTALLDIR)/tools/

install-arm_mte_spawn_client_without_hardened_process_entitlement: arm_mte_spawn_client_without_hardened_process_entitlement
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

install-arm_mte_spawn_client_with_hardened_process_entitlement: arm_mte_spawn_client_with_hardened_process_entitlement
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

install-arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out: arm_mte_spawn_client_with_top_level_hardened_proc_entitlement_and_in_amfi_opt_out
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

install-arm_mte_spawn_client_with_invalid_entitlement_setting: arm_mte_spawn_client_with_invalid_entitlement_setting
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/$< $(INSTALLDIR)/tools/

vm/vm_mteinfo: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
vm/vm_mteinfo: OTHER_CFLAGS += -Wno-implicit-int-conversion -Wno-sign-conversion -Wno-sign-compare -Wno-format-pedantic

vm/vm_mte_reclamation_withmte: arm_mte_utilities.c
vm/vm_mte_reclamation_withmte: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
vm/vm_mte_reclamation_withmte: OTHER_CFLAGS += $(MTE_CFLAGS)
vm/vm_mte_reclamation_withmte: OTHER_LDFLAGS += -ldarwintest_utils
vm/vm_mte_reclamation_withmte: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

CODESIGN_MTE_SOFT:=$(CODESIGN) -i com.apple.internal.arm_mte_soft_mode_test
arm_mte_soft_mode: arm_mte_utilities.c
arm_mte_soft_mode: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_soft_mode: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_soft_mode: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements
arm_mte_soft_mode: CODESIGN = $(CODESIGN_MTE_SOFT)

arm_mte_soft_mode_traced: arm_mte_utilities.c
arm_mte_soft_mode_traced: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_soft_mode_traced: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_soft_mode_traced: CODE_SIGN_ENTITLEMENTS = arm_mte_soft_mode_traced.entitlements
arm_mte_soft_mode_traced: CODESIGN = $(CODESIGN_MTE_SOFT)

CODESIGN_MTE_PREFLIGHT:=$(CODESIGN) -i com.apple.internal.arm_mte_preflight_test
arm_mte_preflight: arm_mte_utilities.c
arm_mte_preflight: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_preflight: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_preflight: CODESIGN = $(CODESIGN_MTE_PREFLIGHT)

CODESIGN_MTE_API:=$(CODESIGN) -i com.apple.internal.arm_mte_api_test
arm_mte_api: arm_mte_utilities.c
arm_mte_api: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_api: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_api: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements
arm_mte_api: CODESIGN = $(CODESIGN_MTE_API)

OTHER_TEST_TARGETS += arm_mte_alias_restriction
arm_mte_alias_restriction: arm_mte_utilities.c
arm_mte_alias_restriction: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_alias_restriction: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements
arm_mte_alias_restriction: OTHER_CFLAGS += $(MTE_CFLAGS)
arm_mte_alias_restriction: arm_mte_alias_restriction.c arm_mte_alias_restriction_helper
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(MTE_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	arm_mte_alias_restriction.c arm_mte_utilities.c -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@

install-arm_mte_alias_restriction: arm_mte_alias_restriction
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

CUSTOM_TARGETS += arm_mte_alias_restriction_helper
EXCLUDED_SOURCES += arm_mte_alias_restriction_helper.c
CODESIGN_MTE_ALIAS_RESTRICTION:=$(CODESIGN) -i com.apple.internal.arm_mte_alias_restriction_opt_in_test
arm_mte_alias_restriction_helper: CODESIGN = $(CODESIGN_MTE_ALIAS_RESTRICTION)
arm_mte_alias_restriction_helper: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_alias_restriction_helper: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements
arm_mte_alias_restriction_helper: arm_mte_alias_restriction_helper.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
		$^ -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@

install-arm_mte_alias_restriction_helper: arm_mte_alias_restriction_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

CUSTOM_TARGETS += arm_mte_driverkit_standin
EXCLUDED_SOURCES += arm_mte_driverkit_standin.c
arm_mte_driverkit_standin: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
arm_mte_driverkit_standin: CODE_SIGN_ENTITLEMENTS = arm_mte_driverkit_standin.entitlements
arm_mte_driverkit_standin: arm_mte_driverkit_standin.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@

install-arm_mte_driverkit_standin: arm_mte_driverkit_standin
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

ifeq ($(PLATFORM),MacOSX)
x18_entitled: OTHER_CFLAGS += -ffixed-x18 -Wno-language-extension-token
x18_entitled: CODE_SIGN_ENTITLEMENTS = x18-entitlements.plist
x18_toggle: OTHER_CFLAGS += -ffixed-x18 -Wno-language-extension-token
x18_toggle: CODE_SIGN_ENTITLEMENTS = x18-toggle-entitlements.plist
x18_unentitled: OTHER_CFLAGS += -ffixed-x18 -Wno-language-extension-token
# Also run x18_toggle tests in a 4k address space (via vm_spawn_tool).
# Uses -n to bypass minirunner respawn, which would lose the 4k spawn attr.
BATS_PLISTS += $(SRCROOT)/x18_toggle_4k.plist
EXCLUDED_SOURCES += x18_toggle_4k.plist
else
EXCLUDED_SOURCES += x18_entitled.c x18_toggle.c x18_unentitled.c x18_toggle_4k.plist
endif

ifneq ($(PLATFORM),MacOSX)
EXCLUDED_SOURCES += x18_legacy.c
else
x18_legacy: OTHER_CFLAGS += -ffixed-x18 -Wno-language-extension-token -Wl,-platform_version -Wl,macos -Wl,10.12 -Wl,10.12
endif



ifeq ($(findstring arm64,$(ARCH_CONFIGS)),)
EXCLUDED_SOURCES += apple_generic_timer.c apple_generic_timer_legacy.c
else
apple_generic_timer: INVALID_ARCHS = armv7k x86_64 x86_64h

apple_generic_timer_legacy: INVALID_ARCHS = armv7k x86_64 x86_64h
ifeq ($(PLATFORM),MacOSX)
apple_generic_timer_legacy: OTHER_CFLAGS += -Wl,-platform_version,macos,14.6,14.6
else ifeq ($(PLATFORM),iPhoneOS)
apple_generic_timer_legacy: OTHER_CFLAGS += -Wl,-platform_version,ios,14.6,14.6
else ifeq ($(PLATFORM),tvOS)
apple_generic_timer_legacy: OTHER_CFLAGS += -Wl,-platform_version,tvos,14.6,14.6
else ifeq ($(PLATFORM),WatchOS)
apple_generic_timer_legacy: OTHER_CFLAGS += -Wl,-platform_version,watchos,10.6,10.6
else
EXCLUDED_SOURCES += apple_generic_timer_legacy.c
endif

ifneq ($(PLATFORM),MacOSX)
EXCLUDED_SOURCES += apple_generic_timer_vmm.c
else
apple_generic_timer_vmm: INVALID_ARCHS = armv7k x86_64 x86_64h
apple_generic_timer_vmm: CODE_SIGN_ENTITLEMENTS = hv_private.entitlements
endif

endif

bingrade: bingrade_helper_arm32 bingrade_helper_arm64 bingrade_helper_arm_fat
bingrade: INVALID_ARCHS = x86_64 x86_64h
# libdarwintest.a doesn't have an arm64 slice on watchOS
ifeq ($(PLATFORM),WatchOS)
bingrade: INVALID_ARCHS += arm64
endif

EXCLUDED_SOURCES += bingrade_helper.c
CUSTOM_TARGETS += bingrade_helper_arm32
bingrade_helper_arm32: OTHER_CFLAGS = -arch arm64_32 -static -nostdlib
bingrade_helper_arm32: bingrade_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- $(SYMROOT)/$@

install-bingrade_helper_arm32: bingrade_helper_arm32
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

CUSTOM_TARGETS += bingrade_helper_arm64
bingrade_helper_arm64: OTHER_CFLAGS = -arch arm64 -static -nostdlib
bingrade_helper_arm64: bingrade_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- $(SYMROOT)/$@

install-bingrade_helper_arm64: bingrade_helper_arm64
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

CUSTOM_TARGETS += bingrade_helper_arm_fat
bingrade_helper_arm_fat: OTHER_CFLAGS = -arch arm64 -arch arm64_32 -arch arm64e -static -nostdlib
bingrade_helper_arm_fat: bingrade_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	$(CODESIGN) -f -s- $(SYMROOT)/$@

install-bingrade_helper_arm_fat: bingrade_helper_arm_fat
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

pmap_bench: INVALID_ARCHS = $(filter-out arm%,$(ARCH_CONFIGS))
pmap_stress: INVALID_ARCHS = $(filter-out arm%,$(ARCH_CONFIGS))
pmap_fault_on_commpage: INVALID_ARCHS = $(filter-out arm%,$(ARCH_CONFIGS))

sptm_info: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
sptm_info: OTHER_CFLAGS += -framework perfdata -isystem $(SDKROOT)/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/platform

tpro_cs: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))

hw_breakpoint_step_arm64: CODE_SIGN_ENTITLEMENTS = hw_breakpoint_step_arm64_entitlements.plist
hw_breakpoint_step_arm64: INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))
hw_breakpoint_step_arm64: excserver
hw_breakpoint_step_arm64: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)

exc_resource_threads: excserver
exc_resource_threads: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
exc_resource_threads: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

mach_service_port: notifyserver
mach_service_port: OTHER_CFLAGS += $(OBJROOT)/notifyServer.c -I $(OBJROOT)

fp_exception: excserver exc_helpers.c
fp_exception: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
fp_exception: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

ptrauth_failure: excserver exc_helpers.c
ptrauth_failure: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT) -Wno-language-extension-token
ptrauth_failure: CODESIGN = $(CODESIGN_HARDENED_RUNTIME)
ptrauth_failure: CODE_SIGN_ENTITLEMENTS = entitlements/set_state_and_exception_port.entitlement

decompression_failure: excserver exc_helpers.c try_read_write.c
decompression_failure: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
decompression_failure: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

ifeq ($(findstring arm64e,$(ARCH_CONFIGS)),)
EXCLUDED_SOURCES += pac_exception_entitlement.c
else
pac_exception_entitlement: excserver exc_helpers.c
pac_exception_entitlement: OTHER_CFLAGS += $(OBJROOT)/excserver.c -Wno-language-extension-token
pac_exception_entitlement: CODE_SIGN_ENTITLEMENTS = pac_exception_entitlement.plist
endif

unrecoverable_trap_test: excserver exc_helpers.c
unrecoverable_trap_test: OTHER_CFLAGS += $(OBJROOT)/excserver.c -Wno-language-extension-token
unrecoverable_trap_test: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement
# libdarwintest.a doesn't have an arm64 slice on watchOS
ifeq ($(PLATFORM),WatchOS)
unrecoverable_trap_test: INVALID_ARCHS += arm64
endif


ifeq ($(findstring arm64,$(ARCH_CONFIGS)),)
EXCLUDED_SOURCES += arm_cpu_capabilities.c
else
arm_cpu_capabilities: INVALID_ARCHS = armv7k x86_64 x86_64h
arm_cpu_capabilities: excserver exc_helpers.c
arm_cpu_capabilities: OTHER_CFLAGS += $(OBJROOT)/excserver.c -Wno-language-extension-token -mcpu=apple-a15
#if HAS_ARM_FEAT_SME
arm_cpu_capabilities: OTHER_CFLAGS += -mcpu=apple-a15+sme2
#endif
# Including PrivateHeaders from both Kernel.framework and System.framework makes
# a mess out of the Mach headers we need to build exception handling support.
# Work around this by only including the arm/ directory.
arm_cpu_capabilities: OTHER_CFLAGS += -isystem $(SDKROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders/arm
arm_cpu_capabilities: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement
endif

ifeq ($(findstring arm64,$(ARCH_CONFIGS)),)
EXCLUDED_SOURCES += sysctl_hv.c
else
sysctl_hv: INVALID_ARCHS = armv7k x86_64 x86_64h
endif

# Disabling building of ldt files as dt_extractmeta crashes
# in build systems. Ref rdar://110251082
# Leaving commented bits for future re-enablement
EXCLUDED_SOURCES += ldt_code32.s ldt.c

#\ifeq ($(findstring x86_64,$(ARCH_CONFIGS)),)
#EXCLUDED_SOURCES += ldt_code32.s ldt.c
#\else # target = osx
#$(OBJROOT)/ldt_mach_exc_server.c:
#	$(MIG) $(CFLAGS) \
#		-user /dev/null \
#		-server $(OBJROOT)/ldt_mach_exc_server.c \
#		-header $(OBJROOT)/ldt_mach_exc.h \
#		mach_exc.defs
#
#ldt: INVALID_ARCHS = $(ARCH_CONFIGS)
#ldt: $(OBJROOT)/ldt_mach_exc_server.c
#ldt: OTHER_CFLAGS += -arch x86_64 -I $(OBJROOT) $(SRCROOT)/ldt_code32.s -Wl,-pagezero_size,0x1000 -Wno-missing-variable-declarations
#ldt: CODE_SIGN_ENTITLEMENTS=ldt_entitlement.plist
#\endif

ifneq ($(PLATFORM),BridgeOS)
EXCLUDED_SOURCES += remote_time.c
else
remote_time: INVALID_ARCHS = armv7 armv7s arm64_32
endif

vm_phys_footprint: OTHER_LDFLAGS += -framework CoreFoundation -framework IOSurface

vm_kern_count_wired_kernelcache: OTHER_CFLAGS += -I$(SDKROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders/mach

debug_control_port_for_pid: CODE_SIGN_ENTITLEMENTS = ./debug_control_port_for_pid_entitlement.plist

prng: OTHER_LDFLAGS += -ldarwintest_utils

preoslog: OTHER_LDFLAGS += -ldarwintest_utils
preoslog: OTHER_CFLAGS += test_utils.c

task_policy: CODE_SIGN_ENTITLEMENTS = ./task_policy_entitlement.plist

OTHER_TEST_TARGETS += task_policy_unentitled
task_policy_unentitled: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist
task_policy_unentitled: OTHER_CFLAGS += -DUNENTITLED
task_policy_unentitled: task_policy.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@


EXCLUDED_SOURCES += get_shared_cache_address.c


ifneq ($(filter iPhoneOS MacOSX, $(PLATFORM)),)
CUSTOM_TARGETS += get_shared_cache_address

get_shared_cache_address: INVALID_ARCHS = arm64 i386 x86_64
get_shared_cache_address: get_shared_cache_address.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/get_shared_cache_address

install-get_shared_cache_address: get_shared_cache_address
	$(CODESIGN) --force --sign - --timestamp=none --identifier=com.apple.get_shared_cache_address $(SYMROOT)/get_shared_cache_address
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/get_shared_cache_address $(INSTALLDIR)/
endif


OTHER_TEST_TARGETS += vm_memory_share_tests

vm_memory_share_tests: INVALID_ARCHS = i386
vm_memory_share_tests: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
vm_memory_share_tests: vm_memory_tests_src/main.c vm_memory_tests_src/common.c vm_memory_tests_src/vm_tests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	echo $(CODESIGN) --force --sign - --timestamp=none --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements "$(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS)" $(SYMROOT)/$@;

# build the mach server as individual helper which does not use libdarwintest
CUSTOM_TARGETS += vm_memory_share_tests_server
vm_memory_share_tests_server: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
vm_memory_share_tests_server: vm_memory_tests_src/server.c vm_memory_tests_src/common.c vm_memory_tests_src/vm_tests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/vm_memory_share_tests_server
	echo $(CODESIGN) --force --sign - --timestamp=none --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements "$(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS)" $(SYMROOT)/$@;

install-vm_memory_share_tests_server: vm_memory_share_tests_server
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/vm_memory_share_tests_server $(INSTALLDIR)/

ifeq ($(PLATFORM),MacOSX)
EXCLUDED_SOURCES += vm/kern_max_task_pmem.c
endif

EXCLUDED_SOURCES += benchmark/helpers.c

vm/fault_throughput: OTHER_CFLAGS += benchmark/helpers.c
vm/fault_throughput: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

.PHONY: install-vm/fault_throughput
install-vm/fault_throughput: vm/fault_throughput
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/fault_throughput $(INSTALLDIR)/vm/

$(SYMROOT)/vm/fault_throughput.lua: $(SRCROOT)/vm/fault_throughput.lua
	mkdir -p $(SYMROOT)/vm
	cp $< $@
	chmod +x $@

.PHONY: install-fault_throughput_benchrun
install-$(SYMROOT)/vm/fault_throughput.lua: $(SYMROOT)/vm/fault_throughput.lua
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/fault_throughput.lua $(INSTALLDIR)/vm/
	chmod +x $(INSTALLDIR)/vm/fault_throughput.lua

EXCLUDED_SOURCES += vm/fault_throughput.plist

CUSTOM_TARGETS += $(SYMROOT)/vm/fault_throughput.lua vm/fault_throughput

ifeq ($(PLATFORM),MacOSX)
mixed_pagesize: vm/mixed_pagesize.c
	mkdir -p $(SYMROOT)/vm
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/vm/$@
	codesign -s - -f --entitlements=entitlements/mixed_pagesize.entitlements $(SYMROOT)/vm/$@

mixed_pagesize_x86_restricted: vm/mixed_pagesize.c
	mkdir -p $(SYMROOT)/vm
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/vm/$@
	codesign -s - -f --entitlements=entitlements/mixed_pagesize_x86_restricted.entitlements $(SYMROOT)/vm/$@

mixed_pagesize_x86_unrestricted: vm/mixed_pagesize.c
	mkdir -p $(SYMROOT)/vm
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/vm/$@
	codesign -s - -f --entitlements=entitlements/mixed_pagesize_x86_unrestricted.entitlements $(SYMROOT)/vm/$@

mixed_pagesize_unentitled: vm/mixed_pagesize.c
	mkdir -p $(SYMROOT)/vm
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/vm/$@

install-mixed_pagesize: mixed_pagesize mixed_pagesize_x86_restricted mixed_pagesize_x86_unrestricted mixed_pagesize_unentitled
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/mixed_pagesize $(INSTALLDIR)/vm/
	cp $(SYMROOT)/vm/mixed_pagesize_x86_restricted $(INSTALLDIR)/vm/
	cp $(SYMROOT)/vm/mixed_pagesize_x86_unrestricted $(INSTALLDIR)/vm/
	cp $(SYMROOT)/vm/mixed_pagesize_unentitled $(INSTALLDIR)/vm/

BATS_PLISTS += $(SRCROOT)/vm/mixed_pagesize.plist

EXCLUDED_SOURCES += vm/mixed_pagesize.c vm/mixed_pagesize.plist
CUSTOM_TARGETS += mixed_pagesize
else
EXCLUDED_SOURCES += vm/mixed_pagesize.c vm/mixed_pagesize.plist
endif

ifeq ($(PLATFORM),MacOSX)
map_jit_x86_64_compat_restricted: INVALID_ARCHS = i386 x86_64 x86_64h
map_jit_x86_64_compat_restricted: map_jit_x86_64_compat.c
	mkdir -p $(SYMROOT)
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) -DEXPECT_MAP_JIT_SUCCESS $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	codesign -s - -f -o runtime --entitlements=entitlements/map_jit_x86_64_restricted.entitlements $(SYMROOT)/$@

map_jit_x86_64_compat_unrestricted: INVALID_ARCHS = i386 x86_64 x86_64h
map_jit_x86_64_compat_unrestricted: map_jit_x86_64_compat.c
	mkdir -p $(SYMROOT)
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) -DEXPECT_MAP_JIT_SUCCESS $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	codesign -s - -f -o runtime --entitlements=entitlements/map_jit_x86_64_unrestricted.entitlements $(SYMROOT)/$@

map_jit_x86_64_compat_unentitled: INVALID_ARCHS = i386 x86_64 x86_64h
map_jit_x86_64_compat_unentitled: map_jit_x86_64_compat.c
	mkdir -p $(SYMROOT)
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	codesign -s - -f -o runtime $(SYMROOT)/$@

install-map_jit_x86_64_compat_restricted: map_jit_x86_64_compat_restricted
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/map_jit_x86_64_compat_restricted $(INSTALLDIR)/

install-map_jit_x86_64_compat_unrestricted: map_jit_x86_64_compat_unrestricted
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/map_jit_x86_64_compat_unrestricted $(INSTALLDIR)/

install-map_jit_x86_64_compat_unentitled: map_jit_x86_64_compat_unentitled
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/map_jit_x86_64_compat_unentitled $(INSTALLDIR)/

CUSTOM_TARGETS += map_jit_x86_64_compat_restricted map_jit_x86_64_compat_unrestricted map_jit_x86_64_compat_unentitled
endif
EXCLUDED_SOURCES += map_jit_x86_64_compat.c

manual_wq_cooperative: manual_wq_cooperative.c
	mkdir -p $(SYMROOT)
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

install-manual_wq_cooperative: manual_wq_cooperative
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/manual_wq_cooperative $(INSTALLDIR)

BATS_PLISTS += $(SRCROOT)/workqueue.plist
EXCLUDED_SOURCES += manual_wq_cooperative.c workqueue.plist
CUSTOM_TARGETS += manual_wq_cooperative

# VM madvise(2) benchmark

BATS_PLISTS += $(SRCROOT)/vm/perf_madvise.plist

vm/perf_madvise: OTHER_CFLAGS += benchmark/helpers.c
vm/perf_madvise: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

.PHONY: install-vm/perf_madvise
install-vm/perf_madvise: vm/perf_madvise
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/perf_madvise $(INSTALLDIR)/vm/

$(SYMROOT)/vm/perf_madvise.lua: $(SRCROOT)/vm/perf_madvise.lua
	mkdir -p $(SYMROOT)/vm
	cp $< $@
	chmod +x $@

.PHONY: install-perf_madvise_benchrun
install-$(SYMROOT)/vm/perf_madvise.lua: $(SYMROOT)/vm/perf_madvise.lua
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/perf_madvise.lua $(INSTALLDIR)/vm
	chmod +x $(INSTALLDIR)/vm/perf_madvise.lua

CUSTOM_TARGETS += $(SYMROOT)/vm/perf_madvise.lua vm/perf_madvise

BATS_PLISTS += $(SRCROOT)/vm/perf_compressor.plist
EXCLUDED_SOURCES += vm/perf_compressor.plist

vm/perf_compressor: OTHER_CFLAGS += benchmark/helpers.c
vm/perf_compressor: CODE_SIGN_ENTITLEMENTS = arm_mte.entitlements

.PHONY: install-vm/perf_compressor
install-vm/perf_compressor: vm/perf_compressor
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/perf_compressor $(INSTALLDIR)/vm/

$(SYMROOT)/vm/perf_compressor.lua: $(SRCROOT)/vm/perf_compressor.lua
	mkdir -p $(SYMROOT)/vm
	cp $< $@
	chmod +x $@

.PHONY: install-$(SYMROOT)/vm/perf_compressor_benchrun
install-$(SYMROOT)/vm/perf_compressor.lua: $(SYMROOT)/vm/perf_compressor.lua
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/perf_compressor.lua $(INSTALLDIR)/vm/
	chmod +x $(INSTALLDIR)/vm/perf_compressor.lua

CUSTOM_TARGETS += $(SYMROOT)/vm/perf_compressor.lua vm/perf_compressor

ioconnectasyncmethod_57641955: OTHER_LDFLAGS += -framework IOKit

ifeq ($(PLATFORM),BridgeOS)
EXCLUDED_SOURCES += ipsec.m exclaves_tests.c exclaves_storage_tests.c exclaves_daemon_notification_test.c
else
ipsec: OTHER_LDFLAGS += -framework Foundation -framework CoreFoundation -framework NetworkExtension
ipsec: CODE_SIGN_ENTITLEMENTS = ipsec.entitlements
endif

test_sysctl_kern_procargs_25397314: OTHER_LDFLAGS += -framework Foundation -ldarwintest_utils

INCLUDED_TEST_SOURCE_DIRS += counter

EXCLUDED_SOURCES += counter/common.c
counter/counter: OTHER_CFLAGS += counter/common.c test_utils.c
counter/counter: OTHER_LDFLAGS += -ldarwintest_utils -ldarwintest

counter/benchmark: OTHER_CFLAGS += counter/common.c benchmark/helpers.c

.PHONY: install-counter/benchmark
install-counter/benchmark: counter/benchmark
	mkdir -p $(INSTALLDIR)/counter
	cp $(SYMROOT)/counter/benchmark $(INSTALLDIR)/counter/

$(SYMROOT)/counter/benchmark.lua: $(SRCROOT)/counter/benchmark.lua
	mkdir -p $(SYMROOT)/counter
	cp $< $@
	chmod +x $@

.PHONY: install-counter_benchrun
install-$(SYMROOT)/counter/benchmark.lua: $(SYMROOT)/counter/benchmark.lua
	mkdir -p $(INSTALLDIR)/counter
	cp $(SYMROOT)/counter/benchmark.lua $(INSTALLDIR)/counter/
	chmod +x $(INSTALLDIR)/counter/benchmark.lua

CUSTOM_TARGETS += $(SYMROOT)/counter/benchmark.lua counter/benchmark

ifneq ($(PLATFORM),MacOSX)
EXCLUDED_SOURCES += vm/page_size_globals.c
else
vm/page_size_globals: INVALID_ARCHS = arm64 arm64e
endif

# Same helper used in execperf, different build system.
static_binary: ../tools/tests/execperf/exit-asm.S
	$(CC) $(DT_CFLAGS) $(CFLAGS) $(filter-out -l%,$(DT_LDFLAGS) $(LDFLAGS) $(OTHER_LDFLAGS)) $< -o $(SYMROOT)/static_binary -static -nostartfiles -nodefaultlibs -Wl,-version_load_command -Wl,-segalign,0x4000 -e _main
	CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/static_binary

install-static_binary: static_binary
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/static_binary $(INSTALLDIR)

CUSTOM_TARGETS += static_binary
EXCLUDED_SOURCES += static_binary.c

test_static_binary_csflags: static_binary
test_static_binary_csflags: OTHER_LDFLAGS += -ldarwintest_utils


libmalloc_apple_array: CODE_SIGN_ENTITLEMENTS = entitlements/libmalloc_apple_array.entitlements
libmalloc_apple_array: OTHER_CFLAGS += -DENTITLED=1 drop_priv.c test_utils.c
libmalloc_apple_array: OTHER_LDFLAGS += -ldarwintest_utils
libmalloc_apple_array: libmalloc_apple_array.c print_apple_array print_apple_array_HR1 print_apple_array_HR2 print_apple_array_hardened_proc print_apple_array_hardened_proc_security print_apple_array_hardened_heap print_apple_array_hardened_heap_security
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

libmalloc_apple_array_unentitled: OTHER_CFLAGS += drop_priv.c test_utils.c
libmalloc_apple_array_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
libmalloc_apple_array_unentitled: libmalloc_apple_array.c print_apple_array print_apple_array_HR1 print_apple_array_HR2 print_apple_array_hardened_proc print_apple_array_hardened_heap
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $(OTHER_CFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array
print_apple_array: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_HR1
print_apple_array_HR1: CODE_SIGN_ENTITLEMENTS=entitlements/enhanced-security-binary-entitlements-1.plist
print_apple_array_HR1: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_HR2
print_apple_array_HR2: CODE_SIGN_ENTITLEMENTS=entitlements/enhanced-security-binary-entitlements-2.plist
print_apple_array_HR2: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_hardened_proc
print_apple_array_hardened_proc: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc.entitlements
print_apple_array_hardened_proc: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_hardened_proc_security
print_apple_array_hardened_proc_security: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-security.entitlements
print_apple_array_hardened_proc_security: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;


CUSTOM_TARGETS += print_apple_array_hardened_heap
print_apple_array_hardened_heap: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-heap.entitlements
print_apple_array_hardened_heap: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_hardened_heap_security
print_apple_array_hardened_heap_security: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-heap-security.entitlements
print_apple_array_hardened_heap_security: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

install-print_apple_array: print_apple_array
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array $(INSTALLDIR)/tools/

install-print_apple_array_HR1: print_apple_array_HR1
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_HR1 $(INSTALLDIR)/tools/

install-print_apple_array_HR2: print_apple_array_HR2
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_HR2 $(INSTALLDIR)/tools/

install-print_apple_array_hardened_proc: print_apple_array_hardened_proc
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_hardened_proc $(INSTALLDIR)/tools/

install-print_apple_array_hardened_proc_security: print_apple_array_hardened_proc_security
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_hardened_proc_security $(INSTALLDIR)/tools/

install-print_apple_array_hardened_heap: print_apple_array_hardened_heap
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_hardened_heap $(INSTALLDIR)/tools/


install-print_apple_array_hardened_heap_security: print_apple_array_hardened_heap_security
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_hardened_heap_security $(INSTALLDIR)/tools/

persona: CODE_SIGN_ENTITLEMENTS = persona.entitlements

rm/persona_adoption: CODE_SIGN_ENTITLEMENTS = persona_adoption.entitlements
rm/persona_adoption: OTHER_LDFLAGS += -ldarwintest_utils
rm/persona_adoption_no_inherit: CODE_SIGN_ENTITLEMENTS = rm/persona_adoption_no_inherit.entitlements
rm/persona_adoption_no_inherit: OTHER_LDFLAGS += -ldarwintest_utils

OTHER_TEST_TARGETS += libmalloc_apple_array libmalloc_apple_array_unentitled

entropy: OTHER_CFLAGS += -framework perfdata

debug_enable_syscall_rejection: OTHER_LDFLAGS += -ldarwintest_utils

thread_set_state_arm64_cpsr: CODE_SIGN_ENTITLEMENTS = entitlements/thread_set_state.entitlement

vm/app_swap: OTHER_LDFLAGS += -ldarwintest_utils

CUSTOM_TARGETS += debug_syscall_rejection_helper
debug_syscall_rejection_helper: debug_syscall_rejection_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@; \
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;


install-debug_syscall_rejection_helper: debug_syscall_rejection_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/debug_syscall_rejection_helper $(INSTALLDIR)/

file_leases: OTHER_CFLAGS += test_utils.c
file_leases: OTHER_LDFLAGS += -ldarwintest_utils
file_leases: CODE_SIGN_ENTITLEMENTS = file_leases.entitlements

iopolicy: OTHER_LDFLAGS += -ldarwintest_utils
iopolicy: CODE_SIGN_ENTITLEMENTS = iopolicy.entitlements

# tests/vm/configurator_*.c use the VM configurator

VM_CONFIGURATOR_SRCS = $(wildcard vm/configurator_*.c)
VM_CONFIGURATOR_TARGETS = $(VM_CONFIGURATOR_SRCS:%.c=%)

$(VM_CONFIGURATOR_TARGETS): vm/configurator/vm_configurator.c
$(VM_CONFIGURATOR_TARGETS): vm/configurator/vm_configurator.h vm/configurator/vm_configurator_tests.h
$(VM_CONFIGURATOR_TARGETS): OTHER_CFLAGS += -Wall -Wextra -g

# exception handling helpers
$(VM_CONFIGURATOR_TARGETS): exc_guard_helper.c try_read_write.c exc_helpers.c test_utils.c excserver
$(VM_CONFIGURATOR_TARGETS): OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
$(VM_CONFIGURATOR_TARGETS): OTHER_LDFLAGS += -ldarwintest_utils
$(VM_CONFIGURATOR_TARGETS): CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

# Convenience target to build all tests that use vm_configurator.c
.PHONY: all-vm-configurator-tests
all-vm-configurator-tests: $(VM_CONFIGURATOR_TARGETS)

# Convenience target to list all test executables that use vm_configurator.c
.PHONY: list-all-vm-configurator-executables
list-all-vm-configurator-executables:
	@ echo $(addprefix $(SYMROOT)/,$(VM_CONFIGURATOR_TARGETS))

vm/corpse_footprint: OTHER_LDFLAGS += -ldarwintest_utils

EXCLUDED_SOURCES += constrained_ctypes_tests.c
CUSTOM_TARGETS += constrained_ctypes_tests_enabled constrained_ctypes_tests_enacted constrained_ctypes_tests_disabled
constrained_ctypes_tests_enabled: OTHER_CFLAGS += -D__CCT_TEST_ENABLED
constrained_ctypes_tests_enabled: OTHER_LDFLAGS += -ldarwintest_utils
constrained_ctypes_tests_enabled: constrained_ctypes_tests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) constrained_ctypes_tests.c -o $(SYMROOT)/constrained_ctypes_tests_enabled
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/constrained_ctypes_tests_enabled;

install-constrained_ctypes_tests_enabled: constrained_ctypes_tests_enabled
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/constrained_ctypes_tests_enabled $(INSTALLDIR)/

constrained_ctypes_tests_enacted: OTHER_CFLAGS += -D__CCT_TEST_ENABLED
constrained_ctypes_tests_enacted: OTHER_CFLAGS += -D__CCT_TEST_ENACTED
# TODO: Migrate to the new -fbounds-safety bounds checks (rdar://134446436)
constrained_ctypes_tests_enacted: OTHER_CFLAGS += -fbounds-safety -fno-bounds-safety-bringup-missing-checks
constrained_ctypes_tests_enacted: OTHER_LDFLAGS += -ldarwintest_utils
constrained_ctypes_tests_enacted: constrained_ctypes_tests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) constrained_ctypes_tests.c -o $(SYMROOT)/constrained_ctypes_tests_enacted
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/constrained_ctypes_tests_enacted;

install-constrained_ctypes_tests_enacted: constrained_ctypes_tests_enacted
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/constrained_ctypes_tests_enacted $(INSTALLDIR)/


constrained_ctypes_tests_disabled: OTHER_LDFLAGS += -ldarwintest_utils
constrained_ctypes_tests_disabled: constrained_ctypes_tests.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) constrained_ctypes_tests.c -o $(SYMROOT)/constrained_ctypes_tests_disabled
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/constrained_ctypes_tests_disabled;

install-constrained_ctypes_tests_disabled: constrained_ctypes_tests_disabled
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/constrained_ctypes_tests_disabled $(INSTALLDIR)/

task_suspend_stats: OTHER_LDFLAGS += -ldarwintest_utils
task_suspend_stats: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist

exec_set_proc_name: OTHER_LDFLAGS += -ldarwintest_utils


exception_ports_info: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

OTHER_TEST_TARGETS += trial_experiment_factors_entitled
trial_experiment_factors_entitled: OTHER_CFLAGS += -DENTITLED=1
trial_experiment_factors_entitled: CODE_SIGN_ENTITLEMENTS=kern-trial.entitlements
trial_experiment_factors_entitled: trial_experiment_factors.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

memorystatus_experiment_factors: CODESIGN_ENTITLEMENTS=./memorystatus/memorystatus_experiment_factors.entitlements
memorystatus_experiment_factors: memorystatus/memorystatus_experiment_factors.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	$(ENV) CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODESIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm/memorystatus_rearm: excserver
vm/memorystatus_rearm: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
vm/memorystatus_rearm: CODE_SIGN_ENTITLEMENTS = vm/memorystatus_rearm.entitlements

ksancov: OTHER_LDFLAGS += -framework IOKit
ksancov: CODE_SIGN_ENTITLEMENTS = ksancov.entitlements

correct_sptm_booted: CODE_SIGN_ENTITLEMENTS = correct_sptm_booted.entitlements
correct_sptm_booted: OTHER_LDFLAGS += -framework CoreFoundation -framework IOKit

test_erm_sysctl_writer: test_erm_sysctl_writer.c
test_erm_sysctl_writer: CODE_SIGN_ENTITLEMENTS = test_erm_sysctl_writer.entitlements

EXCLUDED_SOURCES += test_erm_sysctl_helper.c
CUSTOM_TARGETS += test_erm_sysctl_bin_helper
test_erm_sysctl_bin_helper: test_erm_sysctl_helper.c
	mkdir -p $(SYMROOT)
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) test_erm_sysctl_helper.c -o $(SYMROOT)/$@
	echo $(CODESIGN) --force --sign - --timestamp=none --entitlements test_erm_sysctl_writer.entitlements $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements test_erm_sysctl_writer.entitlements $(SYMROOT)/$@;

install-test_erm_sysctl_bin_helper: test_erm_sysctl_bin_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/test_erm_sysctl_bin_helper $(INSTALLDIR)/



# <<< IMPORTANT NOTE
#     Keep this include at the very end of this Makefile,
#     as it must be included *AFTER* all CUSTOM_TARGETS have been added.
include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets
#     IMPORTANT NOTE >>>


# WARNING: temporary moved after the include of $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets , as this would break macOS build if not.
# to be fixed by: rdar://162807644 (tests/Makefile: tests rely on position of the include Makefile.targets , which is dangerous and not documented)
ifeq ($(PLATFORM),MacOSX)
CUSTOM_TARGETS += nox86exec_helper

nox86exec_helper: INVALID_ARCHS = arm64e arm64
nox86exec_helper: nox86exec_helper.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-posix_spawn_alt_rosetta_helper: nox86exec_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/nox86exec_helper $(INSTALLDIR)/
endif
