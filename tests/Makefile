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
OTHER_CFLAGS += -Wno-c2x-extensions
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

include ktrace/Makefile

INCLUDED_TEST_SOURCE_DIRS += recount
include recount/Makefile
INCLUDED_TEST_SOURCE_DIRS += cpu_counters
include cpu_counters/Makefile

INCLUDED_TEST_SOURCE_DIRS += sched
include sched/Makefile

# Miscellaneous Tests

signal_exit_reason: CODE_SIGN_ENTITLEMENTS = signal_exit_reason.entitlements

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

CUSTOM_TARGETS = sr_entitlement_helper

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

vm/corpse_owned_vmobjects: excserver_protect_state
vm/corpse_owned_vmobjects: OTHER_CFLAGS += $(OBJROOT)/excserver_protect_state.c -I $(OBJROOT)
vm/corpse_owned_vmobjects: CODE_SIGN_ENTITLEMENTS += vm/corpse_owned_vmobjects.entitlements

OTHER_TEST_TARGETS += vm/vm_parameter_validation

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
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

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


CUSTOM_TARGETS += immovable_send_client vm_spawn_tool port_exhaustion_client port_table_limits_client fd_table_limits_client posix_spawnattr_set_crash_behavior_np_child kqworkloop_limits_client
CUSTOM_TARGETS += ipc/hardened_exceptions_entitled_debugger ipc/hardened_exceptions_entitled
CUSTOM_TARGETS += excserver_protect
CUSTOM_TARGETS += excserver_protect_state

exception_tests: excserver_protect exc_helpers.c
exception_tests: CODE_SIGN_ENTITLEMENTS = exception_tests.entitlements
exception_tests: OTHER_CFLAGS += $(OBJROOT)/excserver_protect.c
exception_tests: OTHER_CFLAGS += -I $(OBJROOT)
exception_tests: OTHER_CFLAGS += -DENTITLED=1

ipc/hardened_exceptions: excserver_protect_state exc_helpers.c
ipc/hardened_exceptions: ipc/hardened_exceptions_entitled ipc/hardened_exceptions_entitled_debugger
ipc/hardened_exceptions: OTHER_CFLAGS += $(OBJROOT)/excserver_protect_state.c -I $(OBJROOT)

ipc/hardened_exceptions_entitled: excserver_protect_state
ipc/hardened_exceptions_entitled: CODE_SIGN_ENTITLEMENTS = entitlements/only_one_exception_port.entitlement
ipc/hardened_exceptions_entitled: OTHER_CFLAGS += -I $(OBJROOT)
ipc/hardened_exceptions_entitled: exc_helpers.c ipc/hardened_exceptions.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(OTHER_CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$(filter-out $(CUSTOM_TARGETS), $^) -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --entitlements $(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@

ipc/hardened_exceptions_entitled_debugger: excserver_protect_state
ipc/hardened_exceptions_entitled_debugger: CODE_SIGN_ENTITLEMENTS = entitlements/only_one_exception_port_debugger.entitlement
ipc/hardened_exceptions_entitled_debugger: OTHER_CFLAGS += -I $(OBJROOT)
ipc/hardened_exceptions_entitled_debugger: exc_helpers.c ipc/hardened_exceptions.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(OTHER_CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$(filter-out $(CUSTOM_TARGETS), $^) -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign -  --entitlements $(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@

install-ipc/hardened_exceptions_entitled_debugger: ipc/hardened_exceptions_entitled_debugger
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

install-ipc/hardened_exceptions_entitled: ipc/hardened_exceptions_entitled
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

install-reply_port_defense_client: reply_port_defense_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

immovable_send: excserver
immovable_send: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
immovable_send: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -framework IOKit
immovable_send: immovable_send_client
immovable_send: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

locks: OTHER_LDFLAGS += -ldarwintest_utils

immovable_send_client: immovable_send_client.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) immovable_send_client.c -o $(SYMROOT)/immovable_send_client

install-immovable_send_client: immovable_send_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/immovable_send_client $(INSTALLDIR)/

ipc/sys_perf_notify_test: excserver_protect_state
ipc/sys_perf_notify_test: OTHER_CFLAGS += $(OBJROOT)/excserver_protect_state.c -I $(OBJROOT)
ipc/sys_perf_notify_test: CODE_SIGN_ENTITLEMENTS=entitlements/sys_perf_notify_test.entitlements


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

ipc/task_name_for_pid: CODE_SIGN_ENTITLEMENTS = ipc/task_name_for_pid_entitlement.plist

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

CUSTOM_TARGETS += imm_pinned_control_port_crasher
CUSTOM_TARGETS += imm_pinned_control_port_crasher_3P_hardened

imm_pinned_control_port: excserver_protect
imm_pinned_control_port: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist
imm_pinned_control_port: OTHER_CFLAGS += $(OBJROOT)/excserver_protect.c -I $(OBJROOT)
imm_pinned_control_port: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
imm_pinned_control_port: imm_pinned_control_port_crasher imm_pinned_control_port_crasher_3P_hardened

imm_pinned_control_port_crasher: imm_pinned_control_port_crasher.c cs_helpers.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

imm_pinned_control_port_crasher_3P_hardened: CODE_SIGN_ENTITLEMENTS = entitlements/hardened-binary-entitlements-1.plist
imm_pinned_control_port_crasher_3P_hardened: imm_pinned_control_port_crasher.c cs_helpers.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --entitlements $(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@

install-imm_pinned_control_port_crasher: imm_pinned_control_port_crasher
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$^ $(INSTALLDIR)/

install-imm_pinned_control_port_crasher_3P_hardened: imm_pinned_control_port_crasher_3P_hardened
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$^ $(INSTALLDIR)/

CUSTOM_TARGETS += reply_port_defense_client
CUSTOM_TARGETS += reply_port_defense_client_3P_hardened

reply_port_defense: excserver_protect_state
reply_port_defense: OTHER_CFLAGS += $(OBJROOT)/excserver_protect_state.c -I $(OBJROOT)
reply_port_defense: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
reply_port_defense: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement
reply_port_defense: reply_port_defense_client reply_port_defense_client_3P_hardened

reply_port_defense_client: reply_port_defense_client.c cs_helpers.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@

reply_port_defense_client_3P_hardened: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-binary-entitlements-1.plist
reply_port_defense_client_3P_hardened: reply_port_defense_client.c cs_helpers.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders \
	$^ -o $(SYMROOT)/$@
	$(CODESIGN) --force --sign - --entitlements $(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@

install-reply_port_defense_client: reply_port_defense_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

install-reply_port_defense_client_3P_hardened: reply_port_defense_client_3P_hardened
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/$< $(INSTALLDIR)/

kas_info: OTHER_LDFLAGS += -framework CoreSymbolication
kas_info: CODE_SIGN_ENTITLEMENTS = kernel_symbolication_entitlements.plist

net_bounds_safety: OTHER_CFLAGS += -fbounds-safety

net_no_bounds_safety: OTHER_CFLAGS += -fno-bounds-safety
net_no_bounds_safety: net_bounds_safety.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
OTHER_TEST_TARGETS += net_no_bounds_safety

host_statistics_rate_limiting: cs_helpers.c host_statistics_rate_limiting.c

EXCLUDED_SOURCES += drop_priv.c xnu_quick_test_helpers.c memorystatus_assertion_helpers.c bpflib.c in_cksum.c test_utils.c inet_transfer.c net_test_lib.c cs_helpers.c

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

memorystatus_is_assertion: OTHER_LDFLAGS += -ldarwintest_utils
memorystatus_is_assertion: OTHER_CFLAGS += memorystatus_assertion_helpers.c

memorystatus_vm_map_fork: OTHER_CFLAGS += test_utils.c
memorystatus_vm_map_fork: OTHER_LDFLAGS += -ldarwintest_utils

shared_cache_tests: OTHER_LDFLAGS += -ldarwintest_utils

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

stackshot_accuracy: ./stackshot-entitlements.plist
stackshot_accuracy: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_accuracy: OTHER_CFLAGS += -ldarwintest_utils -Wno-objc-messaging-id
stackshot_accuracy: OTHER_LDFLAGS += -lkdd -ldarwintest_utils -framework Foundation
stackshot_accuracy: INVALID_ARCHS = i386

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

microstackshot_tests: ./stackshot-entitlements.plist
microstackshot_tests: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
microstackshot_tests: OTHER_LDFLAGS = -ldarwintest_utils -framework ktrace -framework kperf -framework CoreFoundation

memorystatus_zone_test: ./stackshot-entitlements.plist
memorystatus_zone_test: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
memorystatus_zone_test: OTHER_CFLAGS += -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
memorystatus_zone_test: OTHER_LDFLAGS += -framework ktrace
memorystatus_zone_test: OTHER_LDFLAGS += -ldarwintest_utils

memcmp_zero: OTHER_CFLAGS += ../osfmk/arm64/memcmp_zero.s

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


ecc_test: OTHER_LDFLAGS += -ldarwintest_utils
CUSTOM_TARGETS += ecc_test_helper

ecc_test_helper:
	$(CC) $(LDFLAGS) $(CFLAGS) ecc_test_helper.c -lm -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-ecc_test_helper: ecc_test_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/ecc_test_helper $(INSTALLDIR)/

vm/test_vm_no_pager: excserver
vm/test_vm_no_pager: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -lkdd -framework Foundation
vm/test_vm_no_pager: OTHER_CFLAGS += -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders $(OBJROOT)/excserver.c -I$(OBJROOT)
vm/test_vm_no_pager: vm/test_vm_no_pager_helper
vm/test_vm_no_pager: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement
CUSTOM_TARGETS += vm/test_vm_no_pager_helper

vm/test_vm_no_pager_helper: vm/test_vm_no_pager_helper.c
	$(CC) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -lm -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-vm/test_vm_no_pager_helper: vm/test_vm_no_pager_helper
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/test_vm_no_pager_helper $(INSTALLDIR)/vm/


kevent_qos: OTHER_CFLAGS += -Wno-unused-macros
kevent_qos: OTHER_CFLAGS += -I $(OBJROOT)/

test_knote_use_after_free: OTHER_CFLAGS += -Wno-unused-macros
test_knote_use_after_free: OTHER_LDFLAGS += -ldarwintest_utils -lpthread

mach_get_times: OTHER_LDFLAGS += -ldarwintest_utils

monotonic_core: ./stackshot-entitlements.plist
monotonic_core: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
monotonic_core: OTHER_LDFLAGS += -framework ktrace

perf_exit: perf_exit_proc
perf_exit: ./stackshot-entitlements.plist
perf_exit: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
perf_exit: OTHER_LDFLAGS = -framework ktrace -ldarwintest_utils
perf_exit: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist

ipc/mach_exc_port_substitute: excserver
ipc/mach_exc_port_substitute: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
ipc/mach_exc_port_substitute: CODE_SIGN_ENTITLEMENTS = ipc/mach_exc_port_substitute.plist

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

os_thread_self_restrict: os_thread_self_restrict.c os_thread_self_restrict-entitlements.plist
os_thread_self_restrict: CODE_SIGN_ENTITLEMENTS=os_thread_self_restrict-entitlements.plist
os_thread_self_restrict: OTHER_LDFLAGS += -sectcreate __TEXT __info_plist os_thread_self_restrict-identifier.plist

# Temporarily disabled.  See rdar://121952316
EXCLUDED_SOURCES += os_thread_self_restrict.c

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


stackshot_idle_25570396: ./stackshot-entitlements.plist
stackshot_idle_25570396: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_idle_25570396: OTHER_LDFLAGS += -lkdd -framework Foundation
stackshot_idle_25570396: OTHER_LDFLAGS += -lkdd -framework Foundation

stackshot_block_owner_14362384: ./stackshot-entitlements.plist
stackshot_block_owner_14362384: CODE_SIGN_ENTITLEMENTS=./stackshot-entitlements.plist
stackshot_block_owner_14362384: OTHER_LDFLAGS += -framework Foundation -lpthread -lkdd
ifeq ($(PLATFORM),MacOSX)
stackshot_block_owner_14362384: OTHER_LDFLAGS += -lpcre
endif

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

INCLUDED_TEST_SOURCE_DIRS += ipc rm workq

include vm/Makefile

big_map_test: CODE_SIGN_ENTITLEMENTS = ./big_map_test_entitlement.plist

task_info_28439149: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist

ipc/ipc_read_inspect: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist

ipc/ipc_thread_ports_race: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
ipc/ipc_thread_ports_race: OTHER_LDFLAGS += -ldarwintest_utils

rm/pthread_setugid: OTHER_LDFLAGS += -ldarwintest_utils

proc_info: recount/recount_test_utils.c
proc_info: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
proc_info: OTHER_LDFLAGS += -ldarwintest_utils

proc_info_list_kthreads: CODE_SIGN_ENTITLEMENTS = ./proc_info_list_kthreads.entitlements

proc_info_44873309: CODE_SIGN_ENTITLEMENTS = ./proc_info_44873309.entitlements

disk_mount_conditioner: disk_mount_conditioner*
disk_mount_conditioner: CODE_SIGN_ENTITLEMENTS=./disk_mount_conditioner-entitlements.plist
disk_mount_conditioner: OTHER_LDFLAGS += -ldarwintest_utils

disk_mount_conditioner: OTHER_TEST_TARGETS += disk_mount_conditioner_unentitled
disk_mount_conditioner_unentitled: OTHER_CFLAGS += -DTEST_UNENTITLED
disk_mount_conditioner_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
disk_mount_conditioner_unentitled: disk_mount_conditioner.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

work_interval_test: CODE_SIGN_ENTITLEMENTS = work_interval_test.entitlements
work_interval_test: OTHER_CFLAGS += -DENTITLED=1

work_interval_data_test: CODE_SIGN_ENTITLEMENTS = work_interval_test.entitlements
work_interval_data_test: OTHER_CFLAGS += -DENTITLED=1
work_interval_data_test: OTHER_LDFLAGS += -lpthread

game_mode: CODE_SIGN_ENTITLEMENTS = game_mode.entitlements
carplay_mode: CODE_SIGN_ENTITLEMENTS = carplay_mode.entitlements

coalition_policy: CODE_SIGN_ENTITLEMENTS = coalition_policy.entitlements

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
socket_bind_35243417: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist
socket_bind_35685803: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist
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

ipv6_bind_race: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

so_bindtodevice: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

v4mappedv6_dontfrag: net_test_lib.c in_cksum.c
v4mappedv6_dontfrag: OTHER_LDFLAGS += -ldarwintest_utils
v4mappedv6_dontfrag: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

network_elevated_logging: CODE_SIGN_ENTITLEMENTS = entitlements/network_elevated_logging.entitlements

CUSTOM_TARGETS += posix_spawn_archpref_helper

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

excserver:
	$(MIG) $(CFLAGS) \
		-sheader $(OBJROOT)/excserver.h \
		-server $(OBJROOT)/excserver.c \
		-header /dev/null -user /dev/null \
		excserver.defs
install-excserver: ;

excserver_protect:
	$(MIG) $(CFLAGS) \
		-DMACH_EXC_SERVER_TASKIDTOKEN \
		-sheader $(OBJROOT)/excserver_protect.h \
		-server $(OBJROOT)/excserver_protect.c \
		-header /dev/null -user /dev/null \
		excserver_protect.defs
install-excserver_protect: ;

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


x18_entitled: OTHER_CFLAGS += -Wno-language-extension-token
x18_entitled: CODE_SIGN_ENTITLEMENTS = x18-entitlements.plist
x18_unentitled: OTHER_CFLAGS += -Wno-language-extension-token
ifneq ($(PLATFORM),MacOSX)
EXCLUDED_SOURCES += x18_legacy.c
else
x18_legacy: OTHER_CFLAGS += -Wno-language-extension-token -Wl,-platform_version -Wl,macos -Wl,10.12 -Wl,10.12
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

pmap_bench: INVALID_ARCHS = $(filter-out arm%,$(ARCH_CONFIGS))

pmap_stress: INVALID_ARCHS = $(filter-out arm%,$(ARCH_CONFIGS))

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

decompression_failure: excserver exc_helpers.c
decompression_failure: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
decompression_failure: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

ipc/kernel_signed_pac_thread_state: excserver
ipc/kernel_signed_pac_thread_state: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
ipc/kernel_signed_pac_thread_state: CODE_SIGN_ENTITLEMENTS = pac_exception_entitlement.plist

ifeq ($(findstring arm64e,$(ARCH_CONFIGS)),)
EXCLUDED_SOURCES += pac_exception_entitlement.c
else
pac_exception_entitlement: excserver exc_helpers.c
pac_exception_entitlement: OTHER_CFLAGS += $(OBJROOT)/excserver.c -Wno-language-extension-token
pac_exception_entitlement: CODE_SIGN_ENTITLEMENTS = pac_exception_entitlement.plist
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

perf_vmfault: OTHER_CFLAGS += benchmark/helpers.c

vm/fault_throughput: OTHER_CFLAGS += benchmark/helpers.c

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

install-mixed_pagesize: mixed_pagesize
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/mixed_pagesize $(INSTALLDIR)/vm/

BATS_PLISTS += $(SRCROOT)/vm/mixed_pagesize.plist

EXCLUDED_SOURCES += vm/mixed_pagesize.c vm/mixed_pagesize.plist
CUSTOM_TARGETS += mixed_pagesize
else
EXCLUDED_SOURCES += vm/mixed_pagesize.c vm/mixed_pagesize.plist
endif

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
EXCLUDED_SOURCES += ipsec.m
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
libmalloc_apple_array: libmalloc_apple_array.c print_apple_array print_apple_array_HR1 print_apple_array_HR2 print_apple_array_hardened_proc print_apple_array_hardened_heap_disable print_apple_array_hardened_heap
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

libmalloc_apple_array_unentitled: OTHER_CFLAGS += drop_priv.c test_utils.c
libmalloc_apple_array_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
libmalloc_apple_array_unentitled: libmalloc_apple_array.c print_apple_array print_apple_array_HR1 print_apple_array_HR2 print_apple_array_hardened_proc print_apple_array_hardened_heap_disable print_apple_array_hardened_heap
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $(OTHER_CFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array
print_apple_array: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_HR1
print_apple_array_HR1: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-binary-entitlements-1.plist
print_apple_array_HR1: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_HR2
print_apple_array_HR2: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-binary-entitlements-2.plist
print_apple_array_HR2: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_hardened_proc
print_apple_array_hardened_proc: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc.entitlements
print_apple_array_hardened_proc: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_hardened_heap_disable
print_apple_array_hardened_heap_disable: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-proc-hardened-heap-override.entitlements
print_apple_array_hardened_heap_disable: print_apple_array.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) --timestamp=none $(SYMROOT)/$@;

CUSTOM_TARGETS += print_apple_array_hardened_heap
print_apple_array_hardened_heap: CODE_SIGN_ENTITLEMENTS=entitlements/hardened-heap-standalone.entitlements
print_apple_array_hardened_heap: print_apple_array.c
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

install-print_apple_array_hardened_heap_disable: print_apple_array_hardened_heap_disable
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_hardened_heap_disable $(INSTALLDIR)/tools/

install-print_apple_array_hardened_heap: print_apple_array_hardened_heap
	mkdir -p $(INSTALLDIR)/tools
	cp $(SYMROOT)/print_apple_array_hardened_heap $(INSTALLDIR)/tools/


persona: CODE_SIGN_ENTITLEMENTS = persona.entitlements
persona_adoption: CODE_SIGN_ENTITLEMENTS = persona_adoption.entitlements

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

INCLUDED_TEST_SOURCE_DIRS += vfs
vfs/freeable_vnodes: OTHER_LDFLAGS += -ldarwintest_utils

vm/vm_reclaim: OTHER_CFLAGS += -Wno-language-extension-token -Wno-c++98-compat memorystatus_assertion_helpers.c
vm/vm_reclaim: OTHER_LDFLAGS += -ldarwintest_utils

vm/vm_reclaim: INVALID_ARCHS = armv7k arm64_32

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
constrained_ctypes_tests_enacted: OTHER_CFLAGS += -fbounds-safety
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

# os_atomic use throws this warning
setitimer: OTHER_CFLAGS += -Wno-c++98-compat -framework perfdata
setitimer: OTHER_LDFLAGS += -framework perfdata


include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets

exception_ports_info: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

vfs/longpaths: vfs/longpaths.c
vfs/longpaths: OTHER_LDFLAGS += -ldarwintest_utils
vfs/longpaths: CODE_SIGN_ENTITLEMENTS = vfs/longpaths.entitlements

memorystatus_experiment_factors: CODESIGN_ENTITLEMENTS=./memorystatus/memorystatus_experiment_factors.entitlements
memorystatus_experiment_factors: memorystatus/memorystatus_experiment_factors.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	$(ENV) CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODESIGN_ENTITLEMENTS) $(SYMROOT)/$@;

