INCLUDED_TEST_SOURCE_DIRS += ipc

# Shared IPC utils exposed via ipc_utils.c
IPC_UTILS = ipc/ipc_utils.c
EXCLUDED_SOURCES += $(IPC_UTILS)

# Rules that apply to all IPC tests
ipc/%: OTHER_CFLAGS += -Wno-format-pedantic $(WERROR)

# Individual test rules (roughly alphabetically)

ipc/connection_port_move_send: $(IPC_UTILS)

ipc/enhanced_v1_entitlement: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/enhanced-v1.plist

ipc/enhanced_v2_entitlement: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/enhanced-v2.plist

ipc/enhanced_v3_entitlement: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/enhanced-v3.plist

EXCLUDED_SOURCES += ipc/control_port_movability_common.c
ipc/entitled_control_port_movability: ipc/control_port_movability_common.c $(IPC_UTILS)
ipc/entitled_control_port_movability: OTHER_LDFLAGS += -ldarwintest
ipc/entitled_control_port_movability: CODE_SIGN_ENTITLEMENTS = entitlements/entitled_control_port_movability.entitlements

ipc/exception_port_registration_policies: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/enhanced-v3.plist

ipc/exception_tests: excserver_protect exc_helpers.c
ipc/exception_tests: $(OBJROOT)/excserver_protect.c
ipc/exception_tests: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/exception_tests.entitlements

ipc/guard_objects_disabled_entitlement: CODE_SIGN_ENTITLEMENTS = entitlements/guard-objects-disabled.plist
ipc/guard_objects_enabled_entitlement: CODE_SIGN_ENTITLEMENTS = entitlements/hardened-proc.entitlements

ipc/hardened_process_version_entitlement: CODE_SIGN_ENTITLEMENTS = entitlements/hardened-proc-version.entitlements

ipc/hardened_runtime_ipc_policy_test: CODESIGN = $(CODESIGN_HARDENED_RUNTIME)

ipc/ipc_read_inspect: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist

ipc/ipc_thread_ports_race: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
ipc/ipc_thread_ports_race: OTHER_LDFLAGS += -ldarwintest_utils

ipc/kernel_signed_pac_thread_state: excserver $(OBJROOT)/excserver.c
ipc/kernel_signed_pac_thread_state: CODE_SIGN_ENTITLEMENTS = pac_exception_entitlement.plist

ipc/mach_exc_port_substitute: excserver $(OBJROOT)/excserver.c
ipc/mach_exc_port_substitute: CODE_SIGN_ENTITLEMENTS = ipc/mach_exc_port_substitute.plist

ipc/mach_exc_interprocess_thread_state: excserver_protect_state
ipc/mach_exc_interprocess_thread_state: exc_helpers.c $(OBJROOT)/excserver_protect_state.c
ipc/mach_exc_interprocess_thread_state: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/mach_exc_interprocess_thread_state_entitlement.plist

ipc/mach_msg_transport: CODE_SIGN_ENTITLEMENTS = entitlements/create_conn_port_with_port_array.entitlements

ipc/mach_port_construct_errors: ipc/ipc_utils.c

ipc/mach_port_description: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist

ipc/port_type_policy: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/port_type_policy.entitlements
ipc/port_type_policy: $(IPC_UTILS)

# platform_restrictions_compat

EXCLUDED_SOURCES += ipc/platform_restrictions_client.c

ipc/platform_restrictions_compat: \
	ipc/platform-restrictions-int-0 \
	ipc/platform-restrictions-int-1 \
	ipc/platform-restrictions-int-2 \
	ipc/platform-restrictions-int-255 \
	ipc/platform-restrictions-int-with-string-value \
	ipc/platform-restrictions-int-with-bool-true-value \
	ipc/platform-restrictions-int-with-bool-false-value \
	ipc/platform-restrictions-str-empty \
	ipc/platform-restrictions-str-invalid \
	ipc/platform-restrictions-str-0 \
	ipc/platform-restrictions-str-1 \
	ipc/platform-restrictions-str-2 \
	ipc/platform-restrictions-str-7 \
	ipc/platform-restrictions-str-8 \
	ipc/platform-restrictions-str-with-int-value \
	ipc/platform-restrictions-str-with-bool-true-value \
	ipc/platform-restrictions-str-with-bool-false-value \
	ipc/platform-restrictions-str-with-trailing-bad-data \
	ipc/platform-restrictions-mixed

CUSTOM_TARGETS += ipc/platform-restrictions-int-0
ipc/platform-restrictions-int-0: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-0.plist
ipc/platform-restrictions-int-0: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-int-1
ipc/platform-restrictions-int-1: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-1.plist
ipc/platform-restrictions-int-1: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-int-2
ipc/platform-restrictions-int-2: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-2.plist
ipc/platform-restrictions-int-2: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-int-255
ipc/platform-restrictions-int-255: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-255.plist
ipc/platform-restrictions-int-255: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-int-with-string-value
ipc/platform-restrictions-int-with-string-value: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-with-string-value.plist
ipc/platform-restrictions-int-with-string-value: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-int-with-bool-true-value
ipc/platform-restrictions-int-with-bool-true-value: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-with-bool-true-value.plist
ipc/platform-restrictions-int-with-bool-true-value: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-int-with-bool-false-value
ipc/platform-restrictions-int-with-bool-false-value: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-int-with-bool-false-value.plist
ipc/platform-restrictions-int-with-bool-false-value: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-empty
ipc/platform-restrictions-str-empty: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-empty.plist
ipc/platform-restrictions-str-empty: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-invalid
ipc/platform-restrictions-str-invalid: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-invalid.plist
ipc/platform-restrictions-str-invalid: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-0
ipc/platform-restrictions-str-0: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-0.plist
ipc/platform-restrictions-str-0: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-1
ipc/platform-restrictions-str-1: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-1.plist
ipc/platform-restrictions-str-1: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-2
ipc/platform-restrictions-str-2: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-2.plist
ipc/platform-restrictions-str-2: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-7
ipc/platform-restrictions-str-7: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-7.plist
ipc/platform-restrictions-str-7: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-8
ipc/platform-restrictions-str-8: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-8.plist
ipc/platform-restrictions-str-8: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-with-int-value
ipc/platform-restrictions-str-with-int-value: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-with-int-value.plist
ipc/platform-restrictions-str-with-int-value: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-with-bool-true-value
ipc/platform-restrictions-str-with-bool-true-value: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-with-bool-true-value.plist
ipc/platform-restrictions-str-with-bool-true-value: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-with-bool-false-value
ipc/platform-restrictions-str-with-bool-false-value: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-with-bool-false-value.plist
ipc/platform-restrictions-str-with-bool-false-value: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-str-with-trailing-bad-data
ipc/platform-restrictions-str-with-trailing-bad-data: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-str-with-trailing-bad-data.plist
ipc/platform-restrictions-str-with-trailing-bad-data: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/platform-restrictions-mixed
ipc/platform-restrictions-mixed: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/platform-restrictions/platform-restrictions-mixed.plist
ipc/platform-restrictions-mixed: ipc/platform_restrictions_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

ifeq ($(PLATFORM),MacOSX)
ipc/rosetta_control_port_movability: INVALID_ARCHS = arm64 arm64e arm
ipc/rosetta_control_port_movability: ipc/control_port_movability_common.c $(IPC_UTILS)
else
EXCLUDED_SOURCES += ipc/rosetta_control_port_movability.c
endif

ipc/script_restrictions_entitlements: CODE_SIGN_ENTITLEMENTS = entitlements/script-restrictions-security.plist

ipc/sys_perf_notify_test: excserver_protect_state $(OBJROOT)/excserver_protect_state.c
ipc/sys_perf_notify_test: CODE_SIGN_ENTITLEMENTS=entitlements/sys_perf_notify_test.entitlements
ipc/sys_perf_notify_test: OTHER_LDFLAGS += -I $(OBJROOT)

ipc/task_name_for_pid: CODE_SIGN_ENTITLEMENTS = ipc/task_name_for_pid_entitlement.plist

ipc/task_suspension:   CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist

ipc/thread_suspension: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist

ipc/tpro_entitlements: CODE_SIGN_ENTITLEMENTS = ipc/entitlements/tpro.plist

# imm_pinned

ipc/imm_pinned_control_port: excserver_protect
ipc/imm_pinned_control_port: ipc/imm_pinned_control_port_crasher ipc/imm_pinned_control_port_crasher_3P_hardened
ipc/imm_pinned_control_port: $(OBJROOT)/excserver_protect.c
ipc/imm_pinned_control_port: CODE_SIGN_ENTITLEMENTS = entitlements/imm_pinned_control_port.entitlements
ipc/imm_pinned_control_port: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -I $(OBJROOT)

## Allow this test to pull {TASK, THREAD}_KERNEL_PORT via get-movable-control-port
ipc/imm_pinned_control_port_entitled: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist
ipc/imm_pinned_control_port_entitled: OTHER_LDFLAGS += -ldarwintest_utils -lpthread

CUSTOM_TARGETS += ipc/imm_pinned_control_port_crasher
ipc/imm_pinned_control_port_crasher: OTHER_LDFLAGS += -ldarwintest_utils
ipc/imm_pinned_control_port_crasher: ipc/imm_pinned_control_port_crasher.c cs_helpers.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/imm_pinned_control_port_crasher_3P_hardened
ipc/imm_pinned_control_port_crasher_3P_hardened: CODE_SIGN_ENTITLEMENTS = entitlements/enhanced-security-binary-entitlements-1.plist
ipc/imm_pinned_control_port_crasher_3P_hardened: OTHER_LDFLAGS += -ldarwintest_utils
ipc/imm_pinned_control_port_crasher_3P_hardened: ipc/imm_pinned_control_port_crasher.c cs_helpers.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)


# Hardened Exceptions

ipc/hardened_exceptions: excserver_protect_state exc_helpers.c $(IPC_UTILS)
ipc/hardened_exceptions: $(OBJROOT)/excserver_protect_state.c

OTHER_TEST_TARGETS += ipc/hardened_exceptions_entitled
ipc/hardened_exceptions_entitled: OTHER_CFLAGS += -DENTITLED
ipc/hardened_exceptions_entitled: CODE_SIGN_ENTITLEMENTS = entitlements/only_one_exception_port.entitlement
ipc/hardened_exceptions_entitled: excserver_protect_state
ipc/hardened_exceptions_entitled: exc_helpers.c ipc/hardened_exceptions.c $(IPC_UTILS) $(OBJROOT)/excserver_protect_state.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

OTHER_TEST_TARGETS += ipc/hardened_exceptions_entitled_debugger
ipc/hardened_exceptions_entitled_debugger: OTHER_CFLAGS += -DENTITLED_DEBUGGER
ipc/hardened_exceptions_entitled_debugger: CODE_SIGN_ENTITLEMENTS = entitlements/only_one_exception_port_debugger.entitlement
ipc/hardened_exceptions_entitled_debugger: excserver_protect_state
ipc/hardened_exceptions_entitled_debugger: exc_helpers.c ipc/hardened_exceptions.c $(IPC_UTILS) $(OBJROOT)/excserver_protect_state.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)


# Reply Port Defense

ipc/reply_port_defense: excserver_protect_state
ipc/reply_port_defense: $(OBJROOT)/excserver_protect_state.c $(IPC_UTILS)
ipc/reply_port_defense: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -I $(OBJROOT)
ipc/reply_port_defense: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement
ipc/reply_port_defense: ipc/reply_port_defense_client ipc/reply_port_defense_client_3P_hardened

CUSTOM_TARGETS += ipc/reply_port_defense_client
ipc/reply_port_defense_client: CODE_SIGN_ENTITLEMENTS=ipc/entitlements/exception_tests.entitlements
ipc/reply_port_defense_client: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
ipc/reply_port_defense_client: ipc/reply_port_defense_client.c cs_helpers.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

CUSTOM_TARGETS += ipc/reply_port_defense_client_3P_hardened
ipc/reply_port_defense_client_3P_hardened: CODE_SIGN_ENTITLEMENTS=entitlements/enhanced-security-binary-entitlements-1.plist
ipc/reply_port_defense_client_3P_hardened: ipc/reply_port_defense_client.c cs_helpers.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

# immovable send

ipc/immovable_send: excserver $(OBJROOT)/excserver.c
ipc/immovable_send: OTHER_CFLAGS +=  -I $(OBJROOT)
ipc/immovable_send: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -framework IOKit
ipc/immovable_send: ipc/immovable_send_client
ipc/immovable_send: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement

CUSTOM_TARGETS += ipc/immovable_send_client
ipc/immovable_send_client: ipc/immovable_send_client.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)

## IPC Makefile Utils that you probably don't need to touch

# Reusable Darwin test compilation functions
define DARWIN_MKDIR
	$(shell [ -d "$(SYMROOT)/$(dir $(1))" ] || mkdir -p $(SYMROOT)/$(dir $(1)))
endef

define DARWIN_COMPILE
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $(foreach f,$(filter %.c %.m %.cpp %.mm %.a,$(1)),$(abspath $(f))) -o $(SYMROOT)/$(2)
endef

define DARWIN_CODESIGN
	@if [ -f "$(CODE_SIGN_ENTITLEMENTS)" ]; then \
		echo $(CODESIGN) --force --sign - --timestamp=none --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$(1); \
		env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements "$(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS)" $(SYMROOT)/$(1); \
	else \
		echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$(1); \
		env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$(1); \
	fi
endef

# Complete compilation function for easy use
# Usage: $(call DARWIN_COMPILE_C_TEST,sources,target)
define DARWIN_COMPILE_C_TEST
	$(call DARWIN_MKDIR,$(2))
	$(call DARWIN_COMPILE,$(1),$(2))
	$(call DARWIN_CODESIGN,$(2))
endef

# Collect all IPC targets (both auto-discovered and custom)
IPC_WILDCARD_RESULT := $(wildcard ipc/*.c)
IPC_FILTERED_RESULT := $(filter-out $(EXCLUDED_SOURCES),$(IPC_WILDCARD_RESULT))
IPC_SOURCES_c := $(patsubst %.c,%,$(IPC_FILTERED_RESULT))
IPC_AUTO_TARGETS := $(filter-out $(OTHER_TEST_TARGETS) $(CUSTOM_TARGETS),$(IPC_SOURCES_c))
IPC_CUSTOM_TARGETS := $(filter ipc/%,$(CUSTOM_TARGETS))
IPC_OTHER_TARGETS := $(filter ipc/%,$(OTHER_TEST_TARGETS))
ALL_IPC_TARGETS := $(IPC_AUTO_TARGETS) $(IPC_CUSTOM_TARGETS) $(IPC_OTHER_TARGETS)

# Install rule for all IPC targets to create directories before use
install-ipc/%: | $(INSTALLDIR)/ipc
	cp $(SYMROOT)/ipc/$* $(INSTALLDIR)/ipc/

# Add directory dependencies to all IPC targets
# this ensures there are no races against wrongly constructed make targets
$(ALL_IPC_TARGETS): | $(OBJROOT)/ipc $(SYMROOT)/ipc

$(OBJROOT)/ipc:
	mkdir -p $(OBJROOT)/ipc
$(SYMROOT)/ipc:
	mkdir -p $(SYMROOT)/ipc
$(INSTALLDIR)/ipc:
	mkdir -p $(INSTALLDIR)/ipc

# Build target for compiling all ipc/ tests
all_ipc: $(IPC_AUTO_TARGETS)
