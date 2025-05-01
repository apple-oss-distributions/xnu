export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = machine
INSTINC_SUBDIRS_X86_64 = i386
INSTINC_SUBDIRS_X86_64H = i386
INSTINC_SUBDIRS_ARM64 = arm arm64

EXPINC_SUBDIRS = machine
EXPINC_SUBDIRS_X86_64 = i386
EXPINC_SUBDIRS_X86_64H = i386
EXPINC_SUBDIRS_ARM64 = arm arm64

MIG_TYPES = \
	clock_types.defs \
	mach_types.defs \
	std_types.defs

MIG_DEFS =	\
	audit_triggers.defs \
	clock.defs \
	clock_priv.defs \
	clock_reply.defs \
	doubleagent_mig.defs \
	exc.defs \
	host_notify_reply.defs \
	host_priv.defs \
	host_security.defs \
	mach_exc.defs \
	mach_host.defs \
	mach_port.defs \
	mach_vm.defs \
	mach_voucher.defs \
	mach_voucher_attr_control.defs \
	memory_entry.defs \
	memory_error_notification.defs \
	notify.defs \
	processor.defs \
	processor_set.defs \
	task.defs \
	task_access.defs \
	telemetry_notification.defs \
	thread_act.defs \
	vm_map.defs

MIG_PRIVATE_DEFS = \
	mach_eventlink.defs \
	restartable.defs \
	sysdiagnose_notification.defs

MACH_PRIVATE_DEFS = \
	coalition_notification.defs \
	fairplayd_notification.defs \
	arcade_upcall.defs \
	ktrace_background.defs \
	mach_notify.defs \
	mach_test_upcall.defs \
	memory_error_notification.defs \
	upl.defs \
	vfs_nspace.defs \
	vm32_map.defs \
	iocompressionstats_notification.defs

#
# MIG-generated headers that are traditionally used by user
# level code.
#
MIG_USHDRS = \
	audit_triggers_server.h \
	clock_reply_server.h \
	coalition_notification_server.h \
	doubleagent_mig_server.h \
	exc_server.h \
	fairplayd_notification_server.h \
	arcade_upcall_server.h \
	memory_error_notification_server.h \
	mach_exc_server.h \
	notify_server.h \
	task_access_server.h \
	telemetry_notification_server.h \
	sysdiagnose_notification_server.h \
	iocompressionstats_notification_server.h \
	vfs_nspace_server.h

MIG_UUHDRS = \
	clock.h \
	clock_priv.h \
	host_priv.h \
	host_security.h \
	ktrace_background.h \
	mach_host.h \
	mach_port.h \
	mach_vm.h \
	mach_voucher.h \
	mach_voucher_attr_control.h \
	memory_entry.h \
	processor.h \
	processor_set.h \
	task.h \
	task_access.h \
	thread_act.h \
	upl.h \
	vm_map.h \
	vfs_nspace.h

MIGINCLUDES = ${MIG_UUHDRS} ${MIG_USHDRS}

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	shared_region.h \
	dyld_pager.h \
	${MIG_TYPES} \
	${MIG_DEFS}

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
# Temporarily install some private defs in both usr/include and usr/local/include.
# They belong in usr/local/include, but installing them in both locations will allow
# clients that compile them by full path to switch without lock-step submissions.
EXTRA_DATAFILES = mach_exc.defs memory_error_notification.defs notify.defs \
	telemetry_notification.defs
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	audit_triggers_types.h \
        boolean.h \
        clock_types.h \
        doubleagent_types.h \
        dyld_kernel.h \
        error.h \
	exception.h \
	exception_types.h \
	host_notify.h \
        host_info.h \
	host_reboot.h \
	host_special_ports.h \
	kern_return.h \
        kmod.h \
        mach_param.h \
	mach_time.h \
	mach_traps.h \
        mach_types.h \
	mach_voucher_types.h \
	machine.h \
        mach_syscalls.h \
        memory_object_types.h \
        message.h \
	mig.h \
	mig_errors.h \
	mig_voucher_support.h \
	mig_strncpy_zerofill_support.h \
	ndr.h \
        notify.h \
	policy.h \
	port.h \
        processor_info.h \
	rpc.h \
	sdt.h \
        semaphore.h \
	shared_memory_server.h \
	std_types.h \
	sync_policy.h \
        syscall_sw.h \
	task_info.h \
	task_inspect.h \
	task_policy.h \
	task_special_ports.h \
        thread_info.h \
	thread_policy.h \
	thread_special_ports.h \
        thread_status.h \
	thread_switch.h \
	time_value.h \
        vm_attributes.h \
        vm_behavior.h \
	vm_inherit.h \
	vm_param.h \
        vm_prot.h \
	vm_purgable.h \
        vm_region.h \
	vm_statistics.h \
	vm_sync.h \
	vm_types.h \
	${EXTRA_DATAFILES})

KERNELFILES = \
	mach_interface.h \
	vm_types_unsafe.h

INSTALL_MI_LIST	= \
	bootstrap.h \
	${DATAFILES}

EXCLAVES_DATAFILES = \
	exclaves.h \
	exclaves_l4.h

# installed into System.framework's PrivateHeaders/mach subdirectory
PRIVATE_DATAFILES = $(sort \
	bootstrap.h \
	coalition.h \
	coalition_notification.defs \
	doubleagent_mig.defs \
	doubleagent_types.h \
	fairplayd_notification.defs \
	iocompressionstats_notification.defs \
	arcade_register.defs \
	arcade_upcall.defs \
	host_info.h \
	ktrace_background.defs \
	mach_eventlink_types.h \
	mach_host.defs \
	mach_time_private.h \
	mach_traps.h \
	memory_error_notification.defs \
	memory_object_types.h \
	mig.h \
	mk_timer.h \
	processor_info.h \
	resource_notify.defs \
	resource_monitors.h \
	semaphore.h \
	sfi_class.h \
	syscall_sw.h \
	sysdiagnose_notification.defs \
	task_info.h \
	task_inspect.h \
	task_policy.h \
	task_policy_private.h \
	thread_policy.h \
	thread_policy_private.h \
	thread_switch.h \
	vfs_nspace.defs \
	vm_prot.h \
	vm_reclaim.h \
	vm_reclaim_private.h \
	${EXCLAVES_DATAFILES} \
	${EXTRA_PRIVATE_DATAFILES} \
	${MIG_PRIVATE_DEFS})

INSTALL_MI_LCL_LIST = $(sort \
	coalition.h \
	mach_time_private.h \
	mk_timer.h \
	resource_monitors.h \
	task_policy_private.h \
	thread_policy_private.h \
	vm_reclaim.h \
	vm_reclaim_private.h \
	${EXCLAVES_DATAFILES} \
	${EXTRA_PRIVATE_DATAFILES})

INSTALL_SF_MI_LCL_LIST = ${INSTALL_MI_LIST} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = $(sort \
	$(filter-out mach_traps.h mach_syscalls.h thread_switch.h, ${DATAFILES} ${KERNELFILES} ${EXTRA_PRIVATE_DATAFILES}))

INSTALL_KF_MI_LCL_LIST = $(sort \
	coalition.h \
	mach_time_private.h \
	task_policy_private.h \
	thread_policy_private.h \
	${EXCLAVES_DATAFILES} \
	$(filter-out mach_traps.h mach_syscalls.h thread_switch.h, ${DATAFILES} ${KERNELFILES} ${EXTRA_PRIVATE_DATAFILES}))

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = mach

EXPORT_MI_LIST	= $(sort \
	coalition.h \
	mach_time_private.h \
	memory_object_control.h \
	resource_monitors.h \
	task_policy_private.h \
	thread_policy_private.h \
	mach_eventlink_types.h \
	sfi_class.h \
	${EXCLAVES_DATAFILES} \
	${DATAFILES} \
	${KERNELFILES} \
	${EXTRA_PRIVATE_DATAFILES})

EXPORT_MI_GEN_LIST = \
	${MIGINCLUDES}

EXPORT_MI_DIR = mach

${MIGINCLUDES} : ${MIG_TYPES}

${MIG_UUHDRS} : \
	%.h : %.defs
	@$(LOG_MIG) $@
	$(_v)$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header $@		\
		$<

${MIG_USHDRS} : \
	%_server.h : %.defs
	@$(LOG_MIG) $@
	$(_v)$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header /dev/null	\
		-sheader $@		\
		$<

#
# Build path
#

INCFLAGS_MAKEFILE= -I..

#
# MIG-generated headers that are traditionally used by kernel
# level code.
#

# sender-side ("user") headers generated by MIG from corresponding .defs
MIG_KUHDRS = \
	audit_triggers.h \
	clock_reply.h \
	doubleagent_mig.h \
	exc.h \
	host_notify_reply.h \
	ktrace_background.h \
	mach_exc.h \
	mach_notify.h \
	mach_test_upcall.h \
	resource_notify.h \
	task_access.h \
	upl.h \
	vm_map.h

# sender-side ("user") source files generated by MIG from corresponding .defs
MIG_KUSRC = \
	audit_triggers_user.c \
	clock_reply_user.c \
	coalition_notification_user.c \
	doubleagent_mig_user.c \
	exc_user.c \
	fairplayd_notification_user.c \
	arcade_upcall_user.c \
	host_notify_reply_user.c \
	ktrace_background_user.c \
	memory_error_notification_user.c \
	mach_exc_user.c \
	mach_notify_user.c \
	mach_test_upcall_user.c \
	resource_notify_user.c \
	task_access_user.c \
	telemetry_notification_user.c \
	iocompressionstats_notification_user.c \
	upl_user.c \
	vfs_nspace_user.c \
	vm_map_user.c \
	sysdiagnose_notification_user.c

MIG_KSHDRS = \
	arcade_register_server.h \
	clock_server.h \
	mach_eventlink_server.h \
	exc_server.h \
	host_priv_server.h \
	host_security_server.h \
	mach_exc_server.h \
	mach_host_server.h \
	mach_notify_server.h \
	mach_port_server.h \
	mach_vm_server.h \
	mach_voucher_server.h \
	memory_entry_server.h \
	processor_server.h \
	processor_set_server.h \
	restartable_server.h \
	task_server.h \
	thread_act_server.h \
	upl_server.h \
	vm_map_server.h \
	vm32_map_server.h

MIG_KSSRC = \
	arcade_register_server.c \
	clock_server.c \
	exc_server.c \
	host_priv_server.c \
	mach_eventlink_server.c \
	mach_exc_server.c \
	mach_host_server.c \
	mach_notify_server.c \
	mach_port_server.c \
	mach_vm_server.c \
	mach_voucher_server.c \
	memory_entry_server.c \
	processor_server.c \
	processor_set_server.c \
	restartable_server.c \
	task_server.c \
	thread_act_server.c \
	upl_server.c \
	vm_map_server.c \
	vm32_map_server.c

#
# JMM -
# Since there are two generated header files with the same name, one for
# install and export, the other for internal use (and they are different)
# we can't explicitly list two rules for the same target.  So rules for
# generating internal headers will be handled implicitly by creating rules
# to generate the internal C sources, and the headers get created as a
# side-effect.
#
#
# This is all temporary scaffolding, as we are moving to a model where
# the MIG-generated code is identical in all environments.  At first, it
# will contain some environment-specific ifdefs, but over time should not
# even require that as we move towards making all the environments look
# the same.
#
COMP_FILES = ${MIG_KUSRC} ${MIG_KSSRC}

do_build_all:: $(COMP_FILES) checked

${COMP_FILES} : ${MIG_TYPES}

${MIG_KUSRC} : \
	%_user.c : %.defs
	@$(LOG_MIG) $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}        \
		-user    $*_user.c              \
		-header  $*.h              \
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

${MIG_KSSRC}: \
	%_server.c : %.defs
	@$(LOG_MIG) $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}        \
		-user    /dev/null              \
		-header  /dev/null              \
		-server  $*_server.c		\
		-sheader $*_server.h		\
		$<

# Empty target for making sure the build doesn't succeed unless
# VM sanitization adoption has been enforced.
checked: ${MIG_KSSRC}
	@$(LOG_MIG) $@
	$(PYTHON) $(VM_SANITIZE_ADOPTION_CHECK) ${MIG_KSSRC}
	touch $@

include $(MakeInc_rule)
include $(MakeInc_dir)
