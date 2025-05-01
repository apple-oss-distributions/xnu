export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	_types

EXPINC_SUBDIRS = \
	_types

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	disk.h dtrace.h dtrace_glue.h dtrace_impl.h fasttrap.h fasttrap_isa.h ioctl_compat.h kdebug.h \
	kern_control.h kernel_types.h proc_info.h protosw.h reboot.h ttychars.h ttydev.h ubc.h vnode.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

# Installs header file for user level -
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
#	  $(DSTROOT)/usr/include/
# Most of these are covered by CoreOSModuleMaps because some of them are mixed
# in with related headers in other directories from other projects, or mixed
# in with headers from other projects in sys/.
DATAFILES = $(sort \
	appleapiopts.h	acct.h aio.h attr.h \
	buf.h cdefs.h clonefile.h conf.h constrained_ctypes.h \
	dir.h dirent.h dkstat.h \
	errno.h ev.h event.h fcntl.h file.h filedesc.h \
	fileport.h filio.h fsgetpath.h gmon.h \
	ioccom.h ioctl.h \
	ipc.h kernel.h kern_event.h lctx.h loadable_fs.h lock.h lockf.h \
	kauth.h kdebug_signpost.h lockstat.h malloc.h \
	mbuf.h mman.h mount.h msg.h msgbuf.h netport.h param.h paths.h pipe.h poll.h \
	proc.h ptrace.h queue.h quota.h resource.h resourcevar.h \
	sbuf.h posix_sem.h posix_shm.h random.h sdt.h\
	select.h sem.h semaphore.h shm.h signal.h signalvar.h snapshot.h socket.h socketvar.h sockio.h stat.h stdio.h \
	sysctl.h syslimits.h syslog.h sys_domain.h termios.h  time.h \
	timeb.h times.h trace.h tty.h ttycom.h \
	ttydefaults.h types.h ucontext.h ucred.h uio.h un.h unistd.h unpcb.h \
	user.h utfconv.h utsname.h vadvise.h vcmd.h \
	vm.h vmmeter.h vmparam.h vnode_if.h vsock.h vstat.h wait.h xattr.h \
	_select.h _structs.h _types.h _endian.h __endian.h domain.h \
	spawn.h timex.h commpage.h log_data.h \
	$(EXTRA_DATAFILES))

# Installs header file for DriverKit drivers -
#	  $(DSTROOT)/System/DriverKit/System/usr/include/
DRIVERKIT_DATAFILES = \
	cdefs.h _types.h _endian.h __endian.h time.h

# Installs header file for Apple internal use in user level -
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
# These are covered by CoreOSModuleMaps because they're mixed in with headers
# from other projects in sys/.
PRIVATE_DATAFILES = $(sort \
	attr.h \
	attr_private.h \
	cdefs.h \
	clonefile.h \
	coalition.h \
	coalition_private.h \
	codesign.h \
	constrained_ctypes.h \
	content_protection.h \
	crossarch.h \
	csr.h \
	decmpfs.h \
	dirent_private.h \
	disk.h \
	disklabel.h \
	domain.h \
	event.h \
	event_log.h \
	event_private.h \
	fcntl.h \
	fileport.h \
	fsctl.h \
	fsevents.h \
	fsgetpath.h \
	fsgetpath_private.h \
	fslog.h \
	guarded.h \
	imgsrc.h \
	ipcs.h \
	kas_info.h \
	kdebug.h \
	kdebug_private.h \
	kdebug_triage.h \
	kern_debug.h \
	kern_event.h \
	kern_memorystatus.h \
	kern_memorystatus_freeze.h \
	kern_overrides.h \
	kern_sysctl.h \
	mbuf.h \
	mman.h \
	monotonic.h \
	persona.h \
	preoslog.h \
	priv.h \
	proc.h \
	proc_info_private.h \
	proc_uuid_policy.h \
	process_policy.h \
	reason.h \
	resource.h \
	resource_private.h \
	sfi.h \
	shm_internal.h \
	snapshot.h \
	socket.h \
	socket_private.h \
	socketvar.h \
	sockio.h \
	sockio_private.h \
	spawn.h \
	spawn_internal.h \
	stackshot.h \
	sys_domain.h \
	tree.h \
	ulock.h \
	unpcb.h \
	ux_exception.h \
	variant_internal.h \
	vsock.h \
	work_interval.h \
	process_policy.h \
	proc_uuid_policy.h \
	priv.h \
	pgo.h \
	memory_maintenance.h \
	commpage.h \
	os_log_coprocessor.h \
	$(EXTRA_PRIVATE_DATAFILES))

# Installs header file for Apple internal use by DriverKit drivers -
#	  $(DSTROOT)/System/DriverKit/System/usr/local/include/
DRIVERKIT_PRIVATE_DATAFILES = \
	appleapiopts.h kdebug.h kdebug_private.h queue.h

# Installs header file for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
KERNELFILES = \
	appleapiopts.h	 attr.h \
	buf.h cdefs.h conf.h constrained_ctypes.h \
	dir.h dirent.h disk.h disklabel.h dkstat.h  \
	errno.h ev.h event.h fcntl.h file.h filio.h \
	ioccom.h ioctl.h ipc.h \
	ioctl_compat.h  kernel.h kernel_types.h kern_event.h lock.h lockf.h \
	kauth.h kdebug.h kdebug_private.h kdebug_kernel.h md5.h kern_control.h \
	imgact.h malloc.h namei.h mman.h mbuf.h mount.h netport.h param.h paths.h \
	proc.h  queue.h random.h resource.h \
	sbuf.h posix_sem.h posix_shm.h resource_private.h sem.h shm.h \
	select.h signal.h socket.h socketvar.h sockio.h stat.h stdio.h \
	sysctl.h syslimits.h syslog.h systm.h sys_domain.h  time.h \
	types.h ubc.h ucontext.h ucred.h uio.h un.h unistd.h unpcb.h \
	utfconv.h unicode.h vm.h vmparam.h vnode.h vnode_if.h vsock.h xattr.h \
	_select.h _structs.h _types.h _endian.h __endian.h protosw.h domain.h \
	kpi_mbuf.h kpi_socket.h kpi_socketfilter.h \
	ttycom.h termios.h msg.h \
	wait.h \
	spawn.h timex.h commpage.h
# The last line was added to export needed headers for the MAC calls
# whose source is outside of the xnu/bsd tree.

# Installs header file for Apple internal use for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_KERNELFILES = \
	acct.h \
	attr_private.h \
	codesign.h \
	cprotect.h \
	content_protection.h \
	csr.h \
	decmpfs.h \
	dirent_private.h \
	disktab.h \
	eventhandler.h \
	event_log.h \
	event_private.h \
	fbt.h \
	fileport.h \
	fsctl.h \
	fslog.h \
	kern_memorystatus.h \
	kern_memorystatus_freeze.h \
	kpi_private.h \
	ktrace.h \
	kdebug_triage.h \
	linker_set.h \
	mach_swapon.h \
	monotonic.h \
	msgbuf.h \
	eventvar.h \
	persona.h \
	preoslog.h \
	proc_info.h \
	proc_info_private.h \
	pthread_shims.h \
	quota.h \
	reboot.h \
	resourcevar.h \
	sem_internal.h \
	shm_internal.h \
	signalvar.h \
	socket_private.h \
	sockio_private.h \
	stackshot.h \
	timeb.h times.h \
	tprintf.h \
	tty.h  ttychars.h \
	ttydefaults.h ttydev.h \
	user.h \
	variant_internal.h \
	vfs_context.h \
	vmmeter.h \
	reason.h \
	spawn_internal.h \
	priv.h \
	pgo.h \
	memory_maintenance.h \
	doc_tombstone.h \
	fsevents.h \
	work_interval.h \
	kern_sysctl.h \
	vsock_transport.h \
	trust_caches.h \
	code_signing.h \
	lockdown_mode.h \

XNU_ONLY_EXPORTS = \
	bsdtask_info.h \
	file_internal.h \
	filedesc.h \
	guarded.h \
	kern_memorystatus_xnu.h \
	mount_internal.h \
	munge.h \
	pipe.h \
	proc_internal.h \
	proc_require.h \
	proc_ro.h \
	pthread_internal.h \
	resourcevar.h \
	semaphore.h \
	tree.h \
	uio_internal.h \
	ulock.h \
	ux_exception.h \
	vnode_internal.h \
	vsock_domain.h \
	code_signing_internal.h \
	trusted_execution_monitor.h \
	coalition.h

# /usr/include
INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

INSTALL_MI_GEN_LIST = syscall.h _posix_availability.h _symbol_aliasing.h

INSTALL_DRIVERKIT_MI_GEN_LIST = _posix_availability.h _symbol_aliasing.h

INSTALL_MI_DIR = sys

EXPORT_MI_LIST	= $(sort ${KERNELFILES} ${PRIVATE_KERNELFILES} ${XNU_ONLY_EXPORTS})

EXPORT_MI_GEN_LIST = syscall.h sysproto.h

EXPORT_MI_DIR = sys

# /usr/local/include
INSTALL_MI_LCL_LIST = $(sort \
	attr_private.h coalition_private.h code_signing.h codesign.h content_protection.h csr.h decmpfs.h dirent_private.h \
	event_log.h event_private.h fsevents.h fsgetpath_private.h guarded.h kdebug_private.h \
	kern_memorystatus.h preoslog.h proc_info_private.h reason.h resource_private.h \
	socket_private.h sockio_private.h stackshot.h work_interval.h ${EXTRA_PRIVATE_DATAFILES})

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_SF_MI_LCL_GEN_LIST = ${INSTALL_MI_GEN_LIST}

INSTALL_DRIVERKIT_MI_LCL_LIST = ${DRIVERKIT_PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST =  ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_KF_MI_LCL_GEN_LIST = sysproto.h

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_GEN_LIST =

MAKESYSCALLS = $(SRCROOT)/bsd/kern/makesyscalls.sh

$(OBJROOT)/cscope.genhdrs:
	$(_v)mkdir -p $(OBJROOT)/cscope.genhdrs

$(OBJROOT)/syscall.codes: $(TARGET)/bsd.syscalls.master
	@$(LOG_GENERATE) "$(ColorLF)$@$(Color0) from $(ColorF)$(<F)$(Color0)"
	$(_v)$(MAKESYSCALLS) $< trace > $@


$(OBJROOT)/trace.codes: $(SRCROOT)/bsd/kern/trace_codes $(OBJROOT)/syscall.codes
	$(_v)sort -g $(SRCROOT)/bsd/kern/trace_codes $(OBJROOT)/syscall.codes >$@

syscall.h: $(TARGET)/bsd.syscalls.master $(OBJROOT)/cscope.genhdrs
	@$(LOG_GENERATE) "$(ColorLF)bsd/sys/$@$(Color0) from $(ColorF)$(<F)$(Color0)"
	@echo "$(OBJPATH)/bsd/sys/$@" > $(OBJROOT)/cscope.genhdrs/$@.path
	$(_v)$(MAKESYSCALLS) $< header > /dev/null

sysproto.h: $(TARGET)/bsd.syscalls.master $(OBJROOT)/cscope.genhdrs
	@$(LOG_GENERATE) "bsd/sys/$@$(Color0) from $(ColorF)$(<F)$(Color0)"
	@echo "$(OBJPATH)/bsd/sys/$@" > $(OBJROOT)/cscope.genhdrs/$@.path
	$(_v)$(MAKESYSCALLS) $< proto > /dev/null

MAKE_POSIX_AVAILABILITY = $(SRCROOT)/bsd/sys/make_posix_availability.sh
_posix_availability.h: $(MAKE_POSIX_AVAILABILITY)
	@$(LOG_GENERATE) "bsd/sys/$@$(Color0)"
	$(_v)$(MAKE_POSIX_AVAILABILITY) "$@"

MAKE_SYMBOL_ALIASING = $(SRCROOT)/bsd/sys/make_symbol_aliasing.sh
_symbol_aliasing.h: $(MAKE_SYMBOL_ALIASING)
	@$(LOG_GENERATE) "bsd/sys/$@$(Color0)"
	$(_v)$(MAKE_SYMBOL_ALIASING) "$(SDKROOT)" "$@"

# generated headers needed early (used by iig during installhdrs of iokit/DriverKit)
SETUP_GEN_LIST = _posix_availability.h _symbol_aliasing.h
ifneq ($(filter 1,$(EXCLAVEKIT) $(EXCLAVECORE)),)
SETUP_GEN_LIST =
endif

do_build_setup:: $(SETUP_GEN_LIST)

TRACE_CODES_DEST = \
	$(DSTROOT)/$(INSTALL_SHARE_MISC_DIR)/trace.codes

$(TRACE_CODES_DEST): $(OBJROOT)/trace.codes
	$(_v)$(MKDIR) $(DSTROOT)/$(INSTALL_SHARE_MISC_DIR)
	@$(LOG_INSTALL) "$(@F)"
	$(_v)$(INSTALL) $(INSTALL_FLAGS) $(OBJROOT)/trace.codes $@

do_textfiles_install_mi:: $(TRACE_CODES_DEST)

ARIADNE_PLISTS = \
	xnu_exclaves.plist \
	xnu_epoch_sync.plist \
	xnu_suspension.plist

ARIADNE_PLISTS_SRC = $(patsubst %,$(SRCROOT)/bsd/kern/ariadne_plists/%,$(ARIADNE_PLISTS))
ARIADNE_PLISTS_DEST = $(patsubst %,$(DSTROOT)/$(INSTALL_ARIADNE_PLISTS_DIR)/%,$(ARIADNE_PLISTS))

$(ARIADNE_PLISTS_DEST): $(ARIADNE_PLISTS_SRC)
	$(_v)$(MKDIR) $(DSTROOT)/$(INSTALL_ARIADNE_PLISTS_DIR)
	@$(LOG_INSTALL) "$(@F)"
	$(_v)$(INSTALL) $(INSTALL_FLAGS) $< $@

do_textfiles_install_mi:: $(ARIADNE_PLISTS_DEST)

include $(MakeInc_rule)
include $(MakeInc_dir)
