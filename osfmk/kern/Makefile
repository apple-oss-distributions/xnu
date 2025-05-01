
export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	exc_guard.h \
	exc_resource.h \
	kern_cdata.h \
	kcdata.h

EMBEDDED_PRIVATE_MODULEMAPFILES = \
	kcdata.modulemap

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
EXTRA_MODULEMAPFILES = $(EMBEDDED_PRIVATE_MODULEMAPFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
EXTRA_PRIVATE_MODULEMAPFILES = $(EMBEDDED_PRIVATE_MODULEMAPFILES)
endif

DATAFILES = $(sort \
	$(EXTRA_DATAFILES))

MODULEMAPFILES = $(sort \
	$(EXTRA_MODULEMAPFILES))

PRIVATE_DATAFILES = $(sort \
	arithmetic_128.h  \
	block_hint.h \
	cambria_layout.h \
	cs_blobs.h \
	debug.h \
	panic_call.h \
	ecc.h \
	lock_stat.h \
	monotonic.h \
	remote_time.h \
	restartable.h \
	trustcache.h \
	turnstile.h \
	socd_client.h \
	$(EXTRA_PRIVATE_DATAFILES))

PRIVATE_MODULEMAPFILES = $(sort \
	kern_debug.modulemap \
	kern_private.modulemap \
	$(EXTRA_PRIVATE_MODULEMAPFILES))

EXPORT_FILES = \
	affinity.h \
	assert.h \
	audit_sessionport.h \
	backtrace.h \
	bits.h \
	circle_queue.h \
	clock.h \
	coalition.h \
	counter.h  \
	cpu_number.h \
	cpu_data.h \
	energy_perf.h \
	ext_paniclog.h \
	extmod_statistics.h \
	hv_io_notifier.h \
	hv_support.h \
	hv_support_kext.h \
	ipc_mig.h \
	ipc_misc.h \
	kalloc.h \
	kext_alloc.h \
	kern_types.h \
	kpc.h \
	ledger.h \
	lock.h \
	lock_attr.h \
	lock_group.h \
	lock_mtx.h \
	lock_rw.h \
	lock_sleep.h \
	lock_types.h \
	locks.h \
	host.h \
	hvg_hypercall.h \
	mach_param.h \
	macro_help.h \
	mpqueue.h \
	page_decrypt.h \
	pms.h \
	policy_internal.h \
	processor.h \
	queue.h \
	mpsc_queue.h \
	percpu.h \
	priority_queue.h \
	sched_prim.h \
	sfi.h \
	simple_lock.h \
	smr_types.h \
	startup.h \
	task.h \
	task_ref.h \
	telemetry.h \
	trap_telemetry.h \
	thread.h \
	thread_call.h \
	thread_group.h \
	timer_call.h \
	waitq.h \
	work_interval.h \
	zalloc.h


# Installs header file for Apple internal use for kernel extensions -
#         $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_EXPORT_FILES = \
	build_config.h \
	copyout_shim.h \
	kern_apfs_reflock.h \
	mach_filter.h \
	mach_node_link.h \
	sched_clutch.h \
	smr.h \
	smr_hash.h \
	socd_client_kern.h \
	task_ident.h \
	ticket_lock.h \
	zalloc_ro_shim.h


XNU_ONLY_EXPORTS = \
	arcade.h \
	btlog.h \
	cpc.h \
	iotrace.h \
	ipc_kobject.h \
	lock_ptr.h \
	mpsc_ring.h \
	recount.h \
	sched_hygiene.h \
	sync_sema.h \
	ux_handler.h \
	workload_config.h \
	kern_stackshot.h \
	thread_test_context.h


INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

INSTALL_MI_LCL_LIST = $(sort cs_blobs.h debug.h panic_call.h ext_paniclog.h ${EXTRA_PRIVATE_DATAFILES})

INSTALL_MODULEMAP_MI_LCL_LIST = ${PRIVATE_MODULEMAPFILES}

INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${EXPORT_FILES}

INSTALL_KF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES} ${EXPORT_FILES} ${PRIVATE_EXPORT_FILES})

INSTALL_MI_DIR = kern

EXPORT_MI_LIST = $(sort ${INSTALL_KF_MI_LIST} ${INSTALL_KF_MI_LCL_LIST} ${XNU_ONLY_EXPORTS})

EXPORT_MI_DIR = kern

# build support for tightbeamc-generated files

ifeq ($(XNU_CONFIG_TIGHTBEAM),1)
TIGHTBEAM_FILES := \
	exclaves_conclave_launcher.tightbeam \
	exclaves_log.tightbeam \
	exclaves_upcalls.tightbeam \
	exclaves_upcalls_v2.tightbeam \
	exclaves_frame_mint.tightbeam \
	exclaves_xnuproxy.tightbeam

TIGHTBEAM_MODULES := \
	ExclaveIndicatorController.tbmodule \
	StackshotTypes.tbmodule \
	Stackshot.tbmodule \
	SharedMemoryBase.tbmodule \
	ExclavesCHelloServer.tbmodule \
	StackshotPanicSetup.tbmodule \
	ExclaveAudioArbiter.tbmodule

endif

# This makes sure to not include any tbmodules which don't exist in the SDK and
# expand the modules listed above to their full path in the SDK. The modules
# should only be needed when actually building with CONFIG_EXCLAVES
# (which can't easily be checked here).
TIGHTBEAM_MODULES := $(patsubst %.tbmodule,$(TIGHTBEAM_MODULE_DIR)/%.tbmodule,$(TIGHTBEAM_MODULES))
TIGHTBEAM_MODULES := $(wildcard $(TIGHTBEAM_MODULES))

TIGHTBEAM_COMBINED_HDR := exclaves.tightbeam.h
# Clear TIGHTBEAM_COMBINED_HDR if there are no tightbeam files/modules to be
# compiled at all.
ifeq ($(strip $(TIGHTBEAM_FILES)),)
ifeq ($(strip $(TIGHTBEAM_MODULES)),)
TIGHTBEAM_COMBINED_HDR :=
endif
endif

TIGHTBEAM_COMBINED_IMPL := $(patsubst %.h,%.c,$(TIGHTBEAM_COMBINED_HDR))

COMP_FILES := $(TIGHTBEAM_COMBINED_HDR) $(TIGHTBEAM_COMBINED_IMPL)

$(TIGHTBEAM_COMBINED_IMPL) : $(TIGHTBEAM_FILES) $(TIGHTBEAM_MODULES)
	@$(LOG_TIGHTBEAMC) "$@"
	$(_v)$(TIGHTBEAMC) build generate-c --output-base $@ --codegen-version 2 $^

$(TIGHTBEAM_COMBINED_HDR) : $(TIGHTBEAM_COMBINED_IMPL)

do_build_all:: $(COMP_FILES)

include $(MakeInc_rule)
include $(MakeInc_dir)
