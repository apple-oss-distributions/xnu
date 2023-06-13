
export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	exc_guard.h \
	exc_resource.h \
	kern_cdata.h \
	kcdata.h

MODULEMAPFILES = \
	kcdata.modulemap

PRIVATE_DATAFILES = \
	arithmetic_128.h  \
	block_hint.h \
	cambria_layout.h \
	cs_blobs.h \
	debug.h \
	ecc.h \
	lock_stat.h \
	monotonic.h \
	remote_time.h \
	restartable.h \
	trustcache.h \
	turnstile.h \
	socd_client.h

PRIVATE_MODULEMAPFILES = \
	kern_debug.modulemap \
	kern_private.modulemap

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
	socd_client_kern.h \
	task_ident.h \
	ticket_lock.h \
	zalloc_ro_shim.h


XNU_ONLY_EXPORTS = \
	arcade.h \
	btlog.h \
	cpu_quiesce.h \
	iotrace.h \
	ipc_kobject.h \
	lock_ptr.h \
	perfmon.h \
	recount.h \
	sched_hygiene.h \
	smr.h \
	smr_hash.h \
	sync_sema.h \
	ux_handler.h \
	workload_config.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

INSTALL_MI_LCL_LIST = cs_blobs.h debug.h

INSTALL_MODULEMAP_MI_LCL_LIST = ${PRIVATE_MODULEMAPFILES}

INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${EXPORT_FILES}

INSTALL_KF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES} ${EXPORT_FILES} ${PRIVATE_EXPORT_FILES})

INSTALL_MI_DIR = kern

EXPORT_MI_LIST = $(sort ${INSTALL_KF_MI_LIST} ${INSTALL_KF_MI_LCL_LIST} ${XNU_ONLY_EXPORTS})

EXPORT_MI_DIR = kern

include $(MakeInc_rule)
include $(MakeInc_dir)
