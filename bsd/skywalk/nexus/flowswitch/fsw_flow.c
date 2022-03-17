/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>

static void fsw_flow_route_ctor(void *, struct flow_route *);
static int fsw_flow_route_resolve(void *, struct flow_route *,
    struct __kern_packet *);

struct flow_owner *
fsw_flow_add(struct nx_flowswitch *fsw, struct nx_flow_req *req0, int *error)
{
	struct kern_nexus *nx = fsw->fsw_nx;
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	nexus_port_t nx_port = req0->nfr_nx_port;
	struct flow_owner_bucket *fob;
	struct flow_owner *fo = NULL;
	void *fo_context = req0->nfr_context;
	boolean_t nx_bound = FALSE;
	boolean_t new_mapping = FALSE;
	struct nx_flow_req req;
	uuid_t uuid_key;
	bool nx_port_pid_bound;
	uint32_t max_flowadv = nx->nx_prov->nxprov_params->nxp_flowadv_max;
	struct proc *p;
	int pid = req0->nfr_pid;
	bool low_latency = ((req0->nfr_flags & NXFLOWREQF_LOW_LATENCY) != 0);
#if SK_LOG
	uuid_string_t uuidstr;
#endif /* SK_LOG */

	*error = 0;

	/*
	 * Make a local copy of the original request; we'll modify the
	 * local copy and write it back to the original upon success.
	 */
	bcopy(req0, &req, sizeof(*req0));
	ASSERT(!uuid_is_null(req.nfr_flow_uuid));

	/*
	 * Interface attach and detach involve holding the flowswitch lock
	 * held as writer.  Given that we might block in msleep() below,
	 * holding the flowswitch RW lock is not an option.  Instead, we
	 * utilize the detach barrier prevent things from going away while
	 * we are here.
	 */
	if (!fsw_detach_barrier_add(fsw)) {
		SK_ERR("netagent detached");
		*error = ENXIO;
		return NULL;
	}

	/*
	 * We insist that PID resolves to a process for flow add, but not for
	 * delete. That's because those events may be posted (to us) after the
	 * corresponding process has exited, and so we still need to be able to
	 * cleanup.
	 */
	p = proc_find(pid);
	if (p == PROC_NULL) {
		SK_ERR("process for pid %d doesn't exist", pid);
		*error = EINVAL;
		fsw_detach_barrier_remove(fsw);
		return NULL;
	}
	req.nfr_proc = p;

	/*
	 * If interface is currently attached, indicate that a bind is in
	 * progress, so that upon releasing the lock any threads attempting
	 * to detach the interface will wait until we're done.
	 */
	fob = flow_mgr_get_fob_by_pid(fm, pid);
	FOB_LOCK_SPIN(fob);
	while (fob->fob_busy_flags & (FOBF_OPEN_BUSY | FOBF_CLOSE_BUSY)) {
		if (++(fob->fob_open_waiters) == 0) {   /* wraparound */
			fob->fob_open_waiters++;
		}
		if ((*error = msleep(&fob->fob_open_waiters, &fob->fob_lock,
		    (PZERO + 1) | PSPIN, __FUNCTION__, NULL)) == EINTR) {
			SK_ERR("%s(%d) binding for uuid %s was interrupted",
			    sk_proc_name_address(p), pid,
			    sk_uuid_unparse(req.nfr_flow_uuid, uuidstr));
			ASSERT(fob->fob_open_waiters > 0);
			fob->fob_open_waiters--;
			FOB_UNLOCK(fob);
			ASSERT(fo == NULL);
			goto unbusy;
		}
	}
	if (__improbable((fob->fob_busy_flags & FOBF_DEAD) != 0)) {
		SK_ERR("%s(%d) binding for flow_uuid %s aborted due to "
		    "dead owner", sk_proc_name_address(p), pid,
		    sk_uuid_unparse(req.nfr_flow_uuid, uuidstr));
		*error = ENXIO;
		goto done;
	}
	ASSERT(!(fob->fob_busy_flags & FOBF_OPEN_BUSY));
	fob->fob_busy_flags |= FOBF_OPEN_BUSY;

	do {
		fo = flow_owner_find_by_pid(fob, pid, fo_context, low_latency);
		if (fo == NULL && nx_port == NEXUS_PORT_ANY) {
			struct nxbind nxb;

			/*
			 * Release lock to maintain ordering with the
			 * flowswitch lock; busy flag is set above.
			 * Also read_random() may block.
			 */
			FOB_UNLOCK(fob);

			uuid_generate_random(uuid_key);

			bzero(&nxb, sizeof(nxb));
			nxb.nxb_flags |= NXBF_MATCH_UNIQUEID;
			nxb.nxb_uniqueid = proc_uniqueid(p);
			nxb.nxb_pid = pid;
			nxb.nxb_flags |= NXBF_MATCH_KEY;
			nxb.nxb_key_len = sizeof(uuid_key);
			nxb.nxb_key = sk_alloc_data(nxb.nxb_key_len,
			    Z_WAITOK | Z_NOFAIL, skmem_tag_nx_key);
			bcopy(uuid_key, nxb.nxb_key, nxb.nxb_key_len);

			/*
			 * Bind a new nexus port.  Directly invoke the
			 * nxdom_bind_port() callback of the nexus since
			 * the nexus instance is already known.  Free
			 * the UUID key upon failure; otherwise callee
			 * will attach it to the nexus port and clean
			 * it up during nxdom_unbind_port().
			 */
			if ((*error = NX_DOM(nx)->nxdom_bind_port(nx,
			    &nx_port, &nxb, NULL)) != 0) {
				sk_free_data(nxb.nxb_key, nxb.nxb_key_len);
				SK_ERR("%s(%d) failed to bind flow_uuid %s to a "
				    "nx_port (err %d)", sk_proc_name_address(p),
				    pid, sk_uuid_unparse(req.nfr_flow_uuid,
				    uuidstr), *error);
				nx_port = NEXUS_PORT_ANY;
				FOB_LOCK_SPIN(fob);
				break;
			}
			ASSERT(nx_port != NEXUS_PORT_ANY);
			nx_bound = TRUE;

			SK_DF(SK_VERB_FLOW, "%s(%d) flow_uuid %s associated with "
			    "ephemeral nx_port %d", sk_proc_name_address(p),
			    pid, sk_uuid_unparse(req.nfr_flow_uuid, uuidstr),
			    (int)nx_port);

			FOB_LOCK_SPIN(fob);
			/*
			 * if there's no interface associated with this,
			 * then bail
			 */
			if (__improbable((fob->fob_busy_flags & FOBF_DEAD) !=
			    0 || fsw->fsw_ifp == NULL ||
			    fsw->fsw_agent_session == NULL)) {
				SK_ERR("%s(%d) binding for flow_uuid %s aborted "
				    "(lost race)", sk_proc_name_address(p),
				    pid, sk_uuid_unparse(req.nfr_flow_uuid,
				    uuidstr));
				*error = ENXIO;
				break;
			}
			nx_port_pid_bound = true;
			uuid_copy(req.nfr_bind_key, uuid_key);
		} else if (fo == NULL) {
			/* make sure request has valid nx_port */
			ASSERT(nx_port != NEXUS_PORT_ANY);
			/*
			 * XXX
			 * Why is this path supported? Normal flows are not
			 * added with a specified port and this check does
			 * nothing to verify if the port is used.
			 *
			 * Using nx_port_is_valid() is wrong because that
			 * assumes the array already has non-zero ports.
			 */
			if (__improbable(nx_port >= NX_PORT_CHUNK)) {
				*error = EINVAL;
				break;
			}
			/* read_random() may block */
			FOB_LOCK_CONVERT(fob);

			nx_port_pid_bound = false;
			uuid_generate_random(uuid_key);

			SK_DF(SK_VERB_FLOW, "%s(%d) flow_uuid %s associated "
			    "with nx_port %d", sk_proc_name_address(p),
			    pid, sk_uuid_unparse(req.nfr_flow_uuid, uuidstr),
			    (int)nx_port);
		} else {
			/* subsequent request should reuse existing port */
			ASSERT(fo->fo_nx_port != NEXUS_PORT_ANY);
			if (nx_port != NEXUS_PORT_ANY &&
			    nx_port != fo->fo_nx_port) {
				*error = EINVAL;
				break;
			}
			/* fillout info for nexus port */
			nx_port = fo->fo_nx_port;
			uuid_copy(uuid_key, fo->fo_key);
			break;
		}

		FOB_LOCK_CONVERT(fob);

		ASSERT(nx_port != NEXUS_PORT_ANY);
		ASSERT(fo == NULL);
		fo = flow_owner_alloc(fob, p, nx_port, nx_port_pid_bound,
		    (max_flowadv != 0), fsw, NULL, fo_context, low_latency);
		if (fo == NULL) {
			*error = ENOMEM;
			break;
		}
		ASSERT(!uuid_is_null(uuid_key));
		uuid_copy(fo->fo_key, uuid_key);
		new_mapping = TRUE;
	} while (0);

	if (*error != 0) {
		goto done;
	}

	/* make sure rule ID isn't already being used */
	struct flow_entry *fe;
	if ((fe = flow_entry_find_by_uuid(fo, req.nfr_flow_uuid)) != NULL) {
#if SK_LOG
		char dbgbuf[FLOWENTRY_DBGBUF_SIZE];
		SK_DSC(p, "flow uuid collision: \"%s\" already exists at "
		    "fe 0x%llx flags 0x%b %s(%d)",
		    fe_as_string(fe, dbgbuf, sizeof(dbgbuf)), SK_KVA(fe),
		    fe->fe_flags, FLOWENTF_BITS, fe->fe_proc_name, fe->fe_pid);
#endif /* SK_LOG */
		*error = EEXIST;
		flow_entry_release(&fe);
		goto done;
	}

	/* return assigned nexus port to caller */
	req.nfr_nx_port = nx_port;
	if (__probable(!fsw_qos_default_restricted())) {
		req.nfr_flags |= NXFLOWREQF_QOS_MARKING;
	} else {
		req.nfr_flags &= ~NXFLOWREQF_QOS_MARKING;
	}

	FOB_LOCK_CONVERT(fob);

	*error = flow_mgr_flow_add(nx, fm, fo, fsw->fsw_ifp, &req,
	    fsw_flow_route_ctor, fsw_flow_route_resolve, fsw);

	if (*error == 0) {
		/* replace original request with our (modified) local copy */
		bcopy(&req, req0, sizeof(*req0));

		SK_DF(SK_VERB_FLOW, "%s(%d) flow_uuid %s is now on "
		    "nx_port %d", sk_proc_name_address(p), pid,
		    sk_uuid_unparse(req.nfr_flow_uuid, uuidstr),
		    (int)nx_port);
	}

done:
	if (__improbable(*error != 0)) {
		SK_ERR("%s(%d) failed to add flow_uuid %s (err %d)",
		    sk_proc_name_address(p), pid,
		    sk_uuid_unparse(req.nfr_flow_uuid, uuidstr), *error);
		if (fo != NULL) {
			if (new_mapping) {
				FOB_LOCK_CONVERT(fob);
				flow_owner_free(fob, fo);
			}
			fo = NULL;
		}
		if (nx_bound) {
			ASSERT(nx_port != NEXUS_PORT_ANY);
			FOB_LOCK_ASSERT_HELD(fob);
			/*
			 * Release lock to maintain ordering with the
			 * flowswitch lock; busy flag is set above.
			 */
			FOB_UNLOCK(fob);
			(void) NX_DOM(nx)->nxdom_unbind_port(nx, nx_port);
			nx_port = NEXUS_PORT_ANY;
			FOB_LOCK_SPIN(fob);
		}
	}
	fob->fob_busy_flags &= ~FOBF_OPEN_BUSY;
	if (__improbable(fob->fob_open_waiters > 0)) {
		fob->fob_open_waiters = 0;
		wakeup(&fob->fob_open_waiters);
	}
	if (__improbable(fob->fob_close_waiters > 0)) {
		fob->fob_close_waiters = 0;
		wakeup(&fob->fob_close_waiters);
	}
	FOB_UNLOCK(fob);

unbusy:
	proc_rele(p);
	p = PROC_NULL;
	/* allow any pending detach to proceed */
	fsw_detach_barrier_remove(fsw);

	return fo;
}

int
fsw_flow_del(struct nx_flowswitch *fsw, struct nx_flow_req *req, bool nolinger,
    void *params)
{
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	struct kern_nexus *nx = fsw->fsw_nx;
	struct flow_owner_bucket *fob;
	struct flow_owner *fo;
	void *fo_context = req->nfr_context;
	pid_t pid = req->nfr_pid;
	bool low_latency = ((req->nfr_flags & NXFLOWREQF_LOW_LATENCY) != 0);
	int error;

	ASSERT(!uuid_is_null(req->nfr_flow_uuid));

	/*
	 * we use the detach barrier to prevent flowswith instance from
	 * going away while we are here.
	 */
	if (!fsw_detach_barrier_add(fsw)) {
		SK_ERR("netagent detached");
		return ENXIO;
	}

	/* find mapping */
	fob = flow_mgr_get_fob_by_pid(fm, pid);
	FOB_LOCK_SPIN(fob);
	while (fob->fob_busy_flags & (FOBF_OPEN_BUSY | FOBF_CLOSE_BUSY)) {
		if (++(fob->fob_close_waiters) == 0) {  /* wraparound */
			fob->fob_close_waiters++;
		}
		(void) msleep(&fob->fob_close_waiters, &fob->fob_lock,
		    (PZERO - 1) | PSPIN, __FUNCTION__, NULL);
	}
	fob->fob_busy_flags |= FOBF_CLOSE_BUSY;

	fo = flow_owner_find_by_pid(fob, pid, fo_context, low_latency);
	if (fo == NULL) {
		error = ENOENT;
		goto done;
	}

	FOB_LOCK_CONVERT(fob);

	/*
	 * Unbind flow.  Note that if "auto close" is enabled, the flows
	 * associated with this fo would have been removed when the channel
	 * opened to the nexus port gets closed.  If we get ENOENT just
	 * treat as as non-fatal and proceed further down.
	 */
	error = flow_owner_destroy_entry(fo, req->nfr_flow_uuid, nolinger,
	    params);
	if (error != 0 && error != ENOENT) {
		goto done;
	}

	/*
	 * If the channel that was connected to the nexus port is no longer
	 * around, i.e. fsw_port_dtor() has been called, and there are no
	 * more flows on the owner, and the owner was bound to PID on the
	 * nexus port in fsw_flow_bind(), remove the nexus binding now to make
	 * this port available.
	 */
	if (RB_EMPTY(&fo->fo_flow_entry_id_head) &&
	    fo->fo_nx_port_destroyed && fo->fo_nx_port_pid_bound) {
		nexus_port_t nx_port = fo->fo_nx_port;
		ASSERT(nx_port != NEXUS_PORT_ANY);
		/*
		 * Release lock to maintain ordering with the
		 * flowswitch lock; busy flag is set above.
		 */
		FOB_UNLOCK(fob);
		(void) NX_DOM(nx)->nxdom_unbind_port(nx, nx_port);
		FOB_LOCK(fob);
		flow_owner_free(fob, fo);
		fo = NULL;
	}
	error = 0;

done:
#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_FLOW) != 0)) {
		uuid_string_t uuidstr;
		if (fo != NULL) {
			SK_DF(SK_VERB_FLOW, "%s(%d) flow_uuid %s (err %d)",
			    fo->fo_name, fo->fo_pid,
			    sk_uuid_unparse(req->nfr_flow_uuid, uuidstr), error);
		} else {
			SK_DF(SK_VERB_FLOW, "pid %d flow_uuid %s (err %d)", pid,
			    sk_uuid_unparse(req->nfr_flow_uuid, uuidstr), error);
		}
	}
#endif /* SK_LOG */

	fob->fob_busy_flags &= ~FOBF_CLOSE_BUSY;
	if (__improbable(fob->fob_open_waiters > 0)) {
		fob->fob_open_waiters = 0;
		wakeup(&fob->fob_open_waiters);
	}
	if (__improbable(fob->fob_close_waiters > 0)) {
		fob->fob_close_waiters = 0;
		wakeup(&fob->fob_close_waiters);
	}
	FOB_UNLOCK(fob);

	/* allow any pending detach to proceed */
	fsw_detach_barrier_remove(fsw);

	return error;
}

static void
fsw_flow_route_ctor(void *arg, struct flow_route *fr)
{
	struct nx_flowswitch *fsw = arg;
	if (fsw->fsw_ctor != NULL) {
		fsw->fsw_ctor(fsw, fr);
	}
}

static int
fsw_flow_route_resolve(void *arg, struct flow_route *fr,
    struct __kern_packet *pkt)
{
	struct nx_flowswitch *fsw = arg;
	return (fsw->fsw_resolve != NULL) ? fsw->fsw_resolve(fsw, fr, pkt) : 0;
}
