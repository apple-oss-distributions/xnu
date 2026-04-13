---- MODULE vmelock ----
(*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
 *)

EXTENDS Naturals, Sequences, TLC

CONSTANTS Threads, Chaos


(* --fair algorithm vmelock {

variables
        (*** wait queues variables ***)
        waitqs          = [e \in Events   |->
                              [q    |-> <<>>,
                               lock |-> FALSE]];        \* a map of events to wait queues
        ret_blocked     = {};                           \* blocked threads
        ret_handoff     = {};
        ret_wakeup      = [t \in Threads \union Chaos |-> {}];
        ret_lock        = [t \in Threads \union Chaos |-> FALSE];

        (*** our vmelock ***)
        vmelock_in_map  = TRUE;
        vmelock         = [excl_waiters   |-> FALSE,
                           shared_waiters |-> FALSE,
                           valid          |-> TRUE,
                           excl_locked    |-> FALSE,
                           read_count     |-> 0];
        map_lock        = [owner          |-> {},
                           readers        |-> {}];
        dbg_vmelock     = [owner          |-> {},
                           readers        |-> {}];

define {
        \* derived constants
        SharedEvent     == "s"
        ExclEvent       == "x"

        Events          == { SharedEvent, ExclEvent }

        ReadCS          == { "rcs", "drcs" }
        WriteCS         == { "wcs", "uwcs", "cwcs" }
        AnyCS           == ReadCS \union WriteCS

        \* predicates
        Range(seq)      == { seq[x] : x \in DOMAIN seq }
        Min(a, b)       == IF a < b THEN a ELSE b

        Lock16Same(s)   == /\ vmelock.valid = s.valid
                           /\ vmelock.excl_locked = s.excl_locked
                           /\ vmelock.read_count = s.read_count

        CanLockS(s)     == /\ s.valid
                           /\ ~s.excl_locked

        CanLockX(s)     == /\ s.valid
                           /\ ~s.excl_locked
                           /\ s.read_count = 0

        \* Invariants
        NoError         == \A t \in Threads \union Chaos:
                           pc[t] # "Error"

        \* Safety
        Exclusion       == \A t1 \in Threads \union Chaos:
                           pc[t1] \in WriteCS => (\A t2 \in Threads \ {t1}: pc[t2] \notin AnyCS)

        \* Liveness
        NoMissingWakeup == \/ ret_blocked = {}
                           \/ \E t \in Threads \ ret_blocked: pc[t] = "block"
                           \/ \E t \in Chaos   \ ret_blocked: pc[t] = "block"
                           \/ \E t \in Threads: pc[t] \notin { "block", "tloop", "Done" }
                           \/ \E t \in Chaos:   pc[t] \notin { "block", "cloop", "Done" }

        \* Symmetry
        Perms           == Permutations(Threads)
}

(******************************************************************************)
(* vm map rwlock                                                              *)
(******************************************************************************)

macro vm_map_ilk_lock_shared()
{
        await map_lock.owner = {};
        map_lock.readers := map_lock.readers \union {self};
}

macro vm_map_ilk_unlock_shared()
{
        map_lock.readers := map_lock.readers \ {self};
}

macro vm_map_ilk_lock_exclusive()
{
        await map_lock.readers = {} /\ map_lock.owner = {};
        map_lock.owner := {self};
}

macro vm_map_ilk_unlock_exclusive()
{
        map_lock.owner := {};
}


(******************************************************************************)
(* Modelization of XNU's wait queues                                          *)
(******************************************************************************)

(*!
 * @abstract
 * Models locking the global wait queue for an event.
 *
 * @param event         The event for which to lock the global wait queue.
 *)
macro waitq_lock(event)
{
        await waitqs[event].lock = FALSE;
        waitqs[event].lock := TRUE;
}

(*!
 * @abstract
 * Models unlocking the global wait queue for an event.
 *
 * @param event         The event for which to unlock the global wait queue.
 *)
macro waitq_unlock(event)
{
        waitqs[event].lock := FALSE;
}

(*!
 * @abstract
 * Models waitq_assert_wait64_locked() followed by waitq_unlock().
 *
 * @discussion
 * This helper cheats by adding the thread to the wait queue and unlocking
 * it atomically.
 *
 * Because the model here is not about validating wait queues,
 * we can take that shortcut and reduce the number of states for TLC.
 *
 * @param event         The event to assert_wait on, and for which
 *                      to unlock the global wait queue.
 *)
macro assert_wait_and_unlock(event)
{
        ret_blocked := ret_blocked \union {self};
        waitqs[event] := [
            q    |-> Append(waitqs[event].q, self),
            lock |-> FALSE
        ];
}

(*!
 * @abstract
 * similar to waitq_wakeup64_all_locked().
 *
 * @param event_all     The event for which to wake up all waiters.
 * @param unlock_all    Whether to unlock the corresponding global wait queue
 *                      upon return.
 *)
macro wakeup_all(event_all, unlock_all)
{
        with (wq_all = waitqs[event_all].q) {
                ret_wakeup[self] := Range(wq_all);
                ret_blocked := ret_blocked \ ret_wakeup[self];
                waitqs[event_all] := [
                    q |-> <<>>,
                    lock |-> ~unlock_all
                ];
        }
}

(*!
 * @abstract
 * similar to waitq_wakeup64_identify_locked()
 *
 * @param arg_event_i   The event for which identify a waiter.
 * @returns             Via ret_wakeup[self]: the number of threads woken up.
 *)
procedure identify(arg_event_i)
{
in:     with (wq_n = waitqs[arg_event_i].q) {
                if (wq_n = << >>) {
                        ret_wakeup[self] := {};
                } else {
                        ret_wakeup[self] := {Head(wq_n)};
                        waitqs[arg_event_i].q := Tail(wq_n);
                };
                return;
        }
}

(*!
 * @abstract
 * similar to waitq_wakeup64_nthreads_locked()
 *
 * @param arg_event_n   The event for which to wake up some waiters.
 * @param arg_count_n   The number of threads to wake up.
 * @param arg_unlock_n  Whether to unlock the corresponding global wait queue
 *                      upon return.
 * @returns             Via ret_wakeup[self]: the number of threads woken up.
 *)
procedure wakeup_n(arg_event_n, arg_count_n, arg_unlock_n)
{
wn:     with (wq_n = waitqs[arg_event_n].q,
            len_n = Len(wq_n),
            n_n = Min(arg_count_n, len_n)) {
                ret_wakeup[self] := { wq_n[x] : x \in 1..n_n };
                ret_blocked := ret_blocked \ ret_wakeup[self];
                waitqs[arg_event_n] := [
                    q    |-> [x \in 1..(len_n - n_n) |-> wq_n[n_n + x]],
                    lock |-> ~arg_unlock_n
                ];
                return;
        }
}

(*!
 * @abstract
 * models thread_block(THREAD_CONTINUE_NULL)
 *)
procedure thread_block(arg_mode_b)
{
bu:     if (arg_mode_b) {
                vm_map_ilk_unlock_exclusive();
        } else {
                vm_map_ilk_unlock_shared();
        };
block:  await self \notin ret_blocked;
bl:     if (arg_mode_b) {
                vm_map_ilk_lock_exclusive();
        } else {
                vm_map_ilk_lock_shared();
        };
        return;
}

(******************************************************************************)
(* vm_entry_wakeup()                                                          *)
(******************************************************************************)

procedure __vm_entry_lock_exclusive_broadcast()
{
xb1:    waitq_lock(ExclEvent);
xb_end: wakeup_all(ExclEvent, TRUE);
        return;
}

procedure __vm_entry_lock_shared_broadcast(arg_clear)
{
sb1:    waitq_lock(SharedEvent);
        if (arg_clear) {
                vmelock.shared_waiters := FALSE;
        };
sb_end: wakeup_all(SharedEvent, TRUE);
        return;
}

(******************************************************************************)
(* vm_entry_*_exclusive                                                       *)
(******************************************************************************)

procedure vm_entry_lock_exclusive(arg_mode_x)
        (*
         * atomic snapshot of the vmelock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable xl_state;
{
        (*
         * We only implement the slowpath here, this function is morally
         * equivalent to __vm_entry_lock_exclusive_contended().
         *
         * The fastpath is just doing "s_cas" outside of the slowpath
         * for performance reasons but doesn't change the state machine.
         * As a result, we elide it and reduce the space TLC has to cover.
         *)
xl_loop: while (TRUE) {
                xl_state := vmelock;
                assert xl_state.valid;
xl_cas:         if (CanLockX(xl_state)) {
                        if (Lock16Same(xl_state)) {
                                xl_state  := defaultInitValue ||
                                dbg_vmelock.owner   := {self} ||
                                vmelock.excl_locked := TRUE   ||
                                ret_lock[self]      := TRUE;
xl_ret_1:                       return;
                        } else {
                                goto xl_loop;
                        }
                };

xl_set_wait:    if (xl_state.excl_waiters) {
                        skip;
                } else if (vmelock = xl_state) {
                        vmelock.excl_waiters   := TRUE;
                } else {
                        goto xl_loop;
                };

xl_aw1:         xl_state := defaultInitValue;
                waitq_lock(ExclEvent);
                assert vmelock.valid;
                if (vmelock.excl_waiters /\ ~CanLockX(vmelock)) {
xl_aw2:                 assert_wait_and_unlock(ExclEvent);
                        call thread_block(arg_mode_x);
xl_aw3:                 ret_lock[self] := (ret_handoff = {self}) ||
                        ret_handoff    := ret_handoff \ {self};
xl_ret_2:               return;
                } else {
xl_aw4:                 waitq_unlock(ExclEvent);
                };
        };
}

procedure __vm_entry_lock_exclusive_wakeup(xw_state)
{
xw_a:   assert /\ vmelock.valid
               /\ vmelock.excl_locked
               /\ dbg_vmelock.owner = {self};

xw_w:   if (xw_state.excl_waiters) {
                waitq_lock(ExclEvent);
                call identify(ExclEvent);
xw_w1:          if (ret_wakeup[self] # {}) {
xw_w_success:           waitq_unlock(ExclEvent);

                        dbg_vmelock.owner := ret_wakeup[self] ||
                        ret_handoff := ret_wakeup[self] ||
                        ret_blocked := ret_blocked \ ret_wakeup[self];
                        goto xw_rst;
                } else {
                        vmelock.excl_waiters   := FALSE ||
                        xw_state               := [vmelock EXCEPT
                            !.excl_waiters   = FALSE];
xw_w_fail:              waitq_unlock(ExclEvent);
                };
        };

xw_s:   if (xw_state.shared_waiters) {
                waitq_lock(SharedEvent);
        };

        if (vmelock # xw_state) {
xw_s_fail:      if (xw_state.shared_waiters) {
                        waitq_unlock(SharedEvent);
                };
                xw_state := vmelock;
                goto xw_a;
        } else {
                dbg_vmelock.owner      := {} ||
                vmelock.shared_waiters := FALSE ||
                vmelock.excl_locked    := FALSE ||
                vmelock.read_count     := 0;
        };

xw_s_success:
        if (xw_state.shared_waiters) {
                wakeup_all(SharedEvent, TRUE);
        };

xw_rst: xw_state := defaultInitValue;
xw_end: return;
}

procedure vm_entry_unlock_exclusive()
{
ux1:    if (vmelock.excl_waiters \/ vmelock.shared_waiters) {
                call __vm_entry_lock_exclusive_wakeup(vmelock);
        } else {
                assert /\ vmelock.valid
                       /\ vmelock.excl_locked
                       /\ dbg_vmelock.owner = {self};
                dbg_vmelock.owner   := {} ||
                vmelock.excl_locked := FALSE ||
                vmelock.read_count  := 0;
        };
ux_end: return;
}

procedure vm_entry_lock_exclusive_to_shared()
        (*
         * atomic snapshot of the vmelock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable d_state;
{
d1:     dbg_vmelock.owner   := {} ||
        dbg_vmelock.readers := {self} ||
        vmelock.excl_locked := FALSE ||
        vmelock.read_count  := 1 ||
        d_state := [vmelock EXCEPT !.excl_locked = FALSE, !.read_count = 1];
d2:     if (d_state.shared_waiters /\ ~d_state.excl_waiters) {
                call __vm_entry_lock_shared_broadcast(TRUE);
        };
d_rst:  d_state := defaultInitValue;
d_end:  return;
}

procedure vm_entry_unlock_exclusive_and_destroy()
        variable xd_state;
{
xd:     assert /\ vmelock.valid
               /\ vmelock.excl_locked
               /\ dbg_vmelock.owner = {self};
        dbg_vmelock.owner := {} ||
        vmelock_in_map    := FALSE ||
        vmelock           := [excl_waiters   |-> FALSE,
                              shared_waiters |-> FALSE,
                              valid          |-> FALSE,
                              excl_locked    |-> FALSE,
                              read_count     |-> 0] ||
        xd_state          := vmelock;

xd1:    if (xd_state.excl_waiters) {
                waitq_lock(ExclEvent);
xd2:            wakeup_all(ExclEvent, TRUE);
        };

xd3:    if (xd_state.shared_waiters) {
                waitq_lock(SharedEvent);
xd4:            wakeup_all(SharedEvent, TRUE);
        };

xd5:    xd_state := defaultInitValue;
xd_ret: return;
}

(******************************************************************************)
(* vm_entry_*_shared()                                                        *)
(******************************************************************************)

procedure vm_entry_lock_shared()
        (*
         * atomic snapshot of the vmelock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable sl_state;
{
        (*
         * We only implement the slowpath here, this function is morally
         * equivalent to __vm_entry_lock_shared_contended().
         *
         * The fastpath is just doing "s_cas" outside of the slowpath
         * for performance reasons but doesn't change the state machine.
         * As a result, we elide it and reduce the space TLC has to cover.
         *)
sl_loop: while (TRUE) {
                sl_state := vmelock;
                assert sl_state.valid;
sl_cas:         if (CanLockS(sl_state)) {
                        vmelock.read_count := vmelock.read_count + 1 ||
                        sl_state := [vmelock EXCEPT
                            !.read_count = vmelock.read_count + 1];
                        if (~CanLockS(sl_state)) {
                                goto sl_loop;
                        };

sl_success:             dbg_vmelock.readers := dbg_vmelock.readers \union {self} ||
                        ret_lock[self] := TRUE;
                        if (sl_state.shared_waiters /\ ~sl_state.excl_waiters) {
                                call __vm_entry_lock_shared_broadcast(TRUE);
                        };
sl_ret_1:               return;
                };

sl_set_wait:    if (sl_state.shared_waiters) {
                        skip;
                } else if (vmelock = sl_state) {
                        vmelock.shared_waiters := TRUE;
                } else {
                        goto sl_loop;
                };

sl_aw1:         sl_state := defaultInitValue;
                waitq_lock(SharedEvent);
                assert vmelock.valid;
                if (vmelock.shared_waiters /\ ~CanLockX(vmelock)) {
sl_aw2:                 assert_wait_and_unlock(SharedEvent);
                        call thread_block(FALSE);
sl_ret_2:               ret_lock[self] := FALSE;
                        return;
                } else {
sl_aw3:                 waitq_unlock(SharedEvent);
                };
        };
}

procedure __vm_entry_lock_shared_wakeup(sw_state)
{
sw_w:   if (sw_state.excl_waiters) {
                call __vm_entry_lock_exclusive_broadcast();
        };

sw_s:   if (sw_state.shared_waiters) {
                call __vm_entry_lock_shared_broadcast(FALSE);
        };

sw_rst: sw_state := defaultInitValue;
sw_end: return;
}

procedure vm_entry_lock_try_shared_to_exclusive()
{
u1:     assert /\ vmelock.valid
               /\ vmelock.read_count # 0
               /\ self \in dbg_vmelock.readers;
        if (vmelock.read_count = 1) {
                dbg_vmelock.owner   := {self} ||
                dbg_vmelock.readers := dbg_vmelock.readers \ {self} ||
                vmelock.excl_locked := TRUE ||
                vmelock.read_count  := 0    ||
                ret_lock[self]      := TRUE;
                return;
        } else {
                dbg_vmelock.readers := dbg_vmelock.readers \ {self} ||
                vmelock.read_count  := vmelock.read_count - 1 ||
                ret_lock[self]      := FALSE;
                return;
        }
}

procedure vm_entry_unlock_shared()
{
us1:    assert /\ vmelock.valid
               /\ vmelock.read_count # 0
               /\ self \in dbg_vmelock.readers;
        dbg_vmelock.readers := dbg_vmelock.readers \ {self} ||
        vmelock.read_count  := vmelock.read_count - 1;
        if (/\ CanLockX(vmelock)
            /\ \/ vmelock.excl_waiters
               \/ vmelock.shared_waiters) {
                call __vm_entry_lock_shared_wakeup(vmelock);
        };
us_end: return;
}

(******************************************************************************)
(* processes                                                                  *)
(******************************************************************************)

fair process (t \in Threads)
{
tmain:  vm_map_ilk_lock_shared();

tloop:  while (vmelock_in_map) {
                either {
rlocktry:               call vm_entry_lock_shared();
rlocktst:               vm_map_ilk_unlock_shared();
                        if (~ret_lock[self]) {
                                goto tagain;
                        };
rcs:                    ret_lock[self] := FALSE;
                        either {
runlock:                        call vm_entry_unlock_shared();
                        } or {
upgradetry:                     call vm_entry_lock_try_shared_to_exclusive();
upgradetst:                     if (~ret_lock[self]) {
                                        goto tagain;
                                };
uwcs:                           ret_lock[self] := FALSE;
uunlock:                        call vm_entry_unlock_exclusive();
                        };
                } or {
wlocktry:               call vm_entry_lock_exclusive(FALSE);
wlocktst:               vm_map_ilk_unlock_shared();
                        if (~ret_lock[self]) {
                                goto tagain;
                        };
wcs:                    ret_lock[self] := FALSE;

                        either {
wunlock:                        call vm_entry_unlock_exclusive();
                        } or {
downgrade:                      call vm_entry_lock_exclusive_to_shared();
drcs:                           skip;
dunlock:                        call vm_entry_unlock_shared();
                        };
                };

tagain:         vm_map_ilk_lock_shared();
        };

tdone:  vm_map_ilk_unlock_shared();
}

fair process (c \in Chaos)
{
cloop:  while (TRUE) either {
abort_x:        if (waitqs[ExclEvent].q # << >>) {
                        ret_blocked := ret_blocked \ {Head(waitqs[ExclEvent].q)} ||
                        waitqs[ExclEvent].q := Tail(waitqs[ExclEvent].q);
                };
        } or {
abort_s:        if (waitqs[SharedEvent].q # << >>) {
                        ret_blocked := ret_blocked \ {Head(waitqs[SharedEvent].q)} ||
                        waitqs[SharedEvent].q := Tail(waitqs[SharedEvent].q);
                };
        } or {
cmain:          vm_map_ilk_lock_exclusive();
clcktry:        call vm_entry_lock_exclusive(TRUE);
clcktst:        if (ret_lock[self]) {
                        (* make the entry impossible to lookup *)
                        vmelock_in_map := FALSE;
                };
cunlock:        vm_map_ilk_unlock_exclusive();
cremove:        if (ret_lock[self]) {
cwcs:                   call vm_entry_unlock_exclusive_and_destroy();
cfree:                  (*
                         * make vmelock of the wrong type, this way any
                         * use-after-free access will cause TLC to trap
                         *)
                        vmelock := defaultInitValue;
                        goto Done;
                };
        };
}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "c599f9a3" /\ chksum(tla) = "1580d182")
CONSTANT defaultInitValue
VARIABLES waitqs, ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
          vmelock_in_map, vmelock, map_lock, dbg_vmelock, pc, stack

(* define statement *)
SharedEvent     == "s"
ExclEvent       == "x"

Events          == { SharedEvent, ExclEvent }

ReadCS          == { "rcs", "drcs" }
WriteCS         == { "wcs", "uwcs", "cwcs" }
AnyCS           == ReadCS \union WriteCS


Range(seq)      == { seq[x] : x \in DOMAIN seq }
Min(a, b)       == IF a < b THEN a ELSE b

Lock16Same(s)   == /\ vmelock.valid = s.valid
                   /\ vmelock.excl_locked = s.excl_locked
                   /\ vmelock.read_count = s.read_count

CanLockS(s)     == /\ s.valid
                   /\ ~s.excl_locked

CanLockX(s)     == /\ s.valid
                   /\ ~s.excl_locked
                   /\ s.read_count = 0


NoError         == \A t \in Threads \union Chaos:
                   pc[t] # "Error"


Exclusion       == \A t1 \in Threads \union Chaos:
                   pc[t1] \in WriteCS => (\A t2 \in Threads \ {t1}: pc[t2] \notin AnyCS)


NoMissingWakeup == \/ ret_blocked = {}
                   \/ \E t \in Threads \ ret_blocked: pc[t] = "block"
                   \/ \E t \in Chaos   \ ret_blocked: pc[t] = "block"
                   \/ \E t \in Threads: pc[t] \notin { "block", "tloop", "Done" }
                   \/ \E t \in Chaos:   pc[t] \notin { "block", "cloop", "Done" }


Perms           == Permutations(Threads)

VARIABLES arg_event_i, arg_event_n, arg_count_n, arg_unlock_n, arg_mode_b, 
          arg_clear, arg_mode_x, xl_state, xw_state, d_state, xd_state, 
          sl_state, sw_state

vars == << waitqs, ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
           vmelock_in_map, vmelock, map_lock, dbg_vmelock, pc, stack, 
           arg_event_i, arg_event_n, arg_count_n, arg_unlock_n, arg_mode_b, 
           arg_clear, arg_mode_x, xl_state, xw_state, d_state, xd_state, 
           sl_state, sw_state >>

ProcSet == (Threads) \cup (Chaos)

Init == (* Global variables *)
        /\ waitqs = [e \in Events   |->
                        [q    |-> <<>>,
                         lock |-> FALSE]]
        /\ ret_blocked = {}
        /\ ret_handoff = {}
        /\ ret_wakeup = [t \in Threads \union Chaos |-> {}]
        /\ ret_lock = [t \in Threads \union Chaos |-> FALSE]
        /\ vmelock_in_map = TRUE
        /\ vmelock = [excl_waiters   |-> FALSE,
                      shared_waiters |-> FALSE,
                      valid          |-> TRUE,
                      excl_locked    |-> FALSE,
                      read_count     |-> 0]
        /\ map_lock = [owner          |-> {},
                       readers        |-> {}]
        /\ dbg_vmelock = [owner          |-> {},
                          readers        |-> {}]
        (* Procedure identify *)
        /\ arg_event_i = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure wakeup_n *)
        /\ arg_event_n = [ self \in ProcSet |-> defaultInitValue]
        /\ arg_count_n = [ self \in ProcSet |-> defaultInitValue]
        /\ arg_unlock_n = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure thread_block *)
        /\ arg_mode_b = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure __vm_entry_lock_shared_broadcast *)
        /\ arg_clear = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure vm_entry_lock_exclusive *)
        /\ arg_mode_x = [ self \in ProcSet |-> defaultInitValue]
        /\ xl_state = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure __vm_entry_lock_exclusive_wakeup *)
        /\ xw_state = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure vm_entry_lock_exclusive_to_shared *)
        /\ d_state = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure vm_entry_unlock_exclusive_and_destroy *)
        /\ xd_state = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure vm_entry_lock_shared *)
        /\ sl_state = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure __vm_entry_lock_shared_wakeup *)
        /\ sw_state = [ self \in ProcSet |-> defaultInitValue]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Threads -> "tmain"
                                        [] self \in Chaos -> "cloop"]

in(self) == /\ pc[self] = "in"
            /\ LET wq_n == waitqs[arg_event_i[self]].q IN
                 /\ IF wq_n = << >>
                       THEN /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = {}]
                            /\ UNCHANGED waitqs
                       ELSE /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = {Head(wq_n)}]
                            /\ waitqs' = [waitqs EXCEPT ![arg_event_i[self]].q = Tail(wq_n)]
                 /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                 /\ arg_event_i' = [arg_event_i EXCEPT ![self] = Head(stack[self]).arg_event_i]
                 /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << ret_blocked, ret_handoff, ret_lock, vmelock_in_map, 
                            vmelock, map_lock, dbg_vmelock, arg_event_n, 
                            arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                            arg_mode_x, xl_state, xw_state, d_state, xd_state, 
                            sl_state, sw_state >>

identify(self) == in(self)

wn(self) == /\ pc[self] = "wn"
            /\ LET wq_n == waitqs[arg_event_n[self]].q IN
                 LET len_n == Len(wq_n) IN
                   LET n_n == Min(arg_count_n[self], len_n) IN
                     /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = { wq_n[x] : x \in 1..n_n }]
                     /\ ret_blocked' = ret_blocked \ ret_wakeup'[self]
                     /\ waitqs' = [waitqs EXCEPT ![arg_event_n[self]] =                        [
                                                                            q    |-> [x \in 1..(len_n - n_n) |-> wq_n[n_n + x]],
                                                                            lock |-> ~arg_unlock_n[self]
                                                                        ]]
                     /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                     /\ arg_event_n' = [arg_event_n EXCEPT ![self] = Head(stack[self]).arg_event_n]
                     /\ arg_count_n' = [arg_count_n EXCEPT ![self] = Head(stack[self]).arg_count_n]
                     /\ arg_unlock_n' = [arg_unlock_n EXCEPT ![self] = Head(stack[self]).arg_unlock_n]
                     /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << ret_handoff, ret_lock, vmelock_in_map, vmelock, 
                            map_lock, dbg_vmelock, arg_event_i, arg_mode_b, 
                            arg_clear, arg_mode_x, xl_state, xw_state, d_state, 
                            xd_state, sl_state, sw_state >>

wakeup_n(self) == wn(self)

bu(self) == /\ pc[self] = "bu"
            /\ IF arg_mode_b[self]
                  THEN /\ map_lock' = [map_lock EXCEPT !.owner = {}]
                  ELSE /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \ {self}]
            /\ pc' = [pc EXCEPT ![self] = "block"]
            /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                            ret_lock, vmelock_in_map, vmelock, dbg_vmelock, 
                            stack, arg_event_i, arg_event_n, arg_count_n, 
                            arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                            xl_state, xw_state, d_state, xd_state, sl_state, 
                            sw_state >>

block(self) == /\ pc[self] = "block"
               /\ self \notin ret_blocked
               /\ pc' = [pc EXCEPT ![self] = "bl"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, map_lock, 
                               dbg_vmelock, stack, arg_event_i, arg_event_n, 
                               arg_count_n, arg_unlock_n, arg_mode_b, 
                               arg_clear, arg_mode_x, xl_state, xw_state, 
                               d_state, xd_state, sl_state, sw_state >>

bl(self) == /\ pc[self] = "bl"
            /\ IF arg_mode_b[self]
                  THEN /\ map_lock.readers = {} /\ map_lock.owner = {}
                       /\ map_lock' = [map_lock EXCEPT !.owner = {self}]
                  ELSE /\ map_lock.owner = {}
                       /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \union {self}]
            /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
            /\ arg_mode_b' = [arg_mode_b EXCEPT ![self] = Head(stack[self]).arg_mode_b]
            /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                            ret_lock, vmelock_in_map, vmelock, dbg_vmelock, 
                            arg_event_i, arg_event_n, arg_count_n, 
                            arg_unlock_n, arg_clear, arg_mode_x, xl_state, 
                            xw_state, d_state, xd_state, sl_state, sw_state >>

thread_block(self) == bu(self) \/ block(self) \/ bl(self)

xb1(self) == /\ pc[self] = "xb1"
             /\ waitqs[ExclEvent].lock = FALSE
             /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = TRUE]
             /\ pc' = [pc EXCEPT ![self] = "xb_end"]
             /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                             vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                             stack, arg_event_i, arg_event_n, arg_count_n, 
                             arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                             xl_state, xw_state, d_state, xd_state, sl_state, 
                             sw_state >>

xb_end(self) == /\ pc[self] = "xb_end"
                /\ LET wq_all == waitqs[ExclEvent].q IN
                     /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = Range(wq_all)]
                     /\ ret_blocked' = ret_blocked \ ret_wakeup'[self]
                     /\ waitqs' = [waitqs EXCEPT ![ExclEvent] =                      [
                                                                    q |-> <<>>,
                                                                    lock |-> ~TRUE
                                                                ]]
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << ret_handoff, ret_lock, vmelock_in_map, vmelock, 
                                map_lock, dbg_vmelock, arg_event_i, 
                                arg_event_n, arg_count_n, arg_unlock_n, 
                                arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                                xw_state, d_state, xd_state, sl_state, 
                                sw_state >>

__vm_entry_lock_exclusive_broadcast(self) == xb1(self) \/ xb_end(self)

sb1(self) == /\ pc[self] = "sb1"
             /\ waitqs[SharedEvent].lock = FALSE
             /\ waitqs' = [waitqs EXCEPT ![SharedEvent].lock = TRUE]
             /\ IF arg_clear[self]
                   THEN /\ vmelock' = [vmelock EXCEPT !.shared_waiters = FALSE]
                   ELSE /\ TRUE
                        /\ UNCHANGED vmelock
             /\ pc' = [pc EXCEPT ![self] = "sb_end"]
             /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                             vmelock_in_map, map_lock, dbg_vmelock, stack, 
                             arg_event_i, arg_event_n, arg_count_n, 
                             arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                             xl_state, xw_state, d_state, xd_state, sl_state, 
                             sw_state >>

sb_end(self) == /\ pc[self] = "sb_end"
                /\ LET wq_all == waitqs[SharedEvent].q IN
                     /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = Range(wq_all)]
                     /\ ret_blocked' = ret_blocked \ ret_wakeup'[self]
                     /\ waitqs' = [waitqs EXCEPT ![SharedEvent] =                      [
                                                                      q |-> <<>>,
                                                                      lock |-> ~TRUE
                                                                  ]]
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ arg_clear' = [arg_clear EXCEPT ![self] = Head(stack[self]).arg_clear]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << ret_handoff, ret_lock, vmelock_in_map, vmelock, 
                                map_lock, dbg_vmelock, arg_event_i, 
                                arg_event_n, arg_count_n, arg_unlock_n, 
                                arg_mode_b, arg_mode_x, xl_state, xw_state, 
                                d_state, xd_state, sl_state, sw_state >>

__vm_entry_lock_shared_broadcast(self) == sb1(self) \/ sb_end(self)

xl_loop(self) == /\ pc[self] = "xl_loop"
                 /\ xl_state' = [xl_state EXCEPT ![self] = vmelock]
                 /\ Assert(xl_state'[self].valid, 
                           "Failure of assertion at line 308, column 17.")
                 /\ pc' = [pc EXCEPT ![self] = "xl_cas"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xw_state, d_state, 
                                 xd_state, sl_state, sw_state >>

xl_cas(self) == /\ pc[self] = "xl_cas"
                /\ IF CanLockX(xl_state[self])
                      THEN /\ IF Lock16Same(xl_state[self])
                                 THEN /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = {self}]
                                         /\ ret_lock' = [ret_lock EXCEPT ![self] = TRUE]
                                         /\ vmelock' = [vmelock EXCEPT !.excl_locked = TRUE]
                                         /\ xl_state' = [xl_state EXCEPT ![self] = defaultInitValue]
                                      /\ pc' = [pc EXCEPT ![self] = "xl_ret_1"]
                                 ELSE /\ pc' = [pc EXCEPT ![self] = "xl_loop"]
                                      /\ UNCHANGED << ret_lock, vmelock, 
                                                      dbg_vmelock, xl_state >>
                      ELSE /\ pc' = [pc EXCEPT ![self] = "xl_set_wait"]
                           /\ UNCHANGED << ret_lock, vmelock, dbg_vmelock, 
                                           xl_state >>
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                vmelock_in_map, map_lock, stack, arg_event_i, 
                                arg_event_n, arg_count_n, arg_unlock_n, 
                                arg_mode_b, arg_clear, arg_mode_x, xw_state, 
                                d_state, xd_state, sl_state, sw_state >>

xl_ret_1(self) == /\ pc[self] = "xl_ret_1"
                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                  /\ xl_state' = [xl_state EXCEPT ![self] = Head(stack[self]).xl_state]
                  /\ arg_mode_x' = [arg_mode_x EXCEPT ![self] = Head(stack[self]).arg_mode_x]
                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, map_lock, 
                                  dbg_vmelock, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, xw_state, d_state, xd_state, 
                                  sl_state, sw_state >>

xl_set_wait(self) == /\ pc[self] = "xl_set_wait"
                     /\ IF xl_state[self].excl_waiters
                           THEN /\ TRUE
                                /\ pc' = [pc EXCEPT ![self] = "xl_aw1"]
                                /\ UNCHANGED vmelock
                           ELSE /\ IF vmelock = xl_state[self]
                                      THEN /\ vmelock' = [vmelock EXCEPT !.excl_waiters = TRUE]
                                           /\ pc' = [pc EXCEPT ![self] = "xl_aw1"]
                                      ELSE /\ pc' = [pc EXCEPT ![self] = "xl_loop"]
                                           /\ UNCHANGED vmelock
                     /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, 
                                     ret_wakeup, ret_lock, vmelock_in_map, 
                                     map_lock, dbg_vmelock, stack, arg_event_i, 
                                     arg_event_n, arg_count_n, arg_unlock_n, 
                                     arg_mode_b, arg_clear, arg_mode_x, 
                                     xl_state, xw_state, d_state, xd_state, 
                                     sl_state, sw_state >>

xl_aw1(self) == /\ pc[self] = "xl_aw1"
                /\ xl_state' = [xl_state EXCEPT ![self] = defaultInitValue]
                /\ waitqs[ExclEvent].lock = FALSE
                /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = TRUE]
                /\ Assert(vmelock.valid, 
                          "Failure of assertion at line 331, column 17.")
                /\ IF vmelock.excl_waiters /\ ~CanLockX(vmelock)
                      THEN /\ pc' = [pc EXCEPT ![self] = "xl_aw2"]
                      ELSE /\ pc' = [pc EXCEPT ![self] = "xl_aw4"]
                /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                stack, arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_mode_b, arg_clear, 
                                arg_mode_x, xw_state, d_state, xd_state, 
                                sl_state, sw_state >>

xl_aw2(self) == /\ pc[self] = "xl_aw2"
                /\ ret_blocked' = (ret_blocked \union {self})
                /\ waitqs' = [waitqs EXCEPT ![ExclEvent] =                  [
                                                               q    |-> Append(waitqs[ExclEvent].q, self),
                                                               lock |-> FALSE
                                                           ]]
                /\ /\ arg_mode_b' = [arg_mode_b EXCEPT ![self] = arg_mode_x[self]]
                   /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "thread_block",
                                                            pc        |->  "xl_aw3",
                                                            arg_mode_b |->  arg_mode_b[self] ] >>
                                                        \o stack[self]]
                /\ pc' = [pc EXCEPT ![self] = "bu"]
                /\ UNCHANGED << ret_handoff, ret_wakeup, ret_lock, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_clear, arg_mode_x, xl_state, 
                                xw_state, d_state, xd_state, sl_state, 
                                sw_state >>

xl_aw3(self) == /\ pc[self] = "xl_aw3"
                /\ /\ ret_handoff' = ret_handoff \ {self}
                   /\ ret_lock' = [ret_lock EXCEPT ![self] = (ret_handoff = {self})]
                /\ pc' = [pc EXCEPT ![self] = "xl_ret_2"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                stack, arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_mode_b, arg_clear, 
                                arg_mode_x, xl_state, xw_state, d_state, 
                                xd_state, sl_state, sw_state >>

xl_ret_2(self) == /\ pc[self] = "xl_ret_2"
                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                  /\ xl_state' = [xl_state EXCEPT ![self] = Head(stack[self]).xl_state]
                  /\ arg_mode_x' = [arg_mode_x EXCEPT ![self] = Head(stack[self]).arg_mode_x]
                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, map_lock, 
                                  dbg_vmelock, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, xw_state, d_state, xd_state, 
                                  sl_state, sw_state >>

xl_aw4(self) == /\ pc[self] = "xl_aw4"
                /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = FALSE]
                /\ pc' = [pc EXCEPT ![self] = "xl_loop"]
                /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                stack, arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_mode_b, arg_clear, 
                                arg_mode_x, xl_state, xw_state, d_state, 
                                xd_state, sl_state, sw_state >>

vm_entry_lock_exclusive(self) == xl_loop(self) \/ xl_cas(self)
                                    \/ xl_ret_1(self) \/ xl_set_wait(self)
                                    \/ xl_aw1(self) \/ xl_aw2(self)
                                    \/ xl_aw3(self) \/ xl_ret_2(self)
                                    \/ xl_aw4(self)

xw_a(self) == /\ pc[self] = "xw_a"
              /\ Assert(/\ vmelock.valid
                        /\ vmelock.excl_locked
                        /\ dbg_vmelock.owner = {self}, 
                        "Failure of assertion at line 346, column 9.")
              /\ pc' = [pc EXCEPT ![self] = "xw_w"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                              ret_lock, vmelock_in_map, vmelock, map_lock, 
                              dbg_vmelock, stack, arg_event_i, arg_event_n, 
                              arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                              arg_mode_x, xl_state, xw_state, d_state, 
                              xd_state, sl_state, sw_state >>

xw_w(self) == /\ pc[self] = "xw_w"
              /\ IF xw_state[self].excl_waiters
                    THEN /\ waitqs[ExclEvent].lock = FALSE
                         /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = TRUE]
                         /\ /\ arg_event_i' = [arg_event_i EXCEPT ![self] = ExclEvent]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "identify",
                                                                     pc        |->  "xw_w1",
                                                                     arg_event_i |->  arg_event_i[self] ] >>
                                                                 \o stack[self]]
                         /\ pc' = [pc EXCEPT ![self] = "in"]
                    ELSE /\ pc' = [pc EXCEPT ![self] = "xw_s"]
                         /\ UNCHANGED << waitqs, stack, arg_event_i >>
              /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                              vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                              arg_event_n, arg_count_n, arg_unlock_n, 
                              arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                              xw_state, d_state, xd_state, sl_state, sw_state >>

xw_w1(self) == /\ pc[self] = "xw_w1"
               /\ IF ret_wakeup[self] # {}
                     THEN /\ pc' = [pc EXCEPT ![self] = "xw_w_success"]
                          /\ UNCHANGED << vmelock, xw_state >>
                     ELSE /\ /\ vmelock' = [vmelock EXCEPT !.excl_waiters = FALSE]
                             /\ xw_state' = [xw_state EXCEPT ![self] =                       [vmelock EXCEPT
                                                                       !.excl_waiters   = FALSE]]
                          /\ pc' = [pc EXCEPT ![self] = "xw_w_fail"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, map_lock, dbg_vmelock, 
                               stack, arg_event_i, arg_event_n, arg_count_n, 
                               arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                               xl_state, d_state, xd_state, sl_state, sw_state >>

xw_w_success(self) == /\ pc[self] = "xw_w_success"
                      /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = FALSE]
                      /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = ret_wakeup[self]]
                         /\ ret_blocked' = ret_blocked \ ret_wakeup[self]
                         /\ ret_handoff' = ret_wakeup[self]
                      /\ pc' = [pc EXCEPT ![self] = "xw_rst"]
                      /\ UNCHANGED << ret_wakeup, ret_lock, vmelock_in_map, 
                                      vmelock, map_lock, stack, arg_event_i, 
                                      arg_event_n, arg_count_n, arg_unlock_n, 
                                      arg_mode_b, arg_clear, arg_mode_x, 
                                      xl_state, xw_state, d_state, xd_state, 
                                      sl_state, sw_state >>

xw_w_fail(self) == /\ pc[self] = "xw_w_fail"
                   /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = FALSE]
                   /\ pc' = [pc EXCEPT ![self] = "xw_s"]
                   /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, 
                                   ret_lock, vmelock_in_map, vmelock, map_lock, 
                                   dbg_vmelock, stack, arg_event_i, 
                                   arg_event_n, arg_count_n, arg_unlock_n, 
                                   arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                                   xw_state, d_state, xd_state, sl_state, 
                                   sw_state >>

xw_s(self) == /\ pc[self] = "xw_s"
              /\ IF xw_state[self].shared_waiters
                    THEN /\ waitqs[SharedEvent].lock = FALSE
                         /\ waitqs' = [waitqs EXCEPT ![SharedEvent].lock = TRUE]
                    ELSE /\ TRUE
                         /\ UNCHANGED waitqs
              /\ IF vmelock # xw_state[self]
                    THEN /\ pc' = [pc EXCEPT ![self] = "xw_s_fail"]
                         /\ UNCHANGED << vmelock, dbg_vmelock >>
                    ELSE /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = {}]
                            /\ vmelock' = [vmelock EXCEPT !.shared_waiters = FALSE,
                                                          !.excl_locked = FALSE,
                                                          !.read_count = 0]
                         /\ pc' = [pc EXCEPT ![self] = "xw_s_success"]
              /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                              vmelock_in_map, map_lock, stack, arg_event_i, 
                              arg_event_n, arg_count_n, arg_unlock_n, 
                              arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                              xw_state, d_state, xd_state, sl_state, sw_state >>

xw_s_fail(self) == /\ pc[self] = "xw_s_fail"
                   /\ IF xw_state[self].shared_waiters
                         THEN /\ waitqs' = [waitqs EXCEPT ![SharedEvent].lock = FALSE]
                         ELSE /\ TRUE
                              /\ UNCHANGED waitqs
                   /\ xw_state' = [xw_state EXCEPT ![self] = vmelock]
                   /\ pc' = [pc EXCEPT ![self] = "xw_a"]
                   /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, 
                                   ret_lock, vmelock_in_map, vmelock, map_lock, 
                                   dbg_vmelock, stack, arg_event_i, 
                                   arg_event_n, arg_count_n, arg_unlock_n, 
                                   arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                                   d_state, xd_state, sl_state, sw_state >>

xw_s_success(self) == /\ pc[self] = "xw_s_success"
                      /\ IF xw_state[self].shared_waiters
                            THEN /\ LET wq_all == waitqs[SharedEvent].q IN
                                      /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = Range(wq_all)]
                                      /\ ret_blocked' = ret_blocked \ ret_wakeup'[self]
                                      /\ waitqs' = [waitqs EXCEPT ![SharedEvent] =                      [
                                                                                       q |-> <<>>,
                                                                                       lock |-> ~TRUE
                                                                                   ]]
                            ELSE /\ TRUE
                                 /\ UNCHANGED << waitqs, ret_blocked, 
                                                 ret_wakeup >>
                      /\ pc' = [pc EXCEPT ![self] = "xw_rst"]
                      /\ UNCHANGED << ret_handoff, ret_lock, vmelock_in_map, 
                                      vmelock, map_lock, dbg_vmelock, stack, 
                                      arg_event_i, arg_event_n, arg_count_n, 
                                      arg_unlock_n, arg_mode_b, arg_clear, 
                                      arg_mode_x, xl_state, xw_state, d_state, 
                                      xd_state, sl_state, sw_state >>

xw_rst(self) == /\ pc[self] = "xw_rst"
                /\ xw_state' = [xw_state EXCEPT ![self] = defaultInitValue]
                /\ pc' = [pc EXCEPT ![self] = "xw_end"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, d_state, 
                                xd_state, sl_state, sw_state >>

xw_end(self) == /\ pc[self] = "xw_end"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ xw_state' = [xw_state EXCEPT ![self] = Head(stack[self]).xw_state]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, d_state, 
                                xd_state, sl_state, sw_state >>

__vm_entry_lock_exclusive_wakeup(self) == xw_a(self) \/ xw_w(self)
                                             \/ xw_w1(self)
                                             \/ xw_w_success(self)
                                             \/ xw_w_fail(self)
                                             \/ xw_s(self)
                                             \/ xw_s_fail(self)
                                             \/ xw_s_success(self)
                                             \/ xw_rst(self)
                                             \/ xw_end(self)

ux1(self) == /\ pc[self] = "ux1"
             /\ IF vmelock.excl_waiters \/ vmelock.shared_waiters
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__vm_entry_lock_exclusive_wakeup",
                                                                    pc        |->  "ux_end",
                                                                    xw_state  |->  xw_state[self] ] >>
                                                                \o stack[self]]
                           /\ xw_state' = [xw_state EXCEPT ![self] = vmelock]
                        /\ pc' = [pc EXCEPT ![self] = "xw_a"]
                        /\ UNCHANGED << vmelock, dbg_vmelock >>
                   ELSE /\ Assert(/\ vmelock.valid
                                  /\ vmelock.excl_locked
                                  /\ dbg_vmelock.owner = {self}, 
                                  "Failure of assertion at line 399, column 17.")
                        /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = {}]
                           /\ vmelock' = [vmelock EXCEPT !.excl_locked = FALSE,
                                                         !.read_count = 0]
                        /\ pc' = [pc EXCEPT ![self] = "ux_end"]
                        /\ UNCHANGED << stack, xw_state >>
             /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                             ret_lock, vmelock_in_map, map_lock, arg_event_i, 
                             arg_event_n, arg_count_n, arg_unlock_n, 
                             arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                             d_state, xd_state, sl_state, sw_state >>

ux_end(self) == /\ pc[self] = "ux_end"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, xw_state, 
                                d_state, xd_state, sl_state, sw_state >>

vm_entry_unlock_exclusive(self) == ux1(self) \/ ux_end(self)

d1(self) == /\ pc[self] = "d1"
            /\ /\ d_state' = [d_state EXCEPT ![self] = [vmelock EXCEPT !.excl_locked = FALSE, !.read_count = 1]]
               /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = {},
                                                     !.readers = {self}]
               /\ vmelock' = [vmelock EXCEPT !.excl_locked = FALSE,
                                             !.read_count = 1]
            /\ pc' = [pc EXCEPT ![self] = "d2"]
            /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                            ret_lock, vmelock_in_map, map_lock, stack, 
                            arg_event_i, arg_event_n, arg_count_n, 
                            arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                            xl_state, xw_state, xd_state, sl_state, sw_state >>

d2(self) == /\ pc[self] = "d2"
            /\ IF d_state[self].shared_waiters /\ ~d_state[self].excl_waiters
                  THEN /\ /\ arg_clear' = [arg_clear EXCEPT ![self] = TRUE]
                          /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__vm_entry_lock_shared_broadcast",
                                                                   pc        |->  "d_rst",
                                                                   arg_clear |->  arg_clear[self] ] >>
                                                               \o stack[self]]
                       /\ pc' = [pc EXCEPT ![self] = "sb1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "d_rst"]
                       /\ UNCHANGED << stack, arg_clear >>
            /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                            ret_lock, vmelock_in_map, vmelock, map_lock, 
                            dbg_vmelock, arg_event_i, arg_event_n, arg_count_n, 
                            arg_unlock_n, arg_mode_b, arg_mode_x, xl_state, 
                            xw_state, d_state, xd_state, sl_state, sw_state >>

d_rst(self) == /\ pc[self] = "d_rst"
               /\ d_state' = [d_state EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "d_end"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, map_lock, 
                               dbg_vmelock, stack, arg_event_i, arg_event_n, 
                               arg_count_n, arg_unlock_n, arg_mode_b, 
                               arg_clear, arg_mode_x, xl_state, xw_state, 
                               xd_state, sl_state, sw_state >>

d_end(self) == /\ pc[self] = "d_end"
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ d_state' = [d_state EXCEPT ![self] = Head(stack[self]).d_state]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, map_lock, 
                               dbg_vmelock, arg_event_i, arg_event_n, 
                               arg_count_n, arg_unlock_n, arg_mode_b, 
                               arg_clear, arg_mode_x, xl_state, xw_state, 
                               xd_state, sl_state, sw_state >>

vm_entry_lock_exclusive_to_shared(self) == d1(self) \/ d2(self)
                                              \/ d_rst(self) \/ d_end(self)

xd(self) == /\ pc[self] = "xd"
            /\ Assert(/\ vmelock.valid
                      /\ vmelock.excl_locked
                      /\ dbg_vmelock.owner = {self}, 
                      "Failure of assertion at line 431, column 9.")
            /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = {}]
               /\ vmelock' = [excl_waiters   |-> FALSE,
                              shared_waiters |-> FALSE,
                              valid          |-> FALSE,
                              excl_locked    |-> FALSE,
                              read_count     |-> 0]
               /\ vmelock_in_map' = FALSE
               /\ xd_state' = [xd_state EXCEPT ![self] = vmelock]
            /\ pc' = [pc EXCEPT ![self] = "xd1"]
            /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                            ret_lock, map_lock, stack, arg_event_i, 
                            arg_event_n, arg_count_n, arg_unlock_n, arg_mode_b, 
                            arg_clear, arg_mode_x, xl_state, xw_state, d_state, 
                            sl_state, sw_state >>

xd1(self) == /\ pc[self] = "xd1"
             /\ IF xd_state[self].excl_waiters
                   THEN /\ waitqs[ExclEvent].lock = FALSE
                        /\ waitqs' = [waitqs EXCEPT ![ExclEvent].lock = TRUE]
                        /\ pc' = [pc EXCEPT ![self] = "xd2"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "xd3"]
                        /\ UNCHANGED waitqs
             /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                             vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                             stack, arg_event_i, arg_event_n, arg_count_n, 
                             arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                             xl_state, xw_state, d_state, xd_state, sl_state, 
                             sw_state >>

xd2(self) == /\ pc[self] = "xd2"
             /\ LET wq_all == waitqs[ExclEvent].q IN
                  /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = Range(wq_all)]
                  /\ ret_blocked' = ret_blocked \ ret_wakeup'[self]
                  /\ waitqs' = [waitqs EXCEPT ![ExclEvent] =                      [
                                                                 q |-> <<>>,
                                                                 lock |-> ~TRUE
                                                             ]]
             /\ pc' = [pc EXCEPT ![self] = "xd3"]
             /\ UNCHANGED << ret_handoff, ret_lock, vmelock_in_map, vmelock, 
                             map_lock, dbg_vmelock, stack, arg_event_i, 
                             arg_event_n, arg_count_n, arg_unlock_n, 
                             arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                             xw_state, d_state, xd_state, sl_state, sw_state >>

xd3(self) == /\ pc[self] = "xd3"
             /\ IF xd_state[self].shared_waiters
                   THEN /\ waitqs[SharedEvent].lock = FALSE
                        /\ waitqs' = [waitqs EXCEPT ![SharedEvent].lock = TRUE]
                        /\ pc' = [pc EXCEPT ![self] = "xd4"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "xd5"]
                        /\ UNCHANGED waitqs
             /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                             vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                             stack, arg_event_i, arg_event_n, arg_count_n, 
                             arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                             xl_state, xw_state, d_state, xd_state, sl_state, 
                             sw_state >>

xd4(self) == /\ pc[self] = "xd4"
             /\ LET wq_all == waitqs[SharedEvent].q IN
                  /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = Range(wq_all)]
                  /\ ret_blocked' = ret_blocked \ ret_wakeup'[self]
                  /\ waitqs' = [waitqs EXCEPT ![SharedEvent] =                      [
                                                                   q |-> <<>>,
                                                                   lock |-> ~TRUE
                                                               ]]
             /\ pc' = [pc EXCEPT ![self] = "xd5"]
             /\ UNCHANGED << ret_handoff, ret_lock, vmelock_in_map, vmelock, 
                             map_lock, dbg_vmelock, stack, arg_event_i, 
                             arg_event_n, arg_count_n, arg_unlock_n, 
                             arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                             xw_state, d_state, xd_state, sl_state, sw_state >>

xd5(self) == /\ pc[self] = "xd5"
             /\ xd_state' = [xd_state EXCEPT ![self] = defaultInitValue]
             /\ pc' = [pc EXCEPT ![self] = "xd_ret"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                             ret_lock, vmelock_in_map, vmelock, map_lock, 
                             dbg_vmelock, stack, arg_event_i, arg_event_n, 
                             arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                             arg_mode_x, xl_state, xw_state, d_state, sl_state, 
                             sw_state >>

xd_ret(self) == /\ pc[self] = "xd_ret"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ xd_state' = [xd_state EXCEPT ![self] = Head(stack[self]).xd_state]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, xw_state, 
                                d_state, sl_state, sw_state >>

vm_entry_unlock_exclusive_and_destroy(self) == xd(self) \/ xd1(self)
                                                  \/ xd2(self) \/ xd3(self)
                                                  \/ xd4(self) \/ xd5(self)
                                                  \/ xd_ret(self)

sl_loop(self) == /\ pc[self] = "sl_loop"
                 /\ sl_state' = [sl_state EXCEPT ![self] = vmelock]
                 /\ Assert(sl_state'[self].valid, 
                           "Failure of assertion at line 478, column 17.")
                 /\ pc' = [pc EXCEPT ![self] = "sl_cas"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sw_state >>

sl_cas(self) == /\ pc[self] = "sl_cas"
                /\ IF CanLockS(sl_state[self])
                      THEN /\ /\ sl_state' = [sl_state EXCEPT ![self] =         [vmelock EXCEPT
                                                                        !.read_count = vmelock.read_count + 1]]
                              /\ vmelock' = [vmelock EXCEPT !.read_count = vmelock.read_count + 1]
                           /\ IF ~CanLockS(sl_state'[self])
                                 THEN /\ pc' = [pc EXCEPT ![self] = "sl_loop"]
                                 ELSE /\ pc' = [pc EXCEPT ![self] = "sl_success"]
                      ELSE /\ pc' = [pc EXCEPT ![self] = "sl_set_wait"]
                           /\ UNCHANGED << vmelock, sl_state >>
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, map_lock, 
                                dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, xw_state, 
                                d_state, xd_state, sw_state >>

sl_success(self) == /\ pc[self] = "sl_success"
                    /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.readers = dbg_vmelock.readers \union {self}]
                       /\ ret_lock' = [ret_lock EXCEPT ![self] = TRUE]
                    /\ IF sl_state[self].shared_waiters /\ ~sl_state[self].excl_waiters
                          THEN /\ /\ arg_clear' = [arg_clear EXCEPT ![self] = TRUE]
                                  /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__vm_entry_lock_shared_broadcast",
                                                                           pc        |->  "sl_ret_1",
                                                                           arg_clear |->  arg_clear[self] ] >>
                                                                       \o stack[self]]
                               /\ pc' = [pc EXCEPT ![self] = "sb1"]
                          ELSE /\ pc' = [pc EXCEPT ![self] = "sl_ret_1"]
                               /\ UNCHANGED << stack, arg_clear >>
                    /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, 
                                    ret_wakeup, vmelock_in_map, vmelock, 
                                    map_lock, arg_event_i, arg_event_n, 
                                    arg_count_n, arg_unlock_n, arg_mode_b, 
                                    arg_mode_x, xl_state, xw_state, d_state, 
                                    xd_state, sl_state, sw_state >>

sl_ret_1(self) == /\ pc[self] = "sl_ret_1"
                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                  /\ sl_state' = [sl_state EXCEPT ![self] = Head(stack[self]).sl_state]
                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, map_lock, 
                                  dbg_vmelock, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, arg_mode_x, xl_state, xw_state, 
                                  d_state, xd_state, sw_state >>

sl_set_wait(self) == /\ pc[self] = "sl_set_wait"
                     /\ IF sl_state[self].shared_waiters
                           THEN /\ TRUE
                                /\ pc' = [pc EXCEPT ![self] = "sl_aw1"]
                                /\ UNCHANGED vmelock
                           ELSE /\ IF vmelock = sl_state[self]
                                      THEN /\ vmelock' = [vmelock EXCEPT !.shared_waiters = TRUE]
                                           /\ pc' = [pc EXCEPT ![self] = "sl_aw1"]
                                      ELSE /\ pc' = [pc EXCEPT ![self] = "sl_loop"]
                                           /\ UNCHANGED vmelock
                     /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, 
                                     ret_wakeup, ret_lock, vmelock_in_map, 
                                     map_lock, dbg_vmelock, stack, arg_event_i, 
                                     arg_event_n, arg_count_n, arg_unlock_n, 
                                     arg_mode_b, arg_clear, arg_mode_x, 
                                     xl_state, xw_state, d_state, xd_state, 
                                     sl_state, sw_state >>

sl_aw1(self) == /\ pc[self] = "sl_aw1"
                /\ sl_state' = [sl_state EXCEPT ![self] = defaultInitValue]
                /\ waitqs[SharedEvent].lock = FALSE
                /\ waitqs' = [waitqs EXCEPT ![SharedEvent].lock = TRUE]
                /\ Assert(vmelock.valid, 
                          "Failure of assertion at line 505, column 17.")
                /\ IF vmelock.shared_waiters /\ ~CanLockX(vmelock)
                      THEN /\ pc' = [pc EXCEPT ![self] = "sl_aw2"]
                      ELSE /\ pc' = [pc EXCEPT ![self] = "sl_aw3"]
                /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                stack, arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_mode_b, arg_clear, 
                                arg_mode_x, xl_state, xw_state, d_state, 
                                xd_state, sw_state >>

sl_aw2(self) == /\ pc[self] = "sl_aw2"
                /\ ret_blocked' = (ret_blocked \union {self})
                /\ waitqs' = [waitqs EXCEPT ![SharedEvent] =                  [
                                                                 q    |-> Append(waitqs[SharedEvent].q, self),
                                                                 lock |-> FALSE
                                                             ]]
                /\ /\ arg_mode_b' = [arg_mode_b EXCEPT ![self] = FALSE]
                   /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "thread_block",
                                                            pc        |->  "sl_ret_2",
                                                            arg_mode_b |->  arg_mode_b[self] ] >>
                                                        \o stack[self]]
                /\ pc' = [pc EXCEPT ![self] = "bu"]
                /\ UNCHANGED << ret_handoff, ret_wakeup, ret_lock, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_clear, arg_mode_x, xl_state, 
                                xw_state, d_state, xd_state, sl_state, 
                                sw_state >>

sl_ret_2(self) == /\ pc[self] = "sl_ret_2"
                  /\ ret_lock' = [ret_lock EXCEPT ![self] = FALSE]
                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                  /\ sl_state' = [sl_state EXCEPT ![self] = Head(stack[self]).sl_state]
                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  vmelock_in_map, vmelock, map_lock, 
                                  dbg_vmelock, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, arg_mode_x, xl_state, xw_state, 
                                  d_state, xd_state, sw_state >>

sl_aw3(self) == /\ pc[self] = "sl_aw3"
                /\ waitqs' = [waitqs EXCEPT ![SharedEvent].lock = FALSE]
                /\ pc' = [pc EXCEPT ![self] = "sl_loop"]
                /\ UNCHANGED << ret_blocked, ret_handoff, ret_wakeup, ret_lock, 
                                vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                                stack, arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_mode_b, arg_clear, 
                                arg_mode_x, xl_state, xw_state, d_state, 
                                xd_state, sl_state, sw_state >>

vm_entry_lock_shared(self) == sl_loop(self) \/ sl_cas(self)
                                 \/ sl_success(self) \/ sl_ret_1(self)
                                 \/ sl_set_wait(self) \/ sl_aw1(self)
                                 \/ sl_aw2(self) \/ sl_ret_2(self)
                                 \/ sl_aw3(self)

sw_w(self) == /\ pc[self] = "sw_w"
              /\ IF sw_state[self].excl_waiters
                    THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__vm_entry_lock_exclusive_broadcast",
                                                                  pc        |->  "sw_s" ] >>
                                                              \o stack[self]]
                         /\ pc' = [pc EXCEPT ![self] = "xb1"]
                    ELSE /\ pc' = [pc EXCEPT ![self] = "sw_s"]
                         /\ stack' = stack
              /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                              ret_lock, vmelock_in_map, vmelock, map_lock, 
                              dbg_vmelock, arg_event_i, arg_event_n, 
                              arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                              arg_mode_x, xl_state, xw_state, d_state, 
                              xd_state, sl_state, sw_state >>

sw_s(self) == /\ pc[self] = "sw_s"
              /\ IF sw_state[self].shared_waiters
                    THEN /\ /\ arg_clear' = [arg_clear EXCEPT ![self] = FALSE]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__vm_entry_lock_shared_broadcast",
                                                                     pc        |->  "sw_rst",
                                                                     arg_clear |->  arg_clear[self] ] >>
                                                                 \o stack[self]]
                         /\ pc' = [pc EXCEPT ![self] = "sb1"]
                    ELSE /\ pc' = [pc EXCEPT ![self] = "sw_rst"]
                         /\ UNCHANGED << stack, arg_clear >>
              /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                              ret_lock, vmelock_in_map, vmelock, map_lock, 
                              dbg_vmelock, arg_event_i, arg_event_n, 
                              arg_count_n, arg_unlock_n, arg_mode_b, 
                              arg_mode_x, xl_state, xw_state, d_state, 
                              xd_state, sl_state, sw_state >>

sw_rst(self) == /\ pc[self] = "sw_rst"
                /\ sw_state' = [sw_state EXCEPT ![self] = defaultInitValue]
                /\ pc' = [pc EXCEPT ![self] = "sw_end"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, xw_state, 
                                d_state, xd_state, sl_state >>

sw_end(self) == /\ pc[self] = "sw_end"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ sw_state' = [sw_state EXCEPT ![self] = Head(stack[self]).sw_state]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, xw_state, 
                                d_state, xd_state, sl_state >>

__vm_entry_lock_shared_wakeup(self) == sw_w(self) \/ sw_s(self)
                                          \/ sw_rst(self) \/ sw_end(self)

u1(self) == /\ pc[self] = "u1"
            /\ Assert(/\ vmelock.valid
                      /\ vmelock.read_count # 0
                      /\ self \in dbg_vmelock.readers, 
                      "Failure of assertion at line 533, column 9.")
            /\ IF vmelock.read_count = 1
                  THEN /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.owner = {self},
                                                                !.readers = dbg_vmelock.readers \ {self}]
                          /\ ret_lock' = [ret_lock EXCEPT ![self] = TRUE]
                          /\ vmelock' = [vmelock EXCEPT !.excl_locked = TRUE,
                                                        !.read_count = 0]
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  ELSE /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.readers = dbg_vmelock.readers \ {self}]
                          /\ ret_lock' = [ret_lock EXCEPT ![self] = FALSE]
                          /\ vmelock' = [vmelock EXCEPT !.read_count = vmelock.read_count - 1]
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                            vmelock_in_map, map_lock, arg_event_i, arg_event_n, 
                            arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                            arg_mode_x, xl_state, xw_state, d_state, xd_state, 
                            sl_state, sw_state >>

vm_entry_lock_try_shared_to_exclusive(self) == u1(self)

us1(self) == /\ pc[self] = "us1"
             /\ Assert(/\ vmelock.valid
                       /\ vmelock.read_count # 0
                       /\ self \in dbg_vmelock.readers, 
                       "Failure of assertion at line 553, column 9.")
             /\ /\ dbg_vmelock' = [dbg_vmelock EXCEPT !.readers = dbg_vmelock.readers \ {self}]
                /\ vmelock' = [vmelock EXCEPT !.read_count = vmelock.read_count - 1]
             /\ IF /\ CanLockX(vmelock')
                   /\ \/ vmelock'.excl_waiters
                      \/ vmelock'.shared_waiters
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__vm_entry_lock_shared_wakeup",
                                                                    pc        |->  "us_end",
                                                                    sw_state  |->  sw_state[self] ] >>
                                                                \o stack[self]]
                           /\ sw_state' = [sw_state EXCEPT ![self] = vmelock']
                        /\ pc' = [pc EXCEPT ![self] = "sw_w"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "us_end"]
                        /\ UNCHANGED << stack, sw_state >>
             /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                             ret_lock, vmelock_in_map, map_lock, arg_event_i, 
                             arg_event_n, arg_count_n, arg_unlock_n, 
                             arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                             xw_state, d_state, xd_state, sl_state >>

us_end(self) == /\ pc[self] = "us_end"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, map_lock, 
                                dbg_vmelock, arg_event_i, arg_event_n, 
                                arg_count_n, arg_unlock_n, arg_mode_b, 
                                arg_clear, arg_mode_x, xl_state, xw_state, 
                                d_state, xd_state, sl_state, sw_state >>

vm_entry_unlock_shared(self) == us1(self) \/ us_end(self)

tmain(self) == /\ pc[self] = "tmain"
               /\ map_lock.owner = {}
               /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \union {self}]
               /\ pc' = [pc EXCEPT ![self] = "tloop"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, dbg_vmelock, 
                               stack, arg_event_i, arg_event_n, arg_count_n, 
                               arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                               xl_state, xw_state, d_state, xd_state, sl_state, 
                               sw_state >>

tloop(self) == /\ pc[self] = "tloop"
               /\ IF vmelock_in_map
                     THEN /\ \/ /\ pc' = [pc EXCEPT ![self] = "rlocktry"]
                             \/ /\ pc' = [pc EXCEPT ![self] = "wlocktry"]
                     ELSE /\ pc' = [pc EXCEPT ![self] = "tdone"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, map_lock, 
                               dbg_vmelock, stack, arg_event_i, arg_event_n, 
                               arg_count_n, arg_unlock_n, arg_mode_b, 
                               arg_clear, arg_mode_x, xl_state, xw_state, 
                               d_state, xd_state, sl_state, sw_state >>

tagain(self) == /\ pc[self] = "tagain"
                /\ map_lock.owner = {}
                /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \union {self}]
                /\ pc' = [pc EXCEPT ![self] = "tloop"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                ret_lock, vmelock_in_map, vmelock, dbg_vmelock, 
                                stack, arg_event_i, arg_event_n, arg_count_n, 
                                arg_unlock_n, arg_mode_b, arg_clear, 
                                arg_mode_x, xl_state, xw_state, d_state, 
                                xd_state, sl_state, sw_state >>

rlocktry(self) == /\ pc[self] = "rlocktry"
                  /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_lock_shared",
                                                           pc        |->  "rlocktst",
                                                           sl_state  |->  sl_state[self] ] >>
                                                       \o stack[self]]
                  /\ sl_state' = [sl_state EXCEPT ![self] = defaultInitValue]
                  /\ pc' = [pc EXCEPT ![self] = "sl_loop"]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, map_lock, 
                                  dbg_vmelock, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, arg_mode_x, xl_state, xw_state, 
                                  d_state, xd_state, sw_state >>

rlocktst(self) == /\ pc[self] = "rlocktst"
                  /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \ {self}]
                  /\ IF ~ret_lock[self]
                        THEN /\ pc' = [pc EXCEPT ![self] = "tagain"]
                        ELSE /\ pc' = [pc EXCEPT ![self] = "rcs"]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, 
                                  dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, arg_mode_x, xl_state, xw_state, 
                                  d_state, xd_state, sl_state, sw_state >>

rcs(self) == /\ pc[self] = "rcs"
             /\ ret_lock' = [ret_lock EXCEPT ![self] = FALSE]
             /\ \/ /\ pc' = [pc EXCEPT ![self] = "runlock"]
                \/ /\ pc' = [pc EXCEPT ![self] = "upgradetry"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                             vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                             stack, arg_event_i, arg_event_n, arg_count_n, 
                             arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                             xl_state, xw_state, d_state, xd_state, sl_state, 
                             sw_state >>

runlock(self) == /\ pc[self] = "runlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_unlock_shared",
                                                          pc        |->  "tagain" ] >>
                                                      \o stack[self]]
                 /\ pc' = [pc EXCEPT ![self] = "us1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

upgradetry(self) == /\ pc[self] = "upgradetry"
                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_lock_try_shared_to_exclusive",
                                                             pc        |->  "upgradetst" ] >>
                                                         \o stack[self]]
                    /\ pc' = [pc EXCEPT ![self] = "u1"]
                    /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, 
                                    ret_wakeup, ret_lock, vmelock_in_map, 
                                    vmelock, map_lock, dbg_vmelock, 
                                    arg_event_i, arg_event_n, arg_count_n, 
                                    arg_unlock_n, arg_mode_b, arg_clear, 
                                    arg_mode_x, xl_state, xw_state, d_state, 
                                    xd_state, sl_state, sw_state >>

upgradetst(self) == /\ pc[self] = "upgradetst"
                    /\ IF ~ret_lock[self]
                          THEN /\ pc' = [pc EXCEPT ![self] = "tagain"]
                          ELSE /\ pc' = [pc EXCEPT ![self] = "uwcs"]
                    /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, 
                                    ret_wakeup, ret_lock, vmelock_in_map, 
                                    vmelock, map_lock, dbg_vmelock, stack, 
                                    arg_event_i, arg_event_n, arg_count_n, 
                                    arg_unlock_n, arg_mode_b, arg_clear, 
                                    arg_mode_x, xl_state, xw_state, d_state, 
                                    xd_state, sl_state, sw_state >>

uwcs(self) == /\ pc[self] = "uwcs"
              /\ ret_lock' = [ret_lock EXCEPT ![self] = FALSE]
              /\ pc' = [pc EXCEPT ![self] = "uunlock"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                              vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                              stack, arg_event_i, arg_event_n, arg_count_n, 
                              arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                              xl_state, xw_state, d_state, xd_state, sl_state, 
                              sw_state >>

uunlock(self) == /\ pc[self] = "uunlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_unlock_exclusive",
                                                          pc        |->  "tagain" ] >>
                                                      \o stack[self]]
                 /\ pc' = [pc EXCEPT ![self] = "ux1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

wlocktry(self) == /\ pc[self] = "wlocktry"
                  /\ /\ arg_mode_x' = [arg_mode_x EXCEPT ![self] = FALSE]
                     /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_lock_exclusive",
                                                              pc        |->  "wlocktst",
                                                              xl_state  |->  xl_state[self],
                                                              arg_mode_x |->  arg_mode_x[self] ] >>
                                                          \o stack[self]]
                  /\ xl_state' = [xl_state EXCEPT ![self] = defaultInitValue]
                  /\ pc' = [pc EXCEPT ![self] = "xl_loop"]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, map_lock, 
                                  dbg_vmelock, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, xw_state, d_state, xd_state, 
                                  sl_state, sw_state >>

wlocktst(self) == /\ pc[self] = "wlocktst"
                  /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \ {self}]
                  /\ IF ~ret_lock[self]
                        THEN /\ pc' = [pc EXCEPT ![self] = "tagain"]
                        ELSE /\ pc' = [pc EXCEPT ![self] = "wcs"]
                  /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                  ret_lock, vmelock_in_map, vmelock, 
                                  dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                  arg_count_n, arg_unlock_n, arg_mode_b, 
                                  arg_clear, arg_mode_x, xl_state, xw_state, 
                                  d_state, xd_state, sl_state, sw_state >>

wcs(self) == /\ pc[self] = "wcs"
             /\ ret_lock' = [ret_lock EXCEPT ![self] = FALSE]
             /\ \/ /\ pc' = [pc EXCEPT ![self] = "wunlock"]
                \/ /\ pc' = [pc EXCEPT ![self] = "downgrade"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                             vmelock_in_map, vmelock, map_lock, dbg_vmelock, 
                             stack, arg_event_i, arg_event_n, arg_count_n, 
                             arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                             xl_state, xw_state, d_state, xd_state, sl_state, 
                             sw_state >>

wunlock(self) == /\ pc[self] = "wunlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_unlock_exclusive",
                                                          pc        |->  "tagain" ] >>
                                                      \o stack[self]]
                 /\ pc' = [pc EXCEPT ![self] = "ux1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

downgrade(self) == /\ pc[self] = "downgrade"
                   /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_lock_exclusive_to_shared",
                                                            pc        |->  "drcs",
                                                            d_state   |->  d_state[self] ] >>
                                                        \o stack[self]]
                   /\ d_state' = [d_state EXCEPT ![self] = defaultInitValue]
                   /\ pc' = [pc EXCEPT ![self] = "d1"]
                   /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, 
                                   ret_wakeup, ret_lock, vmelock_in_map, 
                                   vmelock, map_lock, dbg_vmelock, arg_event_i, 
                                   arg_event_n, arg_count_n, arg_unlock_n, 
                                   arg_mode_b, arg_clear, arg_mode_x, xl_state, 
                                   xw_state, xd_state, sl_state, sw_state >>

drcs(self) == /\ pc[self] = "drcs"
              /\ TRUE
              /\ pc' = [pc EXCEPT ![self] = "dunlock"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                              ret_lock, vmelock_in_map, vmelock, map_lock, 
                              dbg_vmelock, stack, arg_event_i, arg_event_n, 
                              arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                              arg_mode_x, xl_state, xw_state, d_state, 
                              xd_state, sl_state, sw_state >>

dunlock(self) == /\ pc[self] = "dunlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_unlock_shared",
                                                          pc        |->  "tagain" ] >>
                                                      \o stack[self]]
                 /\ pc' = [pc EXCEPT ![self] = "us1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

tdone(self) == /\ pc[self] = "tdone"
               /\ map_lock' = [map_lock EXCEPT !.readers = map_lock.readers \ {self}]
               /\ pc' = [pc EXCEPT ![self] = "Done"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, dbg_vmelock, 
                               stack, arg_event_i, arg_event_n, arg_count_n, 
                               arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                               xl_state, xw_state, d_state, xd_state, sl_state, 
                               sw_state >>

t(self) == tmain(self) \/ tloop(self) \/ tagain(self) \/ rlocktry(self)
              \/ rlocktst(self) \/ rcs(self) \/ runlock(self)
              \/ upgradetry(self) \/ upgradetst(self) \/ uwcs(self)
              \/ uunlock(self) \/ wlocktry(self) \/ wlocktst(self)
              \/ wcs(self) \/ wunlock(self) \/ downgrade(self)
              \/ drcs(self) \/ dunlock(self) \/ tdone(self)

cloop(self) == /\ pc[self] = "cloop"
               /\ \/ /\ pc' = [pc EXCEPT ![self] = "abort_x"]
                  \/ /\ pc' = [pc EXCEPT ![self] = "abort_s"]
                  \/ /\ pc' = [pc EXCEPT ![self] = "cmain"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, map_lock, 
                               dbg_vmelock, stack, arg_event_i, arg_event_n, 
                               arg_count_n, arg_unlock_n, arg_mode_b, 
                               arg_clear, arg_mode_x, xl_state, xw_state, 
                               d_state, xd_state, sl_state, sw_state >>

abort_x(self) == /\ pc[self] = "abort_x"
                 /\ IF waitqs[ExclEvent].q # << >>
                       THEN /\ /\ ret_blocked' = ret_blocked \ {Head(waitqs[ExclEvent].q)}
                               /\ waitqs' = [waitqs EXCEPT ![ExclEvent].q = Tail(waitqs[ExclEvent].q)]
                       ELSE /\ TRUE
                            /\ UNCHANGED << waitqs, ret_blocked >>
                 /\ pc' = [pc EXCEPT ![self] = "cloop"]
                 /\ UNCHANGED << ret_handoff, ret_wakeup, ret_lock, 
                                 vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

abort_s(self) == /\ pc[self] = "abort_s"
                 /\ IF waitqs[SharedEvent].q # << >>
                       THEN /\ /\ ret_blocked' = ret_blocked \ {Head(waitqs[SharedEvent].q)}
                               /\ waitqs' = [waitqs EXCEPT ![SharedEvent].q = Tail(waitqs[SharedEvent].q)]
                       ELSE /\ TRUE
                            /\ UNCHANGED << waitqs, ret_blocked >>
                 /\ pc' = [pc EXCEPT ![self] = "cloop"]
                 /\ UNCHANGED << ret_handoff, ret_wakeup, ret_lock, 
                                 vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

cmain(self) == /\ pc[self] = "cmain"
               /\ map_lock.readers = {} /\ map_lock.owner = {}
               /\ map_lock' = [map_lock EXCEPT !.owner = {self}]
               /\ pc' = [pc EXCEPT ![self] = "clcktry"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, vmelock, dbg_vmelock, 
                               stack, arg_event_i, arg_event_n, arg_count_n, 
                               arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                               xl_state, xw_state, d_state, xd_state, sl_state, 
                               sw_state >>

clcktry(self) == /\ pc[self] = "clcktry"
                 /\ /\ arg_mode_x' = [arg_mode_x EXCEPT ![self] = TRUE]
                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_lock_exclusive",
                                                             pc        |->  "clcktst",
                                                             xl_state  |->  xl_state[self],
                                                             arg_mode_x |->  arg_mode_x[self] ] >>
                                                         \o stack[self]]
                 /\ xl_state' = [xl_state EXCEPT ![self] = defaultInitValue]
                 /\ pc' = [pc EXCEPT ![self] = "xl_loop"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, xw_state, d_state, xd_state, 
                                 sl_state, sw_state >>

clcktst(self) == /\ pc[self] = "clcktst"
                 /\ IF ret_lock[self]
                       THEN /\ vmelock_in_map' = FALSE
                       ELSE /\ TRUE
                            /\ UNCHANGED vmelock_in_map
                 /\ pc' = [pc EXCEPT ![self] = "cunlock"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock, map_lock, dbg_vmelock, 
                                 stack, arg_event_i, arg_event_n, arg_count_n, 
                                 arg_unlock_n, arg_mode_b, arg_clear, 
                                 arg_mode_x, xl_state, xw_state, d_state, 
                                 xd_state, sl_state, sw_state >>

cunlock(self) == /\ pc[self] = "cunlock"
                 /\ map_lock' = [map_lock EXCEPT !.owner = {}]
                 /\ pc' = [pc EXCEPT ![self] = "cremove"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, 
                                 dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

cremove(self) == /\ pc[self] = "cremove"
                 /\ IF ret_lock[self]
                       THEN /\ pc' = [pc EXCEPT ![self] = "cwcs"]
                       ELSE /\ pc' = [pc EXCEPT ![self] = "cloop"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                                 ret_lock, vmelock_in_map, vmelock, map_lock, 
                                 dbg_vmelock, stack, arg_event_i, arg_event_n, 
                                 arg_count_n, arg_unlock_n, arg_mode_b, 
                                 arg_clear, arg_mode_x, xl_state, xw_state, 
                                 d_state, xd_state, sl_state, sw_state >>

cwcs(self) == /\ pc[self] = "cwcs"
              /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "vm_entry_unlock_exclusive_and_destroy",
                                                       pc        |->  "cfree",
                                                       xd_state  |->  xd_state[self] ] >>
                                                   \o stack[self]]
              /\ xd_state' = [xd_state EXCEPT ![self] = defaultInitValue]
              /\ pc' = [pc EXCEPT ![self] = "xd"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                              ret_lock, vmelock_in_map, vmelock, map_lock, 
                              dbg_vmelock, arg_event_i, arg_event_n, 
                              arg_count_n, arg_unlock_n, arg_mode_b, arg_clear, 
                              arg_mode_x, xl_state, xw_state, d_state, 
                              sl_state, sw_state >>

cfree(self) == /\ pc[self] = "cfree"
               /\ vmelock' = defaultInitValue
               /\ pc' = [pc EXCEPT ![self] = "Done"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_handoff, ret_wakeup, 
                               ret_lock, vmelock_in_map, map_lock, dbg_vmelock, 
                               stack, arg_event_i, arg_event_n, arg_count_n, 
                               arg_unlock_n, arg_mode_b, arg_clear, arg_mode_x, 
                               xl_state, xw_state, d_state, xd_state, sl_state, 
                               sw_state >>

c(self) == cloop(self) \/ abort_x(self) \/ abort_s(self) \/ cmain(self)
              \/ clcktry(self) \/ clcktst(self) \/ cunlock(self)
              \/ cremove(self) \/ cwcs(self) \/ cfree(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in ProcSet:  \/ identify(self) \/ wakeup_n(self)
                               \/ thread_block(self)
                               \/ __vm_entry_lock_exclusive_broadcast(self)
                               \/ __vm_entry_lock_shared_broadcast(self)
                               \/ vm_entry_lock_exclusive(self)
                               \/ __vm_entry_lock_exclusive_wakeup(self)
                               \/ vm_entry_unlock_exclusive(self)
                               \/ vm_entry_lock_exclusive_to_shared(self)
                               \/ vm_entry_unlock_exclusive_and_destroy(self)
                               \/ vm_entry_lock_shared(self)
                               \/ __vm_entry_lock_shared_wakeup(self)
                               \/ vm_entry_lock_try_shared_to_exclusive(self)
                               \/ vm_entry_unlock_shared(self))
           \/ (\E self \in Threads: t(self))
           \/ (\E self \in Chaos: c(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Next)
        /\ \A self \in Threads : /\ WF_vars(t(self))
                                 /\ WF_vars(vm_entry_lock_shared(self))
                                 /\ WF_vars(vm_entry_unlock_shared(self))
                                 /\ WF_vars(vm_entry_lock_try_shared_to_exclusive(self))                                 /\ WF_vars(vm_entry_unlock_exclusive(self))
                                 /\ WF_vars(vm_entry_lock_exclusive(self))
                                 /\ WF_vars(vm_entry_lock_exclusive_to_shared(self))                                 /\ WF_vars(thread_block(self))
                                 /\ WF_vars(__vm_entry_lock_shared_broadcast(self))                                 /\ WF_vars(__vm_entry_lock_exclusive_broadcast(self))                                 /\ WF_vars(__vm_entry_lock_shared_wakeup(self))                                 /\ WF_vars(identify(self))
                                 /\ WF_vars(__vm_entry_lock_exclusive_wakeup(self))
        /\ \A self \in Chaos : /\ WF_vars(c(self))
                               /\ WF_vars(vm_entry_lock_exclusive(self))
                               /\ WF_vars(vm_entry_unlock_exclusive_and_destroy(self))                               /\ WF_vars(thread_block(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

(*
 * In order to speed up TLC, eliminate variables that do not meaningfully
 * contribute to state. View must be the same as "vars" but for:
 *
 * - arg_* variables which are copies of the state passed to procedures
 *   for the sake of argument passing and as a result do not matter;
 *
 * - ret_* variables which similarly are used for return value calling
 *   conventions only and are completely derived from values already part
 *   of the state.
 *
 * There is no programatic way to generate this definition unfortunately,
 * so when updating this model, this must be done by hand.
 *)
View == << waitqs, vmelock, vmelock_in_map, map_lock, pc, stack,
           xl_state, xw_state, d_state, xd_state,
           sl_state, sw_state >>

====
\* vim:et sw=8 ts=8 tw=80:
