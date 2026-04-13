---- MODULE rwlock ----
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

CONSTANTS Threads, Urgent, XBias


(* --fair algorithm rwlock {

variables
        (*** wait queues variables ***)
        waitqs          = [e \in Events  |->
                              [q    |-> <<>>,
                               lock |-> FALSE]];        \* a map of events to wait queues
        ret_blocked     = {};                           \* blocked threads
        ret_wakeup      = [t \in Threads |-> 0];
        ret_identify    = [t \in Threads |-> {}];

        (*** try lock return values ***)
        ret_try_u       = [t \in Threads |-> FALSE];
        ret_try_wx      = [t \in Threads |-> FALSE];

        (*** our rwlock ***)
        rwlock          = [
                           (*
                            * Tracking the owner and readers is a debugging
                            * aid for when the model spews an invalid state.
                            *
                            * The model doesn't check them, and will pretend
                            * updating their values is atomic in order
                            * to reduce transitions.
                            *)
                           (*
                           owner         |-> {},
                           readers       |-> {},
                           *)
                           s_waiters     |-> FALSE,
                           u_waiter      |-> FALSE,
                           x_waiters     |-> FALSE,
                           x_urgent      |-> FALSE,
                           u_wanted      |-> FALSE,
                           x_locked      |-> FALSE,
                           r_count       |-> 0];

define {
        \* derived constants
        ReadEvent       == "r"
        WriteEvent      == "w"
        UpgradeEvent    == "u"

        Events          == { ReadEvent, WriteEvent, UpgradeEvent }

        ReadCS          == { "rcs", "urcs", "drcs" }
        WriteCS         == { "wcs", "uwcs", "dwcs" }
        AnyCS           == ReadCS \union WriteCS

        \* predicates
        Range(seq)      == { seq[x] : x \in DOMAIN seq }
        Min(a, b)       == IF a < b THEN a ELSE b

        \* Invariants
        ParamsCorrect   == Urgent \subseteq Threads

        \* Safety
        Exclusion       == \A t1 \in Threads:
                           pc[t1] \in WriteCS => (\A t2 \in Threads \ {t1}: pc[t2] \notin AnyCS)

        \* Liveness
        NoMissingWakeup == \/ ret_blocked = {}
                           \/ \E t \in Threads \ ret_blocked: pc[t] = "block"
                           \/ \E t \in Threads: pc[t] \notin { "block", "rloop", "xloop", "uloop", "dloop" }

        \* Symmetry
        Perms           == Permutations(Threads)
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
                ret_blocked := ret_blocked \ Range(wq_all);
                waitqs[event_all] := [
                    q |-> <<>>,
                    lock |-> ~unlock_all
                ];
        }
}

(*!
 * @abstract
 * similar to waitq_wakeup64_identify_locked().
 *
 * @param event_all     The event for which to wake up all waiters.
 * @param unlock_all    Whether to unlock the corresponding global wait queue
 *                      upon return.
 *)
procedure identify(arg_event_i)
{
i1:     with (wq_n = waitqs[arg_event_i].q, len_n = Len(wq_n)) {
                if (len_n # 0) {
                        ret_identify[self] := ret_identify[self] \union { wq_n[1] };
                        waitqs[arg_event_i] := [
                            q    |-> [x \in 1..(len_n - 1) |-> wq_n[1 + x]],
                            lock |-> TRUE
                        ];
                };
                return;
        }
}

(*!
 * @abstract
 * similar to waitq_resume_identified_thread().
 *)
procedure resume()
{
r1:     ret_blocked := ret_blocked \ ret_identify[self] ||
        ret_identify[self] := {};
        return;
}

(*!
 * @abstract
 * similar to waitq_wakeup64_nthreads_locked()
 *
 * @param arg_event_n   The event for which to wake up some waiters.
 * @param arg_unlock_n  Whether to unlock the corresponding global wait queue
 *                      upon return.
 * @returns             Via ret_wakeup[self]: the number of threads woken up.
 *)
procedure wakeup_1(arg_event_n, arg_unlock_n)
{
wn:     with (wq_n = waitqs[arg_event_n].q,
            len_n = Len(wq_n),
            n_n = Min(1, len_n)) {
                ret_wakeup[self] := n_n;
                ret_blocked := ret_blocked \ { wq_n[x] : x \in 1..n_n };
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
procedure thread_block()
{
block:  await self \notin ret_blocked;
        return;
}

(******************************************************************************)
(* lck_rw_wakeup()                                                            *)
(******************************************************************************)

procedure lck_rw_wakeup_x(xw_word)
{
xw1:    waitq_lock(WriteEvent);
        call identify(WriteEvent);

xw2:    ret_try_wx[self] := ret_identify[self] # {};
        if (~ret_try_wx[self]) {
                waitq_unlock(WriteEvent);
                goto xw_rst;
        };

xw3:    if (~xw_word.x_urgent) {
                call identify(WriteEvent);
        };

xw4:    if (xw_word.x_urgent \/ Len(waitqs[WriteEvent].q) = 0) {
                rwlock.x_urgent := FALSE ||
                rwlock.x_waiters := FALSE;
        };

xw5:    if (xw_word.x_urgent) {
                wakeup_all(WriteEvent, TRUE);
        } else {
                waitq_unlock(WriteEvent);
        };
        call resume();

xw_rst: xw_word := defaultInitValue;
xw_ret: return;
}

procedure lck_rw_wakeup_s()
{
sw1:    waitq_lock(ReadEvent);
        call identify(ReadEvent);

sw2:    if (ret_identify[self] # {}) {
                rwlock.s_waiters := FALSE;
        };

sw3:    wakeup_all(ReadEvent, TRUE);
        call resume();
sw_ret: return;
}

procedure lck_rw_wakeup_u()
{
uw1:    waitq_lock(UpgradeEvent);
        call identify(UpgradeEvent);

uw2:    if (ret_identify[self] # {}) {
                rwlock.u_waiter := FALSE;
        };

uw3:    waitq_unlock(UpgradeEvent);
        call resume();
uw_ret: return;
}

procedure lck_rw_wakeup(arg_w_word)
{
w1:     if (arg_w_word.u_wanted /\ ~arg_w_word.u_waiter) {
                return;
        } else if (arg_w_word.u_wanted) {
                call lck_rw_wakeup_u();
                return;
        } else if (~XBias /\ arg_w_word.s_waiters) {
                call lck_rw_wakeup_s();
                return;
        } else if (arg_w_word.x_waiters /\ arg_w_word.r_count > 0) {
                return;
        } else if (arg_w_word.x_waiters) {
w2:             call lck_rw_wakeup_x(arg_w_word);
w3:             if (ret_try_wx[self]) {
                        return;
                };
        };

w4:     if (arg_w_word.s_waiters) {
                call lck_rw_wakeup_s();
                return;
        };

w_end:  return;
}
(******************************************************************************)
(* lck_rw_{lock,try_lock,unlock}_exclusive()                                  *)
(******************************************************************************)

procedure lck_rw_lock_exclusive()
        (*
         * atomic snapshot of the rwlock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable xl_word;
{
        (*
         * We only implement the slowpath here, this function is morally
         * equivalent lck_rw_lock_x_contended().
         *
         * The fastpath is just doing "s_cas" outside of the slowpath
         * for performance reasons but doesn't change the state machine.
         * As a result, we elide it and reduce the space TLC has to cover.
         *)
x_loop:  while (TRUE) {
                xl_word := rwlock;
x_cas:          if (~xl_word.u_wanted /\ ~xl_word.x_locked /\ xl_word.r_count = 0) {
                        if (xl_word = rwlock) {
                                xl_word := defaultInitValue;
                                \* rwlock.owner := {self} ||
                                rwlock.x_locked := TRUE;
x_ret:                          return;
                        } else {
                                goto x_loop;
                        }
                };

x_aw1:          waitq_lock(WriteEvent);
                xl_word := rwlock;

x_aw2:          if (self \in Urgent) {
                        if (~xl_word.u_wanted /\ ~xl_word.x_locked /\ xl_word.r_count = 0) {
                                goto x_unlock;
                        } else if (xl_word.x_urgent /\ xl_word.x_waiters) {
                                goto x_block;
                        } else if (rwlock = xl_word) {
                                rwlock.x_waiters := TRUE ||
                                rwlock.x_urgent := TRUE;
                                goto x_block;
                        } else {
                                goto x_unlock;
                        };
                } else {
                        if (~xl_word.u_wanted /\ ~xl_word.x_locked /\ xl_word.r_count = 0) {
                                goto x_unlock;
                        } else if (xl_word.x_waiters) {
                                goto x_block;
                        } else if (xl_word = rwlock) {
                                rwlock.x_waiters := TRUE;
                                goto x_block;
                        } else {
                                goto x_unlock;
                        }
                };

x_unlock:       xl_word := defaultInitValue;
                waitq_unlock(WriteEvent);
                goto x_loop;

x_block:        xl_word := defaultInitValue;
                assert_wait_and_unlock(WriteEvent);
                call thread_block();
        };
}

procedure lck_rw_unlock_exclusive()
        (*
         * atomic snapshot of the rwlock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable xu_word;
{
ux1:    \* rwlock.owner := {} ||
        \* atomic_andnot(.lock32 = ~0)
        rwlock.x_locked := FALSE ||
        rwlock.u_wanted := FALSE ||
        rwlock.r_count  := 0 ||
        xu_word := rwlock;

ux3:    if (xu_word.s_waiters \/ xu_word.u_waiter \/ xu_word.x_waiters) {
                call lck_rw_wakeup(xu_word);
        };
ux_rst: xu_word := defaultInitValue;
ux_end: return;
}

procedure lck_rw_lock_exclusive_to_shared()
        (*
         * atomic snapshot of the rwlock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable d_word;
{
d1:     \* rwlock.owner := {} ||
        \* rwlock.readers := rwlock.readers \union {self} ||
        rwlock.x_locked := FALSE ||
        rwlock.r_count  := 1 ||
        d_word := rwlock;
d2:     if (d_word.s_waiters /\ (~XBias \/ ~d_word.x_waiters)) {
                call lck_rw_wakeup(d_word);
        };
d_rst:  d_word := defaultInitValue;
d_end:  return;
}

(******************************************************************************)
(* lck_rw_{lock,unlock}_shared()                                              *)
(******************************************************************************)

procedure lck_rw_lock_shared()
        (*
         * atomic snapshot of the rwlock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable sl_word;
{
        (*
         * We only implement the slowpath here, this function is morally
         * equivalent lck_rw_lock_s_contended().
         *
         * The fastpath is just doing "s_xadd" outside of the slowpath
         * for performance reasons but doesn't change the state machine.
         * As a result, we elide it and reduce the space TLC has to cover.
         *)
s_loop:  while (TRUE) {
                sl_word := rwlock;
                if (~sl_word.u_wanted /\ ~sl_word.x_locked) {
s_xadd:                 rwlock.r_count := rwlock.r_count + 1;
                        if (~rwlock.x_locked) {
s_rst:                          sl_word := defaultInitValue;
                                \* rwlock.readers := rwlock.readers \union {self};
s_end:                          return;
                        } else {
                                goto s_loop;
                        };
                };

s_aw1:          waitq_lock(ReadEvent);
                sl_word := rwlock;

s_aw2:          if (~sl_word.u_wanted /\ ~sl_word.x_locked) {
                        goto s_unlock;
                } else if (sl_word.s_waiters) {
                        goto s_block;
                } else if (rwlock = sl_word) {
                        rwlock.s_waiters := TRUE;
                        goto s_block;
                } else {
                        goto s_unlock;
                };

s_unlock:       sl_word := defaultInitValue;
                waitq_unlock(ReadEvent);
                goto s_loop;

s_block:        sl_word := defaultInitValue;
                assert_wait_and_unlock(ReadEvent);
                call thread_block();
        };
}

procedure lck_rw_unlock_shared()
        (*
         * atomic snapshot of the rwlock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable su_word;
{
us1:    \* rwlock.readers := rwlock.readers \ {self} ||
        rwlock.r_count := rwlock.r_count - 1;
        su_word := rwlock;

us2:    if (su_word.r_count = 0 /\ (su_word.x_waiters \/ su_word.u_waiter)) {
                call lck_rw_wakeup(su_word);
        };
us_rst: su_word := defaultInitValue;
us_end: return;
}

(******************************************************************************)
(* lck_rw_lock_shared_to_exclusive()                                          *)
(******************************************************************************)

procedure __lck_rw_lock_u2x_contended()
        (*
         * atomic snapshot of the rwlock, reset to defaultInitValue
         * once unused, in order to not pollute the model states.
         *)
        variable u_word;
{
uc1:    \* rwlock.owner := {self} ||
        \* rwlock.readers := rwlock.readers \ {self} ||
        rwlock.r_count := rwlock.r_count - 1;

uc_loop:
        while (TRUE) {
                u_word := rwlock;
uc_cas:         if (u_word.r_count = 0) {
                        if (u_word = rwlock) {
                                u_word := defaultInitValue;
                                rwlock.x_locked := TRUE ||
                                rwlock.u_wanted := FALSE ||
                                rwlock.u_waiter := FALSE;
uc_ret:                         return;
                        } else {
                                goto uc_loop;
                        }
                };

uc_aw1:         waitq_lock(UpgradeEvent);
                u_word := rwlock;

uc_aw2:         if (u_word.r_count = 0) {
                        goto uc_unlock;
                } else if (u_word.u_waiter) {
                        goto uc_block;
                } else if (u_word = rwlock) {
                        rwlock.u_waiter := TRUE;
                        goto uc_block;
                } else {
                        goto uc_unlock;
                };

uc_unlock:      u_word := defaultInitValue;
                waitq_unlock(UpgradeEvent);
                goto uc_loop;

uc_block:       u_word := defaultInitValue;
                assert_wait_and_unlock(UpgradeEvent);
                call thread_block();
        };
}

procedure lck_rw_lock_shared_to_exclusive()
{
u_try:  if (rwlock.r_count = 1 /\ ~rwlock.u_wanted) {
                \* rwlock.owner    := {self} ||
                rwlock.x_locked := TRUE ||
                rwlock.r_count  := 0;

u_try1:         ret_try_u[self] := TRUE;
                return;
        } else
        (*
         * Setting u_wanted is not atomic with trying to
         * CAS(r_count=1 -> x_locked=1).
         *
         * However, separating these leads to state explosion
         * when running TLC, so pretend it is atomic.
         *
         * This prevents to enter the slowpath with the rwlock
         * state being {r_count=1, u_wanted=1}, in the model
         * the r_count will always be > 1.
         *
         * If we entered the contended path with r_count=1 either:
         * - the "uc_cas" step will succeed and return,
         * - some other reader incremented r_count and the logic
         *   is similar to entering with r_count > 1.
         * we're hence "obviously" not losing coverage of the algorithm.
         *)
        if (~rwlock.u_wanted) {
                rwlock.u_wanted := TRUE;
u_resv1:        call __lck_rw_lock_u2x_contended();
u_resv2:        ret_try_u[self] := TRUE;
                return;
        };

u_fail: call lck_rw_unlock_shared();
u_ret:  ret_try_u[self] := FALSE;
        return;
}

(******************************************************************************)
(* processes                                                                  *)
(******************************************************************************)

fair process (t \in Threads)
{
thread:
        either {
rloop:          while (TRUE) {
rlock:                  call lck_rw_lock_shared();
rcs:                    skip;
runlock:                call lck_rw_unlock_shared();
                }
        } or {
uloop:          while (TRUE) {
ulock:                  call lck_rw_lock_shared();
urcs:                   skip;
                        call lck_rw_lock_shared_to_exclusive();
upgrade:                if (ret_try_u[self]) {
uwcs:                           skip;
uunlock:                        call lck_rw_unlock_exclusive();
                        };
udone:                  ret_try_u[self] := defaultInitValue;
               };
        } or {
wloop:          while (TRUE) {
wlock:                  call lck_rw_lock_exclusive();
wcs:                    skip;
wunlock:                call lck_rw_unlock_exclusive();
               };
        } or {
dloop:          while (TRUE) {
dlock:                  call lck_rw_lock_exclusive();
dwcs:                   skip;
                        call lck_rw_lock_exclusive_to_shared();
drcs:                   skip;
dunlock:                call lck_rw_unlock_shared();
                };
        }
}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "505d4dbe" /\ chksum(tla) = "e5d557f6")
CONSTANT defaultInitValue
VARIABLES waitqs, ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
          ret_try_wx, rwlock, pc, stack

(* define statement *)
ReadEvent       == "r"
WriteEvent      == "w"
UpgradeEvent    == "u"

Events          == { ReadEvent, WriteEvent, UpgradeEvent }

ReadCS          == { "rcs", "urcs", "drcs" }
WriteCS         == { "wcs", "uwcs", "dwcs" }
AnyCS           == ReadCS \union WriteCS


Range(seq)      == { seq[x] : x \in DOMAIN seq }
Min(a, b)       == IF a < b THEN a ELSE b


ParamsCorrect   == Urgent \subseteq Threads


Exclusion       == \A t1 \in Threads:
                   pc[t1] \in WriteCS => (\A t2 \in Threads \ {t1}: pc[t2] \notin AnyCS)


NoMissingWakeup == \/ ret_blocked = {}
                   \/ \E t \in Threads \ ret_blocked: pc[t] = "block"
                   \/ \E t \in Threads: pc[t] \notin { "block", "rloop", "xloop", "uloop", "dloop" }


Perms           == Permutations(Threads)

VARIABLES arg_event_i, arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
          xl_word, xu_word, d_word, sl_word, su_word, u_word

vars == << waitqs, ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
           ret_try_wx, rwlock, pc, stack, arg_event_i, arg_event_n, 
           arg_unlock_n, xw_word, arg_w_word, xl_word, xu_word, d_word, 
           sl_word, su_word, u_word >>

ProcSet == (Threads)

Init == (* Global variables *)
        /\ waitqs = [e \in Events  |->
                        [q    |-> <<>>,
                         lock |-> FALSE]]
        /\ ret_blocked = {}
        /\ ret_wakeup = [t \in Threads |-> 0]
        /\ ret_identify = [t \in Threads |-> {}]
        /\ ret_try_u = [t \in Threads |-> FALSE]
        /\ ret_try_wx = [t \in Threads |-> FALSE]
        /\ rwlock = [
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                     s_waiters     |-> FALSE,
                     u_waiter      |-> FALSE,
                     x_waiters     |-> FALSE,
                     x_urgent      |-> FALSE,
                     u_wanted      |-> FALSE,
                     x_locked      |-> FALSE,
                     r_count       |-> 0]
        (* Procedure identify *)
        /\ arg_event_i = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure wakeup_1 *)
        /\ arg_event_n = [ self \in ProcSet |-> defaultInitValue]
        /\ arg_unlock_n = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_wakeup_x *)
        /\ xw_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_wakeup *)
        /\ arg_w_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_lock_exclusive *)
        /\ xl_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_unlock_exclusive *)
        /\ xu_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_lock_exclusive_to_shared *)
        /\ d_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_lock_shared *)
        /\ sl_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure lck_rw_unlock_shared *)
        /\ su_word = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure __lck_rw_lock_u2x_contended *)
        /\ u_word = [ self \in ProcSet |-> defaultInitValue]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> "thread"]

i1(self) == /\ pc[self] = "i1"
            /\ LET wq_n == waitqs[arg_event_i[self]].q IN
                 LET len_n == Len(wq_n) IN
                   /\ IF len_n # 0
                         THEN /\ ret_identify' = [ret_identify EXCEPT ![self] = ret_identify[self] \union { wq_n[1] }]
                              /\ waitqs' = [waitqs EXCEPT ![arg_event_i[self]] =                        [
                                                                                     q    |-> [x \in 1..(len_n - 1) |-> wq_n[1 + x]],
                                                                                     lock |-> TRUE
                                                                                 ]]
                         ELSE /\ TRUE
                              /\ UNCHANGED << waitqs, ret_identify >>
                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                   /\ arg_event_i' = [arg_event_i EXCEPT ![self] = Head(stack[self]).arg_event_i]
                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << ret_blocked, ret_wakeup, ret_try_u, ret_try_wx, 
                            rwlock, arg_event_n, arg_unlock_n, xw_word, 
                            arg_w_word, xl_word, xu_word, d_word, sl_word, 
                            su_word, u_word >>

identify(self) == i1(self)

r1(self) == /\ pc[self] = "r1"
            /\ /\ ret_blocked' = ret_blocked \ ret_identify[self]
               /\ ret_identify' = [ret_identify EXCEPT ![self] = {}]
            /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
            /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << waitqs, ret_wakeup, ret_try_u, ret_try_wx, rwlock, 
                            arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                            arg_w_word, xl_word, xu_word, d_word, sl_word, 
                            su_word, u_word >>

resume(self) == r1(self)

wn(self) == /\ pc[self] = "wn"
            /\ LET wq_n == waitqs[arg_event_n[self]].q IN
                 LET len_n == Len(wq_n) IN
                   LET n_n == Min(1, len_n) IN
                     /\ ret_wakeup' = [ret_wakeup EXCEPT ![self] = n_n]
                     /\ ret_blocked' = ret_blocked \ { wq_n[x] : x \in 1..n_n }
                     /\ waitqs' = [waitqs EXCEPT ![arg_event_n[self]] =                        [
                                                                            q    |-> [x \in 1..(len_n - n_n) |-> wq_n[n_n + x]],
                                                                            lock |-> ~arg_unlock_n[self]
                                                                        ]]
                     /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                     /\ arg_event_n' = [arg_event_n EXCEPT ![self] = Head(stack[self]).arg_event_n]
                     /\ arg_unlock_n' = [arg_unlock_n EXCEPT ![self] = Head(stack[self]).arg_unlock_n]
                     /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << ret_identify, ret_try_u, ret_try_wx, rwlock, 
                            arg_event_i, xw_word, arg_w_word, xl_word, xu_word, 
                            d_word, sl_word, su_word, u_word >>

wakeup_1(self) == wn(self)

block(self) == /\ pc[self] = "block"
               /\ self \notin ret_blocked
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, sl_word, su_word, 
                               u_word >>

thread_block(self) == block(self)

xw1(self) == /\ pc[self] = "xw1"
             /\ waitqs[WriteEvent].lock = FALSE
             /\ waitqs' = [waitqs EXCEPT ![WriteEvent].lock = TRUE]
             /\ /\ arg_event_i' = [arg_event_i EXCEPT ![self] = WriteEvent]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "identify",
                                                         pc        |->  "xw2",
                                                         arg_event_i |->  arg_event_i[self] ] >>
                                                     \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "i1"]
             /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
                             ret_try_wx, rwlock, arg_event_n, arg_unlock_n, 
                             xw_word, arg_w_word, xl_word, xu_word, d_word, 
                             sl_word, su_word, u_word >>

xw2(self) == /\ pc[self] = "xw2"
             /\ ret_try_wx' = [ret_try_wx EXCEPT ![self] = ret_identify[self] # {}]
             /\ IF ~ret_try_wx'[self]
                   THEN /\ waitqs' = [waitqs EXCEPT ![WriteEvent].lock = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "xw_rst"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "xw3"]
                        /\ UNCHANGED waitqs
             /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
                             rwlock, stack, arg_event_i, arg_event_n, 
                             arg_unlock_n, xw_word, arg_w_word, xl_word, 
                             xu_word, d_word, sl_word, su_word, u_word >>

xw3(self) == /\ pc[self] = "xw3"
             /\ IF ~xw_word[self].x_urgent
                   THEN /\ /\ arg_event_i' = [arg_event_i EXCEPT ![self] = WriteEvent]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "identify",
                                                                    pc        |->  "xw4",
                                                                    arg_event_i |->  arg_event_i[self] ] >>
                                                                \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "i1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "xw4"]
                        /\ UNCHANGED << stack, arg_event_i >>
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, rwlock, arg_event_n, 
                             arg_unlock_n, xw_word, arg_w_word, xl_word, 
                             xu_word, d_word, sl_word, su_word, u_word >>

xw4(self) == /\ pc[self] = "xw4"
             /\ IF xw_word[self].x_urgent \/ Len(waitqs[WriteEvent].q) = 0
                   THEN /\ rwlock' = [rwlock EXCEPT !.x_urgent = FALSE,
                                                    !.x_waiters = FALSE]
                   ELSE /\ TRUE
                        /\ UNCHANGED rwlock
             /\ pc' = [pc EXCEPT ![self] = "xw5"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, su_word, 
                             u_word >>

xw5(self) == /\ pc[self] = "xw5"
             /\ IF xw_word[self].x_urgent
                   THEN /\ LET wq_all == waitqs[WriteEvent].q IN
                             /\ ret_blocked' = ret_blocked \ Range(wq_all)
                             /\ waitqs' = [waitqs EXCEPT ![WriteEvent] =                      [
                                                                             q |-> <<>>,
                                                                             lock |-> ~TRUE
                                                                         ]]
                   ELSE /\ waitqs' = [waitqs EXCEPT ![WriteEvent].lock = FALSE]
                        /\ UNCHANGED ret_blocked
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "resume",
                                                      pc        |->  "xw_rst" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "r1"]
             /\ UNCHANGED << ret_wakeup, ret_identify, ret_try_u, ret_try_wx, 
                             rwlock, arg_event_i, arg_event_n, arg_unlock_n, 
                             xw_word, arg_w_word, xl_word, xu_word, d_word, 
                             sl_word, su_word, u_word >>

xw_rst(self) == /\ pc[self] = "xw_rst"
                /\ xw_word' = [xw_word EXCEPT ![self] = defaultInitValue]
                /\ pc' = [pc EXCEPT ![self] = "xw_ret"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                arg_w_word, xl_word, xu_word, d_word, sl_word, 
                                su_word, u_word >>

xw_ret(self) == /\ pc[self] = "xw_ret"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ xw_word' = [xw_word EXCEPT ![self] = Head(stack[self]).xw_word]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, arg_w_word, xl_word, 
                                xu_word, d_word, sl_word, su_word, u_word >>

lck_rw_wakeup_x(self) == xw1(self) \/ xw2(self) \/ xw3(self) \/ xw4(self)
                            \/ xw5(self) \/ xw_rst(self) \/ xw_ret(self)

sw1(self) == /\ pc[self] = "sw1"
             /\ waitqs[ReadEvent].lock = FALSE
             /\ waitqs' = [waitqs EXCEPT ![ReadEvent].lock = TRUE]
             /\ /\ arg_event_i' = [arg_event_i EXCEPT ![self] = ReadEvent]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "identify",
                                                         pc        |->  "sw2",
                                                         arg_event_i |->  arg_event_i[self] ] >>
                                                     \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "i1"]
             /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
                             ret_try_wx, rwlock, arg_event_n, arg_unlock_n, 
                             xw_word, arg_w_word, xl_word, xu_word, d_word, 
                             sl_word, su_word, u_word >>

sw2(self) == /\ pc[self] = "sw2"
             /\ IF ret_identify[self] # {}
                   THEN /\ rwlock' = [rwlock EXCEPT !.s_waiters = FALSE]
                   ELSE /\ TRUE
                        /\ UNCHANGED rwlock
             /\ pc' = [pc EXCEPT ![self] = "sw3"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, su_word, 
                             u_word >>

sw3(self) == /\ pc[self] = "sw3"
             /\ LET wq_all == waitqs[ReadEvent].q IN
                  /\ ret_blocked' = ret_blocked \ Range(wq_all)
                  /\ waitqs' = [waitqs EXCEPT ![ReadEvent] =                      [
                                                                 q |-> <<>>,
                                                                 lock |-> ~TRUE
                                                             ]]
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "resume",
                                                      pc        |->  "sw_ret" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "r1"]
             /\ UNCHANGED << ret_wakeup, ret_identify, ret_try_u, ret_try_wx, 
                             rwlock, arg_event_i, arg_event_n, arg_unlock_n, 
                             xw_word, arg_w_word, xl_word, xu_word, d_word, 
                             sl_word, su_word, u_word >>

sw_ret(self) == /\ pc[self] = "sw_ret"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, su_word, 
                                u_word >>

lck_rw_wakeup_s(self) == sw1(self) \/ sw2(self) \/ sw3(self)
                            \/ sw_ret(self)

uw1(self) == /\ pc[self] = "uw1"
             /\ waitqs[UpgradeEvent].lock = FALSE
             /\ waitqs' = [waitqs EXCEPT ![UpgradeEvent].lock = TRUE]
             /\ /\ arg_event_i' = [arg_event_i EXCEPT ![self] = UpgradeEvent]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "identify",
                                                         pc        |->  "uw2",
                                                         arg_event_i |->  arg_event_i[self] ] >>
                                                     \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "i1"]
             /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
                             ret_try_wx, rwlock, arg_event_n, arg_unlock_n, 
                             xw_word, arg_w_word, xl_word, xu_word, d_word, 
                             sl_word, su_word, u_word >>

uw2(self) == /\ pc[self] = "uw2"
             /\ IF ret_identify[self] # {}
                   THEN /\ rwlock' = [rwlock EXCEPT !.u_waiter = FALSE]
                   ELSE /\ TRUE
                        /\ UNCHANGED rwlock
             /\ pc' = [pc EXCEPT ![self] = "uw3"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, su_word, 
                             u_word >>

uw3(self) == /\ pc[self] = "uw3"
             /\ waitqs' = [waitqs EXCEPT ![UpgradeEvent].lock = FALSE]
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "resume",
                                                      pc        |->  "uw_ret" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "r1"]
             /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, ret_try_u, 
                             ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                             arg_unlock_n, xw_word, arg_w_word, xl_word, 
                             xu_word, d_word, sl_word, su_word, u_word >>

uw_ret(self) == /\ pc[self] = "uw_ret"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, su_word, 
                                u_word >>

lck_rw_wakeup_u(self) == uw1(self) \/ uw2(self) \/ uw3(self)
                            \/ uw_ret(self)

w1(self) == /\ pc[self] = "w1"
            /\ IF arg_w_word[self].u_wanted /\ ~arg_w_word[self].u_waiter
                  THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ arg_w_word' = [arg_w_word EXCEPT ![self] = Head(stack[self]).arg_w_word]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  ELSE /\ IF arg_w_word[self].u_wanted
                             THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup_u",
                                                                           pc        |->  Head(stack[self]).pc ] >>
                                                                       \o Tail(stack[self])]
                                  /\ pc' = [pc EXCEPT ![self] = "uw1"]
                                  /\ UNCHANGED arg_w_word
                             ELSE /\ IF ~XBias /\ arg_w_word[self].s_waiters
                                        THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup_s",
                                                                                      pc        |->  Head(stack[self]).pc ] >>
                                                                                  \o Tail(stack[self])]
                                             /\ pc' = [pc EXCEPT ![self] = "sw1"]
                                             /\ UNCHANGED arg_w_word
                                        ELSE /\ IF arg_w_word[self].x_waiters /\ arg_w_word[self].r_count > 0
                                                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                        /\ arg_w_word' = [arg_w_word EXCEPT ![self] = Head(stack[self]).arg_w_word]
                                                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                   ELSE /\ IF arg_w_word[self].x_waiters
                                                              THEN /\ pc' = [pc EXCEPT ![self] = "w2"]
                                                              ELSE /\ pc' = [pc EXCEPT ![self] = "w4"]
                                                        /\ UNCHANGED << stack, 
                                                                        arg_w_word >>
            /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                            ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                            arg_event_n, arg_unlock_n, xw_word, xl_word, 
                            xu_word, d_word, sl_word, su_word, u_word >>

w2(self) == /\ pc[self] = "w2"
            /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup_x",
                                                        pc        |->  "w3",
                                                        xw_word   |->  xw_word[self] ] >>
                                                    \o stack[self]]
               /\ xw_word' = [xw_word EXCEPT ![self] = arg_w_word[self]]
            /\ pc' = [pc EXCEPT ![self] = "xw1"]
            /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                            ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                            arg_event_n, arg_unlock_n, arg_w_word, xl_word, 
                            xu_word, d_word, sl_word, su_word, u_word >>

w3(self) == /\ pc[self] = "w3"
            /\ IF ret_try_wx[self]
                  THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ arg_w_word' = [arg_w_word EXCEPT ![self] = Head(stack[self]).arg_w_word]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "w4"]
                       /\ UNCHANGED << stack, arg_w_word >>
            /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                            ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                            arg_event_n, arg_unlock_n, xw_word, xl_word, 
                            xu_word, d_word, sl_word, su_word, u_word >>

w4(self) == /\ pc[self] = "w4"
            /\ IF arg_w_word[self].s_waiters
                  THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup_s",
                                                                pc        |->  Head(stack[self]).pc ] >>
                                                            \o Tail(stack[self])]
                       /\ pc' = [pc EXCEPT ![self] = "sw1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "w_end"]
                       /\ stack' = stack
            /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                            ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                            arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                            xl_word, xu_word, d_word, sl_word, su_word, u_word >>

w_end(self) == /\ pc[self] = "w_end"
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ arg_w_word' = [arg_w_word EXCEPT ![self] = Head(stack[self]).arg_w_word]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, xl_word, 
                               xu_word, d_word, sl_word, su_word, u_word >>

lck_rw_wakeup(self) == w1(self) \/ w2(self) \/ w3(self) \/ w4(self)
                          \/ w_end(self)

x_loop(self) == /\ pc[self] = "x_loop"
                /\ xl_word' = [xl_word EXCEPT ![self] = rwlock]
                /\ pc' = [pc EXCEPT ![self] = "x_cas"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                xw_word, arg_w_word, xu_word, d_word, sl_word, 
                                su_word, u_word >>

x_cas(self) == /\ pc[self] = "x_cas"
               /\ IF ~xl_word[self].u_wanted /\ ~xl_word[self].x_locked /\ xl_word[self].r_count = 0
                     THEN /\ IF xl_word[self] = rwlock
                                THEN /\ xl_word' = [xl_word EXCEPT ![self] = defaultInitValue]
                                     /\ rwlock' = [rwlock EXCEPT !.x_locked = TRUE]
                                     /\ pc' = [pc EXCEPT ![self] = "x_ret"]
                                ELSE /\ pc' = [pc EXCEPT ![self] = "x_loop"]
                                     /\ UNCHANGED << rwlock, xl_word >>
                     ELSE /\ pc' = [pc EXCEPT ![self] = "x_aw1"]
                          /\ UNCHANGED << rwlock, xl_word >>
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, stack, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xu_word, d_word, sl_word, su_word, u_word >>

x_ret(self) == /\ pc[self] = "x_ret"
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ xl_word' = [xl_word EXCEPT ![self] = Head(stack[self]).xl_word]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xu_word, d_word, sl_word, su_word, u_word >>

x_aw1(self) == /\ pc[self] = "x_aw1"
               /\ waitqs[WriteEvent].lock = FALSE
               /\ waitqs' = [waitqs EXCEPT ![WriteEvent].lock = TRUE]
               /\ xl_word' = [xl_word EXCEPT ![self] = rwlock]
               /\ pc' = [pc EXCEPT ![self] = "x_aw2"]
               /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xu_word, d_word, sl_word, su_word, 
                               u_word >>

x_aw2(self) == /\ pc[self] = "x_aw2"
               /\ IF self \in Urgent
                     THEN /\ IF ~xl_word[self].u_wanted /\ ~xl_word[self].x_locked /\ xl_word[self].r_count = 0
                                THEN /\ pc' = [pc EXCEPT ![self] = "x_unlock"]
                                     /\ UNCHANGED rwlock
                                ELSE /\ IF xl_word[self].x_urgent /\ xl_word[self].x_waiters
                                           THEN /\ pc' = [pc EXCEPT ![self] = "x_block"]
                                                /\ UNCHANGED rwlock
                                           ELSE /\ IF rwlock = xl_word[self]
                                                      THEN /\ rwlock' = [rwlock EXCEPT !.x_waiters = TRUE,
                                                                                       !.x_urgent = TRUE]
                                                           /\ pc' = [pc EXCEPT ![self] = "x_block"]
                                                      ELSE /\ pc' = [pc EXCEPT ![self] = "x_unlock"]
                                                           /\ UNCHANGED rwlock
                     ELSE /\ IF ~xl_word[self].u_wanted /\ ~xl_word[self].x_locked /\ xl_word[self].r_count = 0
                                THEN /\ pc' = [pc EXCEPT ![self] = "x_unlock"]
                                     /\ UNCHANGED rwlock
                                ELSE /\ IF xl_word[self].x_waiters
                                           THEN /\ pc' = [pc EXCEPT ![self] = "x_block"]
                                                /\ UNCHANGED rwlock
                                           ELSE /\ IF xl_word[self] = rwlock
                                                      THEN /\ rwlock' = [rwlock EXCEPT !.x_waiters = TRUE]
                                                           /\ pc' = [pc EXCEPT ![self] = "x_block"]
                                                      ELSE /\ pc' = [pc EXCEPT ![self] = "x_unlock"]
                                                           /\ UNCHANGED rwlock
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, stack, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, sl_word, su_word, 
                               u_word >>

x_unlock(self) == /\ pc[self] = "x_unlock"
                  /\ xl_word' = [xl_word EXCEPT ![self] = defaultInitValue]
                  /\ waitqs' = [waitqs EXCEPT ![WriteEvent].lock = FALSE]
                  /\ pc' = [pc EXCEPT ![self] = "x_loop"]
                  /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, 
                                  ret_try_u, ret_try_wx, rwlock, stack, 
                                  arg_event_i, arg_event_n, arg_unlock_n, 
                                  xw_word, arg_w_word, xu_word, d_word, 
                                  sl_word, su_word, u_word >>

x_block(self) == /\ pc[self] = "x_block"
                 /\ xl_word' = [xl_word EXCEPT ![self] = defaultInitValue]
                 /\ ret_blocked' = (ret_blocked \union {self})
                 /\ waitqs' = [waitqs EXCEPT ![WriteEvent] =                  [
                                                                 q    |-> Append(waitqs[WriteEvent].q, self),
                                                                 lock |-> FALSE
                                                             ]]
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "thread_block",
                                                          pc        |->  "x_loop" ] >>
                                                      \o stack[self]]
                 /\ pc' = [pc EXCEPT ![self] = "block"]
                 /\ UNCHANGED << ret_wakeup, ret_identify, ret_try_u, 
                                 ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                                 arg_unlock_n, xw_word, arg_w_word, xu_word, 
                                 d_word, sl_word, su_word, u_word >>

lck_rw_lock_exclusive(self) == x_loop(self) \/ x_cas(self) \/ x_ret(self)
                                  \/ x_aw1(self) \/ x_aw2(self)
                                  \/ x_unlock(self) \/ x_block(self)

ux1(self) == /\ pc[self] = "ux1"
             /\ /\ rwlock' = [rwlock EXCEPT !.x_locked = FALSE,
                                            !.u_wanted = FALSE,
                                            !.r_count = 0]
                /\ xu_word' = [xu_word EXCEPT ![self] = rwlock]
             /\ pc' = [pc EXCEPT ![self] = "ux3"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, d_word, sl_word, su_word, u_word >>

ux3(self) == /\ pc[self] = "ux3"
             /\ IF xu_word[self].s_waiters \/ xu_word[self].u_waiter \/ xu_word[self].x_waiters
                   THEN /\ /\ arg_w_word' = [arg_w_word EXCEPT ![self] = xu_word[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup",
                                                                    pc        |->  "ux_rst",
                                                                    arg_w_word |->  arg_w_word[self] ] >>
                                                                \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "w1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ux_rst"]
                        /\ UNCHANGED << stack, arg_w_word >>
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, xl_word, 
                             xu_word, d_word, sl_word, su_word, u_word >>

ux_rst(self) == /\ pc[self] = "ux_rst"
                /\ xu_word' = [xu_word EXCEPT ![self] = defaultInitValue]
                /\ pc' = [pc EXCEPT ![self] = "ux_end"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                xw_word, arg_w_word, xl_word, d_word, sl_word, 
                                su_word, u_word >>

ux_end(self) == /\ pc[self] = "ux_end"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ xu_word' = [xu_word EXCEPT ![self] = Head(stack[self]).xu_word]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, d_word, sl_word, su_word, u_word >>

lck_rw_unlock_exclusive(self) == ux1(self) \/ ux3(self) \/ ux_rst(self)
                                    \/ ux_end(self)

d1(self) == /\ pc[self] = "d1"
            /\ /\ d_word' = [d_word EXCEPT ![self] = rwlock]
               /\ rwlock' = [rwlock EXCEPT !.x_locked = FALSE,
                                           !.r_count = 1]
            /\ pc' = [pc EXCEPT ![self] = "d2"]
            /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                            ret_try_u, ret_try_wx, stack, arg_event_i, 
                            arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                            xl_word, xu_word, sl_word, su_word, u_word >>

d2(self) == /\ pc[self] = "d2"
            /\ IF d_word[self].s_waiters /\ (~XBias \/ ~d_word[self].x_waiters)
                  THEN /\ /\ arg_w_word' = [arg_w_word EXCEPT ![self] = d_word[self]]
                          /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup",
                                                                   pc        |->  "d_rst",
                                                                   arg_w_word |->  arg_w_word[self] ] >>
                                                               \o stack[self]]
                       /\ pc' = [pc EXCEPT ![self] = "w1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "d_rst"]
                       /\ UNCHANGED << stack, arg_w_word >>
            /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                            ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                            arg_event_n, arg_unlock_n, xw_word, xl_word, 
                            xu_word, d_word, sl_word, su_word, u_word >>

d_rst(self) == /\ pc[self] = "d_rst"
               /\ d_word' = [d_word EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "d_end"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, sl_word, su_word, 
                               u_word >>

d_end(self) == /\ pc[self] = "d_end"
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ d_word' = [d_word EXCEPT ![self] = Head(stack[self]).d_word]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, sl_word, su_word, u_word >>

lck_rw_lock_exclusive_to_shared(self) == d1(self) \/ d2(self)
                                            \/ d_rst(self) \/ d_end(self)

s_loop(self) == /\ pc[self] = "s_loop"
                /\ sl_word' = [sl_word EXCEPT ![self] = rwlock]
                /\ IF ~sl_word'[self].u_wanted /\ ~sl_word'[self].x_locked
                      THEN /\ pc' = [pc EXCEPT ![self] = "s_xadd"]
                      ELSE /\ pc' = [pc EXCEPT ![self] = "s_aw1"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                xw_word, arg_w_word, xl_word, xu_word, d_word, 
                                su_word, u_word >>

s_aw1(self) == /\ pc[self] = "s_aw1"
               /\ waitqs[ReadEvent].lock = FALSE
               /\ waitqs' = [waitqs EXCEPT ![ReadEvent].lock = TRUE]
               /\ sl_word' = [sl_word EXCEPT ![self] = rwlock]
               /\ pc' = [pc EXCEPT ![self] = "s_aw2"]
               /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, d_word, su_word, 
                               u_word >>

s_aw2(self) == /\ pc[self] = "s_aw2"
               /\ IF ~sl_word[self].u_wanted /\ ~sl_word[self].x_locked
                     THEN /\ pc' = [pc EXCEPT ![self] = "s_unlock"]
                          /\ UNCHANGED rwlock
                     ELSE /\ IF sl_word[self].s_waiters
                                THEN /\ pc' = [pc EXCEPT ![self] = "s_block"]
                                     /\ UNCHANGED rwlock
                                ELSE /\ IF rwlock = sl_word[self]
                                           THEN /\ rwlock' = [rwlock EXCEPT !.s_waiters = TRUE]
                                                /\ pc' = [pc EXCEPT ![self] = "s_block"]
                                           ELSE /\ pc' = [pc EXCEPT ![self] = "s_unlock"]
                                                /\ UNCHANGED rwlock
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, stack, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, sl_word, su_word, 
                               u_word >>

s_unlock(self) == /\ pc[self] = "s_unlock"
                  /\ sl_word' = [sl_word EXCEPT ![self] = defaultInitValue]
                  /\ waitqs' = [waitqs EXCEPT ![ReadEvent].lock = FALSE]
                  /\ pc' = [pc EXCEPT ![self] = "s_loop"]
                  /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, 
                                  ret_try_u, ret_try_wx, rwlock, stack, 
                                  arg_event_i, arg_event_n, arg_unlock_n, 
                                  xw_word, arg_w_word, xl_word, xu_word, 
                                  d_word, su_word, u_word >>

s_block(self) == /\ pc[self] = "s_block"
                 /\ sl_word' = [sl_word EXCEPT ![self] = defaultInitValue]
                 /\ ret_blocked' = (ret_blocked \union {self})
                 /\ waitqs' = [waitqs EXCEPT ![ReadEvent] =                  [
                                                                q    |-> Append(waitqs[ReadEvent].q, self),
                                                                lock |-> FALSE
                                                            ]]
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "thread_block",
                                                          pc        |->  "s_loop" ] >>
                                                      \o stack[self]]
                 /\ pc' = [pc EXCEPT ![self] = "block"]
                 /\ UNCHANGED << ret_wakeup, ret_identify, ret_try_u, 
                                 ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                                 arg_unlock_n, xw_word, arg_w_word, xl_word, 
                                 xu_word, d_word, su_word, u_word >>

s_xadd(self) == /\ pc[self] = "s_xadd"
                /\ rwlock' = [rwlock EXCEPT !.r_count = rwlock.r_count + 1]
                /\ IF ~rwlock'.x_locked
                      THEN /\ pc' = [pc EXCEPT ![self] = "s_rst"]
                      ELSE /\ pc' = [pc EXCEPT ![self] = "s_loop"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, stack, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, su_word, 
                                u_word >>

s_rst(self) == /\ pc[self] = "s_rst"
               /\ sl_word' = [sl_word EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "s_end"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, d_word, su_word, 
                               u_word >>

s_end(self) == /\ pc[self] = "s_end"
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ sl_word' = [sl_word EXCEPT ![self] = Head(stack[self]).sl_word]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, su_word, u_word >>

lck_rw_lock_shared(self) == s_loop(self) \/ s_aw1(self) \/ s_aw2(self)
                               \/ s_unlock(self) \/ s_block(self)
                               \/ s_xadd(self) \/ s_rst(self)
                               \/ s_end(self)

us1(self) == /\ pc[self] = "us1"
             /\ rwlock' = [rwlock EXCEPT !.r_count = rwlock.r_count - 1]
             /\ su_word' = [su_word EXCEPT ![self] = rwlock']
             /\ pc' = [pc EXCEPT ![self] = "us2"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, u_word >>

us2(self) == /\ pc[self] = "us2"
             /\ IF su_word[self].r_count = 0 /\ (su_word[self].x_waiters \/ su_word[self].u_waiter)
                   THEN /\ /\ arg_w_word' = [arg_w_word EXCEPT ![self] = su_word[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_wakeup",
                                                                    pc        |->  "us_rst",
                                                                    arg_w_word |->  arg_w_word[self] ] >>
                                                                \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "w1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "us_rst"]
                        /\ UNCHANGED << stack, arg_w_word >>
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, xl_word, 
                             xu_word, d_word, sl_word, su_word, u_word >>

us_rst(self) == /\ pc[self] = "us_rst"
                /\ su_word' = [su_word EXCEPT ![self] = defaultInitValue]
                /\ pc' = [pc EXCEPT ![self] = "us_end"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                xw_word, arg_w_word, xl_word, xu_word, d_word, 
                                sl_word, u_word >>

us_end(self) == /\ pc[self] = "us_end"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ su_word' = [su_word EXCEPT ![self] = Head(stack[self]).su_word]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, u_word >>

lck_rw_unlock_shared(self) == us1(self) \/ us2(self) \/ us_rst(self)
                                 \/ us_end(self)

uc1(self) == /\ pc[self] = "uc1"
             /\ rwlock' = [rwlock EXCEPT !.r_count = rwlock.r_count - 1]
             /\ pc' = [pc EXCEPT ![self] = "uc_loop"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, su_word, 
                             u_word >>

uc_loop(self) == /\ pc[self] = "uc_loop"
                 /\ u_word' = [u_word EXCEPT ![self] = rwlock]
                 /\ pc' = [pc EXCEPT ![self] = "uc_cas"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, stack, 
                                 arg_event_i, arg_event_n, arg_unlock_n, 
                                 xw_word, arg_w_word, xl_word, xu_word, d_word, 
                                 sl_word, su_word >>

uc_cas(self) == /\ pc[self] = "uc_cas"
                /\ IF u_word[self].r_count = 0
                      THEN /\ IF u_word[self] = rwlock
                                 THEN /\ u_word' = [u_word EXCEPT ![self] = defaultInitValue]
                                      /\ rwlock' = [rwlock EXCEPT !.x_locked = TRUE,
                                                                  !.u_wanted = FALSE,
                                                                  !.u_waiter = FALSE]
                                      /\ pc' = [pc EXCEPT ![self] = "uc_ret"]
                                 ELSE /\ pc' = [pc EXCEPT ![self] = "uc_loop"]
                                      /\ UNCHANGED << rwlock, u_word >>
                      ELSE /\ pc' = [pc EXCEPT ![self] = "uc_aw1"]
                           /\ UNCHANGED << rwlock, u_word >>
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, stack, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, su_word >>

uc_ret(self) == /\ pc[self] = "uc_ret"
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ u_word' = [u_word EXCEPT ![self] = Head(stack[self]).u_word]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, su_word >>

uc_aw1(self) == /\ pc[self] = "uc_aw1"
                /\ waitqs[UpgradeEvent].lock = FALSE
                /\ waitqs' = [waitqs EXCEPT ![UpgradeEvent].lock = TRUE]
                /\ u_word' = [u_word EXCEPT ![self] = rwlock]
                /\ pc' = [pc EXCEPT ![self] = "uc_aw2"]
                /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                xw_word, arg_w_word, xl_word, xu_word, d_word, 
                                sl_word, su_word >>

uc_aw2(self) == /\ pc[self] = "uc_aw2"
                /\ IF u_word[self].r_count = 0
                      THEN /\ pc' = [pc EXCEPT ![self] = "uc_unlock"]
                           /\ UNCHANGED rwlock
                      ELSE /\ IF u_word[self].u_waiter
                                 THEN /\ pc' = [pc EXCEPT ![self] = "uc_block"]
                                      /\ UNCHANGED rwlock
                                 ELSE /\ IF u_word[self] = rwlock
                                            THEN /\ rwlock' = [rwlock EXCEPT !.u_waiter = TRUE]
                                                 /\ pc' = [pc EXCEPT ![self] = "uc_block"]
                                            ELSE /\ pc' = [pc EXCEPT ![self] = "uc_unlock"]
                                                 /\ UNCHANGED rwlock
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, stack, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, su_word, 
                                u_word >>

uc_unlock(self) == /\ pc[self] = "uc_unlock"
                   /\ u_word' = [u_word EXCEPT ![self] = defaultInitValue]
                   /\ waitqs' = [waitqs EXCEPT ![UpgradeEvent].lock = FALSE]
                   /\ pc' = [pc EXCEPT ![self] = "uc_loop"]
                   /\ UNCHANGED << ret_blocked, ret_wakeup, ret_identify, 
                                   ret_try_u, ret_try_wx, rwlock, stack, 
                                   arg_event_i, arg_event_n, arg_unlock_n, 
                                   xw_word, arg_w_word, xl_word, xu_word, 
                                   d_word, sl_word, su_word >>

uc_block(self) == /\ pc[self] = "uc_block"
                  /\ u_word' = [u_word EXCEPT ![self] = defaultInitValue]
                  /\ ret_blocked' = (ret_blocked \union {self})
                  /\ waitqs' = [waitqs EXCEPT ![UpgradeEvent] =                  [
                                                                    q    |-> Append(waitqs[UpgradeEvent].q, self),
                                                                    lock |-> FALSE
                                                                ]]
                  /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "thread_block",
                                                           pc        |->  "uc_loop" ] >>
                                                       \o stack[self]]
                  /\ pc' = [pc EXCEPT ![self] = "block"]
                  /\ UNCHANGED << ret_wakeup, ret_identify, ret_try_u, 
                                  ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                                  arg_unlock_n, xw_word, arg_w_word, xl_word, 
                                  xu_word, d_word, sl_word, su_word >>

__lck_rw_lock_u2x_contended(self) == uc1(self) \/ uc_loop(self)
                                        \/ uc_cas(self) \/ uc_ret(self)
                                        \/ uc_aw1(self) \/ uc_aw2(self)
                                        \/ uc_unlock(self)
                                        \/ uc_block(self)

u_try(self) == /\ pc[self] = "u_try"
               /\ IF rwlock.r_count = 1 /\ ~rwlock.u_wanted
                     THEN /\ rwlock' = [rwlock EXCEPT !.x_locked = TRUE,
                                                      !.r_count = 0]
                          /\ pc' = [pc EXCEPT ![self] = "u_try1"]
                     ELSE /\ IF ~rwlock.u_wanted
                                THEN /\ rwlock' = [rwlock EXCEPT !.u_wanted = TRUE]
                                     /\ pc' = [pc EXCEPT ![self] = "u_resv1"]
                                ELSE /\ pc' = [pc EXCEPT ![self] = "u_fail"]
                                     /\ UNCHANGED rwlock
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, stack, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, sl_word, su_word, 
                               u_word >>

u_try1(self) == /\ pc[self] = "u_try1"
                /\ ret_try_u' = [ret_try_u EXCEPT ![self] = TRUE]
                /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                                arg_unlock_n, xw_word, arg_w_word, xl_word, 
                                xu_word, d_word, sl_word, su_word, u_word >>

u_resv1(self) == /\ pc[self] = "u_resv1"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "__lck_rw_lock_u2x_contended",
                                                          pc        |->  "u_resv2",
                                                          u_word    |->  u_word[self] ] >>
                                                      \o stack[self]]
                 /\ u_word' = [u_word EXCEPT ![self] = defaultInitValue]
                 /\ pc' = [pc EXCEPT ![self] = "uc1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                 arg_event_n, arg_unlock_n, xw_word, 
                                 arg_w_word, xl_word, xu_word, d_word, sl_word, 
                                 su_word >>

u_resv2(self) == /\ pc[self] = "u_resv2"
                 /\ ret_try_u' = [ret_try_u EXCEPT ![self] = TRUE]
                 /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                 /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                                 arg_unlock_n, xw_word, arg_w_word, xl_word, 
                                 xu_word, d_word, sl_word, su_word, u_word >>

u_fail(self) == /\ pc[self] = "u_fail"
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_unlock_shared",
                                                         pc        |->  "u_ret",
                                                         su_word   |->  su_word[self] ] >>
                                                     \o stack[self]]
                /\ su_word' = [su_word EXCEPT ![self] = defaultInitValue]
                /\ pc' = [pc EXCEPT ![self] = "us1"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                                xl_word, xu_word, d_word, sl_word, u_word >>

u_ret(self) == /\ pc[self] = "u_ret"
               /\ ret_try_u' = [ret_try_u EXCEPT ![self] = FALSE]
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_wx, rwlock, arg_event_i, arg_event_n, 
                               arg_unlock_n, xw_word, arg_w_word, xl_word, 
                               xu_word, d_word, sl_word, su_word, u_word >>

lck_rw_lock_shared_to_exclusive(self) == u_try(self) \/ u_try1(self)
                                            \/ u_resv1(self)
                                            \/ u_resv2(self)
                                            \/ u_fail(self) \/ u_ret(self)

thread(self) == /\ pc[self] = "thread"
                /\ \/ /\ pc' = [pc EXCEPT ![self] = "rloop"]
                   \/ /\ pc' = [pc EXCEPT ![self] = "uloop"]
                   \/ /\ pc' = [pc EXCEPT ![self] = "wloop"]
                   \/ /\ pc' = [pc EXCEPT ![self] = "dloop"]
                /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                ret_try_u, ret_try_wx, rwlock, stack, 
                                arg_event_i, arg_event_n, arg_unlock_n, 
                                xw_word, arg_w_word, xl_word, xu_word, d_word, 
                                sl_word, su_word, u_word >>

rloop(self) == /\ pc[self] = "rloop"
               /\ pc' = [pc EXCEPT ![self] = "rlock"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, d_word, sl_word, 
                               su_word, u_word >>

rlock(self) == /\ pc[self] = "rlock"
               /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_lock_shared",
                                                        pc        |->  "rcs",
                                                        sl_word   |->  sl_word[self] ] >>
                                                    \o stack[self]]
               /\ sl_word' = [sl_word EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "s_loop"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, su_word, u_word >>

rcs(self) == /\ pc[self] = "rcs"
             /\ TRUE
             /\ pc' = [pc EXCEPT ![self] = "runlock"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, rwlock, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, su_word, 
                             u_word >>

runlock(self) == /\ pc[self] = "runlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_unlock_shared",
                                                          pc        |->  "rloop",
                                                          su_word   |->  su_word[self] ] >>
                                                      \o stack[self]]
                 /\ su_word' = [su_word EXCEPT ![self] = defaultInitValue]
                 /\ pc' = [pc EXCEPT ![self] = "us1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                 arg_event_n, arg_unlock_n, xw_word, 
                                 arg_w_word, xl_word, xu_word, d_word, sl_word, 
                                 u_word >>

uloop(self) == /\ pc[self] = "uloop"
               /\ pc' = [pc EXCEPT ![self] = "ulock"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, d_word, sl_word, 
                               su_word, u_word >>

ulock(self) == /\ pc[self] = "ulock"
               /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_lock_shared",
                                                        pc        |->  "urcs",
                                                        sl_word   |->  sl_word[self] ] >>
                                                    \o stack[self]]
               /\ sl_word' = [sl_word EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "s_loop"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, su_word, u_word >>

urcs(self) == /\ pc[self] = "urcs"
              /\ TRUE
              /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_lock_shared_to_exclusive",
                                                       pc        |->  "upgrade" ] >>
                                                   \o stack[self]]
              /\ pc' = [pc EXCEPT ![self] = "u_try"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                              ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                              arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                              xl_word, xu_word, d_word, sl_word, su_word, 
                              u_word >>

upgrade(self) == /\ pc[self] = "upgrade"
                 /\ IF ret_try_u[self]
                       THEN /\ pc' = [pc EXCEPT ![self] = "uwcs"]
                       ELSE /\ pc' = [pc EXCEPT ![self] = "udone"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, stack, 
                                 arg_event_i, arg_event_n, arg_unlock_n, 
                                 xw_word, arg_w_word, xl_word, xu_word, d_word, 
                                 sl_word, su_word, u_word >>

uwcs(self) == /\ pc[self] = "uwcs"
              /\ TRUE
              /\ pc' = [pc EXCEPT ![self] = "uunlock"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                              ret_try_u, ret_try_wx, rwlock, stack, 
                              arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                              arg_w_word, xl_word, xu_word, d_word, sl_word, 
                              su_word, u_word >>

uunlock(self) == /\ pc[self] = "uunlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_unlock_exclusive",
                                                          pc        |->  "udone",
                                                          xu_word   |->  xu_word[self] ] >>
                                                      \o stack[self]]
                 /\ xu_word' = [xu_word EXCEPT ![self] = defaultInitValue]
                 /\ pc' = [pc EXCEPT ![self] = "ux1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                 arg_event_n, arg_unlock_n, xw_word, 
                                 arg_w_word, xl_word, d_word, sl_word, su_word, 
                                 u_word >>

udone(self) == /\ pc[self] = "udone"
               /\ ret_try_u' = [ret_try_u EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "uloop"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_wx, rwlock, stack, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xl_word, xu_word, d_word, sl_word, su_word, 
                               u_word >>

wloop(self) == /\ pc[self] = "wloop"
               /\ pc' = [pc EXCEPT ![self] = "wlock"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, d_word, sl_word, 
                               su_word, u_word >>

wlock(self) == /\ pc[self] = "wlock"
               /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_lock_exclusive",
                                                        pc        |->  "wcs",
                                                        xl_word   |->  xl_word[self] ] >>
                                                    \o stack[self]]
               /\ xl_word' = [xl_word EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "x_loop"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xu_word, d_word, sl_word, su_word, u_word >>

wcs(self) == /\ pc[self] = "wcs"
             /\ TRUE
             /\ pc' = [pc EXCEPT ![self] = "wunlock"]
             /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                             ret_try_u, ret_try_wx, rwlock, stack, arg_event_i, 
                             arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                             xl_word, xu_word, d_word, sl_word, su_word, 
                             u_word >>

wunlock(self) == /\ pc[self] = "wunlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_unlock_exclusive",
                                                          pc        |->  "wloop",
                                                          xu_word   |->  xu_word[self] ] >>
                                                      \o stack[self]]
                 /\ xu_word' = [xu_word EXCEPT ![self] = defaultInitValue]
                 /\ pc' = [pc EXCEPT ![self] = "ux1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                 arg_event_n, arg_unlock_n, xw_word, 
                                 arg_w_word, xl_word, d_word, sl_word, su_word, 
                                 u_word >>

dloop(self) == /\ pc[self] = "dloop"
               /\ pc' = [pc EXCEPT ![self] = "dlock"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, stack, 
                               arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                               arg_w_word, xl_word, xu_word, d_word, sl_word, 
                               su_word, u_word >>

dlock(self) == /\ pc[self] = "dlock"
               /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_lock_exclusive",
                                                        pc        |->  "dwcs",
                                                        xl_word   |->  xl_word[self] ] >>
                                                    \o stack[self]]
               /\ xl_word' = [xl_word EXCEPT ![self] = defaultInitValue]
               /\ pc' = [pc EXCEPT ![self] = "x_loop"]
               /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                               ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                               arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                               xu_word, d_word, sl_word, su_word, u_word >>

dwcs(self) == /\ pc[self] = "dwcs"
              /\ TRUE
              /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_lock_exclusive_to_shared",
                                                       pc        |->  "drcs",
                                                       d_word    |->  d_word[self] ] >>
                                                   \o stack[self]]
              /\ d_word' = [d_word EXCEPT ![self] = defaultInitValue]
              /\ pc' = [pc EXCEPT ![self] = "d1"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                              ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                              arg_event_n, arg_unlock_n, xw_word, arg_w_word, 
                              xl_word, xu_word, sl_word, su_word, u_word >>

drcs(self) == /\ pc[self] = "drcs"
              /\ TRUE
              /\ pc' = [pc EXCEPT ![self] = "dunlock"]
              /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                              ret_try_u, ret_try_wx, rwlock, stack, 
                              arg_event_i, arg_event_n, arg_unlock_n, xw_word, 
                              arg_w_word, xl_word, xu_word, d_word, sl_word, 
                              su_word, u_word >>

dunlock(self) == /\ pc[self] = "dunlock"
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "lck_rw_unlock_shared",
                                                          pc        |->  "dloop",
                                                          su_word   |->  su_word[self] ] >>
                                                      \o stack[self]]
                 /\ su_word' = [su_word EXCEPT ![self] = defaultInitValue]
                 /\ pc' = [pc EXCEPT ![self] = "us1"]
                 /\ UNCHANGED << waitqs, ret_blocked, ret_wakeup, ret_identify, 
                                 ret_try_u, ret_try_wx, rwlock, arg_event_i, 
                                 arg_event_n, arg_unlock_n, xw_word, 
                                 arg_w_word, xl_word, xu_word, d_word, sl_word, 
                                 u_word >>

t(self) == thread(self) \/ rloop(self) \/ rlock(self) \/ rcs(self)
              \/ runlock(self) \/ uloop(self) \/ ulock(self) \/ urcs(self)
              \/ upgrade(self) \/ uwcs(self) \/ uunlock(self)
              \/ udone(self) \/ wloop(self) \/ wlock(self) \/ wcs(self)
              \/ wunlock(self) \/ dloop(self) \/ dlock(self) \/ dwcs(self)
              \/ drcs(self) \/ dunlock(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in ProcSet:  \/ identify(self) \/ resume(self)
                               \/ wakeup_1(self) \/ thread_block(self)
                               \/ lck_rw_wakeup_x(self)
                               \/ lck_rw_wakeup_s(self)
                               \/ lck_rw_wakeup_u(self)
                               \/ lck_rw_wakeup(self)
                               \/ lck_rw_lock_exclusive(self)
                               \/ lck_rw_unlock_exclusive(self)
                               \/ lck_rw_lock_exclusive_to_shared(self)
                               \/ lck_rw_lock_shared(self)
                               \/ lck_rw_unlock_shared(self)
                               \/ __lck_rw_lock_u2x_contended(self)
                               \/ lck_rw_lock_shared_to_exclusive(self))
           \/ (\E self \in Threads: t(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Next)
        /\ \A self \in Threads : /\ WF_vars(t(self))
                                 /\ WF_vars(lck_rw_lock_shared(self))
                                 /\ WF_vars(lck_rw_unlock_shared(self))
                                 /\ WF_vars(lck_rw_lock_shared_to_exclusive(self))                                 /\ WF_vars(lck_rw_unlock_exclusive(self))
                                 /\ WF_vars(lck_rw_lock_exclusive(self))
                                 /\ WF_vars(lck_rw_lock_exclusive_to_shared(self))                                 /\ WF_vars(thread_block(self))
                                 /\ WF_vars(identify(self))
                                 /\ WF_vars(resume(self))
                                 /\ WF_vars(lck_rw_wakeup_x(self))
                                 /\ WF_vars(lck_rw_wakeup_s(self))
                                 /\ WF_vars(lck_rw_wakeup_u(self))
                                 /\ WF_vars(lck_rw_wakeup(self))
                                 /\ WF_vars(__lck_rw_lock_u2x_contended(self))

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
View == << waitqs, rwlock, pc, stack,
           xl_word, xu_word, d_word,
           sl_word, su_word, u_word >>

====
\* vim:et sw=8 ts=8 tw=80:
