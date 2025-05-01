# Atomic Condition Variables for Thread Synchronization

Quickly synchronizing when multiple threads could send wakeups.

## Overview

`sched_cond_*` (see `sched_prim.h`) provides a means of optimized wake/sleep
synchronization on kernel threads. Specifically, it provides a wrapper for
`assert_wait`/`thread_block` & `thread_wake` patterns with fast paths.

## Interfaces
* `sched_cond_t` / `sched_cond_atomic_t` - Atomic condition variable type to synchronize on
* `sched_cond_init(sched_cond_t *cond)` - Initialize the atomic condition var
* `sched_cond_wait(sched_cond_t *cond, ...)` - Set state to inactive and wait for a wakeup on cond
* `sched_cond_signal(sched_cond_t *cond, ...)` - Issue a wakeup on cond for the specified thread
* `sched_cond_ack(sched_cond_t *cond)` - Acknowledge the wakeup on cond and set state to active

## Limitations of Existing Interfaces

Consider the following example of a producer-consumer relationship.

### Producer Thread
```c
while(1) {
	...
	thread_wake_thread(..., consumer_thread); // (A)
}
```
### Consumer Thread
```c
void work_loop_continuation() 
{
	// (B)
	...
	assert_wait(...); // (C)
	thread_block(..., work_loop_continuation); // (D)
}
```

This scheme has two key inefficiences:
1. Multiple calls to wake the consumer thread (A) may be made before the consumer_thread has awoken.
   This results in precious CPU cycles being spent in (A) to wake the thread despite the fact that 
   it has already been queued.
2. If in the time since waking (B) and blocking (D), the consumer thread has been sent a wakeup (A), 
   the thread will still yield (D), thus spending precious CPU cycles setting itself up to block only 
   to be immediately queued once more.


## Example Usage 

`sched_cond_t` and its functions provide fast paths for (1) and (2) by wrapping `thread_wake_thread` and 
`assert_wait/thread_block` with atomic bit operations. 

Using these enhancements, the previous example can be revised to:

### Producer Thread
```c
while(1) {
	...
	sched_cond_signal(&my_cond, ...); // (E)
}
```
### Consumer Thread
```c
void work_loop_continuation() 
{
	sched_cond_ack(&my_cond); // (F)
	while (1) {
		...
		sched_cond_wait(&my_cond, ..., work_loop_continuation); // (G)
	}
}
```

In this example, the producer thread signals the consumer (E), resulting in an explicit wake (A) iff the consumer is 
not awake and has not already been issued an un-acked wakeup. Conversely, the consumer acks the wakeup (F) once awake, 
signalling that it is active and clearing the queued wakeup. Once done with its consumption it attempts to wait on the 
cond (G), signalling that it is inactive and checking for any wakeups that have been issued since the last ack (F). 
If a wakeup has been issued, the consumer immediately acks the wakeup and returns to re-enter the work loop. Else, 
it will block as in (D).

### On acknowledging wakeups

One may note that the adoption of `sched_cond_*` involves adding an additional step (ack) to the consumers work loop. This 
step is critical for two reasons.

1. Wakeups can be coalesced without potential loss of data. By ack-ing the wakeup *prior* to doing work, wakeups 
    that are issued while the thread is active are guaranteed to be observed because the consumer will check for wakeups since the 
    last ack before giong to sleep.
2. Wakeups need not explicitly `thread_wake` the consumer thread if it is already awake. This is because the consumer thread will not 
    block if it observes a wakeup has been issued while it was awake.

