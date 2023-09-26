/*
 * Copyright (c) 2000-2020 Apple, Inc. All rights reserved.
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

#ifdef __x86_64__
#include <i386/mp.h>
#include <i386/cpu_data.h>
#include <i386/bit_routines.h>
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <i386/serial_io.h>
#endif /* __x86_64__ */

#include <machine/machine_cpu.h>
#include <libkern/OSAtomic.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <console/video_console.h>
#include <console/serial_protos.h>
#include <kern/startup.h>
#include <kern/thread.h>
#include <kern/cpu_data.h>
#include <kern/sched_prim.h>
#include <libkern/section_keywords.h>

#if __arm64__
#include <machine/machine_routines.h>
#include <arm/cpu_data_internal.h>
#endif

#ifdef CONFIG_XNUPOST
#include <tests/xnupost.h>
kern_return_t console_serial_test(void);
kern_return_t console_serial_parallel_log_tests(void);
#endif

/* Structure representing the console ring buffer. */
static struct {
	/* The ring buffer backing store. */
	char *buffer;

	/* The total length of the ring buffer. */
	int len;

	/**
	 * The number of characters that have been written into the buffer that need
	 * to be drained.
	 */
	int used;

	/**
	 * Number of reserved regions in the buffer. These are regions that are
	 * currently being written into by various CPUs. We use this as a way of
	 * determining when it's safe to drain the buffer.
	 */
	int nreserved;

	/* The location in the buffer thats written to next. */
	char *write_ptr;

	/* The location in the buffer that will be drained next. */
	char *read_ptr;

	/* Synchronizes the flushing of the ring buffer to hardware */
	lck_mtx_t flush_lock;

	/**
	 * Synchronizes reserving space in the ring buffer and ensures that only
	 * completed writes are flushed.
	 */
	lck_ticket_t write_lock;
} console_ring;

/**
 * We don't dedicate any buffer space to specific CPUs, but this value is used
 * to scale the size of the console buffer by the number of CPUs.
 *
 * How many bytes-per-cpu to allocate in the console ring buffer. Also affects
 * the maximum number of bytes a single console thread can drain.
 */
#define CPU_CONS_BUF_SIZE 256

/* Scale the size of the console ring buffer by the number of CPUs. */
#define KERN_CONSOLE_RING_SIZE vm_map_round_page(CPU_CONS_BUF_SIZE * (MAX_CPUS + 1), PAGE_SIZE - 1)

#define MAX_FLUSH_SIZE_LOCK_HELD 16
#define MAX_TOTAL_FLUSH_SIZE (MAX(2, MAX_CPUS) * CPU_CONS_BUF_SIZE)

extern int serial_getc(void);
extern void serial_putc_options(char, bool);

#if DEBUG || DEVELOPMENT
TUNABLE(bool, allow_printf_from_interrupts_disabled_context, "nointr_consio", false);
#else
#define allow_printf_from_interrupts_disabled_context false
#endif

SECURITY_READ_ONLY_EARLY(struct console_ops) cons_ops[] = {
	{
		.putc = serial_putc_options, .getc = _serial_getc,
	},
	{
		.putc = vcputc_options, .getc = _vcgetc,
	},
};

SECURITY_READ_ONLY_EARLY(uint32_t) nconsops = (sizeof cons_ops / sizeof cons_ops[0]);

#if __x86_64__
uint32_t cons_ops_index = VC_CONS_OPS;
#else
SECURITY_READ_ONLY_LATE(uint32_t) cons_ops_index = VC_CONS_OPS;
#endif

LCK_GRP_DECLARE(console_lck_grp, "console");

/* If the NMI string is entered into the console, the system will enter the debugger. */
#define NMI_STRING_SIZE 32
char nmi_string[NMI_STRING_SIZE] = "afDIGHr84A84jh19Kphgp428DNPdnapq";
static int nmi_counter           = 0;

/**
 * This is used to prevent console output from going through the console ring
 * buffer synchronization in cases where that could cause issues (e.g., during
 * panics/stackshots and going down for sleep).
 */
static bool console_suspended = false;

/**
 * Controls console output for underlying serial or video console.
 * To be used only by core console and init accessors.
 */
int disableConsoleOutput;

/**
 * Enforce policies around when console I/O is allowed. Most importantly about
 * not performing console I/O while interrupts are disabled (which can cause
 * serious latency issues).
 *
 * @return True if console I/O should be allowed, false otherwise.
 */
static inline bool
console_io_allowed(void)
{
	if (!allow_printf_from_interrupts_disabled_context &&
	    !console_suspended &&
	    startup_phase >= STARTUP_SUB_EARLY_BOOT &&
	    !ml_get_interrupts_enabled()) {
#if defined(__arm64__) || DEBUG || DEVELOPMENT
		panic("Console I/O from interrupt-disabled context");
#else
		return false;
#endif
	}

	return true;
}

/**
 * Initialize the console ring buffer and console lock. It's still possible to
 * call console_write() before initializing the ring buffer. In that case the
 * data will get outputted directly to the underlying serial/video console
 * without synchronization.
 *
 * This function is also safe to call multiple times. Any call after the first
 * will return early without doing anything.
 */
void
console_init(void)
{
	if (console_ring.len != 0) {
		return;
	}

	kmem_alloc(kernel_map, (vm_offset_t *)&console_ring.buffer,
	    KERN_CONSOLE_RING_SIZE + ptoa(2), KMA_NOFAIL | KMA_PERMANENT |
	    KMA_KOBJECT | KMA_PERMANENT | KMA_GUARD_FIRST | KMA_GUARD_LAST |
	    KMA_ZERO | KMA_DATA, VM_KERN_MEMORY_OSFMK);

	console_ring.buffer   += PAGE_SIZE; /* Skip past the first guard page. */
	console_ring.len       = KERN_CONSOLE_RING_SIZE;
	console_ring.used      = 0;
	console_ring.nreserved = 0;
	console_ring.read_ptr  = console_ring.buffer;
	console_ring.write_ptr = console_ring.buffer;

	lck_mtx_init(&console_ring.flush_lock, &console_lck_grp, LCK_ATTR_NULL);
	lck_ticket_init(&console_ring.write_lock, &console_lck_grp);
}

/**
 * Returns true when the console has already been initialized.
 */
static inline bool
is_console_initialized(void)
{
	return console_ring.len == KERN_CONSOLE_RING_SIZE;
}

/**
 * Return the index to the currently selected console (serial/video). This is
 * an index into the "cons_ops[]" array of function pointer structs.
 */
static inline uint32_t
get_cons_ops_index(void)
{
	uint32_t idx = cons_ops_index;

	if (idx >= nconsops) {
		panic("Bad cons_ops_index: %d", idx);
	}

	return idx;
}

/**
 * Helper function for outputting a character to the underlying console
 * (either video or serial) with the possibility of sleeping waiting for
 * an interrupt indicating the console is ready.
 *
 * @note assumes console_ring.read lock is held if poll == false
 *
 * @param c The character to print.
 * @param poll Whether or not this call should poll instead of going to sleep
 *             waiting for an interrupt when the hardware device isn't ready
 */
static inline void
_cnputc(char c, bool poll)
{
	bool in_debugger = (kernel_debugger_entry_count > 0);
	const uint32_t idx = get_cons_ops_index();

	poll = poll || in_debugger;

	if (c == '\n') {
		_cnputc('\r', poll);
	}

	cons_ops[idx].putc(c, poll);
}

/**
 * Helper function for outputting characters directly to the underlying console
 * (either video or serial).
 *
 * @note disableConsoleOutput is to be used only by core console and init accessors
 *       such as this function. Returns early if the serial output is disabled.
 *
 * @param c The array of characters to print.
 * @param poll Whether or not this call should poll instead of going to sleep
 *             waiting for an interrupt when the hardware device isn't ready
 * @param size The number of characters to print to the console.
 */
static inline void
_cnputs(char *c, int size, bool poll)
{
	if (disableConsoleOutput) {
		return;
	}

	assert(c != NULL);

	while (size-- > 0) {
		_cnputc(*c, poll);
		c++;
	}
}

/**
 * Attempt to reserve space for a number of characters in the console ring
 * buffer. Space in the ring buffer must be reserved before new characters can
 * be entered.
 *
 * Every call to this function should be paired with a corresponding call to
 * console_ring_unreserve_space().
 *
 * @note If space is successfully reserved, this will disable preemption because
 *       otherwise, console_ring_try_empty() could take arbitrarily long.
 *
 * @param nchars The number of characters to reserve.
 *
 * @return If the wanted number of characters could not be reserved, then return
 *         NULL. Otherwise, return a pointer to the beginning of the reserved
 *         space.
 */
static inline char*
console_ring_reserve_space(int nchars)
{
	char *write_ptr = NULL;
	lck_ticket_lock(&console_ring.write_lock, &console_lck_grp);
	if ((console_ring.len - console_ring.used) >= nchars) {
		console_ring.used += nchars;
		mp_disable_preemption();
		os_atomic_inc(&console_ring.nreserved, relaxed);

		/* Return out the pointer to the beginning of the just reserved space. */
		write_ptr = console_ring.write_ptr;

		/* Move the console ring's write pointer to the beginning of the next free space. */
		const ptrdiff_t write_index = console_ring.write_ptr - console_ring.buffer;
		console_ring.write_ptr = console_ring.buffer + ((write_index + nchars) % console_ring.len);
	}
	lck_ticket_unlock(&console_ring.write_lock);
	return write_ptr;
}

/**
 * Decrement the number of reserved spaces in the console ring (now that the data
 * has been written) and re-enable preemption.
 *
 * Every call to this function should be paired with a corresponding call to
 * console_ring_reserve_space().
 */
static inline void
console_ring_unreserve_space(void)
{
	assert(console_ring.nreserved > 0);

	os_atomic_dec(&console_ring.nreserved, relaxed);
	mp_enable_preemption();
}

/**
 * Write a single character into the console ring buffer and handle moving the
 * write pointer circularly around the buffer.
 *
 * @note Space to write this character must have already been reserved using
 *       console_ring_reserve_space().
 *
 * @param write_ptr Pointer into the reserved space in the buffer to write the
 *                  character. This pointer will get moved to the next valid
 *                  location to write a character so the same pointer can be
 *                  passed into subsequent calls to write multiple characters.
 * @param ch The character to insert into the ring buffer.
 */
static inline void
console_ring_put(char **write_ptr, char ch)
{
	assert(console_ring.nreserved > 0);
	**write_ptr = ch;
	++(*write_ptr);
	if ((*write_ptr - console_ring.buffer) == console_ring.len) {
		*write_ptr = console_ring.buffer;
	}
}

/**
 * Attempt to drain the console ring buffer if no other CPUs are already doing
 * so.
 *
 * @param fail_fast If true, this function returns immediately instead of
 *                  sleeping if the thread fails to acquire the console flush
 *                  mutex.
 *
 * @note This function should not be called with preemption disabled.
 *
 * @note To prevent one CPU from holding the console lock for too long, only
 *       MAX_FLUSH_SIZE_LOCK_HELD number of characters can be drained at a time
 *       with the lock held. The lock will be dropped between each drain of size
 *       MAX_FLUSH_SIZE_LOCK_HELD to allow another CPU to grab the lock. If
 *       another CPU grabs the lock, then the original thread can stop draining
 *       and return instead of sleeping for the lock.
 *
 * @note To prevent one thread from being the drain thread for too long (presumably
 *       that thread has other things it wants to do besides draining serial), the
 *       total number of characters a single call to this function can drain is
 *       restricted to MAX_TOTAL_FLUSH_SIZE.
 */
static void
console_ring_try_empty(bool fail_fast)
{
	char flush_buf[MAX_FLUSH_SIZE_LOCK_HELD];

	int nchars_out       = 0;
	int total_chars_out  = 0;
	int size_before_wrap = 0;
	bool in_debugger = (kernel_debugger_entry_count > 0);

	if (__improbable(!console_io_allowed()) || get_preemption_level() != 0) {
		return;
	}

	do {
		if (__probable(!in_debugger) && fail_fast && !lck_mtx_try_lock(&console_ring.flush_lock)) {
			return;
		} else if (__probable(!in_debugger) && !fail_fast) {
			lck_mtx_lock(&console_ring.flush_lock);
		}

		if (__probable(!in_debugger)) {
			lck_ticket_lock(&console_ring.write_lock, &console_lck_grp);

			/**
			 * If we've managed to grab the write lock, but there's still space
			 * reserved in the buffer, then other CPUs are actively writing into
			 * the ring, wait for them to finish.
			 */
			while (os_atomic_load(&console_ring.nreserved, relaxed) > 0) {
				cpu_pause();
			}
		}

		/* Try small chunk at a time, so we allow writes from other cpus into the buffer. */
		nchars_out = MIN(console_ring.used, (int)sizeof(flush_buf));

		/* Account for data to be read before wrap around. */
		size_before_wrap = (int)((console_ring.buffer + console_ring.len) - console_ring.read_ptr);
		if (nchars_out > size_before_wrap) {
			nchars_out = size_before_wrap;
		}

		/**
		 * Copy the characters to be drained into a separate flush buffer, and
		 * move the console read pointer to the next chunk of data that needs to
		 * be drained.
		 */
		if (nchars_out > 0) {
			memcpy(flush_buf, console_ring.read_ptr, nchars_out);
			const ptrdiff_t read_index = console_ring.read_ptr - console_ring.buffer;
			console_ring.read_ptr = console_ring.buffer + ((read_index + nchars_out) % console_ring.len);
			console_ring.used -= nchars_out;
		}

		if (__probable(!in_debugger)) {
			lck_ticket_unlock(&console_ring.write_lock);
		}

		/**
		 * Output characters to the underlying console (serial/video). We should
		 * only poll if the console is suspended.
		 */
		if (nchars_out > 0) {
			total_chars_out += nchars_out;
			_cnputs(flush_buf, nchars_out, console_suspended);
		}

		if (__probable(!in_debugger)) {
			lck_mtx_unlock(&console_ring.flush_lock);
		}

		/**
		 * Prevent this thread from sleeping on the lock again if another thread
		 * grabs it after we drop it.
		 */
		fail_fast = true;

		/*
		 * In case we end up being the console drain thread for far too long,
		 * break out. Except in panic/suspend cases where we should clear out
		 * the full buffer.
		 */
		if (!console_suspended && (total_chars_out >= MAX_TOTAL_FLUSH_SIZE)) {
			break;
		}
	} while (nchars_out > 0);
}

/**
 * Notify the console subystem that all following console writes should skip
 * synchronization and get outputted directly to the underlying console. This is
 * important for cases like panic/stackshots and going down for sleep where
 * assumptions about the state of the system could cause hangs or nested panics.
 */
void
console_suspend()
{
	console_suspended = true;
	console_ring_try_empty(false);
}

/**
 * Notify the console subsystem that it is now safe to use the console ring
 * buffer synchronization when writing console data.
 */
void
console_resume()
{
	console_suspended = false;
}

/**
 * Write a string of characters to the underlying video or serial console in a
 * synchronized manner. By synchronizing access to a global console buffer, this
 * prevents the serial output from appearing interleaved to the end user when
 * multiple CPUs are outputting to the console at the same time.
 *
 * @note It's safe to call this function even before the console buffer has been
 *       initialized. In that case, the data will be sent directly to the
 *       underlying console with no buffering. This is the same for when the
 *       console is suspended.
 *
 * @note disableConsoleOutput is to be used only by core console and init accessors
 *       such as this function. Returns early if the serial output is disabled and
 *       skips lock acquisition.
 *
 * @param str The string of characters to print.
 * @param size The number of characters in `str` to print.
 */
void
console_write(char *str, int size)
{
	if (disableConsoleOutput) {
		return;
	}

	assert(str != NULL);

	char *write_ptr = NULL;
	int chunk_size = CPU_CONS_BUF_SIZE;
	int i = 0;

	if (__improbable(console_suspended || !is_console_initialized() || pmap_in_ppl())) {
		/*
		 * Output directly to console in the following cases:
		 * 1. If this is early in boot before the console has been initialized.
		 * 2. If we're heading into suspend.
		 * 3. If we're in the kernel debugger for a panic/stackshot. If any of
		 *    the other cores happened to halt while holding any of the console
		 *    locks, attempting to use the normal path will result in sadness.
		 * 4. If we're in the PPL. As we synchronize the ring buffer with a
		 *    mutex and preemption is disabled in the PPL, any writes must go
		 *    directly to the hardware device.
		 */
		_cnputs(str, size, true);
		return;
	} else if (__improbable(!console_io_allowed())) {
		return;
	}

	while (size > 0) {
		/**
		 * Restrict the maximum number of characters that can be reserved at
		 * once. This helps prevent one CPU from reserving too much and starving
		 * out the other CPUs.
		 */
		if (size < chunk_size) {
			chunk_size = size;
		}

		/**
		 * Attempt to reserve space in the ring buffer and if that fails, then
		 * keep attempting to drain the ring buffer until there's enough space.
		 * We can't flush the serial console with preemption disabled so return
		 * early to drop the message in that case.
		 */
		while ((write_ptr = console_ring_reserve_space(chunk_size)) == NULL) {
			if (get_preemption_level() != 0) {
				return;
			}

			console_ring_try_empty(false);
		}

		for (i = 0; i < chunk_size; i++) {
			console_ring_put(&write_ptr, str[i]);
		}

		console_ring_unreserve_space();
		str = &str[i];
		size -= chunk_size;
	}

	/* Do good faith flush if preemption is not disabled */
	if (get_preemption_level() == 0) {
		console_ring_try_empty(true);
	}
}

/**
 * Output a character directly to the underlying console (either video or serial).
 * This directly bypasses the console serial buffer (as provided by console_write())
 * and all of the synchronization that provides.
 *
 * @note This function can cause serial data to get printed interleaved if being
 *       called on multiple CPUs at the same time. Only use this function if
 *       there's a specific reason why this serial data can't get synchronized
 *       through the console buffer.
 *
 * @note disableConsoleOutput is to be used only by core console and init accessors
 *       such as this function. Returns early if the serial output is disabled.
 *
 * @param c The character to print.
 */
void
console_write_unbuffered(char c)
{
	if (disableConsoleOutput) {
		return;
	}

	_cnputc(c, true);
}

/**
 * Write a single character to the selected console (video or serial).
 *
 * @param c The character to print.
 */
void
console_write_char(char c)
{
	console_write(&c, 1);
}

/**
 * Wrapper around the platform-dependent serial input method which handles
 * waiting for a new character and checking for the NMI string.
 *
 * @param wait True if this function should block until a character appears.
 *
 * @return The character if one was read, -1 otherwise.
 */
int
_serial_getc(bool wait)
{
	int c = -1;

	do {
		c = serial_getc();
	} while (wait && c < 0);

	/* Check for the NMI string. */
	if (c == nmi_string[nmi_counter]) {
		nmi_counter++;
		if (nmi_counter == NMI_STRING_SIZE) {
			/* We've got the NMI string, now do an NMI. */
			Debugger("Automatic NMI");
			nmi_counter = 0;
			return '\n';
		}
	} else if (c != -1) {
		nmi_counter = 0;
	}

	return c;
}

/**
 * Typically the video console doesn't support input, but we call into the
 * pexpert to give each platform an opportunity to provide console input through
 * alternative methods if it so desires.
 *
 * Usually a platform will either not provide any input, or will grab input from
 * the serial driver.
 *
 * @return The character if one was read, or -1 otherwise.
 */
int
_vcgetc(__unused bool wait)
{
	char c;

	if (0 == PE_stub_poll_input(0, &c)) {
		return c;
	} else {
		return -1;
	}
}

/**
 * Block until a character is available from the console and return it.
 *
 * @return The character retrieved from the console.
 */
int
console_read_char(void)
{
	const uint32_t idx = get_cons_ops_index();
	return cons_ops[idx].getc(true);
}

/**
 * Attempt to read a character from the console, and if one isn't available,
 * then return immediately.
 *
 * @return The character if one is available, -1 otherwise.
 */
int
console_try_read_char(void)
{
	const uint32_t idx = get_cons_ops_index();
	return cons_ops[idx].getc(false);
}

#ifdef CONFIG_XNUPOST
static uint32_t cons_test_ops_count = 0;

/*
 * Log to console by multiple methods - printf, unbuffered write, console_write()
 */
static void
log_to_console_func(void * arg __unused, wait_result_t wres __unused)
{
	uint64_t thread_id = current_thread()->thread_id;
	char somedata[10] = "123456789";
	for (int i = 0; i < 26; i++) {
		os_atomic_inc(&cons_test_ops_count, relaxed);
		printf(" thid: %llu printf iteration %d\n", thread_id, i);
		console_write_unbuffered((char)('A' + i));
		console_write_unbuffered('\n');
		console_write((char *)somedata, sizeof(somedata));
		delay(10);
	}
	printf("finished the log_to_console_func operations\n\n");
}

/* Test that outputting to the console can occur on multiple threads at the same time. */
kern_return_t
console_serial_parallel_log_tests(void)
{
	thread_t thread;
	kern_return_t kr;
	cons_test_ops_count = 0;

	kr = kernel_thread_start(log_to_console_func, NULL, &thread);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	delay(100);

	log_to_console_func(NULL, 0);

	/* wait until other thread has also finished */
	while (cons_test_ops_count < 52) {
		delay(1000);
	}

	thread_deallocate(thread);
	T_LOG("parallel_logging tests is now complete. From this point forward we expect full lines\n");
	return KERN_SUCCESS;
}

/* Basic serial test that prints serial output through various methods (printf/T_LOG). */
kern_return_t
console_serial_test(void)
{
	unsigned long i;
	char buffer[CPU_CONS_BUF_SIZE];

	T_LOG("Checking console_ring status.");
	T_ASSERT_EQ_INT(console_ring.len, KERN_CONSOLE_RING_SIZE, "Console ring size is not correct.");

	/* setup buffer to be chars */
	for (i = 0; i < CPU_CONS_BUF_SIZE; i++) {
		buffer[i] = (char)('0' + (i % 10));
	}
	buffer[CPU_CONS_BUF_SIZE - 1] = '\0';

	T_LOG("Printing %d char string to serial one char at a time.", CPU_CONS_BUF_SIZE);
	for (i = 0; i < CPU_CONS_BUF_SIZE; i++) {
		printf("%c", buffer[i]);
	}
	printf("End\n");
	T_LOG("Printing %d char string to serial as a whole", CPU_CONS_BUF_SIZE);
	printf("%s\n", buffer);

	T_LOG("Using console_write call repeatedly for 100 iterations");
	for (i = 0; i < 100; i++) {
		console_write(&buffer[0], 14);
		if ((i % 6) == 0) {
			printf("\n");
		}
	}
	printf("\n");

	T_LOG("Using T_LOG to print buffer %s", buffer);
	return KERN_SUCCESS;
}
#endif
