/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1986, 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)subr_prf.c	8.4 (Berkeley) 5/4/95
 */
/* HISTORY
 * 22-Sep-1997 Umesh Vaishampayan (umeshv@apple.com)
 *	Cleaned up m68k crud. Fixed vlog() to do logpri() for ppc, too.
 *
 * 17-July-97  Umesh Vaishampayan (umeshv@apple.com)
 *	Eliminated multiple definition of constty which is defined
 *	in bsd/dev/XXX/cons.c
 *
 * 26-MAR-1997 Umesh Vaishampayan (umeshv@NeXT.com
 *      Fixed tharshing format in many functions. Cleanup.
 *
 * 17-Jun-1995 Mac Gillon (mgillon) at NeXT
 *	Purged old history
 *	New version based on 4.4 and NS3.3
 */

#include <stdarg.h>
#include <sys/conf.h>
#include <sys/file_internal.h>
#include <sys/ioctl.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/msgbuf.h>
#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/reboot.h>
#include <sys/subr_prf.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/tprintf.h>
#include <sys/tty.h>

#include <console/serial_protos.h>
#include <kern/task.h> /* for get_bsdthreadtask_info() */
#include <kern/sched_prim.h>  /* for preemption_enabled() */
#include <libkern/libkern.h>
#include <os/log_private.h>

struct snprintf_arg {
	char *str;
	size_t remain;
};

struct putchar_args {
	int flags;
	struct tty *tty;
	bool last_char_was_cr;
};

static void snprintf_func(int, void *);
static void putchar(int c, void *arg);

/*
 * In case console is off, debugger_panic_str contains argument to last call to
 * panic.
 */
extern const char *debugger_panic_str;

extern struct tty cons;     /* standard console tty */
extern struct tty       *copy_constty(void);               /* current console device */
extern struct tty       *set_constty(struct tty *);

extern int __doprnt(const char *, va_list, void (*)(int, void *), void *, int, int);
extern void console_write_char(char);  /* standard console putc */

static void
putchar_args_init(struct putchar_args *pca, struct session *sessp)
{
	session_lock(sessp);
	pca->flags = TOTTY;
	pca->tty   = sessp->s_ttyp;
	if (pca->tty != TTY_NULL) {
		ttyhold(pca->tty);
	}
	session_unlock(sessp);
}

static void
putchar_args_destroy(struct putchar_args *pca)
{
	if (pca->tty != TTY_NULL) {
		ttyfree(pca->tty);
	}
}

/*
 * Uprintf prints to the controlling terminal for the current process.
 * It may block if the tty queue is overfull.  No message is printed if
 * the queue does not clear in a reasonable time.
 */
void
uprintf(const char *fmt, ...)
{
	struct proc *p = current_proc();
	struct putchar_args pca;
	struct pgrp *pg;
	va_list ap;

	pg = proc_pgrp(p, NULL);

	if ((p->p_flag & P_CONTROLT) && pg) {
		putchar_args_init(&pca, pg->pg_session);

		if (pca.tty != NULL) {
			tty_lock(pca.tty);
		}
		va_start(ap, fmt);
		__doprnt(fmt, ap, putchar, &pca, 10, FALSE);
		va_end(ap);
		if (pca.tty != NULL) {
			tty_unlock(pca.tty);
		}

		putchar_args_destroy(&pca);
	}

	pgrp_rele(pg);
}

tpr_t
tprintf_open(struct proc *p)
{
	struct session *sessp;
	struct pgrp *pg;

	pg = proc_pgrp(p, &sessp);

	if ((p->p_flag & P_CONTROLT) && sessp->s_ttyvp) {
		return pg;
	}

	pgrp_rele(pg);
	return PGRP_NULL;
}

void
tprintf_close(tpr_t pg)
{
	pgrp_rele(pg);
}

static void
tprintf_impl(tpr_t tpr, const char *fmt, va_list ap)
{
	va_list ap2;
	struct putchar_args pca;

	if (tpr) {
		putchar_args_init(&pca, tpr->pg_session);

		if (pca.tty) {
			/* ttycheckoutq(), tputchar() require a locked tp */
			tty_lock(pca.tty);
			if (ttycheckoutq(pca.tty, 0)) {
				/* going to the tty; leave locked */
				va_copy(ap2, ap);
				__doprnt(fmt, ap2, putchar, &pca, 10, FALSE);
				va_end(ap2);
			}
			tty_unlock(pca.tty);
		}

		putchar_args_destroy(&pca);
	}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, ap, __builtin_return_address(0));
#pragma clang diagnostic pop
}

/*
 * tprintf prints on the controlling terminal associated
 * with the given session.
 *
 * NOTE:	No one else should call this function!!!
 */
void
tprintf(tpr_t tpr, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tprintf_impl(tpr, fmt, ap);
	va_end(ap);
}

/*
 * tprintf_thd takes the session reference, calls tprintf
 * with user inputs, and then drops the reference.
 */
void
tprintf_thd(thread_t thd, const char *fmt, ...)
{
	struct proc * p = thd ? get_bsdthreadtask_info(thd) : NULL;
	tpr_t tpr = p ? tprintf_open(p) : NULL;
	va_list ap;

	va_start(ap, fmt);
	tprintf_impl(tpr, fmt, ap);
	va_end(ap);

	tprintf_close(tpr);
}

/*
 * Ttyprintf displays a message on a tty; it should be used only by
 * the tty driver, or anything that knows the underlying tty will not
 * be revoke(2)'d away.  Other callers should use tprintf.
 *
 * Locks:	It is assumed that the tty_lock() is held over the call
 *		to this function.  Ensuring this is the responsibility
 *		of the caller.
 */
void
ttyprintf(struct tty *tp, const char *fmt, ...)
{
	va_list ap;

	if (tp != NULL) {
		struct putchar_args pca;
		pca.flags = TOTTY;
		pca.tty   = tp;

		va_start(ap, fmt);
		__doprnt(fmt, ap, putchar, &pca, 10, TRUE);
		va_end(ap);
	}
}

void
logtime(time_t secs)
{
	printf("Time 0x%lx Message ", secs);
}

int
prf(const char *fmt, va_list ap, int flags, struct tty *ttyp)
{
	struct putchar_args pca;

	pca.flags = flags;
	pca.tty   = ttyp;

	__doprnt(fmt, ap, putchar, &pca, 10, TRUE);

	return 0;
}

/*
 * Warn that a system table is full.
 */
void
tablefull(const char *tab)
{
	log(LOG_ERR, "%s: table is full\n", tab);
}

/*
 * Print a character on console or users terminal.
 * If destination is console then the last MSGBUFS characters
 * are saved in msgbuf for inspection later.
 *
 * Locks:	If TOTTY is set, we assume that the tty lock is held
 *		over the call to this function.
 */
/*ARGSUSED*/
void
putchar(int c, void *arg)
{
	struct putchar_args *pca = arg;
	char **sp = (char**) pca->tty;
	struct tty *constty = NULL;
	struct tty *freetp = NULL;
	const bool allow_constty = preemption_enabled();

	if (allow_constty) {
		constty = copy_constty();
	}

	if (debugger_panic_str && allow_constty && constty != NULL) {
		if (tty_islocked(constty)) {
			ttyfree_locked(constty);
		} else {
			ttyfree(constty);
		}
		constty = NULL;
		freetp = set_constty(NULL);
		if (freetp != NULL) {
			if (tty_islocked(freetp)) {
				ttyfree_locked(freetp);
			} else {
				ttyfree(freetp);
			}
			freetp = NULL;
		}
	}
	if ((pca->flags & TOCONS) && pca->tty == NULL && constty) {
		pca->tty = constty;
		pca->flags |= TOTTY;
	}
	if ((pca->flags & TOTTY) && pca->tty && tputchar(c, pca->tty) < 0 &&
	    (pca->flags & TOCONS) && pca->tty == constty && allow_constty) {
		if (tty_islocked(constty)) {
			ttyfree_locked(constty);
		} else {
			ttyfree(constty);
		}
		constty = NULL;
		freetp = set_constty(NULL);
		if (freetp) {
			if (tty_islocked(freetp)) {
				ttyfree_locked(freetp);
			} else {
				ttyfree(freetp);
			}
			freetp = NULL;
		}
	}
	if ((pca->flags & TOLOG) && c != '\0' && c != '\r' && c != 0177) {
		log_putc((char)c);
	}
	if ((pca->flags & TOLOGLOCKED) && c != '\0' && c != '\r' && c != 0177) {
		log_putc_locked(msgbufp, (char)c);
	}
	if ((pca->flags & TOCONS) && constty == NULL && c != '\0') {
		console_write_char((char)c);
	}
	if (pca->flags & TOSTR) {
		**sp = (char)c;
		(*sp)++;
	}

	pca->last_char_was_cr = ('\n' == c);
	if (constty) {
		if (tty_islocked(constty)) {
			ttyfree_locked(constty);
		} else {
			ttyfree(constty);
		}
	}
}

bool
printf_log_locked(bool addcr, const char *fmt, ...)
{
	bool retval;
	va_list args;

	va_start(args, fmt);
	retval = vprintf_log_locked(fmt, args, addcr);
	va_end(args);

	return retval;
}

bool
vprintf_log_locked(const char *fmt, va_list ap, bool driverkit)
{
	struct putchar_args pca;

	pca.flags = TOLOGLOCKED;
	if (driverkit && enable_dklog_serial_output) {
		pca.flags |= TOCONS;
	}
	pca.tty   = NULL;
	pca.last_char_was_cr = false;
	__doprnt(fmt, ap, putchar, &pca, 10, TRUE);
	if (driverkit) {
		putchar('\n', &pca);
	}
	return pca.last_char_was_cr;
}

#if CONFIG_VSPRINTF
/*
 * Scaled down version of vsprintf(3).
 *
 * Deprecation Warning:
 *	vsprintf() is being deprecated. Please use vsnprintf() instead.
 */
int
vsprintf(char *buf, const char *cfmt, va_list ap)
{
	int retval;
	struct snprintf_arg info;

	info.str = buf;
	info.remain = 999999;

	retval = __doprnt(cfmt, ap, snprintf_func, &info, 10, FALSE);
	if (info.remain >= 1) {
		*info.str++ = '\0';
	}
	return 0;
}
#endif  /* CONFIG_VSPRINTF */

/*
 * Scaled down version of snprintf(3).
 */
int
snprintf(char *str, size_t size, const char *format, ...)
{
	int retval;
	va_list ap;

	va_start(ap, format);
	retval = vsnprintf(str, size, format, ap);
	va_end(ap);
	return retval;
}

const char *
tsnprintf(char *__counted_by(count)dst, size_t count, const char *fmt, ...)
{
	const char *result;
	va_list ap;

	va_start(ap, fmt);
	result = vtsnprintf(dst, count, fmt, ap);
	va_end(ap);
	return result;
}

/*
 * Scaled down version of vsnprintf(3).
 */
int
vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	struct snprintf_arg info;
	int retval;

	info.str = str;
	info.remain = size;
	retval = __doprnt(format, ap, snprintf_func, &info, 10, FALSE);
	if (info.remain >= 1) {
		*info.str++ = '\0';
	}
	return retval;
}

const char *
vtsnprintf(char *__counted_by(count)dst, size_t count, const char *fmt, va_list ap)
{
	if (count == 0) {
		return NULL;
	}
	(void) vsnprintf(dst, count, fmt, ap);
	return __unsafe_forge_null_terminated(const char *, dst);
}

int
vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int i;

	i = vsnprintf(buf, size, fmt, args);
	/* Note: XNU's printf never returns negative values */
	if ((uint32_t)i < size) {
		return i;
	}
	if (size == 0) {
		return 0;
	}
	if (size > INT_MAX) {
		return INT_MAX;
	}
	return (int)(size - 1);
}

int
scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}

static void
snprintf_func(int ch, void *arg)
{
	struct snprintf_arg *const info = arg;

	if (info->remain >= 2) {
		*info->str++ = (char)ch;
		info->remain--;
	}
}
