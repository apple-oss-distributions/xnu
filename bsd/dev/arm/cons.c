/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 */
/*
 * Copyright (c) 1987, 1988 NeXT, Inc.
 *
 * HISTORY 7-Jan-93  Mac Gillon (mgillon) at NeXT Integrated POSIX support
 *
 * 12-Aug-87  John Seamons (jks) at NeXT Ported to NeXT.
 */

/*
 * Indirect driver for console.
 */
#include <kern/locks.h>
#include <machine/cons.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/uio.h>

static struct tty      *_constty;               /* current console device */
static LCK_GRP_DECLARE(_constty_lock_grp, "constty");
static LCK_MTX_DECLARE(_constty_lock, &_constty_lock_grp);

struct tty *
copy_constty(void)
{
	struct tty *result = NULL;
	lck_mtx_lock(&_constty_lock);
	if (_constty != NULL) {
		ttyhold(_constty);
		result = _constty;
	}
	lck_mtx_unlock(&_constty_lock);
	return result;
}

struct tty *
set_constty(struct tty *new_tty)
{
	struct tty *old_tty = NULL;
	lck_mtx_lock(&_constty_lock);
	old_tty = _constty;
	_constty = new_tty;
	if (_constty) {
		ttyhold(_constty);
	}
	lck_mtx_unlock(&_constty_lock);

	return old_tty;
}

/*
 * The km driver supplied the default console device for the systems
 * (usually a raw frame buffer driver, but potentially a serial driver).
 */
extern struct tty *km_tty[1];

/*
 * cdevsw[] entries for the console device driver
 */
int cnopen(__unused dev_t dev, int flag, int devtype, proc_t pp);
int cnclose(__unused dev_t dev, int flag, int mode, proc_t pp);
int cnread(__unused dev_t dev, struct uio *uio, int ioflag);
int cnwrite(__unused dev_t dev, struct uio *uio, int ioflag);
int cnioctl(__unused dev_t dev, u_long cmd, caddr_t addr, int flg, proc_t p);
int cnselect(__unused dev_t dev, int flag, void * wql, proc_t p);

int
cnopen(__unused dev_t dev, int flag, int devtype, struct proc *pp)
{
	int error;
	struct tty *constty = copy_constty();
	if (constty) {
		dev = constty->t_dev;
	} else {
		dev = km_tty[0]->t_dev;
	}
	error = (*cdevsw[major(dev)].d_open)(dev, flag, devtype, pp);
	if (constty != NULL) {
		ttyfree(constty);
	}
	return error;
}


int
cnclose(__unused dev_t dev, int flag, int mode, struct proc *pp)
{
	int error;
	struct tty *constty = copy_constty();
	if (constty) {
		dev = constty->t_dev;
	} else {
		dev = km_tty[0]->t_dev;
	}
	error = (*cdevsw[major(dev)].d_close)(dev, flag, mode, pp);
	if (constty != NULL) {
		ttyfree(constty);
	}
	return error;
}


int
cnread(__unused dev_t dev, struct uio *uio, int ioflag)
{
	int error;
	struct tty *constty = copy_constty();
	if (constty) {
		dev = constty->t_dev;
	} else {
		dev = km_tty[0]->t_dev;
	}
	error = (*cdevsw[major(dev)].d_read)(dev, uio, ioflag);
	if (constty != NULL) {
		ttyfree(constty);
	}
	return error;
}


int
cnwrite(__unused dev_t dev, struct uio *uio, int ioflag)
{
	int error;
	struct tty *constty = copy_constty();
	if (constty) {
		dev = constty->t_dev;
	} else {
		dev = km_tty[0]->t_dev;
	}
	error = (*cdevsw[major(dev)].d_write)(dev, uio, ioflag);
	if (constty != NULL) {
		ttyfree(constty);
	}
	return error;
}


int
cnioctl(__unused dev_t dev, u_long cmd, caddr_t addr, int flag, struct proc *p)
{
	int error;
	struct tty *constty = copy_constty();
	struct tty *freetp = NULL;
	if (constty) {
		dev = constty->t_dev;
	} else {
		dev = km_tty[0]->t_dev;
	}

	/*
	 * XXX This check prevents the cons.c code from being shared between
	 * XXX all architectures; it is probably not needed on ARM, either,
	 * XXX but I have no test platforms or ability to run a kernel.
	 *
	 * Superuser can always use this to wrest control of console
	 * output from the "virtual" console.
	 */
	if ((unsigned) cmd == TIOCCONS && constty) {
		error = proc_suser(p);
		if (error) {
			goto finish;
		}
		freetp = set_constty(NULL);
		if (freetp) {
			ttyfree(freetp);
			freetp = NULL;
		}
	} else {
		error = (*cdevsw[major(dev)].d_ioctl)(dev, cmd, addr, flag, p);
	}
finish:
	if (constty != NULL) {
		ttyfree(constty);
	}
	return error;
}


int
cnselect(__unused dev_t dev, int flag, void *wql, struct proc *p)
{
	int error;
	struct tty *constty = copy_constty();
	if (constty) {
		dev = constty->t_dev;
	} else {
		dev = km_tty[0]->t_dev;
	}
	error = (*cdevsw[major(dev)].d_select)(dev, flag, wql, p);
	if (constty != NULL) {
		ttyfree(constty);
	}
	return error;
}
