/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/**
 * @defgroup posix POSIX skin.
 *
 * Xenomai POSIX skin is an implementation of a small subset of the Single
 * Unix specification over Xenomai generic RTOS core.
 *
 * The following table gives equivalence between native API services and POSIX
 * services.
 *
 * <CENTER>
 * <TABLE>
 * <TR><TH>Native API services</TH> <TH>POSIX API services</TH></TR>
 * <TR><TD>@ref alarm</TD>          <TD>@ref posix_time</TD></TR>
 * <TR><TD>@ref cond</TD>           <TD>@ref posix_cond</TD></TR>
 * <TR><TD>@ref event</TD>          <TD>no direct equivalence, <BR>
 *                                      see @ref posix_cond</TD></TR>
 * <TR><TD>@ref native_heap</TD>    <TD>@ref posix_shm</TD></TR>
 * <TR><TD>@ref interrupt</TD>      <TD>@ref posix_intr</TD></TR>
 * <TR><TD>@ref mutex</TD>          <TD>@ref posix_mutex</TD></TR>
 * <TR><TD>@ref pipe</TD>           <TD>no direct equivalence, <BR>
 *                                      see @ref posix_mq</TD></TR>
 * <TR><TD>@ref native_queue</TD>   <TD>@ref posix_mq</TD></TR>
 * <TR><TD>@ref semaphore</TD>      <TD>@ref posix_sem</TD></TR>
 * <TR><TD>@ref task</TD>           <TD>@ref posix_thread</TD></TR>
 * <TR><TD>@ref native_timer</TD>   <TD>@ref posix_time</TD></TR>
 * </TABLE>
 * </CENTER>
 *
 */

#ifdef __KERNEL__
#include <posix/syscall.h>
#endif /* __KERNEL__ */
#include <posix/posix.h>
#include <posix/internal.h>
#include <posix/cond.h>
#include <posix/mutex.h>
#include <posix/sem.h>
#include <posix/sig.h>
#include <posix/thread.h>
#include <posix/tsd.h>
#include <posix/mq.h>
#include <posix/intr.h>
#include <posix/timer.h>
#include <posix/registry.h>
#include <posix/shm.h>

MODULE_DESCRIPTION("POSIX/PSE51 interface");
MODULE_AUTHOR("gilles.chanteperdrix@laposte.net");
MODULE_LICENSE("GPL");

static u_long tick_arg = CONFIG_XENO_OPT_POSIX_PERIOD;
module_param_named(tick_arg, tick_arg, ulong, 0444);
MODULE_PARM_DESC(tick_arg, "Fixed clock tick value (us), 0 for tick-less mode");

static u_long time_slice_arg = 1;	/* Default (round-robin) time slice */
module_param_named(time_slice, time_slice_arg, ulong, 0444);
MODULE_PARM_DESC(time_slice, "Default time slice (in ticks)");

xntbase_t *pse51_tbase;

static void pse51_shutdown(int xtype)
{
	pse51_thread_pkg_cleanup();
#ifdef CONFIG_XENO_OPT_POSIX_SHM
	pse51_shm_pkg_cleanup();
#endif /* CONFIG_XENO_OPT_POSIX_SHM */
	pse51_timer_pkg_cleanup();
	pse51_mq_pkg_cleanup();
	pse51_cond_pkg_cleanup();
	pse51_tsd_pkg_cleanup();
	pse51_sem_pkg_cleanup();
	pse51_mutex_pkg_cleanup();
	pse51_signal_pkg_cleanup();
	pse51_reg_pkg_cleanup();
#ifdef CONFIG_XENO_OPT_POSIX_INTR
	pse51_intr_pkg_cleanup();
#endif /* CONFIG_XENO_OPT_POSIX_INTR */
#ifdef CONFIG_XENO_OPT_PERVASIVE
	pse51_syscall_cleanup();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	xntbase_free(pse51_tbase);
	xnpod_shutdown(xtype);
}

int SKIN_INIT(posix)
{
	int err;

	xnprintf("starting POSIX services.\n");

	err = xnpod_init();
	if (err != 0)
		goto fail;

	err = xntbase_alloc("posix", tick_arg * 1000, 0, &pse51_tbase);
	if (err)
	    goto fail_shutdown_pod;

	xntbase_start(pse51_tbase);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	err = pse51_syscall_init();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	if (err != 0) {
		xntbase_free(pse51_tbase);
	fail_shutdown_pod:
		xnpod_shutdown(err);
	  fail:
		xnlogerr("POSIX skin init failed, code %d.\n", err);
		return err;
	}

	pse51_reg_pkg_init(64, 128);	/* FIXME: replace with compilation constants. */
	pse51_signal_pkg_init();
	pse51_mutex_pkg_init();
	pse51_sem_pkg_init();
	pse51_tsd_pkg_init();
	pse51_cond_pkg_init();
	pse51_mq_pkg_init();
#ifdef CONFIG_XENO_OPT_POSIX_INTR
	pse51_intr_pkg_init();
#endif /* CONFIG_XENO_OPT_POSIX_INTR */
	pse51_timer_pkg_init();
#ifdef CONFIG_XENO_OPT_POSIX_SHM
	pse51_shm_pkg_init();
#endif /* CONFIG_XENO_OPT_POSIX_SHM */

	pse51_thread_pkg_init(module_param_value(time_slice_arg));

	return 0;
}

void SKIN_EXIT(posix)
{
	xnprintf("stopping POSIX services.\n");
	pse51_shutdown(XNPOD_NORMAL_EXIT);
}

module_init(__posix_skin_init);
module_exit(__posix_skin_exit);
