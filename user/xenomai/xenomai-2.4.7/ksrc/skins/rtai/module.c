/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
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

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#ifdef __KERNEL__
#include <rtai/syscall.h>
#include <rtai/fifo.h>
#endif /* __KERNEL__ */
#include <rtai/task.h>
#include <rtai/sem.h>
#include <rtai/shm.h>

MODULE_DESCRIPTION("RTAI API emulator");
MODULE_AUTHOR("rpm@xenomai.org");
MODULE_LICENSE("GPL");

static u_long tick_arg = CONFIG_XENO_OPT_RTAI_PERIOD;
module_param_named(tick_arg, tick_arg, ulong, 0444);
MODULE_PARM_DESC(tick_arg, "Fixed clock tick value (us), 0 for tick-less mode");

static u_long sync_time;
module_param_named(sync_time, sync_time, ulong, 0444);
MODULE_PARM_DESC(sync_time, "Set non-zero to synchronize on master time base");

xntbase_t *rtai_tbase;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
xnptree_t __rtai_ptree = {

	.dir = NULL,
	.name = "rtai",
	.entries = 0,
};
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static void rtai_shutdown(int xtype)
{
#ifdef CONFIG_XENO_OPT_RTAI_SHM
	__rtai_shm_pkg_cleanup();
#endif /* CONFIG_XENO_OPT_RTAI_SHM */

#ifdef CONFIG_XENO_OPT_RTAI_FIFO
	__rtai_fifo_pkg_cleanup();
#endif /* CONFIG_XENO_OPT_RTAI_FIFO */

#ifdef CONFIG_XENO_OPT_RTAI_SEM
	__rtai_sem_pkg_cleanup();
#endif /* CONFIG_XENO_OPT_RTAI_SEM */

	__rtai_task_pkg_cleanup();

#ifdef CONFIG_XENO_OPT_PERVASIVE
	__rtai_syscall_cleanup();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	xntbase_free(rtai_tbase);
	xnpod_shutdown(xtype);
}

int SKIN_INIT(rtai)
{
	int err;

	err = xnpod_init();

	if (err)
		goto fail;

	err = xntbase_alloc("rtai", tick_arg * 1000, sync_time ? 0 : XNTBISO,
			    &rtai_tbase);

	if (err)
		goto cleanup_pod;

	xntbase_start(rtai_tbase);

	err = __rtai_task_pkg_init();

	if (err)
		goto cleanup_tbase;

#ifdef CONFIG_XENO_OPT_RTAI_SEM
	err = __rtai_sem_pkg_init();

	if (err)
		goto cleanup_task;
#endif /* CONFIG_XENO_OPT_RTAI_SEM */

#ifdef CONFIG_XENO_OPT_RTAI_FIFO
	err = __rtai_fifo_pkg_init();

	if (err)
		goto cleanup_sem;
#endif /* CONFIG_XENO_OPT_RTAI_FIFO */

#ifdef CONFIG_XENO_OPT_RTAI_SHM
	err = __rtai_shm_pkg_init();

	if (err)
		goto cleanup_fifo;
#endif /* CONFIG_XENO_OPT_RTAI_SHM */

#ifdef CONFIG_XENO_OPT_PERVASIVE
	err = __rtai_syscall_init();

	if (err)
		goto cleanup_shm;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnprintf("starting RTAI emulator.\n");

	return 0;		/* SUCCESS. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
      cleanup_shm:
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_RTAI_SHM
	__rtai_shm_pkg_cleanup();

      cleanup_fifo:
#endif /* CONFIG_XENO_OPT_RTAI_SHM */

#ifdef CONFIG_XENO_OPT_RTAI_FIFO
	__rtai_fifo_pkg_cleanup();

      cleanup_sem:
#endif /* CONFIG_XENO_OPT_RTAI_FIFO */

#ifdef CONFIG_XENO_OPT_RTAI_SEM
	__rtai_sem_pkg_cleanup();

      cleanup_task:
#endif /* CONFIG_XENO_OPT_RTAI_SEM */

	__rtai_task_pkg_cleanup();

      cleanup_tbase:

	xntbase_free(rtai_tbase);

      cleanup_pod:

#ifdef CONFIG_XENO_OPT_PERVASIVE
	__rtai_syscall_cleanup();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	xnpod_shutdown(XNPOD_NORMAL_EXIT);

      fail:

	return err;
}

void SKIN_EXIT(rtai)
{
	xnprintf("stopping RTAI emulator.\n");
	rtai_shutdown(XNPOD_NORMAL_EXIT);
}

module_init(__rtai_skin_init);
module_exit(__rtai_skin_exit);

EXPORT_SYMBOL(rtai_tbase);
