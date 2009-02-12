/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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

/*!
 * \defgroup native Native Xenomai API.
 *
 * The native Xenomai programming interface available to real-time
 * applications. This API is built over the abstract RTOS core
 * implemented by the Xenomai nucleus.
 *
 */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#ifdef __KERNEL__
#include <linux/init.h>
#include <native/syscall.h>
#endif /* __KERNEL__ */
#include <native/task.h>
#include <native/timer.h>
#include <native/sem.h>
#include <native/event.h>
#include <native/mutex.h>
#include <native/cond.h>
#include <native/pipe.h>
#include <native/queue.h>
#include <native/heap.h>
#include <native/alarm.h>
#include <native/intr.h>
#include <native/misc.h>

MODULE_DESCRIPTION("Native skin");
MODULE_AUTHOR("rpm@xenomai.org");
MODULE_LICENSE("GPL");

static u_long tick_arg = CONFIG_XENO_OPT_NATIVE_PERIOD;
module_param_named(tick_arg, tick_arg, ulong, 0444);
MODULE_PARM_DESC(tick_arg, "Fixed clock tick value (us), 0 for tick-less mode");

xntbase_t *__native_tbase;

xeno_rholder_t __native_global_rholder;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
xnptree_t __native_ptree = {

	.dir = NULL,
	.name = "native",
	.entries = 0,
};
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int SKIN_INIT(native)
{
	int err;

	initq(&__native_global_rholder.alarmq);
	initq(&__native_global_rholder.condq);
	initq(&__native_global_rholder.eventq);
	initq(&__native_global_rholder.heapq);
	initq(&__native_global_rholder.intrq);
	initq(&__native_global_rholder.mutexq);
	initq(&__native_global_rholder.pipeq);
	initq(&__native_global_rholder.queueq);
	initq(&__native_global_rholder.semq);
	initq(&__native_global_rholder.ioregionq);

	err = xnpod_init();

	if (err)
		goto fail;

	err = xntbase_alloc("native", tick_arg * 1000, 0, &__native_tbase);

	if (err)
		goto fail;

	xntbase_start(__native_tbase);

	err = __native_misc_pkg_init();

	if (err)
		goto cleanup_pod;

	err = __native_task_pkg_init();

	if (err)
		goto cleanup_misc;

	err = __native_sem_pkg_init();

	if (err)
		goto cleanup_task;

	err = __native_event_pkg_init();

	if (err)
		goto cleanup_sem;

	err = __native_mutex_pkg_init();

	if (err)
		goto cleanup_event;

	err = __native_cond_pkg_init();

	if (err)
		goto cleanup_mutex;

	err = __native_pipe_pkg_init();

	if (err)
		goto cleanup_cond;

	err = __native_queue_pkg_init();

	if (err)
		goto cleanup_pipe;

	err = __native_heap_pkg_init();

	if (err)
		goto cleanup_queue;

	err = __native_alarm_pkg_init();

	if (err)
		goto cleanup_heap;

	err = __native_intr_pkg_init();

	if (err)
		goto cleanup_alarm;

	err = __native_syscall_init();

	if (err)
		goto cleanup_intr;

	xnprintf("starting native API services.\n");

	return 0;		/* SUCCESS. */

      cleanup_intr:

	__native_intr_pkg_cleanup();

      cleanup_alarm:

	__native_alarm_pkg_cleanup();

      cleanup_heap:

	__native_heap_pkg_cleanup();

      cleanup_queue:

	__native_queue_pkg_cleanup();

      cleanup_pipe:

	__native_pipe_pkg_cleanup();

      cleanup_cond:

	__native_cond_pkg_cleanup();

      cleanup_mutex:

	__native_mutex_pkg_cleanup();

      cleanup_event:

	__native_event_pkg_cleanup();

      cleanup_sem:

	__native_sem_pkg_cleanup();

      cleanup_task:

	__native_task_pkg_cleanup();

      cleanup_misc:

	__native_misc_pkg_cleanup();

      cleanup_pod:

	xntbase_free(__native_tbase);

	xnpod_shutdown(err);

      fail:

	xnlogerr("native skin init failed, code %d.\n", err);

	return err;
}

void SKIN_EXIT(native)
{
	xnprintf("stopping native API services.\n");

	__native_intr_pkg_cleanup();
	__native_alarm_pkg_cleanup();
	__native_heap_pkg_cleanup();
	__native_queue_pkg_cleanup();
	__native_pipe_pkg_cleanup();
	__native_cond_pkg_cleanup();
	__native_mutex_pkg_cleanup();
	__native_event_pkg_cleanup();
	__native_sem_pkg_cleanup();
	__native_task_pkg_cleanup();
	__native_misc_pkg_cleanup();
	__native_syscall_cleanup();

	xntbase_free(__native_tbase);

	xnpod_shutdown(XNPOD_NORMAL_EXIT);
}

module_init(__native_skin_init);
module_exit(__native_skin_exit);
