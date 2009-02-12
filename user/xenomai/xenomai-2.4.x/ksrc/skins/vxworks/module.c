/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <vxworks/defs.h>
#ifdef __KERNEL__
#include <vxworks/syscall.h>
#endif /* __KERNEL__ */

MODULE_DESCRIPTION("VxWorks(R) virtual machine");
MODULE_AUTHOR("gilles.chanteperdrix@laposte.net");
MODULE_LICENSE("GPL");

static u_long tick_arg = CONFIG_XENO_OPT_VXWORKS_PERIOD;
module_param_named(tick_arg, tick_arg, ulong, 0444);
MODULE_PARM_DESC(tick_arg, "Fixed clock tick value (us)");

u_long sync_time;
module_param_named(sync_time, sync_time, ulong, 0444);
MODULE_PARM_DESC(sync_time, "Set non-zero to synchronize on master time base");

xntbase_t *wind_tbase;

wind_rholder_t __wind_global_rholder;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
xnptree_t __vxworks_ptree = {

	.dir = NULL,
	.name = "vxworks",
	.entries = 0,
};
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int SKIN_INIT(vxworks)
{
	int err;

	initq(&__wind_global_rholder.wdq);
	initq(&__wind_global_rholder.msgQq);
	initq(&__wind_global_rholder.semq);

	/* The following fields are unused in the global holder;
	   still, we initialize them not to leave such data in an
	   invalid state. */
	xnsynch_init(&__wind_global_rholder.wdsynch, XNSYNCH_FIFO);
	initq(&__wind_global_rholder.wdpending);
	__wind_global_rholder.wdcount = 0;

	err = xnpod_init();

	if (err != 0)
		goto fail_core;

	err = wind_sysclk_init(tick_arg * 1000);

	if (err != 0) {
		xnpod_shutdown(err);

	fail_core:
		xnlogerr("VxWorks skin init failed, code %d.\n", err);
		return err;
	}

	wind_wd_init();
	wind_task_hooks_init();
	wind_sem_init();
	wind_msgq_init();
	wind_task_init();
#ifdef CONFIG_XENO_OPT_PERVASIVE
	wind_syscall_init();
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnprintf("starting VxWorks services.\n");

	return 0;
}

void SKIN_EXIT(vxworks)
{
	xnprintf("stopping VxWorks services.\n");
	wind_task_cleanup();
	wind_sysclk_cleanup();
	wind_msgq_cleanup();
	wind_sem_cleanup();
	wind_wd_cleanup();
	wind_task_hooks_cleanup();
#ifdef CONFIG_XENO_OPT_PERVASIVE
	wind_syscall_cleanup();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	xnpod_shutdown(XNPOD_NORMAL_EXIT);
}

module_init(__vxworks_skin_init);
module_exit(__vxworks_skin_exit);

/* exported API : */

EXPORT_SYMBOL(wind_current_context_errno);
EXPORT_SYMBOL(wind_tbase);
EXPORT_SYMBOL(printErrno);
EXPORT_SYMBOL(errnoSet);
EXPORT_SYMBOL(errnoGet);
EXPORT_SYMBOL(errnoOfTaskGet);
EXPORT_SYMBOL(errnoOfTaskSet);
EXPORT_SYMBOL(taskSpawn);
EXPORT_SYMBOL(taskInit);
EXPORT_SYMBOL(taskActivate);
EXPORT_SYMBOL(taskExit);
EXPORT_SYMBOL(taskDelete);
EXPORT_SYMBOL(taskDeleteForce);
EXPORT_SYMBOL(taskSuspend);
EXPORT_SYMBOL(taskResume);
EXPORT_SYMBOL(taskRestart);
EXPORT_SYMBOL(taskPrioritySet);
EXPORT_SYMBOL(taskPriorityGet);
EXPORT_SYMBOL(taskLock);
EXPORT_SYMBOL(taskUnlock);
EXPORT_SYMBOL(taskIdSelf);
EXPORT_SYMBOL(taskSafe);
EXPORT_SYMBOL(taskUnsafe);
EXPORT_SYMBOL(taskDelay);
EXPORT_SYMBOL(taskIdVerify);
EXPORT_SYMBOL(taskTcb);
EXPORT_SYMBOL(taskCreateHookAdd);
EXPORT_SYMBOL(taskCreateHookDelete);
EXPORT_SYMBOL(taskSwitchHookAdd);
EXPORT_SYMBOL(taskSwitchHookDelete);
EXPORT_SYMBOL(taskDeleteHookAdd);
EXPORT_SYMBOL(taskDeleteHookDelete);
EXPORT_SYMBOL(taskName);
EXPORT_SYMBOL(taskNameToId);
EXPORT_SYMBOL(taskIdDefault);
EXPORT_SYMBOL(taskIsReady);
EXPORT_SYMBOL(taskIsSuspended);
EXPORT_SYMBOL(semGive);
EXPORT_SYMBOL(semTake);
EXPORT_SYMBOL(semFlush);
EXPORT_SYMBOL(semDelete);
EXPORT_SYMBOL(semBCreate);
EXPORT_SYMBOL(semMCreate);
EXPORT_SYMBOL(semCCreate);
EXPORT_SYMBOL(wdCreate);
EXPORT_SYMBOL(wdDelete);
EXPORT_SYMBOL(wdStart);
EXPORT_SYMBOL(wdCancel);
EXPORT_SYMBOL(msgQCreate);
EXPORT_SYMBOL(msgQDelete);
EXPORT_SYMBOL(msgQNumMsgs);
EXPORT_SYMBOL(msgQReceive);
EXPORT_SYMBOL(msgQSend);
EXPORT_SYMBOL(intContext);
EXPORT_SYMBOL(intCount);
EXPORT_SYMBOL(intLevelSet);
EXPORT_SYMBOL(intLock);
EXPORT_SYMBOL(intUnlock);
EXPORT_SYMBOL(sysClkConnect);
EXPORT_SYMBOL(sysClkDisable);
EXPORT_SYMBOL(sysClkEnable);
EXPORT_SYMBOL(sysClkRateGet);
EXPORT_SYMBOL(sysClkRateSet);
EXPORT_SYMBOL(tickAnnounce);
EXPORT_SYMBOL(tickGet);
EXPORT_SYMBOL(tickSet);
EXPORT_SYMBOL(kernelTimeSlice);
EXPORT_SYMBOL(kernelVersion);
EXPORT_SYMBOL(taskInfoGet);
