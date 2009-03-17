/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <uitron/task.h>
#include <uitron/sem.h>
#include <uitron/flag.h>
#include <uitron/mbx.h>
#include <uitron/syscall.h>

MODULE_DESCRIPTION("uITRON interface");
MODULE_AUTHOR("rpm@xenomai.org");
MODULE_LICENSE("GPL");

static u_long tick_arg = CONFIG_XENO_OPT_UITRON_PERIOD;
module_param_named(tick_arg, tick_arg, ulong, 0444);
MODULE_PARM_DESC(tick_arg, "Fixed clock tick value (us)");

static u_long sync_time;
module_param_named(sync_time, sync_time, ulong, 0444);
MODULE_PARM_DESC(sync_time, "Set non-zero to synchronize on master time base");

xntbase_t *ui_tbase;

ui_rholder_t __ui_global_rholder;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
xnptree_t __uitron_ptree = {

	.dir = NULL,
	.name = "uitron",
	.entries = 0,
};
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int SKIN_INIT(uitron)
{
	int err;

	initq(&__ui_global_rholder.flgq);
	initq(&__ui_global_rholder.mbxq);
	initq(&__ui_global_rholder.semq);

	err = xnpod_init();

	if (err)
		goto fail;

	err = xntbase_alloc("uitron", tick_arg * 1000,
			    sync_time ? 0 : XNTBISO, &ui_tbase);

	if (err)
		goto cleanup_pod;

	xntbase_start(ui_tbase);

	err = uitask_init();

	if (err)
		goto cleanup_tbase;

	err = uisem_init();

	if (err)
		goto cleanup_task;
		
	err = uiflag_init();

	if (err)
		goto cleanup_sem;
		
	err = uimbx_init();

	if (err)
		goto cleanup_flag;
		
#ifdef CONFIG_XENO_OPT_PERVASIVE
	ui_syscall_init();
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnprintf("starting uITRON services.\n");

	return 0;

cleanup_flag:

	uiflag_cleanup();

cleanup_sem:

	uisem_cleanup();

cleanup_task:

	uitask_cleanup();

cleanup_tbase:

	xntbase_free(ui_tbase);

cleanup_pod:

	xnpod_shutdown(err);

fail:

	xnlogerr("uITRON skin init failed, code %d.\n", err);

	return err;
}

void SKIN_EXIT(uitron)
{
	xnprintf("stopping uITRON services.\n");
	uimbx_cleanup();
	uiflag_cleanup();
	uisem_cleanup();
	uitask_cleanup();

#ifdef CONFIG_XENO_OPT_PERVASIVE
	ui_syscall_cleanup();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	xntbase_free(ui_tbase);
	xnpod_shutdown(XNPOD_NORMAL_EXIT);
}

module_init(__uitron_skin_init);
module_exit(__uitron_skin_exit);

EXPORT_SYMBOL(ui_tbase);
