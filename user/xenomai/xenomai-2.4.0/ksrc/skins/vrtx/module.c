/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003,2006 Philippe Gerum <rpm@xenomai.org>.
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

#include <vrtx/event.h>
#include <vrtx/task.h>
#include <vrtx/sem.h>
#include <vrtx/mb.h>
#include <vrtx/mx.h>
#include <vrtx/queue.h>
#include <vrtx/pt.h>
#include <vrtx/heap.h>
#include <vrtx/syscall.h>

MODULE_DESCRIPTION("VRTX(R) virtual machine");
MODULE_AUTHOR("jpinon@idealx.com, rpm@xenomai.org");
MODULE_LICENSE("GPL");

static u_long tick_arg = CONFIG_XENO_OPT_VRTX_PERIOD;
module_param_named(tick_arg, tick_arg, ulong, 0444);
MODULE_PARM_DESC(tick_arg, "Fixed clock tick value (us)");

static u_long sync_time;
module_param_named(sync_time, sync_time, ulong, 0444);
MODULE_PARM_DESC(sync_time, "Set non-zero to synchronize on master time base");

static u_long workspace_size_arg = 32 * 1024;	/* Default size of VRTX workspace */
module_param_named(workspace_size, workspace_size_arg, ulong, 0444);
MODULE_PARM_DESC(workspace_size, "Size of VRTX workspace (in bytes)");

static u_long task_stacksize_arg = 4096;	/* Default size of VRTX tasks */
module_param_named(task_stacksize, task_stacksize_arg, ulong, 0444);
MODULE_PARM_DESC(task_stacksize, "Default size of VRTX task stack (in bytes)");

xntbase_t *vrtx_tbase;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
xnptree_t __vrtx_ptree = {

	.dir = NULL,
	.name = "vrtx",
	.entries = 0,
};
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int sc_gversion(void)
{
	return VRTX_SKIN_VERSION;
}

int SKIN_INIT(vrtx)
{
	int err;

	err = xnpod_init();

	if (err != 0)
		goto fail;

	err = xntbase_alloc("vrtx", tick_arg * 1000, sync_time ? 0 : XNTBISO,
			    &vrtx_tbase);

	if (err != 0)
		goto fail_core;

	xntbase_start(vrtx_tbase);

	/* the VRTX workspace, or sysheap, is accessed (sc_halloc) with
	 * hid #0.  We must ensure it is the first heap created, so
	 * vrtxheap_init must be called right now.
	 */
	err = vrtxheap_init(module_param_value(workspace_size_arg));

	if (err != 0) {
		xntbase_free(vrtx_tbase);
	fail_core:
		xnpod_shutdown(err);
	fail:
		xnlogerr("VRTX skin init failed, code %d.\n", err);
		return err;
	}

	vrtxevent_init();
	vrtxsem_init();
	vrtxqueue_init();
	vrtxpt_init();
	vrtxmb_init();
	vrtxmx_init();
	vrtxtask_init(module_param_value(task_stacksize_arg));
#ifdef CONFIG_XENO_OPT_PERVASIVE
	vrtxsys_init();
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnprintf("starting VRTX services.\n");

	return 0;
}

void SKIN_EXIT(vrtx)
{
	xnprintf("stopping VRTX services.\n");

	vrtxtask_cleanup();
	vrtxpt_cleanup();
	vrtxqueue_cleanup();
	vrtxmb_cleanup();
	vrtxmx_cleanup();
	vrtxsem_cleanup();
	vrtxevent_cleanup();
	vrtxheap_cleanup();
#ifdef CONFIG_XENO_OPT_PERVASIVE
	vrtxsys_cleanup();
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	xntbase_free(vrtx_tbase);
	xnpod_shutdown(XNPOD_NORMAL_EXIT);
}

module_init(__vrtx_skin_init);
module_exit(__vrtx_skin_exit);

EXPORT_SYMBOL(vrtx_tbase);

EXPORT_SYMBOL(sc_accept);
EXPORT_SYMBOL(sc_adelay);
EXPORT_SYMBOL(sc_delay);
EXPORT_SYMBOL(sc_fclear);
EXPORT_SYMBOL(sc_fcreate);
EXPORT_SYMBOL(sc_fdelete);
EXPORT_SYMBOL(sc_finquiry);
EXPORT_SYMBOL(sc_fpend);
EXPORT_SYMBOL(sc_fpost);
EXPORT_SYMBOL(sc_gblock);
EXPORT_SYMBOL(sc_gclock);
EXPORT_SYMBOL(sc_gtime);
EXPORT_SYMBOL(sc_gversion);
EXPORT_SYMBOL(sc_halloc);
EXPORT_SYMBOL(sc_hcreate);
EXPORT_SYMBOL(sc_hdelete);
EXPORT_SYMBOL(sc_hfree);
EXPORT_SYMBOL(sc_hinquiry);
EXPORT_SYMBOL(sc_lock);
EXPORT_SYMBOL(sc_maccept);
EXPORT_SYMBOL(sc_mcreate);
EXPORT_SYMBOL(sc_mdelete);
EXPORT_SYMBOL(sc_minquiry);
EXPORT_SYMBOL(sc_mpend);
EXPORT_SYMBOL(sc_mpost);
EXPORT_SYMBOL(sc_pcreate);
EXPORT_SYMBOL(sc_pdelete);
EXPORT_SYMBOL(sc_pend);
EXPORT_SYMBOL(sc_pextend);
EXPORT_SYMBOL(sc_pinquiry);
EXPORT_SYMBOL(sc_post);
EXPORT_SYMBOL(sc_qaccept);
EXPORT_SYMBOL(sc_qbrdcst);
EXPORT_SYMBOL(sc_qcreate);
EXPORT_SYMBOL(sc_qdelete);
EXPORT_SYMBOL(sc_qecreate);
EXPORT_SYMBOL(sc_qinquiry);
EXPORT_SYMBOL(sc_qjam);
EXPORT_SYMBOL(sc_qpend);
EXPORT_SYMBOL(sc_qpost);
EXPORT_SYMBOL(sc_rblock);
EXPORT_SYMBOL(sc_saccept);
EXPORT_SYMBOL(sc_sclock);
EXPORT_SYMBOL(sc_screate);
EXPORT_SYMBOL(sc_sdelete);
EXPORT_SYMBOL(sc_sinquiry);
EXPORT_SYMBOL(sc_spend);
EXPORT_SYMBOL(sc_spost);
EXPORT_SYMBOL(sc_stime);
EXPORT_SYMBOL(sc_tcreate);
EXPORT_SYMBOL(sc_tdelete);
EXPORT_SYMBOL(sc_tecreate);
EXPORT_SYMBOL(sc_tinquiry);
EXPORT_SYMBOL(sc_tpriority);
EXPORT_SYMBOL(sc_tresume);
EXPORT_SYMBOL(sc_tslice);
EXPORT_SYMBOL(sc_tsuspend);
EXPORT_SYMBOL(sc_unlock);
EXPORT_SYMBOL(ui_timer);
