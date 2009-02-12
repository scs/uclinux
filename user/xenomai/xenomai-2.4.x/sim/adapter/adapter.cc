/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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
 *
 * Description: Simulation Adapter module for the Xenomai nanokernel.
 */

#include <xeno_config.h>
#include <stdio.h>
#include "nucleus/pod.h"
#include "nucleus/synch.h"
#include "vm/manager.h"
#include "vm/interrupt.h"
#include "vm/display.h"

static xntbase_t *timebase = &nktbase;

#define sim_current_cpu() 0	// This code must not be instrumented!

extern void (*gcic_dinsn)(int);

extern void (*gcic_dframe)(int);

extern "C" {

static const char *mvm_get_thread_mode (void *tcbarg)

{
    xnthread_t *kthread = ((xnarchtcb_t *)tcbarg)->kthread;
    static TclList modeString;

    modeString.clear();

    if (!kthread)
	return modeString;

    // DO NOT USE pod.h accessors since it contains instrumented code!

    if (kthread->state & XNLOCK)
	modeString.append("lock");

    if (kthread->state & XNRRB)
	modeString.append("rrb");

    if (kthread->state & XNASDI)
	modeString.append("asdi");

    if (kthread->asrlevel > 0)
	modeString.append("asr");

    if (kthread->state & XNBOOST)
	modeString.append(CString().format("boost=%d",kthread->ops->get_denormalized_prio(kthread)));
    else
	modeString.append(CString().format("prio=%d",kthread->ops->get_denormalized_prio(kthread)));

    return modeString;
}

void mvm_declare_tbase(xntbase_t *base)
{
    timebase = base;
}

static unsigned long long mvm_get_jiffies (void)
{
    return MvmManager::This->testFlags(MVM_SIMREADY) ? timebase->jiffies : 0;
}

static void kdoor(mvm_trace_sched) (xnthread_t *thread,
				    u_long mask)
{
    int s;

    if (thread->__mvm_display_context.graph == NULL)
	/* No state diagram declared for the thread:
	   return silently. */
	return;

    /* States precedence order:
       XNDORMANT overrides any subsequent runtime states.
       XNSUSP overrides XNPEND (additive suspension).
       XNPEND overrides XNDELAY (watchdog set on resource wait). */

    /* A thread pending on a kernel mutex is put in an internal
       suspended state that appears like a runnable (READY) state
       from an external standpoint. */
    
    if (mask & XNDORMANT)
	s = 0;			// Dormant
    else if (mask & XNSUSP)
	s = 1;			// Forcibly suspended
    else if (mask & XNPEND)
	s = 2;			// Pending on a resource
    else if (mask & XNDELAY)
	s = 3;			// Delayed
    else if (mask & XNREADY)
	s = 4;			// Ready to run
    else if (mask & XNRUNNING)
	s = 5;			// Running
    else
	s = 6;			// Dead

    thread->__mvm_display_context.graph->setState(s);
}

void mvm_finalize_init (void)

{
    nkpod->schedhook = &kdoor(mvm_trace_sched);
    xnarchtcb_t *tcb = (xnarchtcb_t *)MvmManager::This->getRootThread()->getTcbArg();
    tcb->kthread = &nkpod->sched[sim_current_cpu()].rootcb;
    MvmManager::This->setFlags(MVM_SIMREADY);
}

int mvm_test_predicate (int pred)

{
    // Can't use the pod.h accessors since they are instrumented and
    // we need to run this code with at no time charge. The following
    // accessors are nucleus-dependent but safe in our context.

    if (!nkpod)
	return 0;

    switch (pred)
	{
	case MVM_ON_CALLOUT:

	    return !!(nkpod->sched[sim_current_cpu()].status & XNKCOUT);

	case MVM_ON_IHANDLER:

	    return MvmIrqManager::This->onHandlerP();

	case MVM_ON_ASYNCH:

	    if (MvmIrqManager::This->onHandlerP() || (nkpod->status & XNKCOUT))
		return 1;

	    return 0;
	}

    return 0;
}

int mvm_get_thread_imask (void *tcbarg) {
    return ((xnarchtcb_t *)tcbarg)->vmthread->getIntrMask();
}

const char *mvm_get_thread_state (void *tcbarg) {
    return ((xnarchtcb_t *)tcbarg)->kthread->__mvm_display_context.graph->getStateLabel();
}

static void kroot(mvm_thread_trampoline) (void *tcbarg)

{
    xnarchtcb_t *tcb = (xnarchtcb_t *)tcbarg;

    tcb->vmthread = mvm_thread_self();

    if (tcb->kthread)
	    xnpod_welcome_thread(tcb->kthread, tcb->imask);

    tcb->entry(tcb->cookie);

    if (tcb->kthread)
	xnpod_delete_thread(tcb->kthread);
}

static void real_dinsn (int tag) {

    MvmManager::This->khook(traceInsn)(tag);
}

static void real_dframe (int tag) {

    MvmManager::This->khook(trackFrame)(tag);
}

int mvm_run (void *tcbarg, void *faddr)

{
    MvmManager::trampoline = &kroot(mvm_thread_trampoline);
    MvmManager::threadmode = &mvm_get_thread_mode;
    MvmManager::jiffies = &mvm_get_jiffies;
    MvmManager::predicate = &mvm_test_predicate;
    MvmManager::This->initialize(new XenoThread(tcbarg,faddr,0,"Linux"));
    gcic_dinsn = &real_dinsn;
    gcic_dframe = &real_dframe;

    int xcode = MvmManager::This->run();

    while (MvmManager::This->testFlags(MVM_SIMREADY))
	MvmManager::currentThread->delay(0);

    return xcode;
}

void mvm_create_display (mvm_displayctx_t *ctx,
			 mvm_displayctl_t *ctl,
			 void *obj,
			 const char *name)
{
    ctx->dashboard = new MvmDashboard(name,
				      ctl->prefix,
				      NULL,
				      ctx,
				      ctl->objctl);
    ctx->graph = new MvmGraph(name,
			      ctl->group,
			      ctl->sarray);
    ctx->control = ctl;
    ctx->obj = obj;
    ctx->dashboard->ifInit();
    ctx->graph->ifInit();
}

void mvm_delete_display (mvm_displayctx_t *ctx)

{
    if (ctx->dashboard != NULL)
	{
	delete ctx->dashboard;
	ctx->dashboard = NULL;
	}

    if (ctx->graph != NULL)
	{
	delete ctx->graph;
	ctx->graph = NULL;
	}
}

void mvm_send_display (mvm_displayctx_t *ctx, const char *s) {
    ctx->dashboard->ifInfo(MVM_IFACE_DASHBOARD_INFO,s,-1);
}

void kdoor(mvm_post_graph) (mvm_displayctx_t *ctx, int state) {

    if (ctx->graph != NULL)
	ctx->graph->setState(state);
}

void mvm_tcl_build_pendq (mvm_tcl_listobj_t *tclist,
			  xnsynch_t *synch)
{
    mvm_tcl_listobj_t _tclist;
    xnpholder_t *holder;

    mvm_tcl_init_list(&_tclist);

    for (holder = getheadpq(xnsynch_wait_queue(synch));
	 holder; holder = nextpq(xnsynch_wait_queue(synch),holder))
	{
	xnthread_t *kthread = link2thread(holder,plink);
	mvm_tcl_append_int(&_tclist,xnthread_archtcb(kthread)->vmthread->getOid());
	mvm_tcl_append(&_tclist,xnthread_archtcb(kthread)->vmthread->ifGetName());
	mvm_tcl_append_list(tclist,&_tclist);
	}

    mvm_tcl_destroy_list(&_tclist);
}

}
