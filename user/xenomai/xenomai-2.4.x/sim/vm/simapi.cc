/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
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

#include <xeno_config.h>
#include <stdio.h>
#include <memory.h>
#include <malloc.h>
#include <stdarg.h>
#include <errno.h>
#include "vm/monitor.h"
#include "vm/manager.h"
#include "vm/interrupt.h"
#include "vm/display.h"
#include "vmutils/toolshop.h"

static char **mvmargv;

static int mvmargc;

static int mvmcr0;

static u_long mvmcr1;

static const char *mvmcr2;

static int mvmcr3;

static MvmIrq *mvmirqs[MVM_IRQ_LEVELS];

static MvmIrq *mvmtimer;

extern "C" {

static void dummy_dinsn (int) {
}

static void dummy_dframe (int) {
}

// Ensure the callouts invoked on behalf of C++ class ctors()
// branch to innocuous places.

void (*gcic_dinsn)(int) = &dummy_dinsn;

void (*gcic_dframe)(int) = &dummy_dframe;

static void mvm_bp (void) { // Xenoscope breakpoint routine
}

static void mvm_eh (int xnum) { // Xenoscope exception handler
}

void mvm_init (int argc, char *argv[])

{
    MvmManager::dcr0 = &mvmcr0;
    MvmManager::dcr1 = &mvmcr1;
    MvmManager::dcr2 = &mvmcr2;
    MvmManager::dcr3 = &mvmcr3;
    new MvmManager(ZEROTIME,ZEROTIME,&argc,argv);

    for (int ac = 1; ac < argc; ac++)
	{
	// Remove -Q prefix in front of the local options
	if (argv[ac][0] == '-' && argv[ac][1] == 'Q')
	    strcpy(argv[ac] + 1, argv[ac] + 2);
	}

    mvmargv = argv;
    mvmargc = argc;
    MvmManager::preamble = &mvm_bp;
    MvmManager::breakpoint = &mvm_bp;
    MvmManager::exception = &mvm_eh;
}

// mvm_switch() bumps into a specific LWP context. It determines the
// last active context, according to the focus specified by the
// current value of the control registers. "System" focus bumps into
// the last thread, ISR or callout executing context.  "Thread" focus
// bumps into the specified real-time thread.

void mvm_switch (void)

{
    MvmContext context;

    if (!MvmManager::This)
	{
	mvm_bp();
	return;
	}

    if (MVM_CR_FLAGS & MVM_CREG_THREAD_SCOPE)
	{
	context.type = XThreadContext;
	context.internalID = MVM_CR_ID;
	}
    else
	context = MvmManager::This->getContext();

    XenoThread *thread = MvmManager::This->findThread(context); // never NULL

    MVM_CR_FLAGS = 0;
    MvmMonitor::exportFocus(thread->getContextString());
    thread->bumpInto();
}

void mvm_sleep (unsigned long ticks)
{
    XenoThread::currentThread->delay((double)MvmManager::This->getMvmTick() * ticks);
}

int mvm_hook_irq (unsigned irq,
		  void (*handler)(unsigned irq,
				  void *cookie),
		  void *cookie)
{
    if (irq >= MVM_IRQ_LEVELS)
	return -EINVAL;

    if (mvmirqs[irq] != NULL)
	return -EBUSY;

    mvmirqs[irq] = new MvmIrq((int)irq,(void (*)(int,void *))handler,cookie);

    return 0;
}

int mvm_release_irq (unsigned irq)

{
    if (irq >= MVM_IRQ_LEVELS || mvmirqs[irq] == NULL)
	return -EINVAL;

    MvmIrqManager::This->destroyIrq(mvmirqs[irq]);
    mvmirqs[irq] = NULL;

    return 0;
}

int mvm_enable_irq (unsigned irq)

{
    if (irq >= MVM_IRQ_LEVELS || mvmirqs[irq] == NULL)
	return -EINVAL;

    mvmirqs[irq]->clrStatus(MVM_IRQ_MASKED);

    return 0;
}

int mvm_disable_irq (unsigned irq)

{
    if (irq >= MVM_IRQ_LEVELS || mvmirqs[irq] == NULL)
	return -EINVAL;

    mvmirqs[irq]->setStatus(MVM_IRQ_MASKED);

    return 0;
}

int mvm_post_irq (unsigned irq)

{
    if (irq >= MVM_IRQ_LEVELS || mvmirqs[irq] == NULL)
	return -EINVAL;

    MvmIrqManager::This->postIrq(mvmirqs[irq]);
    MvmIrqManager::This->dispatchIrq();

    return 0;
}

int mvm_set_irqmask (int level)

{
    int oldmask = MVM_CR_IMASK;

    if (level < 0)
	level = MVM_IRQ_LEVELS;

    MVM_CR_IMASK = level;
    MvmIrqManager::This->dispatchIrq();

    return oldmask;
}

int mvm_get_irqmask (void) {

    return MVM_CR_IMASK;
}

int mvm_start_timer (unsigned long nstick,
		     void (*tickhandler)(void))
{
    mvmtimer = new MvmIrq(1,(void (*)(int,void *))tickhandler,NULL,"MvmTimer");

    if (nstick > 0)
	/* Periodic time source, arm it now. */
	mvmtimer->configure(CfEventPeriodical,
			    CString().format("%f usc",(double)nstick / 1000.0));
    return 0;
}

void mvm_program_timer (unsigned long delay) {

    if (mvmtimer)
	mvmtimer->configure(CfEventTimer,
			    CString().format("%f usc",(double)MvmClock + (double)delay / 1000.0));
}

void mvm_stop_timer (void)

{
    if (mvmtimer)
	{
	MvmIrqManager::This->destroyIrq(mvmtimer);
	mvmtimer = NULL;
	}
}

void *mvm_create_callback (void (*handler)(int,void *), void *cookie) {

    return new MvmIrq(2,handler,cookie,"MvmCallback");
}

void mvm_delete_callback (void *cbhandle) {

    MvmIrq *irq = (MvmIrq *)cbhandle;
    MvmIrqManager::This->destroyIrq(irq);
}

void mvm_schedule_callback (void *cbhandle, unsigned long ns)

{
    MvmIrq *irq = (MvmIrq *)cbhandle;

    if (ns > 0)
	irq->configure(CfEventTimer,
		       CString().format("%f usc",(double)MvmClock + (double)ns / 1000.0));
    else
	irq->configure(CfEventNull,NULL); // un-schedule
}

/* mvm_spawn_thread() -- spawn a new thread which is left in a
 * suspended state. The interrupt manager trace flags are inherited by
 * the new thread since its the only XenoThread object whose flags can
 * denote an undergoing 'system' trace. This way, the new thread will
 * stop in its user prologue as expected, even if it was not known at
 * the time the step command (dbStepIn/Over) was issued by the
 * Xenoscope to the simulation monitor. */

XenoThread *mvm_spawn_thread (void *tcbarg,
			      void *faddr,
			      const char *name)
{
    XenoThread *thread = new XenoThread(tcbarg,faddr,0,name);
    thread->ifInit();
    thread->stepInherit(MvmIrqManager::This);
    thread->suspend();

    return thread;
}

void mvm_restart_thread (struct XenoThread *thread) {
    thread->restart();
}

XenoThread *mvm_thread_self (void) {
    return XenoThread::runningThread;
}

unsigned long long mvm_get_cpu_time (void) {
    return (unsigned long long)(MvmClock * 1000.0);
}

unsigned long mvm_get_cpu_freq (void) {
    return (unsigned long)MvmManager::This->getMvmFreq();
}

void kdoor(mvm_switch_threads) (struct XenoThread *out,
				struct XenoThread *in)
{
    in->resume();
    out->suspend();
}

void mvm_finalize_switch_threads (struct XenoThread *dead,
				  struct XenoThread *in)
{
    in->resume();
    dead->cancel();
}

void mvm_finalize_thread (struct XenoThread *dead) {
    dead->cancel();
}

void kdoor(mvm_terminate) (int xcode) {
    MvmManager::This->finish(xcode);
}

void kdoor(mvm_break) (void) {
    MvmManager::This->suspendSimulation();
}

void kdoor(mvm_fatal) (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    MvmManager::This->kdoor(fatal)(format,ap);
    va_end(ap);
}

void kdoor(mvm_join_threads) (void) {
    mvm_thread_self()->joinClientThreads();
}

void mvm_tcl_init_list (TclList **tclist) {
    *tclist = new TclList;
}

void mvm_tcl_destroy_list (TclList **tclist) {
    delete *tclist;
}

void mvm_tcl_set (TclList **tclist,
		  const char *s) {
    (*tclist)->set(s);
}

void mvm_tcl_append (TclList **tclist,
		     const char *s) {
    (*tclist)->append(s);
}

void mvm_tcl_clear (TclList **tclist) {
    (*tclist)->clear();
}

void mvm_tcl_append_int (TclList **tclist,
			 u_long n) {
    (*tclist)->append(n);
}

void mvm_tcl_append_hex (TclList **tclist,
			 u_long n) {
    (*tclist)->appendx(n);
}

void mvm_tcl_append_list (TclList **tclist,
			  TclList **tclist2) {
    (*tclist)->append(**tclist2);
}

const char *mvm_tcl_value (TclList **tclist) {
    return (*tclist)->get();
}

void mvm_dummy_objctl (struct mvm_displayctx *ctx,
		       int op,
		       const char *arg) {
}

}
