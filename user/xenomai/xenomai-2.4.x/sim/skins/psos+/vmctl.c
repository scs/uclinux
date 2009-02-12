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
 */

#include "xeno_config.h"
#include "psos+/task.h"
#include "psos+/queue.h"

MVM_DECL_DISPLAY_CONTROL(psostask,
			 mvm_psostask_objctl,
			 "Tasks",
			 "DORMANT",
			 "SUSPENDED",
			 "BLOCKED",
			 "DELAYED",
			 "READY",
			 "RUNNING",
			 "DEAD");

void mvm_psostask_objctl (mvm_displayctx_t *ctx,
			  int op,
			  const char *arg)
{
    mvm_tcl_listobj_t __tclist, _tclist, tclist;
    psostask_t *task;
    unsigned sigs;
    int n;

    task = thread2psostask((xnthread_t *)ctx->obj);

    mvm_tcl_init_list(&tclist);
    mvm_tcl_init_list(&_tclist);
    mvm_tcl_init_list(&__tclist);

    switch (op)
	{
	case 1:	/* Expose */

	    mvm_tcl_set(&_tclist,"prio");
	    mvm_tcl_append_int(&_tclist,xnthread_current_priority(&task->threadbase));
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_tcl_set(&_tclist,"ilevel");
	    mvm_tcl_append_int(&_tclist,mvm_get_thread_imask(xnthread_archtcb(&task->threadbase)));
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_tcl_set(&_tclist,"signals");
	    mvm_tcl_clear(&__tclist);

	    sigs = xnthread_pending_signals(&task->threadbase);

	    for (n = 0; n < 32; n++)
		{
		mvm_tcl_append_int(&__tclist,sigs & 1);
		sigs >>= 1;
		}
    
	    mvm_tcl_append_list(&_tclist,&__tclist);
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_tcl_set(&_tclist,"notepad");
	    mvm_tcl_clear(&__tclist);

	    for (n = 0; n < PSOSTASK_NOTEPAD_REGS; n++)
		mvm_tcl_append_hex(&__tclist,task->notepad[n]);
    
	    mvm_tcl_append_list(&_tclist,&__tclist);
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_tcl_set(&_tclist,"state");
	    mvm_tcl_append(&_tclist,mvm_get_thread_state(xnthread_archtcb(&task->threadbase)));
	    mvm_tcl_append_list(&tclist,&_tclist);

	    if (xnthread_test_state(&task->threadbase,XNDELAY))
		{
		mvm_tcl_set(&_tclist,"timeout");
		mvm_tcl_append_int(&_tclist,xnthread_timeout(&task->threadbase));
		mvm_tcl_append_list(&tclist,&_tclist);
		}

	    mvm_send_display(ctx,mvm_tcl_value(&tclist));

	    break;

	case 2:	/* Configure */

	    break;
	}

    mvm_tcl_destroy_list(&__tclist);
    mvm_tcl_destroy_list(&_tclist);
    mvm_tcl_destroy_list(&tclist);
}

MVM_DECL_DISPLAY_CONTROL(psosqueue,
			 mvm_psosqueue_objctl,
			 "Queues",
			 "EMPTY",
			 "PENDED",
			 "POSTED",
			 "FULL",
			 "JAMMED");

void mvm_psosqueue_objctl (mvm_displayctx_t *ctx,
			   int op,
			   const char *arg)
{
    mvm_tcl_listobj_t ___tclist, __tclist, _tclist, tclist;
    xnholder_t *holder;
    psosqueue_t *queue;
    psosmbuf_t *mbuf;

    queue = synch2psosqueue((xnsynch_t *)ctx->obj);

    mvm_tcl_init_list(&tclist);
    mvm_tcl_init_list(&_tclist);
    mvm_tcl_init_list(&__tclist);
    mvm_tcl_init_list(&___tclist);

    switch (op)
	{
	case 1:	/* Expose */

	    mvm_tcl_set(&_tclist,"type");
	    mvm_tcl_append(&_tclist,xnsynch_test_flags(&queue->synchbase,Q_VARIABLE) ?
			   "variable" : "fixed");
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_tcl_set(&_tclist,"sleepers");
	    mvm_tcl_build_pendq(&__tclist,&queue->synchbase);
	    mvm_tcl_append_list(&_tclist,&__tclist);
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_tcl_set(&_tclist,"messages");

	    for (holder = getheadq(&queue->inq);
		 holder; holder = nextq(&queue->inq,holder))
		{
		mvm_tcl_clear(&___tclist);

		mbuf = link2psosmbuf(holder);

		if (xnsynch_test_flags(&queue->synchbase,Q_VARIABLE))
		    {
		    int nbytes = mbuf->len < 16 ? mbuf->len : 16;
		    char *dstart, *dend;

		    for (dstart = mbuf->data, dend = mbuf->data + nbytes;
			 dstart < dend; dstart++)
			mvm_tcl_append_hex(&___tclist,(u_long)*dstart);

		    mvm_tcl_append(&___tclist,"(sz=");
		    mvm_tcl_append_int(&___tclist,mbuf->len);
		    mvm_tcl_append(&___tclist,")");
		    }
		else
		    {
		    u_long *dstart, *dend;

		    /* psosmbuf->data is aligned on a long word boundary,
		       so we can dereference it safely. */
		    for (dstart = (u_long *)mbuf->data,
			     dend = (u_long *)mbuf->data + 4;
			 dstart < dend; dstart++)
			mvm_tcl_append_hex(&___tclist,*dstart);
		    }

		mvm_tcl_append_list(&__tclist,&___tclist);
		}
    
	    mvm_tcl_append_list(&_tclist,&__tclist);
	    mvm_tcl_append_list(&tclist,&_tclist);

	    mvm_send_display(ctx,mvm_tcl_value(&tclist));

	    break;

	case 2:	/* Configure */

	    break;
	}

    mvm_tcl_destroy_list(&___tclist);
    mvm_tcl_destroy_list(&__tclist);
    mvm_tcl_destroy_list(&_tclist);
    mvm_tcl_destroy_list(&tclist);
}
