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

typedef struct wind_hook {
	FUNCPTR function;
	xnholder_t link;

#define link2wind_hook(ln) container_of(ln, wind_hook_t, link)

} wind_hook_t;

static xnqueue_t wind_create_hooks_q;
static xnqueue_t wind_switch_hooks_q;
static xnqueue_t wind_delete_hooks_q;
static wind_task_t *previous_task;

static void create_hook(xnthread_t *xnthread);
static void switch_hook(xnthread_t *xnthread);
static void delete_hook(xnthread_t *xnthread);

void wind_task_hooks_init(void)
{
	initq(&wind_create_hooks_q);
	initq(&wind_switch_hooks_q);
	initq(&wind_delete_hooks_q);

	previous_task = NULL;

	xnpod_add_hook(XNHOOK_THREAD_START, create_hook);
	xnpod_add_hook(XNHOOK_THREAD_SWITCH, switch_hook);
	xnpod_add_hook(XNHOOK_THREAD_DELETE, delete_hook);
}

static inline void free_hooks_queue(xnqueue_t *queue)
{
	xnholder_t *holder;
	xnholder_t *next_holder;

	for (holder = getheadq(queue); holder; holder = next_holder) {
		next_holder = nextq(queue, holder);
		removeq(queue, holder);
		xnfree(link2wind_hook(holder));
	}
}

void wind_task_hooks_cleanup(void)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	free_hooks_queue(&wind_create_hooks_q);
	free_hooks_queue(&wind_switch_hooks_q);
	free_hooks_queue(&wind_delete_hooks_q);

	xnpod_remove_hook(XNHOOK_THREAD_START, create_hook);
	xnpod_remove_hook(XNHOOK_THREAD_SWITCH, switch_hook);
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, delete_hook);

	xnlock_put_irqrestore(&nklock, s);
}

#define hook_add( queue,adder,wind_hook ) \
({	\
    wind_hook_t * hook = (wind_hook_t *) xnmalloc(sizeof(wind_hook_t)); \
    spl_t s; \
    int err = OK; \
    if(!hook) { 					\
        wind_errnoset(S_taskLib_TASK_HOOK_TABLE_FULL); \
        err = ERROR; \
        goto hook_done; \
    } \
    hook->function = wind_hook; \
    inith(&hook->link); \
    xnlock_get_irqsave(&nklock, s); \
    adder(queue, &hook->link); \
    xnlock_put_irqrestore(&nklock, s); \
hook_done: \
    err; })

static inline STATUS hook_del(xnqueue_t *queue, FUNCPTR wind_hook)
{
	xnholder_t *holder;
	spl_t s;

	for (holder = getheadq(queue); holder; holder = nextq(queue, holder))
		if (link2wind_hook(holder)->function == wind_hook)
			break;

	if (!holder) {
		wind_errnoset(S_taskLib_TASK_HOOK_NOT_FOUND);
		return ERROR;
	}

	xnlock_get_irqsave(&nklock, s);
	removeq(queue, holder);
	xnlock_put_irqrestore(&nklock, s);

	return OK;
}

STATUS taskCreateHookAdd(wind_create_hook hook)
{
	error_check(xnpod_asynch_p(), -EPERM, return ERROR);

	return hook_add(&wind_create_hooks_q, appendq, (FUNCPTR) hook);
}

STATUS taskCreateHookDelete(wind_create_hook hook)
{
	error_check(xnpod_asynch_p(), -EPERM, return ERROR);

	return hook_del(&wind_create_hooks_q, (FUNCPTR) hook);
}

STATUS taskSwitchHookAdd(wind_switch_hook hook)
{
	error_check(xnpod_asynch_p(), -EPERM, return ERROR);

	return hook_add(&wind_switch_hooks_q, appendq, (FUNCPTR) hook);
}

STATUS taskSwitchHookDelete(wind_switch_hook hook)
{
	error_check(xnpod_asynch_p(), -EPERM, return ERROR);

	return hook_del(&wind_switch_hooks_q, (FUNCPTR) hook);
}

STATUS taskDeleteHookAdd(wind_delete_hook hook)
{
	error_check(xnpod_asynch_p(), -EPERM, return ERROR);

	return hook_add(&wind_delete_hooks_q, prependq, (FUNCPTR) hook);
}

STATUS taskDeleteHookDelete(wind_delete_hook hook)
{
	error_check(xnpod_asynch_p(), -EPERM, return ERROR);

	return hook_del(&wind_delete_hooks_q, (FUNCPTR) hook);
}

static void create_hook(xnthread_t *xnthread)
{
	xnholder_t *holder;
	wind_task_t *task = thread2wind_task(xnthread);
	wind_create_hook hook;

	for (holder = getheadq(&wind_create_hooks_q); holder != NULL;
	     holder = nextq(&wind_create_hooks_q, holder)) {
		hook = (wind_create_hook) (link2wind_hook(holder)->function);
		hook(task);
	}
}

static void switch_hook(xnthread_t *xnthread)
{
	xnholder_t *holder;
	wind_task_t *task;
	wind_switch_hook hook;

	task = thread2wind_task(xnthread);

	for (holder = getheadq(&wind_switch_hooks_q); holder != NULL;
	     holder = nextq(&wind_switch_hooks_q, holder)) {
		hook = (wind_switch_hook) (link2wind_hook(holder)->function);
		hook(previous_task, task);
	}
	previous_task = task;
}

static void delete_hook(xnthread_t *xnthread)
{
	xnholder_t *holder;
	wind_task_t *task = thread2wind_task(xnthread);
	wind_delete_hook hook;

	for (holder = getheadq(&wind_delete_hooks_q); holder != NULL;
	     holder = nextq(&wind_delete_hooks_q, holder)) {
		hook = (wind_delete_hook) (link2wind_hook(holder)->function);
		hook(task);
	}
}
