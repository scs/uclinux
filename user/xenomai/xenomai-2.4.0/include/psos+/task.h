/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _PSOS_TASK_H
#define _PSOS_TASK_H

#include <psos+/event.h>

#define PSOSTASK_NOTEPAD_REGS 16

#define PSOS_TASK_MAGIC 0x81810101

typedef struct psostask {

    unsigned magic;   /* Magic code - must be first */

    xnholder_t link;	/* Link in psostaskq */

#define link2psostask(ln) container_of(ln, psostask_t, link)

    char name[XNOBJECT_NAME_LEN];

    xnthread_t threadbase;

    void (*entry)(u_long,u_long,u_long,u_long);

    u_long args[4];

    u_long notepad[PSOSTASK_NOTEPAD_REGS];

    psosevent_t evgroup; /* Event flags group */

    xngqueue_t alarmq;	/* List of outstanding alarms */

    union { /* Saved args for current synch. wait operation */

	struct {
	    u_long flags;
	    u_long events;
	} evgroup;

	struct psosmbuf *qmsg;

	struct {
	    u_long size;
	    void *chunk;
	} region;

    } waitargs;

} psostask_t;

static inline psostask_t *thread2psostask (xnthread_t *t)
{
    return t ? container_of(t, psostask_t, threadbase) : NULL;
}

#define psos_current_task() thread2psostask(xnpod_current_thread())

#ifdef __cplusplus
extern "C" {
#endif

static inline xnflags_t psos_mode_to_xeno (u_long mode)
{
    xnflags_t xnmode = 0;

    if (mode & T_NOPREEMPT)
	xnmode |= XNLOCK;

    if (mode & T_TSLICE)
	xnmode |= XNRRB;

    if (mode & T_NOASR)
	xnmode |= XNASDI;

    xnmode |= (mode & (T_SHIELD|T_TRAPSW|T_RPIOFF));

    return xnmode;
}

static inline u_long xeno_mode_to_psos (xnflags_t xnmode)
{
    u_long mode = 0;

    if (xnmode & XNLOCK)
	mode |= T_NOPREEMPT;

    if (xnmode & XNRRB)
	mode |= T_TSLICE;

    if (xnmode & XNASDI)
	mode |= T_NOASR;

    mode |= (xnmode & (XNSHIELD|XNTRAPSW|XNRPIOFF));

    return mode;
}

void psostask_init(u_long rrperiod);

void psostask_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* !_PSOS_TASK_H */
