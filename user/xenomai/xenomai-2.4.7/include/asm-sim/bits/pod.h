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

#ifndef _XENO_ASM_SIM_BITS_POD_H
#define _XENO_ASM_SIM_BITS_POD_H

#include <sys/time.h>
#include <time.h>
#include <xeno_config.h>

#define xnarch_start_timer(tick_handler, cpu)	\
  ({ mvm_start_timer(0, tick_handler); 0; })

#define xnarch_stop_timer(cpu)	mvm_stop_timer()

#define xnarch_leave_root(rootcb)  do { } while(0)

#define xnarch_enter_root(rootcb)  do { } while(0)

static inline void xnarch_switch_to (xnarchtcb_t *out_tcb,
				     xnarchtcb_t *in_tcb)
{
    __mvm_breakable(mvm_switch_threads)(out_tcb->vmthread,in_tcb->vmthread);
}

static inline void xnarch_finalize_and_switch (xnarchtcb_t *dead_tcb,
					       xnarchtcb_t *next_tcb)
{
    mvm_finalize_switch_threads(dead_tcb->vmthread,next_tcb->vmthread);
}

static inline void xnarch_finalize_no_switch (xnarchtcb_t *dead_tcb)
{
    if (dead_tcb->vmthread)	/* Might be unstarted. */
	mvm_finalize_thread(dead_tcb->vmthread);
}

static inline void xnarch_init_root_tcb (xnarchtcb_t *tcb,
					 struct xnthread *thread,
					 const char *name)
{
    tcb->vmthread = mvm_thread_self();
}

static inline void xnarch_init_thread (xnarchtcb_t *tcb,
				       void (*entry)(void *),
				       void *cookie,
				       int imask,
				       struct xnthread *thread,
				       char *name)
{
    tcb->imask = imask;
    tcb->kthread = thread;
    tcb->entry = entry;
    tcb->cookie = cookie;

    if (tcb->vmthread)	/* Restarting thread */
	{
	mvm_restart_thread(tcb->vmthread);
	return;
	}

    tcb->vmthread = mvm_spawn_thread(tcb,(void *)entry,name);
}

static inline void xnarch_enable_fpu(xnarchtcb_t *current_tcb)
{
    /* Nop */
}

static inline void xnarch_init_fpu(xnarchtcb_t *tcb)
{
    /* Nop */
}

static inline void xnarch_save_fpu(xnarchtcb_t *tcb)
{
    /* Nop */
}

static inline void xnarch_restore_fpu(xnarchtcb_t *tcb)
{
    /* Nop */
}

int xnarch_setimask (int imask)
{
    return mvm_set_irqmask(imask);
}

static inline int xnarch_send_ipi (unsigned cpumask)
{
    return 0;
}

static inline int xnarch_hook_ipi (void (*handler)(void))
{
    return 0;
}

static inline int xnarch_release_ipi (void)
{
    return 0;
}

static inline void xnarch_escalate (void)
{
    void xnpod_schedule_handler(void);
    xnpod_schedule_handler();
}

#define xnarch_notify_ready()    mvm_finalize_init()
#define xnarch_notify_halt()	/* Nullified */
#define xnarch_notify_shutdown() /* Nullified */

static inline unsigned long long xnarch_get_host_time(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL)) {
        printf("Warning, gettimeofday failed, error %d\n", errno);
        return 0;
    }

    return tv.tv_sec * 1000000000ULL + tv.tv_usec * 1000;
}

#endif /* !_XENO_ASM_SIM_BITS_POD_H */
