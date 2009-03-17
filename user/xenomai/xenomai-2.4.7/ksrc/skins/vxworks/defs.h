/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 * Copyright (C) 2003,2007 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _vxworks_defs_h
#define _vxworks_defs_h

#include <nucleus/xenomai.h>
#include <nucleus/registry.h>
#include <vxworks/vxworks.h>
#include <vxworks/ppd.h>

#define WIND_MAGIC(n) (0x8383##n##n)
#define WIND_TASK_MAGIC WIND_MAGIC(01)
#define WIND_SEM_MAGIC  WIND_MAGIC(02)
#define WIND_WD_MAGIC   WIND_MAGIC(03)
#define WIND_MSGQ_MAGIC WIND_MAGIC(04)

/* Given a handle 'h', return a pointer to the control block of an
   object of type 't' whose magic word should be 'm'. */

#define wind_h2obj_active(h,m,t) \
    ((h) && (((void *)h) != (void *)ERROR) && ((t *)(h))->magic == (m) ? ((t *)(h)) : NULL)

/* Same as previously, but check for a deleted object, just returning
   a boolean value since the object would not be accessible if
   destroyed. The following test will remain valid until the destroyed
   object memory has been recycled for another usage. */

#define wind_mark_deleted(t) ((t)->magic = 0)

struct wind_sem;

typedef struct wind_sem wind_sem_t;

typedef struct sem_vtbl {

    STATUS (*take) (wind_sem_t *, xnticks_t);
    STATUS (*give) (wind_sem_t *);
    STATUS (*flush) (wind_sem_t *);
    const char *type;

} sem_vtbl_t;

struct wind_sem {

    unsigned int magic;

    xnsynch_t synchbase;

#define synch2wind_sem(syncb) container_of(syncb, wind_sem_t, synchbase)

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

    /*
     * count has a different meaning for the different kinds of
     * semaphores : binary semaphore : binary state of the semaphore,
     * counting semaphore: the semaphore count, mutex: the recursion
     * count.
     */
    unsigned count;
    
    xnholder_t rlink;		/* !< Link in resource queue. */
#define rlink2sem(ln)	container_of(ln, wind_sem_t, rlink)
    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

    const sem_vtbl_t * vtbl;
};

static inline void wind_sem_flush_rq(xnqueue_t *rq)
{
	wind_flush_rq(wind_sem_t, rq, sem);
}

typedef struct wind_msg {

    xnholder_t link;

#define link2wind_msg(ln) container_of(ln, wind_msg_t, link)

    unsigned int length;
    
    char buffer[0];

} wind_msg_t;

typedef struct wind_msgq {

    unsigned int magic;
    
    UINT msg_length;

    xnholder_t * free_list;     /* simply linked list of free messages */

    xnqueue_t msgq;             /* queue of messages available for reading */

    xnsynch_t synchbase;        /* pended readers or writers */

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

    xnholder_t rlink;		/* !< Link in resource queue. */
#define rlink2msgQ(ln)	container_of(ln, wind_msgq_t, rlink)
    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} wind_msgq_t;

static inline void wind_msgq_flush_rq(xnqueue_t *rq)
{
	wind_flush_rq(wind_msgq_t, rq, msgQ);
}

typedef struct wind_tcb wind_task_t;

typedef struct wind_wd {

    unsigned magic;		/* Magic code - must be first */

    xntimer_t timerbase;

    wind_timer_t handler;
    long arg;

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    wind_rholder_t *rh;		/* !< Resource holder of owner. */
    wind_wd_utarget_t wdt;	/* !< User-space handler and arg. */
    xnholder_t plink;		/* !< Link in owner's pending queue. */
#define link2wind_wd(ln) container_of(ln, wind_wd_t, plink)
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */
#define rlink2wd(ln)		container_of(ln, wind_wd_t, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} wind_wd_t;

static inline void wind_wd_flush_rq(xnqueue_t *rq)
{
	wind_flush_rq(wind_wd_t, rq, wd);
}

/* Internal flag marking a user-space task. */
#define VX_SHADOW 0x8000

#define WIND_TASK_OPTIONS_MASK \
(VX_FP_TASK|VX_PRIVATE_ENV|VX_NO_STACK_FILL|VX_UNBREAKABLE|VX_SHADOW) 

#define wind_current_task() (thread2wind_task(xnpod_current_thread()))

static inline void wind_errnoset(int err)
{
	*xnthread_get_errno_location(xnpod_current_thread()) = err;
}

static inline int wind_errnoget(void)
{
	return *xnthread_get_errno_location(xnpod_current_thread());
}

#define error_check(cond, status, action) do    \
{                                               \
    if ((cond))                                 \
        {                                       \
        wind_errnoset(status);                  \
        action;                                 \
        }                                       \
} while (0)


#define check_NOT_ISR_CALLABLE(action) do               \
{                                                       \
    if(xnpod_asynch_p())                                \
        {                                               \
        wind_errnoset(S_intLib_NOT_ISR_CALLABLE);       \
        action;                                         \
        }                                               \
} while(0)


#define check_alloc(type, ptr, action) do               \
{                                                       \
    ptr = (type *) xnmalloc (sizeof(type));             \
    if(!ptr)                                            \
        {                                               \
        wind_errnoset(S_memLib_NOT_ENOUGH_MEMORY);      \
        action;                                         \
        }                                               \
} while(0)


#define check_OBJ_ID_ERROR(id,type,ptr,magic,action) do \
{                                                       \
    ptr = wind_h2obj_active(id, magic, type);           \
    if(!ptr)                                            \
        {                                               \
        wind_errnoset(S_objLib_OBJ_ID_ERROR);           \
        action;                                         \
        }                                               \
} while(0)


/* Must be called with nklock locked, interrupts off. */
static inline void taskSafeInner (xnthread_t *cur)
{
	if (xnthread_get_magic(cur) == VXWORKS_SKIN_MAGIC) {
		wind_task_t *task = thread2wind_task(cur);
		task->safecnt++;
	}
}

/* Must be called with nklock locked, interrupts off.
   Returns :
   - 0 if the safe count was zero or decremented but no rescheduling is needed.
   - 1 if the safe count was decremented and rescheduling is needed.
*/
static inline int taskUnsafeInner (xnthread_t *cur)
{
	wind_task_t *task;

	if (xnthread_get_magic(cur) != VXWORKS_SKIN_MAGIC)
		/*
		 * We utterly lie here, but cross-API calls to obtain
		 * VxWorks task safetiness are more than borderline
		 * anyway. We basically allow this to make
		 * semGive/semTake available to non-VxWorks tasks.
		 */
		return 0;

	task = thread2wind_task(cur);

	if (task->safecnt > 0 && --task->safecnt == 0)
		return xnsynch_flush(&task->safesync,0) == XNSYNCH_RESCHED;

	return 0;
}

extern xntbase_t *wind_tbase;

/* modules initialization and cleanup: */
#ifdef __cplusplus
extern "C" {
#endif

    int wind_sysclk_init(u_long period);

    void wind_sysclk_cleanup(void);
    

    void wind_task_init(void);

    void wind_task_cleanup(void);


    void wind_task_hooks_init(void);
    
    void wind_task_hooks_cleanup(void);


    void wind_sem_init(void);

    void wind_sem_cleanup(void);


    void wind_wd_init(void);

    void wind_wd_cleanup(void);


    void wind_msgq_init(void);

    void wind_msgq_cleanup(void);


    void wind_set_rrperiod( xnticks_t ticks );

    
#ifdef __cplusplus
}
#endif

#endif /* !_vxworks_defs_h */
