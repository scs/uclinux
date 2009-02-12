/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_TASK_H
#define _XENO_TASK_H

#include <nucleus/core.h>
#include <nucleus/thread.h>
#include <native/types.h>

/* Creation flags. */
#define T_FPU     XNFPU
#define T_SUSP    XNSUSP
/* <!> High bits must not conflict with XNFPU|XNSHADOW|XNSHIELD|XNSUSP. */
#define T_CPU(cpu) (1 << (24 + (cpu & 7))) /* Up to 8 cpus [0-7] */
#define T_CPUMASK  0xff000000

/*! 
  \ingroup native
  @defgroup native_task_status Task Status 
  @brief Defines used to specify task state and/or mode 
  @{
 */

#define T_BLOCKED  XNPEND     /**< See #XNPEND    */
#define T_DELAYED  XNDELAY    /**< See #XNDELAY   */
#define T_READY    XNREADY    /**< See #XNREADY   */
#define T_DORMANT  XNDORMANT  /**< See #XNDORMANT */
#define T_STARTED  XNSTARTED  /**< See #XNSTARTED */
#define T_BOOST    XNBOOST    /**< See #XNBOOST   */
#define T_LOCK     XNLOCK     /**< See #XNLOCK    */
#define T_RRB      XNRRB      /**< See #XNRRB     */
#define T_NOSIG    XNASDI     /**< See #XNASDI    */ 
#define T_SHIELD   XNSHIELD   /**< See #XNSHIELD  */ 
#define T_WARNSW   XNTRAPSW   /**< See #XNTRAPSW  */ 
#define T_RPIOFF   XNRPIOFF   /**< See #XNRPIOFF  */ 
#define T_PRIMARY  0x00000200	/* Recycle internal bits status which */
#define T_JOINABLE 0x00000400	/* won't be passed to the nucleus.  */
/*! @} */ /* Ends doxygen-group native_task_status */

/* Task hook types. */
#define T_HOOK_START  XNHOOK_THREAD_START
#define T_HOOK_SWITCH XNHOOK_THREAD_SWITCH
#define T_HOOK_DELETE XNHOOK_THREAD_DELETE
#define T_DESC(cookie) thread2rtask(cookie)

/* Priority range (POSIXish, same bounds as Xenomai's). */
#define T_LOPRIO  XNCORE_LOW_PRIO
#define T_HIPRIO  XNCORE_HIGH_PRIO

typedef struct rt_task_placeholder {
    xnhandle_t opaque;
    unsigned long opaque2;
} RT_TASK_PLACEHOLDER;

struct rt_queue_msg;
struct rt_task;

/** Structure containing task-information useful to users.
 *
 *  @see rt_task_inquire()
 */
typedef struct rt_task_info {
    
    int bprio;  /**< Base priority. */

    int cprio; /**< Current priority. May change through Priority Inheritance.*/
    
    unsigned status; /**< Task's status. @see native_task_status */ 
    
    RTIME relpoint; /**< Time of next release.*/ 
    
    char name[XNOBJECT_NAME_LEN];  /**< Symbolic name assigned at creation. */

    RTIME exectime; /**< Execution time in primary mode in nanoseconds. */

    int modeswitches; /**< Number of primary->secondary mode switches. */

    int ctxswitches; /**< Number of context switches. */

    int pagefaults; /**< Number of triggered page faults. */

} RT_TASK_INFO;

#define RT_MCB_FSTORE_LIMIT  64

/** Structure used in passing messages between tasks.
  @see rt_task_send(), rt_task_reply(), rt_task_receive()
*/
typedef struct rt_task_mcb {

    int flowid;   /**< Flow identifier. */

    int opcode;   /**< Operation code. */

    caddr_t data; /**< Message address. */

    size_t size;  /**< Message size (bytes). */

} RT_TASK_MCB;

#if (defined(__KERNEL__) || defined(__XENO_SIM__)) && !defined(DOXYGEN_CPP)

#include <nucleus/synch.h>

#define XENO_TASK_MAGIC 0x55550101

typedef struct rt_task {

    unsigned magic;   /* !< Magic code - must be first */

    xnholder_t link;

#define link2rtask(ln)		container_of(ln, RT_TASK, link)

    xnthread_t thread_base;

    char rname[XNOBJECT_NAME_LEN]; /* !< Name in registry. Not the same as
                                      thread name for anonymous threads. */
    int suspend_depth;

    int overrun;

    xnsynch_t safesynch;	/* !< Safe synchronization object. */

    u_long safelock;		/* !< Safe lock count. */

    u_long cstamp;		/* !< Creation stamp. */

    xnarch_cpumask_t affinity;

    union { /* Saved args for current synch. wait operation. */

	struct {
	    int mode;
	    unsigned long mask;
	} event;

	struct rt_queue_msg *qmsg;

	struct {
	    size_t size;
	    void *block;
	} heap;
	
#ifdef CONFIG_XENO_OPT_NATIVE_MPS
	struct {
	    RT_TASK_MCB mcb_s; /* Send area. */
	    RT_TASK_MCB mcb_r; /* Reply area. */
	} mps;
#endif /* CONFIG_XENO_OPT_NATIVE_MPS */

    } wait_args;

#ifdef CONFIG_XENO_OPT_NATIVE_MPS
    xnsynch_t mrecv,
	      msendq;

    int flowgen;		/* !< Flow id. generator. */
#endif /* CONFIG_XENO_OPT_NATIVE_MPS */

} RT_TASK;

static inline RT_TASK *thread2rtask (xnthread_t *t)
{
    return t ? container_of(t, RT_TASK, thread_base) : NULL;
}

#define xeno_current_task() thread2rtask(xnpod_current_thread())

#ifdef __cplusplus
extern "C" {
#endif

void __native_task_safe(RT_TASK *task);

void __native_task_unsafe(RT_TASK *task);

int __native_task_safewait(RT_TASK *task);

int __native_task_pkg_init(void);

void __native_task_pkg_cleanup(void);

/* Public kernel interface */

int rt_task_add_hook(int type,
		     void (*routine)(void *cookie));

int rt_task_remove_hook(int type,
			void (*routine)(void *cookie));

int rt_task_catch(void (*handler)(rt_sigset_t));

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_TASK_PLACEHOLDER RT_TASK;

#ifdef __cplusplus
extern "C" {
#endif

int rt_task_shadow(RT_TASK *task,
		   const char *name,
		   int prio,
		   int mode);

int rt_task_bind(RT_TASK *task,
		 const char *name,
		 RTIME timeout);

static inline int rt_task_unbind (RT_TASK *task)

{
    task->opaque = XN_NO_HANDLE;
    return 0;
}

int rt_task_join(RT_TASK *task);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface */

int rt_task_create(RT_TASK *task,
		   const char *name,
		   int stksize,
		   int prio,
		   int mode);

int rt_task_start(RT_TASK *task,
		  void (*fun)(void *cookie),
		  void *cookie);

int rt_task_suspend(RT_TASK *task);

int rt_task_resume(RT_TASK *task);

int rt_task_delete(RT_TASK *task);

int rt_task_yield(void);

int rt_task_set_periodic(RT_TASK *task,
			 RTIME idate,
			 RTIME period);

int rt_task_wait_period(unsigned long *overruns_r);

int rt_task_set_priority(RT_TASK *task,
			 int prio);

int rt_task_sleep(RTIME delay);

int rt_task_sleep_until(RTIME date);

int rt_task_unblock(RT_TASK *task);

int rt_task_inquire(RT_TASK *task,
		     RT_TASK_INFO *info);

int rt_task_notify(RT_TASK *task,
		   rt_sigset_t signals);

int rt_task_set_mode(int clrmask,
		     int setmask,
		     int *mode_r);

RT_TASK *rt_task_self(void);

int rt_task_slice(RT_TASK *task,
		  RTIME quantum);

ssize_t rt_task_send(RT_TASK *task,
		     RT_TASK_MCB *mcb_s,
		     RT_TASK_MCB *mcb_r,
		     RTIME timeout);

int rt_task_receive(RT_TASK_MCB *mcb_r,
		    RTIME timeout);

int rt_task_reply(int flowid,
		  RT_TASK_MCB *mcb_s);

static inline int rt_task_spawn(RT_TASK *task,
				const char *name,
				int stksize,
				int prio,
				int mode,
				void (*entry)(void *cookie),
				void *cookie)
{
    int err = rt_task_create(task,name,stksize,prio,mode);

    if (!err)
	err = rt_task_start(task,entry,cookie);

    return err;
}

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_TASK_H */
