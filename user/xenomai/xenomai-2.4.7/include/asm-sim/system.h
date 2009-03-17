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
 * This file implements the interface between the Xenomai nucleus and
 * the Minute Virtual Machine.
 */

#ifndef _XENO_ASM_SIM_SYSTEM_H
#define _XENO_ASM_SIM_SYSTEM_H

#include <asm/param.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <xeno_config.h>

struct xnthread;
struct xnsynch;
struct xntbase;
struct XenoThread;
struct mvm_displayctx;
struct mvm_displayctl;
struct TclList;
typedef struct TclList *mvm_tcl_listobj_t;

typedef struct xnarchtcb {	/* Per-thread arch-dependent block */

    struct xnthread *kthread;	/* Kernel thread pointer (opaque) */
    struct XenoThread *vmthread;  /* Simulation thread pointer (opaque) */
    void (*entry)(void *);	/* Thread entry */
    void *cookie;		/* Thread cookie passed on entry */
    int imask;			/* Initial interrupt mask */

} xnarchtcb_t;

typedef void *xnarch_fltinfo_t;	/* Unused but required */

#define xnarch_fault_trap(fi)   0
#define xnarch_fault_code(fi)   0
#define xnarch_fault_pc(fi)     0L
#define xnarch_fault_notify(fi) 1
#define xnarch_fault_um(fi)     0

typedef int spl_t;

#define splhigh(x)  ((x) = mvm_set_irqmask(-1))
#define splexit(x)  mvm_set_irqmask(x)
#define splnone()   mvm_set_irqmask(0)
#define splget(x)   ((x) = mvm_get_irqmask())

typedef unsigned long xnlock_t;

#define XNARCH_LOCK_UNLOCKED 0

#define xnlock_init(lock)              do { } while(0)
#define xnlock_get(lock)               do { } while(0)
#define xnlock_put(lock)               do { } while(0)
#define xnlock_get_irqsave(lock,x)     ((x) = mvm_set_irqmask(-1))
#define xnlock_put_irqrestore(lock,x)  mvm_set_irqmask(x)
#define xnlock_clear_irqoff(lock)      mvm_set_irqmask(-1)
#define xnlock_clear_irqon(lock)       mvm_set_irqmask(0)
#define xnlock_sync_irq(lock, x)			\
	do {						\
		xnlock_put_irqrestore(lock, x);		\
		xnlock_get_irqsave(lock, x);		\
	} while(0)

#define DECLARE_XNLOCK(lock)
#define DECLARE_EXTERN_XNLOCK(lock)
#define DEFINE_XNLOCK(lock)
#define DEFINE_PRIVATE_XNLOCK(lock)

#define XNARCH_NR_CPUS              1

#define XNARCH_NR_IRQS              256

/* Should be equal to the value used for creating the mvmtimer object (mvm_start_timer). */
#define XNARCH_TIMER_IRQ	    1

#define XNARCH_THREAD_STACKSZ 0 /* Let the simulator choose. */
#define XNARCH_ROOT_STACKSZ   0	/* Only a placeholder -- no stack */

#define XNARCH_PROMPT "Xenomai/sim: "
#define xnarch_loginfo(fmt,args...)  fprintf(stdout, XNARCH_PROMPT fmt , ##args)
#define xnarch_logwarn(fmt,args...)  fprintf(stderr, XNARCH_PROMPT fmt , ##args)
#define xnarch_logerr(fmt,args...)   fprintf(stderr, XNARCH_PROMPT fmt , ##args)
#define xnarch_printf(fmt,args...)   fprintf(stdout, fmt , ##args)
#define printk(fmt,args...)          xnarch_loginfo(fmt , ##args)

typedef unsigned long xnarch_cpumask_t;
#define xnarch_num_online_cpus()         XNARCH_NR_CPUS
#define xnarch_cpu_online_map            ((1<<xnarch_num_online_cpus()) - 1)
#define xnarch_cpu_set(cpu, mask)        ((mask) |= 1 << (cpu))
#define xnarch_cpu_clear(cpu, mask)      ((mask) &= 1 << (cpu))
#define xnarch_cpus_clear(mask)          ((mask) = 0UL)
#define xnarch_cpu_isset(cpu, mask)      (!!((mask) & (1 << (cpu))))
#define xnarch_cpus_and(dst, src1, src2) ((dst) = (src1) & (src2))
#define xnarch_cpus_equal(mask1, mask2)  ((mask1) == (mask2))
#define xnarch_cpus_empty(mask)          ((mask) == 0UL)
#define xnarch_cpumask_of_cpu(cpu)       (1 << (cpu))
#define xnarch_first_cpu(mask)           (ffnz(mask))
#define XNARCH_CPU_MASK_ALL              (~0UL)

#define xnarch_ullmod(ull,uld,rem)   ((*rem) = ((ull) % (uld)))
#define xnarch_uldivrem(ull,uld,rem) ((u_long)xnarch_ulldiv((ull),(uld),(rem)))
#define xnarch_uldiv(ull, d)         xnarch_uldivrem(ull, d, NULL)
#define xnarch_ulmod(ull, d)         ({ u_long _rem;                    \
                                        xnarch_uldivrem(ull,d,&_rem); _rem; })
#define xnarch_divmod64(a,b,r)       ({ if (r) \
				                *r = (a) % (b);		\
			                (a) / (b); })
#define xnarch_div64(a,b)            ((a) / (b))
#define xnarch_mod64(a,b)            ((a) % (b))

static inline int xnarch_imuldiv(int i, int mult, int div)
{
    unsigned long long ull = (unsigned long long) (unsigned) i * (unsigned) mult;
    return ull / (unsigned) div;
}

static inline unsigned long long __xnarch_ullimd(unsigned long long ull,
                                                 u_long m,
                                                 u_long d)
{
    unsigned long long mh, ml;
    u_long h, l, mlh, mll, qh, r, ql;

    h = ull >> 32; l = ull & 0xffffffff; /* Split ull. */
    mh = (unsigned long long) h * m;
    ml = (unsigned long long) l * m;
    mlh = ml >> 32; mll = ml & 0xffffffff; /* Split ml. */
    mh += mlh;
    qh = mh / d;
    r = mh % d;
    ml = (((unsigned long long) r) << 32) + mll; /* assemble r and mll */
    ql = ml / d;

    return (((unsigned long long) qh) << 32) + ql;
}

static inline long long xnarch_llimd(long long ll, u_long m, u_long d)
{
    if (ll < 0)
        return -__xnarch_ullimd(-ll, m, d);

    return __xnarch_ullimd(ll, m, d);
}

static inline unsigned long long xnarch_ullmul(unsigned long m1,
                                               unsigned long m2)
{
    return (unsigned long long) m1 * m2;
}

static inline unsigned long long xnarch_ulldiv(unsigned long long ull,
					       unsigned long uld,
					       unsigned long *rem)
{
    if (rem)
	*rem = ull % uld;

    return ull / uld;
}

static inline unsigned long ffnz(unsigned long word)
{
    return ffsl(word) - 1;
}

#define xnarch_stack_size(tcb)    0
#define xnarch_stack_base(tcb)	  NULL
#define xnarch_stack_end(tcb)	  NULL
#define xnarch_fpu_ptr(tcb)       NULL
#define xnarch_user_task(tcb)     NULL
#define xnarch_user_pid(tcb)      0

/* Under the MVM, preemption only occurs at the C-source line level,
   so we just need plain C bitops and counter support. */

typedef int atomic_counter_t;
typedef unsigned long atomic_flags_t;

#define xnarch_memory_barrier()
#define xnarch_atomic_set(pcounter,i)          (*(pcounter) = (i))
#define xnarch_atomic_get(pcounter)            (*(pcounter))
#define xnarch_atomic_inc(pcounter)            (++(*(pcounter)))
#define xnarch_atomic_dec(pcounter)            (--(*(pcounter)))
#define xnarch_atomic_inc_and_test(pcounter)   (!(++(*(pcounter))))
#define xnarch_atomic_dec_and_test(pcounter)   (!(--(*(pcounter))))
#define xnarch_atomic_set_mask(pflags,mask)    (*(pflags) |= (mask))
#define xnarch_atomic_clear_mask(pflags,mask)  (*(pflags) &= ~(mask))

typedef struct xnarch_heapcb {

#if (__GNUC__ <= 2)
    int old_gcc_dislikes_emptiness;
#endif

} xnarch_heapcb_t;

static inline void xnarch_init_heapcb (xnarch_heapcb_t *cb)
{
}

#define __mvm_breakable(f) f ## _kdoor_

static inline int __attribute__ ((unused))
xnarch_read_environ (const char *name, const char **ptype, void *pvar)
{
    char *value;

    if (*ptype == NULL)
	return 0;	/* Already read in */

    value = getenv(name);

    if (!value)
	return -1;

    if (**ptype == 's')
	*((char **)pvar) = value;
    else if (strstr(*ptype,"int"))
	*((int *)pvar) = atoi(value);
    else if (strstr(*ptype,"long"))
	*((u_long *)pvar) = (u_long)atol(value);

    *ptype = NULL;

    return 1;
}

/* Module arg macros */
#define vartype(var)               var ## _ ## tYpE
#define MODULE_DESCRIPTION(s);
#define MODULE_LICENSE(s);
#define MODULE_AUTHOR(s);
#define MODULE_PARM_DESC(name,desc);
#define module_param_named(name,var,type,perm)  static const char *vartype(var) = #type
#define module_param_value(var)   ({ xnarch_read_environ(#var,&vartype(var),&var); var; })

/* Nullify other kernel macros */
#define EXPORT_SYMBOL(sym);
#define module_init(sym);
#define module_exit(sym);
#define __init
#define __exit

/* Kernel markers */
#define trace_mark(...);

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#ifdef __cplusplus
extern "C" {
#endif

void xnpod_welcome_thread(struct xnthread *, int);

void mvm_init(int argc,
	      char *argv[]);

int mvm_run(void *tcbarg,
	    void *faddr);

void mvm_finalize_init(void);

void mvm_declare_tbase(struct xntbase *base);

void mvm_sleep(unsigned long ticks);

int mvm_hook_irq(unsigned irq,
		 void (*handler)(unsigned irq,
				 void *cookie),
		 void *cookie);

int mvm_release_irq(unsigned irq);

int mvm_post_irq(unsigned irq);

int mvm_enable_irq(unsigned irq);

int mvm_disable_irq(unsigned irq);

int mvm_set_irqmask(int level);

int mvm_get_irqmask(void);

int mvm_start_timer(unsigned long nstick,
		    void (*tickhandler)(void));

void mvm_program_timer(unsigned long delay);

void mvm_stop_timer(void);

void *mvm_create_callback(void (*handler)(void *),
			  void *cookie);

void mvm_delete_callback (void *cbhandle);

void mvm_schedule_callback(void *cbhandle,
			   unsigned long ns);

unsigned long long mvm_get_cpu_time(void);

unsigned long mvm_get_cpu_freq(void);

struct XenoThread *mvm_spawn_thread(void *tcbarg,
				    void *faddr,
				    const char *name);

int mvm_get_thread_imask (void *tcbarg);

const char *mvm_get_thread_state(void *tcbarg);

void mvm_restart_thread(struct XenoThread *thread);

struct XenoThread *mvm_thread_self(void);

void __mvm_breakable(mvm_switch_threads)(struct XenoThread *out,
					 struct XenoThread *in);

void mvm_finalize_switch_threads(struct XenoThread *dead,
				 struct XenoThread *in);

void mvm_finalize_thread(struct XenoThread *dead);

void __mvm_breakable(mvm_terminate)(int xcode);

void __mvm_breakable(mvm_fatal)(const char *format, ...);

void __mvm_breakable(mvm_break)(void);

void __mvm_breakable(mvm_join_threads)(void);

void mvm_create_display(struct mvm_displayctx *ctx,
			struct mvm_displayctl *ctl,
			void *obj,
			const char *name);

void mvm_delete_display(struct mvm_displayctx *ctx);

void mvm_send_display(struct mvm_displayctx *ctx,
		      const char *s);

void __mvm_breakable(mvm_post_graph)(struct mvm_displayctx *ctx,
				     int state);

void mvm_tcl_init_list(mvm_tcl_listobj_t *tclist);

void mvm_tcl_destroy_list(mvm_tcl_listobj_t *tclist);

void mvm_tcl_set(mvm_tcl_listobj_t *tclist,
		 const char *s);

void mvm_tcl_append(mvm_tcl_listobj_t *tclist,
		    const char *s);

void mvm_tcl_clear(mvm_tcl_listobj_t *tclist);

void mvm_tcl_append_int(mvm_tcl_listobj_t *tclist,
			u_long n);

void mvm_tcl_append_hex(mvm_tcl_listobj_t *tclist,
			u_long n);

void mvm_tcl_append_list(mvm_tcl_listobj_t *tclist,
			 mvm_tcl_listobj_t *tclist2);

const char *mvm_tcl_value(mvm_tcl_listobj_t *tclist);

void mvm_tcl_build_pendq(mvm_tcl_listobj_t *tclist,
			 struct xnsynch *synch);

static inline unsigned long long xnarch_tsc_to_ns (unsigned long long ts)
{
    return ts;
}

static inline unsigned long long xnarch_tsc_to_ns_rounded (unsigned long long ts)
{
    return ts;
}

static inline unsigned long long xnarch_ns_to_tsc (unsigned long long ns)
{
    return ns;
}

static inline unsigned long long xnarch_get_cpu_time (void)
{
    return mvm_get_cpu_time();
}

static inline unsigned long long xnarch_get_cpu_tsc (void)
{
    return mvm_get_cpu_time();
}

static inline unsigned long xnarch_get_cpu_freq (void)
{
    return mvm_get_cpu_freq();
}

static inline void xnarch_halt (const char *emsg)
{
    __mvm_breakable(mvm_fatal)("%s",emsg);
}

static inline void *xnarch_alloc_host_mem (u_long bytes)
{
    void *chunk = malloc(bytes);
    if (chunk)
	    memset(chunk, 0xa5, bytes);
    return chunk;
}

static inline void xnarch_free_host_mem (void *chunk, u_long bytes)
{
    memset(chunk, 0xdb, bytes);
    free(chunk);
}

#define xnarch_current_cpu()  0

#define cpu_relax()           do { } while(0)

int xnarch_setimask(int imask);

#ifdef __cplusplus
}
#endif

typedef struct mvm_displayctl {

    void (*objctl)(struct mvm_displayctx *ctx, int op, const char *arg);
    const char *prefix;		/* Tcl prefix for iface procs */
    const char *group;		/* Plotting group of state diagram */
    const char *const *sarray;	/* States displayed in state diagram */

} mvm_displayctl_t;

#define MVM_DECL_DISPLAY_CONTROL(tag,objctl,group,slist...) \
void objctl(struct mvm_displayctx *ctx, int op, const char *arg); \
static const char *__mvm_sarray ## tag [] = { slist, NULL }; \
 mvm_displayctl_t __mvm_displayctl_ ## tag = { \
 objctl, \
 #tag, \
 (group), \
 __mvm_sarray ## tag, \
}

struct MvmDashboard;
struct MvmGraph;

typedef struct mvm_displayctx {

    struct MvmDashboard *dashboard; /* A control board */
    struct MvmGraph *graph;	/* A state diagram */
    mvm_displayctl_t *control;	/* The associated control block */
    void *obj;			/* The rt-iface object */

} mvm_displayctx_t;

#define XNARCH_DECL_DISPLAY_CONTEXT() \
mvm_displayctx_t __mvm_display_context

#define xnarch_init_display_context(obj) \
do { \
(obj)->__mvm_display_context.dashboard = NULL; \
(obj)->__mvm_display_context.graph = NULL; \
} while(0)

#define xnarch_create_display(obj,name,tag) \
do { \
extern mvm_displayctl_t __mvm_displayctl_ ## tag; \
mvm_create_display(&(obj)->__mvm_display_context,&__mvm_displayctl_ ## tag,obj,name); \
} while(0)

#define xnarch_delete_display(obj) \
mvm_delete_display(&(obj)->__mvm_display_context)

#define xnarch_post_graph(obj,state) \
__mvm_breakable(mvm_post_graph)(&(obj)->__mvm_display_context,state)

#define xnarch_post_graph_if(obj,state,cond) \
do \
if (cond) \
__mvm_breakable(mvm_post_graph)(&(obj)->__mvm_display_context,state); \
while(0)

/* Time base export */
#define xnarch_declare_tbase(base)		mvm_declare_tbase(base)

/* Tracer interface */
#define xnarch_trace_max_begin(v)		({int err = -ENOSYS; err; })
#define xnarch_trace_max_end(v)		({int err = -ENOSYS; err; })
#define xnarch_trace_max_reset()		({int err = -ENOSYS; err; })
#define xnarch_trace_user_start()		({int err = -ENOSYS; err; })
#define xnarch_trace_user_stop(v)		({int err = -ENOSYS; err; })
#define xnarch_trace_user_freeze(v, once)	({int err = -ENOSYS; err; })
#define xnarch_trace_special(id, v)		({int err = -ENOSYS; err; })
#define xnarch_trace_special_u64(id, v)	({int err = -ENOSYS; err; })
#define xnarch_trace_pid(pid, prio)		({int err = -ENOSYS; err; })
#define xnarch_trace_panic_freeze()		({int err = -ENOSYS; err; })
#define xnarch_trace_panic_dump()		({int err = -ENOSYS; err; })
#define xnarch_trace_tick(delay_tsc)		({int err = -ENOSYS; err; })

#ifndef PAGE_SIZE
#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#endif /* !PAGE_SIZE */

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE-1))
#endif /* !PAGE_MASK */

#ifndef PAGE_ALIGN
#define PAGE_ALIGN(addr)  (((addr)+PAGE_SIZE-1)&PAGE_MASK)
#endif /* !PAGE_ALIGN */

#define ____cacheline_aligned_in_smp /* No SMP simulation support anyway. */

/* Simulator has only one root thread, so Linux semaphores are only faked. */
struct semaphore {
    unsigned count;
};
#define sema_init(s, v)       ((s)->count = (v))
#define down(s) ({                              \
        while (!(s)->count) /* deadlock */      \
                ;                               \
        --(s)->count;                           \
        })
#define down_interruptible(s) (down(s),0)
#define up(s)                 (++(s)->count)

/* Copied from linux/err.h */
#define IS_ERR_VALUE(x) ((x) > (unsigned long)-1000L)

static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

#endif /* !_XENO_ASM_SIM_SYSTEM_H */
