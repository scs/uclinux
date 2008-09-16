/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_POSIX_PTHREAD_H
#define _XENO_POSIX_PTHREAD_H

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/xenomai.h>

#ifdef __KERNEL__
#include <linux/types.h>
#include <sched.h>
#endif /* __KERNEL__ */

#ifdef __XENO_SIM__
#include <posix_overrides.h>
#define PTHREAD_STACK_MIN   8192
#else /* __XENO_SIM__ */
#define PTHREAD_STACK_MIN   1024
#endif /* __XENO_SIM__ */

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

#define PTHREAD_INHERIT_SCHED  0
#define PTHREAD_EXPLICIT_SCHED 1

#define PTHREAD_SCOPE_SYSTEM  0
#define PTHREAD_SCOPE_PROCESS 1

#define PTHREAD_MUTEX_NORMAL     0
#define PTHREAD_MUTEX_RECURSIVE  1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT    0

#define PTHREAD_PRIO_NONE    0
#define PTHREAD_PRIO_INHERIT 1
#define PTHREAD_PRIO_PROTECT 2

#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED  1

#define PTHREAD_CANCEL_ENABLE  0
#define PTHREAD_CANCEL_DISABLE 1

#define PTHREAD_CANCEL_DEFERRED     2
#define PTHREAD_CANCEL_ASYNCHRONOUS 3

#define PTHREAD_CANCELED  ((void *)-2)

#define PTHREAD_DESTRUCTOR_ITERATIONS 4
#define PTHREAD_KEYS_MAX 128

#define PTHREAD_ONCE_INIT { 0x86860808, 0 }

struct timespec;

struct pse51_thread;

typedef struct pse51_thread *pthread_t;

typedef struct pse51_threadattr {

	unsigned magic;
	int detachstate;
	size_t stacksize;
	int inheritsched;
	int policy;
	struct sched_param schedparam;

	/* Non portable */
	char *name;
	int fp;
	xnarch_cpumask_t affinity;

} pthread_attr_t;

/* pthread_mutexattr_t and pthread_condattr_t fit on 32 bits, for compatibility
   with libc. */
typedef struct pse51_mutexattr {
	unsigned magic: 24;
	unsigned type: 2;
	unsigned protocol: 2;
	unsigned pshared: 1;
} pthread_mutexattr_t;

typedef struct pse51_condattr {
	unsigned magic: 24;
	unsigned clock: 2;
	unsigned pshared: 1;
} pthread_condattr_t;

struct pse51_key;
typedef struct pse51_key *pthread_key_t;

typedef struct pse51_once {
	unsigned magic;
	int routine_called;
} pthread_once_t;

#ifdef __KERNEL__
/* The following definitions are copied from linuxthread pthreadtypes.h. */
struct _pthread_fastlock
{
  long int __status;
  int __spinlock;
};

typedef struct
{
  struct _pthread_fastlock __c_lock;
  long __c_waiting;
  char __padding[48 - sizeof (struct _pthread_fastlock)
		 - sizeof (long) - sizeof (long long)];
  long long __align;
} pthread_cond_t;

typedef struct
{
  int __m_reserved;
  int __m_count;
  long __m_owner;
  int __m_kind;
  struct _pthread_fastlock __m_lock;
} pthread_mutex_t;

#endif /* __KERNEL__ */

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include <sched.h>
#include_next <pthread.h>
#include <nucleus/thread.h>
#include <nucleus/intr.h>

struct timespec;

#endif /* __KERNEL__ || __XENO_SIM__ */

#define PTHREAD_PRIO_NONE    0
#define PTHREAD_PRIO_INHERIT 1
#define PTHREAD_PRIO_PROTECT 2

#define PTHREAD_SHIELD     XNSHIELD
#define PTHREAD_WARNSW     XNTRAPSW
#define PTHREAD_LOCK_SCHED XNLOCK
#define PTHREAD_RPIOFF     XNRPIOFF
#define PTHREAD_PRIMARY    XNTHREAD_STATE_SPARE1

#define PTHREAD_INOAUTOENA  XN_ISR_NOENABLE
#define PTHREAD_IPROPAGATE  XN_ISR_PROPAGATE

#define PTHREAD_IENABLE     0
#define PTHREAD_IDISABLE    1

struct pse51_mutex;

union __xeno_mutex {
    pthread_mutex_t native_mutex;
    struct __shadow_mutex {
	unsigned magic;
	struct pse51_mutex *mutex;
    } shadow_mutex;
};

struct pse51_cond;

union __xeno_cond {
    pthread_cond_t native_cond;
    struct __shadow_cond {
	unsigned magic;
	struct pse51_cond *cond;
    } shadow_cond;
};

struct pse51_interrupt;

typedef struct pse51_interrupt *pthread_intr_t;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#ifdef __cplusplus
extern "C" {
#endif

int pthread_attr_init(pthread_attr_t *attr);

int pthread_attr_destroy(pthread_attr_t *attr);

int pthread_attr_getdetachstate(const pthread_attr_t *attr,
				int *detachstate);

int pthread_attr_setdetachstate(pthread_attr_t *attr,
				int detachstate);

int pthread_attr_getstackaddr(const pthread_attr_t *attr,
			      void **stackaddr);

int pthread_attr_setstackaddr(pthread_attr_t *attr,
			      void *stackaddr);

int pthread_attr_getstacksize(const pthread_attr_t *attr,
			      size_t *stacksize);

int pthread_attr_setstacksize(pthread_attr_t *attr,
			      size_t stacksize);

int pthread_attr_getinheritsched(const pthread_attr_t *attr,
				 int *inheritsched);

int pthread_attr_setinheritsched(pthread_attr_t *attr,
				 int inheritsched);

int pthread_attr_getschedpolicy(const pthread_attr_t *attr,
				int *policy);

int pthread_attr_setschedpolicy(pthread_attr_t *attr,
				int policy);

int pthread_attr_getschedparam(const pthread_attr_t *attr,
			       struct sched_param *par);

int pthread_attr_setschedparam(pthread_attr_t *attr,
			       const struct sched_param *par);

int pthread_attr_getscope(const pthread_attr_t *attr,
			  int *scope);

int pthread_attr_setscope(pthread_attr_t *attr,
			  int scope);

int pthread_attr_getname_np(const pthread_attr_t *attr,
			    const char **name);

int pthread_attr_setname_np(pthread_attr_t *attr,
			    const char *name);

int pthread_attr_getfp_np(const pthread_attr_t *attr,
			  int *use_fp);

int pthread_attr_setfp_np(pthread_attr_t *attr,
			  int use_fp);

int pthread_attr_getaffinity_np (const pthread_attr_t *attr,
                                 xnarch_cpumask_t *mask);

int pthread_attr_setaffinity_np (pthread_attr_t *attr,
                                 xnarch_cpumask_t mask);

int pthread_create(pthread_t *tid,
		   const pthread_attr_t *attr,
		   void *(*start) (void *),
		   void *arg );

int pthread_detach(pthread_t thread);

int pthread_equal(pthread_t t1,
		  pthread_t t2);

void pthread_exit(void *value_ptr);

int pthread_join(pthread_t thread,
		 void **value_ptr);

pthread_t pthread_self(void);

int pthread_getschedparam(pthread_t tid,
			  int *pol,
			  struct sched_param *par);

int pthread_setschedparam(pthread_t tid,
			  int pol,
			  const struct sched_param *par);

int pthread_mutexattr_init(pthread_mutexattr_t *attr);

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);

int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr,
			      int *type);

int pthread_mutexattr_settype(pthread_mutexattr_t *attr,
			      int type);

int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr,
				  int *proto);

int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr,
				  int proto);

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared);

int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared);

int pthread_mutex_init(pthread_mutex_t *mutex,
		       const pthread_mutexattr_t *attr);

int pthread_mutex_destroy(pthread_mutex_t *mutex);

int pthread_mutex_trylock(pthread_mutex_t *mutex);

int pthread_mutex_lock(pthread_mutex_t *mutex);

int pthread_mutex_timedlock(pthread_mutex_t *mutex,
			    const struct timespec *to);

int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_condattr_init(pthread_condattr_t *attr);

int pthread_condattr_destroy(pthread_condattr_t *attr);

int pthread_condattr_getclock(const pthread_condattr_t *attr,
			      clockid_t *clk_id);

int pthread_condattr_setclock(pthread_condattr_t *attr,
			      clockid_t clk_id);

int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared);

int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);

int pthread_cond_init(pthread_cond_t *cond,
		      const pthread_condattr_t *attr);

int pthread_cond_destroy(pthread_cond_t *cond);

int pthread_cond_wait(pthread_cond_t *cond,
		      pthread_mutex_t *mutex);

int pthread_cond_timedwait(pthread_cond_t *cond,
			   pthread_mutex_t *mutex, 
                           const struct timespec *abstime);

int pthread_cond_signal(pthread_cond_t *cond);

int pthread_cond_broadcast(pthread_cond_t *cond);

int pthread_cancel(pthread_t thread);

void pthread_cleanup_push(void (*routine)(void *),
			  void *arg);

void pthread_cleanup_pop(int execute);

int pthread_setcancelstate(int state,
			   int *oldstate);

int pthread_setcanceltype(int type,
			  int *oldtype);

void pthread_testcancel(void);

int pthread_key_create(pthread_key_t *key,
		       void (*destructor)(void *));

int pthread_key_delete(pthread_key_t key);

void *pthread_getspecific(pthread_key_t key);

int pthread_setspecific(pthread_key_t key,
			const void *value);

int pthread_once(pthread_once_t *once_control,
		 void (*init_routine)(void));

int pthread_make_periodic_np(pthread_t thread,
			     struct timespec *starttp,
			     struct timespec *periodtp);

int pthread_wait_np(unsigned long *overruns_r);

int pthread_set_mode_np(int clrmask,
			int setmask);

int pthread_set_name_np(pthread_t thread,
			const char *name);

int pthread_intr_attach_np(pthread_intr_t *intr,
			   unsigned irq,
			   xnisr_t isr,
                           xniack_t iack);

int pthread_intr_detach_np(pthread_intr_t intr);

int pthread_intr_control_np(pthread_intr_t intr,
			    int cmd);

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

#ifdef __cplusplus
extern "C" {
#endif

int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr,
				  int *proto);

int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr,
				  int proto);

int pthread_condattr_getclock(const pthread_condattr_t *attr,
			      clockid_t *clk_id);

int pthread_condattr_setclock(pthread_condattr_t *attr,
			      clockid_t clk_id);

int pthread_make_periodic_np(pthread_t thread,
			     struct timespec *starttp,
			     struct timespec *periodtp);

int pthread_wait_np(unsigned long *overruns_r);

int pthread_set_mode_np(int clrmask,
			int setmask);

int pthread_set_name_np(pthread_t thread,
			const char *name);

int pthread_intr_attach_np(pthread_intr_t *intr,
			   unsigned irq,
			   int mode);

int pthread_intr_detach_np(pthread_intr_t intr);

int pthread_intr_wait_np(pthread_intr_t intr,
			 const struct timespec *to);

int pthread_intr_control_np(pthread_intr_t intr,
			    int cmd);

int __real_pthread_create(pthread_t *tid,
			  const pthread_attr_t *attr,
			  void *(*start) (void *),
			  void *arg);

int __real_pthread_detach(pthread_t thread);

int __real_pthread_getschedparam(pthread_t thread,
				 int *policy,
				 struct sched_param *param);

int __real_pthread_setschedparam(pthread_t thread,
				 int policy,
				 const struct sched_param *param);
int __real_pthread_yield(void);

int __real_pthread_mutex_init(pthread_mutex_t *mutex,
			      const pthread_mutexattr_t *attr);

int __real_pthread_mutex_destroy(pthread_mutex_t *mutex);

int __real_pthread_mutex_lock(pthread_mutex_t *mutex);

int __real_pthread_mutex_timedlock(pthread_mutex_t *mutex,
				   const struct timespec *to);

int __real_pthread_mutex_trylock(pthread_mutex_t *mutex);

int __real_pthread_mutex_unlock(pthread_mutex_t *mutex);

int __real_pthread_cond_init (pthread_cond_t *cond,
			      const pthread_condattr_t *attr);

int __real_pthread_cond_destroy(pthread_cond_t *cond);

int __real_pthread_cond_wait(pthread_cond_t *cond,
			     pthread_mutex_t *mutex);

int __real_pthread_cond_timedwait(pthread_cond_t *cond,
				  pthread_mutex_t *mutex,
				  const struct timespec *abstime);

int __real_pthread_cond_signal(pthread_cond_t *cond);

int __real_pthread_cond_broadcast(pthread_cond_t *cond);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* _XENO_POSIX_PTHREAD_H */
