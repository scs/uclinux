/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <semaphore.h>
#include <posix/syscall.h>

extern int __pse51_muxid;

static pthread_attr_t default_attr;
static int linuxthreads;

static void (*old_sigharden_handler)(int sig);

static void __pthread_sigharden_handler(int sig)
{
	if (old_sigharden_handler &&
	    old_sigharden_handler != &__pthread_sigharden_handler)
		old_sigharden_handler(sig);

	XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_XENO_DOMAIN);
}

int __wrap_pthread_setschedparam(pthread_t thread,
				 int policy, const struct sched_param *param)
{
	pthread_t myself = pthread_self();
	int err, promoted;

	err = -XENOMAI_SKINCALL5(__pse51_muxid,
				 __pse51_thread_setschedparam,
				 thread, policy, param, myself, &promoted);

	if (err == EPERM)
		return __real_pthread_setschedparam(thread, policy, param);
	else
		__real_pthread_setschedparam(thread, policy, param);

	if (!err && promoted) {
		old_sigharden_handler = signal(SIGHARDEN, &__pthread_sigharden_handler);
		if (policy != SCHED_OTHER)
			XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_XENO_DOMAIN);
	}

	return err;
}

int __wrap_pthread_getschedparam(pthread_t thread,
				 int *__restrict__ policy,
				 struct sched_param *__restrict__ param)
{
	int err;

	err = -XENOMAI_SKINCALL3(__pse51_muxid,
				 __pse51_thread_getschedparam,
				 thread, policy, param);

	if (err == ESRCH)
		return __real_pthread_getschedparam(thread, policy, param);

	return err;
}

int __wrap_sched_yield(void)
{
	int err = -XENOMAI_SKINCALL0(__pse51_muxid, __pse51_sched_yield);

	if (err == -1)
		err = __real_sched_yield();

	return err;
}

int __wrap_pthread_yield(void)
{
	return __wrap_sched_yield();
}

struct pthread_iargs {
	void *(*start) (void *);
	void *arg;
	int policy;
	int parent_prio, prio;
	sem_t sync;
	int ret;
};

static void *__pthread_trampoline(void *arg)
{
	struct pthread_iargs *iargs = (struct pthread_iargs *)arg;
	void *(*start) (void *), *cookie;
	pthread_t tid = pthread_self();
	struct sched_param param;
	void *status = NULL;
	int parent_prio, policy;
	long err;

	old_sigharden_handler = signal(SIGHARDEN, &__pthread_sigharden_handler);

	param.sched_priority = iargs->prio;
	policy = iargs->policy;
	parent_prio = iargs->parent_prio;

	/* Do _not_ inline the call to pthread_self() in the syscall
	   macro: this trashes the syscall regs on some archs. */
	err = XENOMAI_SKINCALL1(__pse51_muxid, __pse51_thread_create, tid);
	iargs->ret = -err;

	/* We must save anything we'll need to use from *iargs on our own
	   stack now before posting the sync sema4, since our released
	   parent could unwind the stack space onto which the iargs struct
	   is laid on before we actually get the CPU back. */

	start = iargs->start;
	cookie = iargs->arg;

	__real_sem_post(&iargs->sync);

	if (!err) {
		/* Broken pthread libs ignore some of the thread attribute specs
		   passed to pthread_create(3), so we force the scheduling policy
		   once again here. */
		__real_pthread_setschedparam(tid, policy, &param);

		/* If the thread running pthread_create runs with the same
		   priority as us, we should leave it running, as if there never
		   was a synchronization with a semaphore. */
		if (param.sched_priority == parent_prio)
			__wrap_sched_yield();

		if (policy != SCHED_OTHER)
			XENOMAI_SYSCALL1(__xn_sys_migrate, XENOMAI_XENO_DOMAIN);
		status = start(cookie);
	} else
		status = (void *)-err;

	pthread_exit(status);
}

int __wrap_pthread_create(pthread_t *tid,
			  const pthread_attr_t * attr,
			  void *(*start) (void *), void *arg)
{
	struct pthread_iargs iargs;
	pthread_attr_t iattr;
	int inherit, err;
	struct sched_param param;
	pthread_t ltid;

	if (!attr)
		attr = &default_attr;
		
	pthread_attr_getinheritsched(attr, &inherit);
	__wrap_pthread_getschedparam(pthread_self(), &iargs.policy, &param);
	iargs.parent_prio = param.sched_priority;
	if (inherit == PTHREAD_EXPLICIT_SCHED) {
		pthread_attr_getschedpolicy(attr, &iargs.policy);
		pthread_attr_getschedparam(attr, &param);
	}
	iargs.prio = param.sched_priority;

	memcpy(&iattr, attr, sizeof(pthread_attr_t));
	if (linuxthreads && geteuid()) {
		/* Work around linuxthreads shortcoming: it doesn't believe
		   that it could have RT power as non-root and fails the
		   thread creation overeagerly. */
		pthread_attr_setinheritsched(&iattr, PTHREAD_EXPLICIT_SCHED);
		param.sched_priority = 0;
		pthread_attr_setschedpolicy(&iattr, SCHED_OTHER);
		pthread_attr_setschedparam(&iattr, &param);
	} else
		/* Get the created thread to temporarily inherit pthread_create
		   caller priority */
		pthread_attr_setinheritsched(&iattr, PTHREAD_INHERIT_SCHED);
	attr = &iattr;

	/* First start a native POSIX thread, then associate a Xenomai shadow to
	   it. */

	iargs.start = start;
	iargs.arg = arg;
	iargs.ret = EAGAIN;
	__real_sem_init(&iargs.sync, 0, 0);

	err = __real_pthread_create(&ltid, attr,
				    &__pthread_trampoline, &iargs);

	if (!err)
		while (__real_sem_wait(&iargs.sync) && errno == EINTR) ;
	__real_sem_destroy(&iargs.sync);

	err = err ?: iargs.ret;

	if (!err)
		*tid = ltid;

	return err;
}

int pthread_make_periodic_np(pthread_t thread,
			     struct timespec *starttp,
			     struct timespec *periodtp)
{
	return -XENOMAI_SKINCALL3(__pse51_muxid,
				  __pse51_thread_make_periodic,
				  thread, starttp, periodtp);
}

int pthread_wait_np(unsigned long *overruns_r)
{
	int err, oldtype;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

	err = -XENOMAI_SKINCALL1(__pse51_muxid,
				 __pse51_thread_wait, overruns_r);

	pthread_setcanceltype(oldtype, NULL);

	return err;
}

int pthread_set_mode_np(int clrmask, int setmask)
{
	extern int xeno_sigxcpu_no_mlock;
	int err;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_thread_set_mode, clrmask, setmask);

	/* Silently deactivate our internal handler for SIGXCPU. At that
	   point, we know that the process memory has been properly
	   locked, otherwise we would have caught the latter signal upon
	   thread creation. */

	if (!err && xeno_sigxcpu_no_mlock)
		xeno_sigxcpu_no_mlock = !(setmask & PTHREAD_WARNSW);

	return err;
}

int pthread_set_name_np(pthread_t thread, const char *name)
{
	return -XENOMAI_SKINCALL2(__pse51_muxid,
				  __pse51_thread_set_name, thread, name);
}

int __wrap_pthread_kill(pthread_t thread, int sig)
{
	int err;
	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_thread_kill, thread, sig);

	if (err == ESRCH)
		return __real_pthread_kill(thread, sig);

	return err;
}

static __attribute__((constructor)) void pse51_thread_init(void)
{
	pthread_attr_init(&default_attr);
#ifdef _CS_GNU_LIBPTHREAD_VERSION
	{
		char vers[128];
		linuxthreads =
			!confstr(_CS_GNU_LIBPTHREAD_VERSION, vers, sizeof(vers))
			|| strstr(vers, "linuxthreads");
	}
#else /* !_CS_GNU_LIBPTHREAD_VERSION */
	linuxthreads = 1;
#endif /* !_CS_GNU_LIBPTHREAD_VERSION */
}
