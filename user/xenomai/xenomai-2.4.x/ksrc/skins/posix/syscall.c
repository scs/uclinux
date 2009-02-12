/**
 * @file
 * This file is part of the Xenomai project.
 *
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org> 
 * Copyright (C) 2005 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <asm/xenomai/wrappers.h>
#include <nucleus/jhash.h>
#include <nucleus/ppd.h>
#include <posix/syscall.h>
#include <posix/posix.h>
#include <posix/thread.h>
#include <posix/mutex.h>
#include <posix/cond.h>
#include <posix/mq.h>
#include <posix/intr.h>
#include <posix/registry.h>	/* For PSE51_MAXNAME. */
#include <posix/sem.h>
#include <posix/shm.h>
#include <posix/timer.h>
#if defined(CONFIG_XENO_SKIN_RTDM) || defined (CONFIG_XENO_SKIN_RTDM_MODULE)
#include <rtdm/rtdm_driver.h>
#define RTDM_FD_MAX CONFIG_XENO_OPT_RTDM_FILDES
#endif /* RTDM */

int pse51_muxid;

struct pthread_jhash {

#define PTHREAD_HASHBITS 8

	pthread_t k_tid;
	struct pse51_hkey hkey;
	struct pthread_jhash *next;
};

static struct pthread_jhash *__jhash_buckets[1 << PTHREAD_HASHBITS];	/* Guaranteed zero */

/* We want to keep the native pthread_t token unmodified for
   Xenomai mapped threads, and keep it pointing at a genuine
   NPTL/LinuxThreads descriptor, so that portions of the POSIX
   interface which are not overriden by Xenomai fall back to the
   original Linux services. If the latter invoke Linux system calls,
   the associated shadow thread will simply switch to secondary exec
   mode to perform them. For this reason, we need an external index to
   map regular pthread_t values to Xenomai's internal thread ids used
   in syscalling the POSIX skin, so that the outer interface can keep
   on using the former transparently. Semaphores and mutexes do not
   have this constraint, since we fully override their respective
   interfaces with Xenomai-based replacements. */

static inline struct pthread_jhash *__pthread_hash(const struct pse51_hkey
						   *hkey, pthread_t k_tid)
{
	struct pthread_jhash **bucketp;
	struct pthread_jhash *slot;
	u32 hash;
	spl_t s;

	slot = (struct pthread_jhash *)xnmalloc(sizeof(*slot));

	if (!slot)
		return NULL;

	slot->hkey = *hkey;
	slot->k_tid = k_tid;

	hash = jhash2((u32 *) & slot->hkey,
		      sizeof(slot->hkey) / sizeof(u32), 0);

	bucketp = &__jhash_buckets[hash & ((1 << PTHREAD_HASHBITS) - 1)];

	xnlock_get_irqsave(&nklock, s);
	slot->next = *bucketp;
	*bucketp = slot;
	xnlock_put_irqrestore(&nklock, s);

	return slot;
}

static inline void __pthread_unhash(const struct pse51_hkey *hkey)
{
	struct pthread_jhash **tail, *slot;
	u32 hash;
	spl_t s;

	hash = jhash2((u32 *) hkey, sizeof(*hkey) / sizeof(u32), 0);

	tail = &__jhash_buckets[hash & ((1 << PTHREAD_HASHBITS) - 1)];

	xnlock_get_irqsave(&nklock, s);

	slot = *tail;

	while (slot != NULL &&
	       (slot->hkey.u_tid != hkey->u_tid || slot->hkey.mm != hkey->mm)) {
		tail = &slot->next;
		slot = *tail;
	}

	if (slot)
		*tail = slot->next;

	xnlock_put_irqrestore(&nklock, s);

	if (slot)
		xnfree(slot);
}

static pthread_t __pthread_find(const struct pse51_hkey *hkey)
{
	struct pthread_jhash *slot;
	pthread_t k_tid;
	u32 hash;
	spl_t s;

	hash = jhash2((u32 *) hkey, sizeof(*hkey) / sizeof(u32), 0);

	xnlock_get_irqsave(&nklock, s);

	slot = __jhash_buckets[hash & ((1 << PTHREAD_HASHBITS) - 1)];

	while (slot != NULL &&
	       (slot->hkey.u_tid != hkey->u_tid || slot->hkey.mm != hkey->mm))
		slot = slot->next;

	k_tid = slot ? slot->k_tid : NULL;

	xnlock_put_irqrestore(&nklock, s);

	return k_tid;
}

static int __pthread_create(struct task_struct *curr, struct pt_regs *regs)
{
	struct sched_param param;
	struct pse51_hkey hkey;
	pthread_attr_t attr;
	pthread_t k_tid;
	int err;

	/* We have been passed the pthread_t identifier the user-space
	   POSIX library has assigned to our caller; we'll index our
	   internal pthread_t descriptor in kernel space on it. */
	hkey.u_tid = __xn_reg_arg1(regs);
	hkey.mm = curr->mm;

	/* Build a default thread attribute, then make sure that a few
	   critical fields are set in a compatible fashion wrt to the
	   calling context. */

	pthread_attr_init(&attr);
	attr.policy = curr->policy;
	param.sched_priority = curr->rt_priority;
	attr.detachstate = PTHREAD_CREATE_DETACHED;
	attr.schedparam = param;
	attr.fp = 1;
	attr.name = curr->comm;

	err = pthread_create(&k_tid, &attr, NULL, NULL);

	if (err)
		return -err;	/* Conventionally, our error codes are negative. */

	err = xnshadow_map(&k_tid->threadbase, NULL);

	if (!err && !__pthread_hash(&hkey, k_tid))
		err = -ENOMEM;

	if (err)
		pse51_thread_abort(k_tid, NULL);
	else
		k_tid->hkey = hkey;

	return err;
}

#define __pthread_detach  __pse51_call_not_available

static pthread_t __pthread_shadow(struct task_struct *curr,
				  struct pse51_hkey *hkey)
{
	pthread_attr_t attr;
	pthread_t k_tid;
	int err;

	pthread_attr_init(&attr);
	attr.detachstate = PTHREAD_CREATE_DETACHED;
	attr.name = curr->comm;

	err = pthread_create(&k_tid, &attr, NULL, NULL);

	if (err)
		return ERR_PTR(-err);

	err = xnshadow_map(&k_tid->threadbase, NULL);

	if (!err && !__pthread_hash(hkey, k_tid))
		err = -EAGAIN;

	if (err)
		pse51_thread_abort(k_tid, NULL);
	else
		k_tid->hkey = *hkey;

	return err ? ERR_PTR(err) : k_tid;
}

static int __pthread_setschedparam(struct task_struct *curr,
				   struct pt_regs *regs)
{
	int policy, err, promoted = 0;
	struct sched_param param;
	struct pse51_hkey hkey;
	pthread_t k_tid;

	policy = __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg3(regs), sizeof(param)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &param,
			    (void __user *)__xn_reg_arg3(regs), sizeof(param));

	hkey.u_tid = __xn_reg_arg1(regs);
	hkey.mm = curr->mm;
	k_tid = __pthread_find(&hkey);

	if (!k_tid && __xn_reg_arg1(regs) == __xn_reg_arg4(regs)) {
		/* If the syscall applies to "current", and the latter is not
		   a Xenomai thread already, then shadow it. */
		k_tid = __pthread_shadow(curr, &hkey);
		if (IS_ERR(k_tid))
			return PTR_ERR(k_tid);

		promoted = 1;
	}
	if (k_tid)
		err = -pthread_setschedparam(k_tid, policy, &param);
	else
		/* target thread is not a real-time thread, and is not current,
		   so can not be promoted, try again with the real
		   pthread_setschedparam service. */
		err = -EPERM;

	if (!err)
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs),
				  &promoted, sizeof(promoted));

	return err;
}

static int __pthread_getschedparam(struct task_struct *curr,
				   struct pt_regs *regs)
{
	struct sched_param param;
	struct pse51_hkey hkey;
	pthread_t k_tid;
	int policy, err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(int)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(param)))
		return -EFAULT;

	hkey.u_tid = __xn_reg_arg1(regs);
	hkey.mm = curr->mm;
	k_tid = __pthread_find(&hkey);

	if (!k_tid)
		return -ESRCH;

	err = -pthread_getschedparam(k_tid, &policy, &param);

	if (!err) {
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg2(regs),
				  &policy, sizeof(int));

		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg3(regs),
				  &param, sizeof(param));
	}
	
	return err;
}

static int __sched_yield(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_t thread = thread2pthread(xnshadow_thread(curr));
	struct sched_param param;
	int policy;

	pthread_getschedparam(thread, &policy, &param);
	sched_yield();

	return policy == SCHED_OTHER;
}

static int __pthread_make_periodic_np(struct task_struct *curr,
				      struct pt_regs *regs)
{
	struct timespec startt, periodt;
	struct pse51_hkey hkey;
	pthread_t k_tid;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(startt)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg3(regs), sizeof(periodt)))
		return -EFAULT;

	hkey.u_tid = __xn_reg_arg1(regs);
	hkey.mm = curr->mm;
	k_tid = __pthread_find(&hkey);

	__xn_copy_from_user(curr,
			    &startt,
			    (void __user *)__xn_reg_arg2(regs), sizeof(startt));

	__xn_copy_from_user(curr,
			    &periodt,
			    (void __user *)__xn_reg_arg3(regs),
			    sizeof(periodt));

	return -pthread_make_periodic_np(k_tid, &startt, &periodt);
}

static int __pthread_wait_np(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned long overruns;
	int err;

	if (__xn_reg_arg1(regs) &&
	    !__xn_access_ok(curr, VERIFY_WRITE, __xn_reg_arg1(regs),
			    sizeof(overruns)))
		return -EFAULT;

	err = -pthread_wait_np(&overruns);

	if (__xn_reg_arg1(regs) && (err == 0 || err == -ETIMEDOUT))
		__xn_copy_to_user(curr, (void __user *)__xn_reg_arg1(regs),
				  &overruns, sizeof(overruns));

	return err;
}

static int __pthread_set_mode_np(struct task_struct *curr, struct pt_regs *regs)
{
	xnflags_t clrmask, setmask;

	clrmask = __xn_reg_arg1(regs);
	setmask = __xn_reg_arg2(regs);

	return -pthread_set_mode_np(clrmask, setmask);
}

static int __pthread_set_name_np(struct task_struct *curr, struct pt_regs *regs)
{
	char name[XNOBJECT_NAME_LEN];
	struct pse51_hkey hkey;
	pthread_t k_tid;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(name)))
		return -EFAULT;

	__xn_strncpy_from_user(curr, name,
			       (const char __user *)__xn_reg_arg2(regs),
			       sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	hkey.u_tid = __xn_reg_arg1(regs);
	hkey.mm = curr->mm;
	k_tid = __pthread_find(&hkey);

	return -pthread_set_name_np(k_tid, name);
}

static int __pthread_kill(struct task_struct *curr, struct pt_regs *regs)
{
	struct pse51_hkey hkey;
	pthread_t k_tid;

	hkey.u_tid = __xn_reg_arg1(regs);
	hkey.mm = curr->mm;
	k_tid = __pthread_find(&hkey);

	if(!k_tid)
		return -ESRCH;

	return -pthread_kill(k_tid, __xn_reg_arg2(regs));
}

static int __sem_init(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;
	unsigned value;
	int pshared;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	pshared = (int)__xn_reg_arg2(regs);
	value = (unsigned)__xn_reg_arg3(regs);

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	if (sem_init(&sm.native_sem, pshared, value) == -1)
		return -thread_get_errno();

	__xn_copy_to_user(curr,
			  (void __user *)&usm->shadow_sem,
			  &sm.shadow_sem, sizeof(usm->shadow_sem));

	return 0;
}

static int __sem_post(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	return sem_post(&sm.native_sem) == 0 ? 0 : -thread_get_errno();
}

static int __sem_wait(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	return sem_wait(&sm.native_sem) == 0 ? 0 : -thread_get_errno();
}

static int __sem_timedwait(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;
	struct timespec ts;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(ts)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	__xn_copy_from_user(curr,
			    &ts,
			    (void __user *)__xn_reg_arg2(regs), sizeof(ts));

	return sem_timedwait(&sm.native_sem, &ts) == 0 ? 0 : -thread_get_errno();
}

static int __sem_trywait(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	return sem_trywait(&sm.native_sem) == 0 ? 0 : -thread_get_errno();
}

static int __sem_getvalue(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;
	int err, sval;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(sval)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	err = sem_getvalue(&sm.native_sem, &sval);

	if (err)
		return -thread_get_errno();

	__xn_copy_to_user(curr,
			  (void __user *)__xn_reg_arg2(regs),
			  &sval, sizeof(sval));
	return 0;
}

static int __sem_destroy(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem sm, *usm;
	int err;
	spl_t s;

	usm = (union __xeno_sem *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)usm, sizeof(*usm)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)&usm->shadow_sem,
			    sizeof(sm.shadow_sem));

	err = sem_destroy(&sm.native_sem);

	if (err) {
		xnlock_put_irqrestore(&nklock, s);
		return -thread_get_errno();
	}

	__xn_copy_to_user(curr,
			  (void __user *)&usm->shadow_sem,
			  &sm.shadow_sem, sizeof(usm->shadow_sem));

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

static int __sem_open(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_sem *sm;
	char name[PSE51_MAXNAME];
	pse51_assoc_t *assoc;
	unsigned long uaddr;
	pse51_usem_t *usm;
	int oflags;
	long len;
	spl_t s;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg1(regs), sizeof(uaddr)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &uaddr,
			    (void __user *)__xn_reg_arg1(regs), sizeof(uaddr));

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uaddr, sizeof(sem_t)))
		return -EFAULT;

	len = __xn_strncpy_from_user(curr,
				     name,
				     (char *)__xn_reg_arg2(regs), sizeof(name));

	if (len < 0)
		return len;

	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	oflags = __xn_reg_arg3(regs);

	if (!(oflags & O_CREAT))
		sm = (union __xeno_sem *)sem_open(name, oflags);
	else
		sm = (union __xeno_sem *)sem_open(name,
						  oflags,
						  (mode_t) __xn_reg_arg4(regs),
						  (unsigned)__xn_reg_arg5(regs));

	if (sm == SEM_FAILED)
		return -thread_get_errno();

	xnlock_get_irqsave(&pse51_assoc_lock, s);
	assoc = pse51_assoc_lookup(&pse51_queues()->usems,
				   (u_long)sm->shadow_sem.sem);

	if (assoc) {
		usm = assoc2usem(assoc);
		++usm->refcnt;
		xnlock_put_irqrestore(&nklock, s);
		goto got_usm;
	}
	
	xnlock_put_irqrestore(&pse51_assoc_lock, s);

	usm = (pse51_usem_t *) xnmalloc(sizeof(*usm));

	if (!usm) {
		sem_close(&sm->native_sem);
		return -ENOSPC;
	}

	usm->uaddr = uaddr;
	usm->refcnt = 1;

	xnlock_get_irqsave(&pse51_assoc_lock, s);
	assoc =
		pse51_assoc_lookup(&pse51_queues()->usems,
				   (u_long)sm->shadow_sem.sem);

	if (assoc) {
		assoc2usem(assoc)->refcnt++;
		xnlock_put_irqrestore(&nklock, s);
		xnfree(usm);
		usm = assoc2usem(assoc);
		goto got_usm;
	}
	
	pse51_assoc_insert(&pse51_queues()->usems,
			   &usm->assoc,
			   (u_long)sm->shadow_sem.sem);
	xnlock_put_irqrestore(&pse51_assoc_lock, s);

got_usm:

	if (usm->uaddr == uaddr)
		/* First binding by this process. */
		__xn_copy_to_user(curr,
				  (void __user *)usm->uaddr,
				  &sm->shadow_sem, sizeof(sm->shadow_sem));
	else
		/* Semaphore already bound by this process in user-space. */
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg1(regs),
				  &usm->uaddr, sizeof(unsigned long));

	return 0;
}

static int __sem_close(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	union __xeno_sem sm;
	unsigned long uaddr;
	pse51_usem_t *usm;
	int closed, err;
	spl_t s;

	uaddr = (unsigned long)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)uaddr, sizeof(sem_t)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &sm.shadow_sem,
			    (void __user *)uaddr, sizeof(sm.shadow_sem));

	xnlock_get_irqsave(&pse51_assoc_lock, s);

	assoc =
	    pse51_assoc_lookup(&pse51_queues()->usems,
			       (u_long)sm.shadow_sem.sem);

	if (!assoc) {
		xnlock_put_irqrestore(&pse51_assoc_lock, s);
		return -EINVAL;
	}

	usm = assoc2usem(assoc);

	if ((closed = (--usm->refcnt == 0)))
		pse51_assoc_remove(&pse51_queues()->usems,
				   (u_long)sm.shadow_sem.sem);

	err = sem_close(&sm.native_sem);

	xnlock_put_irqrestore(&pse51_assoc_lock, s);

	if (!err) {
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg2(regs),
				  &closed, sizeof(int));

		return 0;
	}

	return -thread_get_errno();
}

static int __sem_unlink(struct task_struct *curr, struct pt_regs *regs)
{
	char name[PSE51_MAXNAME];
	long len;

	len = __xn_strncpy_from_user(curr,
				     name,
				     (char *)__xn_reg_arg1(regs), sizeof(name));

	if (len < 0)
		return len;

	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	return sem_unlink(name) == 0 ? 0 : -thread_get_errno();
}

static int __clock_getres(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec ts;
	clockid_t clock_id;
	int err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(ts)))
		return -EFAULT;

	clock_id = __xn_reg_arg1(regs);

	err = clock_getres(clock_id, &ts);

	if (!err)
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg2(regs),
				  &ts, sizeof(ts));
	return err ? -thread_get_errno() : 0;
}

static int __clock_gettime(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec ts;
	clockid_t clock_id;
	int err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(ts)))
		return -EFAULT;

	clock_id = __xn_reg_arg1(regs);

	err = clock_gettime(clock_id, &ts);

	if (!err)
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg2(regs),
				  &ts, sizeof(ts));
	return err ? -thread_get_errno() : 0;
}

static int __clock_settime(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec ts;
	clockid_t clock_id;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(ts)))
		return -EFAULT;

	clock_id = __xn_reg_arg1(regs);

	__xn_copy_from_user(curr,
			    &ts,
			    (void __user *)__xn_reg_arg2(regs), sizeof(ts));

	return clock_settime(clock_id, &ts) ? -thread_get_errno() : 0;
}

static int __clock_nanosleep(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec rqt, rmt, *rmtp = NULL;
	clockid_t clock_id;
	int flags, err;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg3(regs), sizeof(rqt)))
		return -EFAULT;

	if (__xn_reg_arg4(regs)) {
		if (!__xn_access_ok
		    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(rmt)))
			return -EFAULT;

		rmtp = &rmt;
	}

	clock_id = __xn_reg_arg1(regs);

	flags = (int)__xn_reg_arg2(regs);

	__xn_copy_from_user(curr,
			    &rqt,
			    (void __user *)__xn_reg_arg3(regs), sizeof(rqt));

	err = clock_nanosleep(clock_id, flags, &rqt, rmtp);

	if (err != EINTR)
		return -err;

	if (rmtp)
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg4(regs),
				  rmtp, sizeof(*rmtp));
	return -EINTR;
}

static int __pthread_mutexattr_init(struct task_struct *curr,
				    struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	err = pthread_mutexattr_init(&attr);

	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));
	return 0;
}

static int __pthread_mutexattr_destroy(struct task_struct *curr,
				       struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_destroy(&attr);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_mutexattr_gettype(struct task_struct *curr,
				       struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err, type, *utypep;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	utypep = (int *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)utypep, sizeof(*utypep)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_gettype(&attr, &type);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)utypep,&type,sizeof(*utypep));

	return 0;
}

static int __pthread_mutexattr_settype(struct task_struct *curr,
				       struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err, type;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	type = (int) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_settype(&attr, type);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_mutexattr_getprotocol(struct task_struct *curr,
					   struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err, proto, *uprotop;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	uprotop = (int *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uprotop, sizeof(*uprotop)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_getprotocol(&attr, &proto);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uprotop,&proto,sizeof(*uprotop));

	return 0;
}

static int __pthread_mutexattr_setprotocol(struct task_struct *curr,
					   struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err, proto;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	proto = (int) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_setprotocol(&attr, proto);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_mutexattr_getpshared(struct task_struct *curr,
					  struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err, pshared, *upsharedp;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	upsharedp = (int *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)upsharedp, sizeof(*upsharedp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_getpshared(&attr, &pshared);
	if (err)
		return -err;

	__xn_copy_to_user(curr,
			  (void __user *)upsharedp,
			  &pshared,
			  sizeof(*upsharedp));

	return 0;
}

static int __pthread_mutexattr_setpshared(struct task_struct *curr,
					  struct pt_regs *regs)
{
	pthread_mutexattr_t attr, *uattrp;
	int err, pshared;

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg1(regs);

	pshared = (int) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_mutexattr_setpshared(&attr, pshared);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_mutex_init(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_mutexattr_t locattr, *attr, *uattrp;
	union __xeno_mutex mx, *umx;
	int err;

	umx = (union __xeno_mutex *)__xn_reg_arg1(regs);

	uattrp = (pthread_mutexattr_t *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	if (uattrp) {
		if (!__xn_access_ok
		    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
			return -EFAULT;

		__xn_copy_from_user(curr,
				    &locattr,(void __user *)
				    uattrp,
				    sizeof(locattr));

		attr = &locattr;
	} else
		attr = NULL;

	err = pthread_mutex_init(&mx.native_mutex, attr);
	
	if (err)
		return -err;

	__xn_copy_to_user(curr,
			  (void __user *)&umx->shadow_mutex,
			  &mx.shadow_mutex, sizeof(umx->shadow_mutex));

	return 0;
}

static int __pthread_mutex_destroy(struct task_struct *curr,
				   struct pt_regs *regs)
{
	union __xeno_mutex mx, *umx;
	int err;

	umx = (union __xeno_mutex *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	err = pthread_mutex_destroy(&mx.native_mutex);

	if (err)
		return -err;
	
	__xn_copy_to_user(curr,
			  (void __user *)&umx->shadow_mutex,
			  &mx.shadow_mutex, sizeof(umx->shadow_mutex));

	return 0;
}

static int __pthread_mutex_lock(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_mutex mx, *umx;

	umx = (union __xeno_mutex *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	return -pse51_mutex_timedlock_break(&mx.shadow_mutex, 0, XN_INFINITE);
}

static int __pthread_mutex_timedlock(struct task_struct *curr,
				     struct pt_regs *regs)
{
	union __xeno_mutex mx, *umx;
	struct timespec ts;

	umx = (union __xeno_mutex *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	if (!__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(ts)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	__xn_copy_from_user(curr,
			    &ts,
			    (void __user *)__xn_reg_arg2(regs), sizeof(ts));

	return -pse51_mutex_timedlock_break(&mx.shadow_mutex,
					    1, ts2ticks_ceil(&ts) + 1);
}

static int __pthread_mutex_trylock(struct task_struct *curr,
				   struct pt_regs *regs)
{
	union __xeno_mutex mx, *umx;

	umx = (union __xeno_mutex *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	return -pthread_mutex_trylock(&mx.native_mutex);
}

static int __pthread_mutex_unlock(struct task_struct *curr,
				  struct pt_regs *regs)
{
	union __xeno_mutex mx, *umx;

	umx = (union __xeno_mutex *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	return -pthread_mutex_unlock(&mx.native_mutex);
}

static int __pthread_condattr_init(struct task_struct *curr,
				   struct pt_regs *regs)
{
	pthread_condattr_t attr, *uattrp;
	int err;

	uattrp = (pthread_condattr_t *) __xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	err = pthread_condattr_init(&attr);

	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));
	return 0;
}

static int __pthread_condattr_destroy(struct task_struct *curr,
				      struct pt_regs *regs)
{
	pthread_condattr_t attr, *uattrp;
	int err;

	uattrp = (pthread_condattr_t *) __xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_condattr_destroy(&attr);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_condattr_getclock(struct task_struct *curr,
				       struct pt_regs *regs)
{
	pthread_condattr_t attr, *uattrp;
	clockid_t clock, *uclockp;
	int err;

	uattrp = (pthread_condattr_t *) __xn_reg_arg1(regs);

	uclockp = (clockid_t *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uclockp, sizeof(*uclockp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_condattr_getclock(&attr, &clock);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uclockp,&clock,sizeof(*uclockp));

	return 0;
}

static int __pthread_condattr_setclock(struct task_struct *curr,
				       struct pt_regs *regs)
{
	pthread_condattr_t attr, *uattrp;
	clockid_t clock;
	int err;

	uattrp = (pthread_condattr_t *) __xn_reg_arg1(regs);

	clock = (clockid_t) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_condattr_setclock(&attr, clock);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_condattr_getpshared(struct task_struct *curr,
					 struct pt_regs *regs)
{
	pthread_condattr_t attr, *uattrp;
	int err, pshared, *upsharedp;

	uattrp = (pthread_condattr_t *) __xn_reg_arg1(regs);

	upsharedp = (int *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)upsharedp, sizeof(*upsharedp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_condattr_getpshared(&attr, &pshared);
	if (err)
		return -err;

	__xn_copy_to_user(curr,
			  (void __user *)upsharedp,
			  &pshared,
			  sizeof(*upsharedp));

	return 0;
}

static int __pthread_condattr_setpshared(struct task_struct *curr,
					 struct pt_regs *regs)
{
	pthread_condattr_t attr, *uattrp;
	int err, pshared;

	uattrp = (pthread_condattr_t *) __xn_reg_arg1(regs);

	pshared = (int) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)uattrp, sizeof(*uattrp)))
		return -EFAULT;

	__xn_copy_from_user(curr,&attr,(void __user *)uattrp,sizeof(attr));

	err = pthread_condattr_setpshared(&attr, pshared);
	if (err)
		return -err;

	__xn_copy_to_user(curr,(void __user *)uattrp,&attr,sizeof(*uattrp));

	return 0;
}

static int __pthread_cond_init(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_condattr_t locattr, *attr, *uattrp;
	union __xeno_cond cnd, *ucnd;
	int err;

	ucnd = (union __xeno_cond *)__xn_reg_arg1(regs);

	uattrp = (pthread_condattr_t *) __xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, (void __user *)ucnd, sizeof(*ucnd)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &cnd.shadow_cond,
			    (void __user *)&ucnd->shadow_cond,
			    sizeof(cnd.shadow_cond));

	if (uattrp) {
		if (!__xn_access_ok
		    (curr, VERIFY_READ, (void __user *)uattrp, sizeof(*uattrp)))
			return -EFAULT;

		__xn_copy_from_user(curr,
				    &locattr,
				    (void __user *)uattrp,
				    sizeof(locattr));

		attr = &locattr;
	} else
		attr = NULL;

	err = pthread_cond_init(&cnd.native_cond, attr);

	if (err)
		return -err;

	__xn_copy_to_user(curr,
			  (void __user *)&ucnd->shadow_cond,
			  &cnd.shadow_cond, sizeof(ucnd->shadow_cond));

	return 0;
}

static int __pthread_cond_destroy(struct task_struct *curr,
				  struct pt_regs *regs)
{
	union __xeno_cond cnd, *ucnd;
	int err;

	ucnd = (union __xeno_cond *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)ucnd, sizeof(*ucnd)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &cnd.shadow_cond,
			    (void __user *)&ucnd->shadow_cond,
			    sizeof(cnd.shadow_cond));

	err = pthread_cond_destroy(&cnd.native_cond);

	if (err)
		return -err;

	__xn_copy_to_user(curr,
			  (void __user *)&ucnd->shadow_cond,
			  &cnd.shadow_cond, sizeof(ucnd->shadow_cond));

	return 0;
}

/* pthread_cond_wait_prologue(cond, mutex, count_ptr, timed, timeout) */
static int __pthread_cond_wait_prologue(struct task_struct *curr,
					struct pt_regs *regs)
{
	xnthread_t *cur = xnshadow_thread(curr);
	union __xeno_cond cnd, *ucnd;
	union __xeno_mutex mx, *umx;
	unsigned timed, count;
	struct timespec ts;
	int err;

	ucnd = (union __xeno_cond *)__xn_reg_arg1(regs);
	umx = (union __xeno_mutex *)__xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)ucnd, sizeof(*ucnd)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	if (!__xn_access_ok(curr, VERIFY_WRITE,
			    (void __user *)__xn_reg_arg3(regs), sizeof(count)))
		return -EFAULT;
	
	timed = __xn_reg_arg4(regs);
	if (timed && !__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)__xn_reg_arg5(regs), sizeof(ts)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &cnd.shadow_cond,
			    (void __user *)&ucnd->shadow_cond,
			    sizeof(cnd.shadow_cond));

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	if (timed) {
		__xn_copy_from_user(curr, &ts,
				    (void __user *)__xn_reg_arg5(regs),
				    sizeof(ts));

		err = pse51_cond_timedwait_prologue(cur,
						    &cnd.shadow_cond,
						    &mx.shadow_mutex,
						    &count,
						    timed,
						    ts2ticks_ceil(&ts) + 1);
	} else
		err = pse51_cond_timedwait_prologue(cur,
						    &cnd.shadow_cond,
						    &mx.shadow_mutex,
						    &count,
						    timed,
						    XN_INFINITE);

	if (err == EINTR) {
		do {
			xnthread_clear_info(cur, XNKICKED);
			err = pse51_cond_timedwait_epilogue(cur, &cnd.shadow_cond,
							    &mx.shadow_mutex, count);
		}
		while (err == EINTR);
		xnthread_set_info(cur, XNKICKED);
		err = EINTR;
	}


	if (!err || err == EINTR || err == ETIMEDOUT)
		__xn_copy_to_user(curr, (void __user *) __xn_reg_arg3(regs),
				  &count, sizeof(count));

	return -err;
}

/* pthread_cond_wait_epilogue(cond, mutex, count) */
static int __pthread_cond_wait_epilogue(struct task_struct *curr,
					struct pt_regs *regs)
{
	xnthread_t *cur = xnshadow_thread(curr);
	union __xeno_cond cnd, *ucnd;
	union __xeno_mutex mx, *umx;
	unsigned count;

	ucnd = (union __xeno_cond *)__xn_reg_arg1(regs);
	umx = (union __xeno_mutex *)__xn_reg_arg2(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)ucnd, sizeof(*ucnd)))
		return -EFAULT;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)umx, sizeof(*umx)))
		return -EFAULT;

	count = __xn_reg_arg3(regs);

	__xn_copy_from_user(curr,
			    &cnd.shadow_cond,
			    (void __user *)&ucnd->shadow_cond,
			    sizeof(cnd.shadow_cond));

	__xn_copy_from_user(curr,
			    &mx.shadow_mutex,
			    (void __user *)&umx->shadow_mutex,
			    sizeof(mx.shadow_mutex));

	
	return -pse51_cond_timedwait_epilogue(cur, &cnd.shadow_cond,
					      &mx.shadow_mutex, count);
}

static int __pthread_cond_signal(struct task_struct *curr, struct pt_regs *regs)
{
	union __xeno_cond cnd, *ucnd;

	ucnd = (union __xeno_cond *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)ucnd, sizeof(*ucnd)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &cnd.shadow_cond,
			    (void __user *)&ucnd->shadow_cond,
			    sizeof(cnd.shadow_cond));

	return -pthread_cond_signal(&cnd.native_cond);
}

static int __pthread_cond_broadcast(struct task_struct *curr,
				    struct pt_regs *regs)
{
	union __xeno_cond cnd, *ucnd;

	ucnd = (union __xeno_cond *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, (void __user *)ucnd, sizeof(*ucnd)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &cnd.shadow_cond,
			    (void __user *)&ucnd->shadow_cond,
			    sizeof(cnd.shadow_cond));

	return -pthread_cond_broadcast(&cnd.native_cond);
}

/* mq_open(name, oflags, mode, attr, ufd) */
static int __mq_open(struct task_struct *curr, struct pt_regs *regs)
{
	struct mq_attr locattr, *attr;
	char name[PSE51_MAXNAME];
	pse51_ufd_t *assoc;
	int err, oflags;
	mqd_t kqd, uqd;
	unsigned len;
	mode_t mode;

	len = __xn_strncpy_from_user(curr,
				     name,
				     (const char __user *)__xn_reg_arg1(regs),
				     sizeof(name));
	if (len <= 0)
		return -EFAULT;

	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	oflags = __xn_reg_arg2(regs);
	mode = __xn_reg_arg3(regs);

	if ((oflags & O_CREAT) && __xn_reg_arg4(regs)) {
		if (!__xn_access_ok
		    (curr, VERIFY_READ, __xn_reg_arg4(regs), sizeof(attr)))
			return -EFAULT;

		__xn_copy_from_user(curr,
				    &locattr,
				    (struct mq_attr *)__xn_reg_arg4(regs),
				    sizeof(locattr));

		attr = &locattr;
	} else
		attr = NULL;

	kqd = mq_open(name, oflags, mode, attr);

	if (kqd == -1)
		return -thread_get_errno();

	uqd = __xn_reg_arg5(regs);

	assoc = (pse51_ufd_t *) xnmalloc(sizeof(*assoc));
	if (!assoc) {
		mq_close(kqd);
		return -ENOSPC;
	}

	assoc->kfd = kqd;

	err = pse51_assoc_insert(&pse51_queues()->uqds,
				 &assoc->assoc,
				 (u_long)uqd);

	if (err) {
		xnfree(assoc);
		mq_close(kqd);
	}

	return err;
}

static int __mq_close(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	mqd_t uqd;
	int err;

	uqd = (mqd_t) __xn_reg_arg1(regs);

	assoc = pse51_assoc_remove(&pse51_queues()->uqds, (u_long)uqd);

	if (!assoc)
		return -EBADF;

	err = mq_close(assoc2ufd(assoc)->kfd);
	xnfree(assoc2ufd(assoc));

	return !err ? 0 : -thread_get_errno();
}

static int __mq_unlink(struct task_struct *curr, struct pt_regs *regs)
{
	char name[PSE51_MAXNAME];
	unsigned len;
	int err;

	len = __xn_strncpy_from_user(curr,
				     name,
				     (const char __user *)__xn_reg_arg1(regs),
				     sizeof(name));
	if (len <= 0)
		return -EFAULT;

	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	err = mq_unlink(name);

	return err ? -thread_get_errno() : 0;
}

static int __mq_getattr(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	struct mq_attr attr;
	pse51_ufd_t *ufd;
	int err;

	assoc = pse51_assoc_lookup(&pse51_queues()->uqds,
				   (u_long)__xn_reg_arg1(regs));
	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(attr)))
		return -EFAULT;

	err = mq_getattr(ufd->kfd, &attr);

	if (err)
		return -thread_get_errno();

	__xn_copy_to_user(curr,
			  (void __user *)__xn_reg_arg2(regs),
			  &attr, sizeof(attr));
	return 0;
}

static int __mq_setattr(struct task_struct *curr, struct pt_regs *regs)
{
	struct mq_attr attr, oattr;
	pse51_assoc_t *assoc;
	pse51_ufd_t *ufd;
	int err;

	assoc = pse51_assoc_lookup(&pse51_queues()->uqds,
				   (u_long)__xn_reg_arg1(regs));
	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(attr)))
		return -EFAULT;

	__xn_copy_from_user(curr, &attr, (struct mq_attr *)__xn_reg_arg2(regs),
			    sizeof(attr));

	if (__xn_reg_arg3(regs) &&
	    !__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg3(regs),
			    sizeof(oattr)))
		return -EFAULT;

	err = mq_setattr(ufd->kfd, &attr, &oattr);

	if (err)
		return -thread_get_errno();

	if (__xn_reg_arg3(regs))
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg3(regs),
				  &oattr, sizeof(oattr));
	return 0;
}

/* mq_send(q, buffer, len, prio) */
static int __mq_send(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	pse51_msg_t *msg;
	pse51_ufd_t *ufd;
	pse51_mq_t *mq;
	unsigned prio;
	size_t len;

	len = (size_t) __xn_reg_arg3(regs);
	prio = __xn_reg_arg4(regs);

	assoc =
	    pse51_assoc_lookup(&pse51_queues()->uqds,
			       (u_long)__xn_reg_arg1(regs));

	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (len > 0 && !__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), len))
		return -EFAULT;

	msg = pse51_mq_timedsend_inner(&mq, ufd->kfd, len, NULL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	if(__xn_copy_from_user(curr, msg->data,
			       (void __user *)__xn_reg_arg2(regs), len)) {
		pse51_mq_finish_send(ufd->kfd, mq, msg);
		return -EFAULT;
	}
	msg->len = len;
	pse51_msg_set_prio(msg, prio);

	return pse51_mq_finish_send(ufd->kfd, mq, msg);
}

/* mq_timedsend(q, buffer, len, prio, timeout) */
static int __mq_timedsend(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec timeout, *timeoutp;
	pse51_assoc_t *assoc;
	pse51_msg_t *msg;
	pse51_ufd_t *ufd;
	pse51_mq_t *mq;
	unsigned prio;
	size_t len;

	len = (size_t) __xn_reg_arg3(regs);
	prio = __xn_reg_arg4(regs);

	assoc =
	    pse51_assoc_lookup(&pse51_queues()->uqds,
			       (u_long)__xn_reg_arg1(regs));

	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (__xn_reg_arg5(regs) &&
	    !__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg5(regs),
			    sizeof(timeout)))
		return -EFAULT;

	if (len > 0 && !__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), len))
		return -EFAULT;

	if (__xn_reg_arg5(regs)) {
		__xn_copy_from_user(curr,
				    &timeout,
				    (struct timespec __user *)
				    __xn_reg_arg5(regs), sizeof(timeout));
		timeoutp = &timeout;
	} else
		timeoutp = NULL;

	msg = pse51_mq_timedsend_inner(&mq, ufd->kfd, len, timeoutp);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	if(__xn_copy_from_user(curr, msg->data,
			       (void __user *)__xn_reg_arg2(regs), len)) {
		pse51_mq_finish_send(ufd->kfd, mq, msg);
		return -EFAULT;
	}
	msg->len = len;
	pse51_msg_set_prio(msg, prio);

	return pse51_mq_finish_send(ufd->kfd, mq, msg);
}

/* mq_receive(qd, buffer, &len, &prio)*/
static int __mq_receive(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	pse51_ufd_t *ufd;
	pse51_msg_t *msg;
	pse51_mq_t *mq;
	unsigned prio;
	ssize_t len;
	int err;

	assoc = pse51_assoc_lookup(&pse51_queues()->uqds,
				   (u_long)__xn_reg_arg1(regs));
	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(len)))
		return -EFAULT;

	__xn_copy_from_user(curr, &len, (ssize_t *) __xn_reg_arg3(regs),
			    sizeof(len));

	if (__xn_reg_arg4(regs)
	    && !__xn_access_ok(curr, VERIFY_WRITE,
			       __xn_reg_arg4(regs), sizeof(prio)))
		return -EFAULT;

	if (len > 0 && !__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), len))
		return -EFAULT;

	msg = pse51_mq_timedrcv_inner(&mq, ufd->kfd, len, NULL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	if (__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
			      msg->data, msg->len)) {
		pse51_mq_finish_rcv(ufd->kfd, mq, msg);
		return -EFAULT;
	}
	len = msg->len;
	prio = pse51_msg_get_prio(msg);

	err = pse51_mq_finish_rcv(ufd->kfd, mq, msg);
	if (err)
		return err;

	__xn_copy_to_user(curr,
			  (void __user *)__xn_reg_arg3(regs),
			  &len, sizeof(len));

	if (__xn_reg_arg4(regs))
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg4(regs),
				  &prio, sizeof(prio));

	return 0;
}

/* mq_timedreceive(qd, buffer, &len, &prio, timeout) */
static int __mq_timedreceive(struct task_struct *curr, struct pt_regs *regs)
{
	struct timespec timeout, *timeoutp;
	pse51_assoc_t *assoc;
	pse51_ufd_t *ufd;
	pse51_msg_t *msg;
	pse51_mq_t *mq;
	unsigned prio;
	ssize_t len;
	int err;

	assoc = pse51_assoc_lookup(&pse51_queues()->uqds,
				   (u_long)__xn_reg_arg1(regs));
	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(len)))
		return -EFAULT;

	__xn_copy_from_user(curr, &len, (ssize_t *) __xn_reg_arg3(regs),
			    sizeof(len));

	if (__xn_reg_arg4(regs)
	    && !__xn_access_ok(curr, VERIFY_WRITE,
			       __xn_reg_arg4(regs), sizeof(prio)))
		return -EFAULT;

	if (__xn_reg_arg5(regs) &&
	    !__xn_access_ok(curr, VERIFY_READ, __xn_reg_arg5(regs),
			    sizeof(timeout)))
		return -EFAULT;

	if (len > 0 && !__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), len))
		return -EFAULT;

	if (__xn_reg_arg5(regs)) {
		__xn_copy_from_user(curr,
				    &timeout,
				    (struct timespec __user *)
				    __xn_reg_arg5(regs), sizeof(timeout));
		timeoutp = &timeout;
	} else
		timeoutp = NULL;

	msg = pse51_mq_timedrcv_inner(&mq, ufd->kfd, len, timeoutp);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	if (__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs),
			      msg->data, msg->len)) {
		pse51_mq_finish_rcv(ufd->kfd, mq, msg);
		return -EFAULT;
	}
	len = msg->len;
	prio = pse51_msg_get_prio(msg);

	err = pse51_mq_finish_rcv(ufd->kfd, mq, msg);
	if (err)
		return err;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(len)) ||
	    __xn_copy_to_user(curr, (void __user *)__xn_reg_arg3(regs),
			      &len, sizeof(len)))
		return -EFAULT;

	if (__xn_reg_arg4(regs))
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg4(regs),
				  &prio, sizeof(prio));

	return 0;
}

static int __mq_notify(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	struct sigevent sev;
	pse51_ufd_t *ufd;

	assoc =
	    pse51_assoc_lookup(&pse51_queues()->uqds,
			       (u_long)__xn_reg_arg1(regs));

	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(sev)))
		return -EFAULT;

	__xn_copy_from_user(curr, &sev, (char *)__xn_reg_arg2(regs),
			    sizeof(sev));

	if (mq_notify(ufd->kfd, &sev))
		return -thread_get_errno();

	return 0;
}

#ifdef CONFIG_XENO_OPT_POSIX_INTR

static int __pse51_intr_handler(xnintr_t *cookie)
{
	pthread_intr_t intr = PTHREAD_IDESC(cookie);

	++intr->pending;

	if (xnsynch_nsleepers(&intr->synch_base) > 0)
		xnsynch_flush(&intr->synch_base, 0);

	if (intr->mode & XN_ISR_PROPAGATE)
		return XN_ISR_PROPAGATE | (intr->mode & XN_ISR_NOENABLE);

	return XN_ISR_HANDLED | (intr->mode & XN_ISR_NOENABLE);
}

static int __intr_attach(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_intr_t intr;
	int err, mode;
	unsigned irq;

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg1(regs), sizeof(intr)))
		return -EFAULT;

	/* Interrupt line number. */
	irq = (unsigned)__xn_reg_arg2(regs);

	/* Interrupt control mode. */
	mode = (int)__xn_reg_arg3(regs);

	if (mode & ~(XN_ISR_NOENABLE | XN_ISR_PROPAGATE))
		return -EINVAL;

	err = pthread_intr_attach_np(&intr, irq, &__pse51_intr_handler, NULL);

	if (err == 0) {
		intr->mode = mode;
		__xn_copy_to_user(curr,
				  (void __user *)__xn_reg_arg1(regs),
				  &intr, sizeof(intr));
	}

	return !err ? 0 : -thread_get_errno();
}

static int __intr_detach(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_intr_t intr = (struct pse51_interrupt *)__xn_reg_arg1(regs);
	int err = pthread_intr_detach_np(intr);

	return !err ? 0 : -thread_get_errno();
}

static int __intr_wait(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_intr_t intr = (pthread_intr_t) __xn_reg_arg1(regs);
	struct timespec ts;
	xnthread_t *thread;
	xnticks_t timeout;
	int err = 0;
	spl_t s;

	if (__xn_reg_arg2(regs)) {
		if (!__xn_access_ok
		    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(ts)))
			return -EFAULT;

		__xn_copy_from_user(curr,
				    &ts,
				    (void __user *)__xn_reg_arg2(regs),
				    sizeof(ts));

		if (ts.tv_sec == 0 && ts.tv_nsec == 0)
			return -EINVAL;

		timeout = ts2ticks_ceil(&ts) + 1;
	} else
		timeout = XN_INFINITE;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(intr, PSE51_INTR_MAGIC, struct pse51_interrupt)) {
		xnlock_put_irqrestore(&nklock, s);
		return -EINVAL;
	}

	if (intr->owningq != pse51_kqueues(0)) {
		xnlock_put_irqrestore(&nklock, s);
		return -EPERM;
	}

	if (!intr->pending) {
		thread = xnpod_current_thread();

		if (xnthread_base_priority(thread) != XNCORE_IRQ_PRIO)
			/* Renice the waiter above all regular threads if needed. */
			xnpod_renice_thread(thread, XNCORE_IRQ_PRIO);

		xnsynch_sleep_on(&intr->synch_base, timeout, XN_RELATIVE);

		if (xnthread_test_info(thread, XNRMID))
			err = -EIDRM;	/* Interrupt object deleted while pending. */
		else if (xnthread_test_info(thread, XNTIMEO))
			err = -ETIMEDOUT;	/* Timeout. */
		else if (xnthread_test_info(thread, XNBREAK))
			err = -EINTR;	/* Unblocked. */
		else {
			err = intr->pending;
			intr->pending = 0;
		}
	} else {
		err = intr->pending;
		intr->pending = 0;
	}

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

static int __intr_control(struct task_struct *curr, struct pt_regs *regs)
{
	pthread_intr_t intr = (pthread_intr_t) __xn_reg_arg1(regs);
	int err, cmd = (int)__xn_reg_arg2(regs);

	err = pthread_intr_control_np(intr, cmd);

	return !err ? 0 : -thread_get_errno();
}

#else /* !CONFIG_XENO_OPT_POSIX_INTR */

#define __intr_attach  __pse51_call_not_available
#define __intr_detach  __pse51_call_not_available
#define __intr_wait    __pse51_call_not_available
#define __intr_control __pse51_call_not_available

#endif /* !CONFIG_XENO_OPT_POSIX_INTR */

static int __timer_create(struct task_struct *curr, struct pt_regs *regs)
{
	struct sigevent sev;
	timer_t tm;
	int rc;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(sev)))
		return -EFAULT;

	__xn_copy_from_user(curr, &sev, (char *)__xn_reg_arg2(regs),
			    sizeof(sev));

	rc = timer_create((clockid_t) __xn_reg_arg1(regs), &sev, &tm);

	if (!rc) {
		if (!__xn_access_ok
		    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(tm))) {
			timer_delete(tm);
			return -EFAULT;
		}

		__xn_copy_to_user(curr, (char *)__xn_reg_arg3(regs), &tm,
				  sizeof(tm));
	}

	return rc == 0 ? 0 : -thread_get_errno();
}

static int __timer_delete(struct task_struct *curr, struct pt_regs *regs)
{
	int rc;

	rc = timer_delete((timer_t) __xn_reg_arg1(regs));

	return rc == 0 ? 0 : -thread_get_errno();
}

static int __timer_settime(struct task_struct *curr, struct pt_regs *regs)
{
	struct itimerspec newv, oldv, *oldvp;
	int rc;

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg3(regs), sizeof(newv)))
		return -EFAULT;

	oldvp = __xn_reg_arg4(regs) == 0 ? NULL : &oldv;

	__xn_copy_from_user(curr, &newv, (char *)__xn_reg_arg3(regs),
			    sizeof(newv));

	rc = timer_settime((timer_t) __xn_reg_arg1(regs),
			   (int)__xn_reg_arg2(regs), &newv, oldvp);

	if (!rc && oldvp) {
		if (!__xn_access_ok
		    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(oldv))) {
			timer_settime((timer_t) __xn_reg_arg1(regs),
				      (int)__xn_reg_arg2(regs), oldvp, NULL);

			return -EFAULT;
		}

		__xn_copy_to_user(curr,
				  (char *)__xn_reg_arg4(regs),
				  oldvp, sizeof(oldv));
	}

	return rc == 0 ? 0 : -thread_get_errno();
}

static int __timer_gettime(struct task_struct *curr, struct pt_regs *regs)
{
	struct itimerspec val;
	int rc;

	rc = timer_gettime((timer_t) __xn_reg_arg1(regs), &val);

	if (!rc) {
		if (!__xn_access_ok
		    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(val)))
			return -EFAULT;

		__xn_copy_to_user(curr, (char *)__xn_reg_arg2(regs), &val,
				  sizeof(val));
	}

	return rc == 0 ? 0 : -thread_get_errno();
}

static int __timer_getoverrun(struct task_struct *curr, struct pt_regs *regs)
{
	int rc;

	rc = timer_getoverrun((timer_t) __xn_reg_arg1(regs));

	return rc >= 0 ? rc : -thread_get_errno();
}

#ifdef CONFIG_XENO_OPT_POSIX_SELECT
static int fd_valid_p(int fd)
{
	pse51_assoc_t *assoc;
#if defined(CONFIG_XENO_SKIN_RTDM) || defined (CONFIG_XENO_SKIN_RTDM_MODULE)
	const int rtdm_fd_start = FD_SETSIZE - RTDM_FD_MAX;
	
	if (fd >= rtdm_fd_start) {
		struct rtdm_dev_context *ctx;
		ctx = rtdm_context_get(fd - rtdm_fd_start);
		if (ctx) {
			rtdm_context_unlock(ctx);
			return 1;
		}
		return 0;
	}
#endif /* RTDM */

	assoc = pse51_assoc_lookup(&pse51_queues()->uqds, fd);
	return assoc != NULL;
}

static int first_fd_valid_p(fd_set *fds[XNSELECT_MAX_TYPES], int nfds)
{
	int i, fd;

	for (i = 0; i < XNSELECT_MAX_TYPES; i++)
		if (fds[i]
		    && (fd = find_first_bit(fds[i]->fds_bits, nfds)) < nfds)
			return fd_valid_p(fd);

	/* All empty is correct, used as a "sleep" mechanism by strange
	   applications. */
	return 1;
}

static int select_bind_one(struct xnselector *selector, unsigned type, int fd)
{
	pse51_assoc_t *assoc;
#if defined(CONFIG_XENO_SKIN_RTDM) || defined (CONFIG_XENO_SKIN_RTDM_MODULE)
	const int rtdm_fd_start = FD_SETSIZE - RTDM_FD_MAX;

	if (fd >= rtdm_fd_start)
		return rtdm_select_bind(fd - rtdm_fd_start,
					selector, type, fd);
#endif /* CONFIG_XENO_SKIN_RTDM */

	assoc = pse51_assoc_lookup(&pse51_queues()->uqds, fd);
	if (!assoc)
		return -EBADF;

	return pse51_mq_select_bind(assoc2ufd(assoc)->kfd, selector, type, fd);
}

static int select_bind_all(struct xnselector *selector,
			   fd_set *fds[XNSELECT_MAX_TYPES], int nfds)
{
	unsigned fd, type;
	int err;

	for (type = 0; type < XNSELECT_MAX_TYPES; type++) {
		fd_set *set = fds[type];
		if (set)
			for (fd = find_first_bit(set->fds_bits, nfds);
			     fd < nfds;
			     fd = find_next_bit(set->fds_bits, nfds, fd + 1)) {
				err = select_bind_one(selector, type, fd);
				if (err)
					return err;
			}
	}

	return 0;
}

/* int select(int, fd_set *, fd_set *, fd_set *, struct timeval *) */
static int __select(struct task_struct *curr, struct pt_regs *regs)
{
	fd_set __user *ufd_sets[XNSELECT_MAX_TYPES] = {
		[XNSELECT_READ] = (fd_set __user *) __xn_reg_arg2(regs),
		[XNSELECT_WRITE] = (fd_set __user *) __xn_reg_arg3(regs),
		[XNSELECT_EXCEPT] = (fd_set __user *) __xn_reg_arg4(regs)
	};
	fd_set *in_fds[XNSELECT_MAX_TYPES] = {NULL, NULL, NULL};
	fd_set *out_fds[XNSELECT_MAX_TYPES] = {NULL, NULL, NULL};
	fd_set in_fds_storage[XNSELECT_MAX_TYPES],
		out_fds_storage[XNSELECT_MAX_TYPES];
	xnticks_t timeout = XN_INFINITE;
	xntmode_t mode = XN_RELATIVE;
	struct xnselector *selector;
	struct timeval tv;
	pthread_t thread;
	int i, err, nfds;

	thread = pse51_current_thread();
	if (!thread)
		return -EPERM;

	if (__xn_reg_arg5(regs)) {
		if (__xn_access_ok(curr, VERIFY_WRITE,
				   __xn_reg_arg5(regs), sizeof(tv)))
			return -EFAULT;

		if (__xn_copy_from_user(curr, &tv,
					(void __user *)__xn_reg_arg5(regs),
					sizeof(tv)))
			return -EFAULT;

		if (tv.tv_usec > 1000000)
			return -EINVAL;

		timeout = clock_get_ticks(CLOCK_MONOTONIC) + tv2ticks_ceil(&tv);
		mode = XN_ABSOLUTE;
	}

	nfds = __xn_reg_arg1(regs);

	for (i = 0; i < XNSELECT_MAX_TYPES; i++)
		if (ufd_sets[i]) {
			in_fds[i] = &in_fds_storage[i];
			out_fds[i] = & out_fds_storage[i];
			if (__xn_access_ok(curr, VERIFY_WRITE,
					   ufd_sets[i], sizeof(fd_set)))
				return -EFAULT;

			if (__xn_copy_from_user(curr, in_fds[i],
						(void __user *) ufd_sets[i],
						__FDELT(nfds + __NFDBITS - 1)
						* sizeof(long)))
				return -EFAULT;
		}

	selector = thread->selector;
	if (!selector) {
		/* This function may be called from pure Linux fd_sets, we want
		   to avoid the xnselector allocation in this case, so, we do a
		   simple test: test if the first file descriptor we find in the
		   fd_set is an RTDM descriptor or a message queue descriptor. */
		if (!first_fd_valid_p(in_fds, nfds))
			return -EBADF;

		if (!(selector = xnmalloc(sizeof(*thread->selector))))
			return -ENOMEM;
		xnselector_init(selector);
		thread->selector = selector;

		/* Bind directly the file descriptors, we do not need to go
		   through xnselect returning -ECHRNG */
		if ((err = select_bind_all(selector, in_fds, nfds)))
			return err;
	}

	do {
		err = xnselect(selector, out_fds, in_fds, nfds, timeout, mode);

		if (err == -ECHRNG) {
			int err = select_bind_all(selector, out_fds, nfds);
			if (err)
				return err;
		}
	} while (err == -ECHRNG);

	if (__xn_reg_arg5(regs) && (err > 0 || err == -EINTR)) {
		xnsticks_t diff = timeout - clock_get_ticks(CLOCK_MONOTONIC);
		if (diff > 0)
			ticks2tv(&tv, diff);
		else
			tv.tv_sec = tv.tv_usec = 0;

		if (__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs),
				      &tv, sizeof(tv)))
			return -EFAULT;
	}

	if (err > 0)
		for (i = 0; i < XNSELECT_MAX_TYPES; i++)
			if (ufd_sets[i]
			    && __xn_copy_to_user(curr,
						 (void __user *) ufd_sets[i],
						 out_fds[i], sizeof(fd_set)))
				return -EFAULT;
	return err;
}
#else /* !CONFIG_XENO_OPT_POSIX_SELECT */
#define __select __pse51_call_not_available
#endif /* !CONFIG_XENO_OPT_POSIX_SELECT */

#ifdef CONFIG_XENO_OPT_POSIX_SHM

/* shm_open(name, oflag, mode, ufd) */
static int __shm_open(struct task_struct *curr, struct pt_regs *regs)
{
	char name[PSE51_MAXNAME];
	int ufd, kfd, oflag, err;
	pse51_ufd_t *assoc;
	unsigned len;
	mode_t mode;

	len = __xn_strncpy_from_user(curr,
				     name,
				     (const char __user *)__xn_reg_arg1(regs),
				     sizeof(name));
	if (len <= 0)
		return -EFAULT;

	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	oflag = (int)__xn_reg_arg2(regs);
	mode = (mode_t) __xn_reg_arg3(regs);

	kfd = shm_open(name, oflag, mode);

	if (kfd == -1)
		return -thread_get_errno();

	assoc = (pse51_ufd_t *) xnmalloc(sizeof(*assoc));

	if (!assoc) {
		pse51_shm_close(kfd);
		return -ENOSPC;
	}

	assoc->kfd = kfd;

	ufd = (int)__xn_reg_arg4(regs);

	err =
	    pse51_assoc_insert(&pse51_queues()->ufds, &assoc->assoc,(u_long)ufd);

	if (err) {
		xnfree(assoc);
		close(kfd);
	}

	return err;
}

/* shm_unlink(name) */
static int __shm_unlink(struct task_struct *curr, struct pt_regs *regs)
{
	char name[PSE51_MAXNAME];
	unsigned len;
	int err;

	len = __xn_strncpy_from_user(curr,
				     name,
				     (const char __user *)__xn_reg_arg1(regs),
				     sizeof(name));
	if (len <= 0)
		return -EFAULT;

	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	err = shm_unlink(name);

	return !err ? 0 : -thread_get_errno();
}

/* shm_close(ufd) */
static int __shm_close(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	pse51_ufd_t *ufd;
	int err;

	assoc =
	    pse51_assoc_remove(&pse51_queues()->ufds,
			       (u_long)__xn_reg_arg1(regs));

	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	err = close(ufd->kfd);
	xnfree(ufd);

	return !err ? 0 : -thread_get_errno();
}

/* ftruncate(ufd, len) */
static int __ftruncate(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	pse51_ufd_t *ufd;
	off_t len;
	int err;

	len = (off_t) __xn_reg_arg2(regs);

	assoc =
	    pse51_assoc_lookup(&pse51_queues()->ufds,
			       (u_long)__xn_reg_arg1(regs));

	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	err = ftruncate(ufd->kfd, len);

	return !err ? 0 : -thread_get_errno();
}

typedef struct {
	void *kaddr;
	unsigned long len;
	xnheap_t *ioctl_cookie;
	unsigned long heapsize;
	unsigned long offset;
} pse51_mmap_param_t;

/* mmap_prologue(len, ufd, off, pse51_mmap_param_t *mmap_param) */
static int __mmap_prologue(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_mmap_param_t mmap_param;
	pse51_assoc_t *assoc;
	pse51_ufd_t *ufd;
	size_t len;
	off_t off;
	int err;

	len = (size_t) __xn_reg_arg1(regs);
	off = (off_t) __xn_reg_arg3(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg4(regs), sizeof(mmap_param)))
		return -EFAULT;

	assoc =
	    pse51_assoc_lookup(&pse51_queues()->ufds,
			       (u_long)__xn_reg_arg2(regs));

	if (!assoc)
		return -EBADF;

	ufd = assoc2ufd(assoc);

	/* We do not care for the real flags and protection, this mapping is a
	   placeholder. */
	mmap_param.kaddr = mmap(NULL,
				len,
				PROT_READ | PROT_WRITE,
				MAP_SHARED, ufd->kfd, off);

	if (mmap_param.kaddr == MAP_FAILED)
		return -thread_get_errno();

	if ((err =
	     pse51_xnheap_get(&mmap_param.ioctl_cookie, mmap_param.kaddr))) {
		munmap(mmap_param.kaddr, len);
		return err;
	}

	mmap_param.len = len;
	mmap_param.heapsize = xnheap_extentsize(mmap_param.ioctl_cookie);
	mmap_param.offset = xnheap_mapped_offset(mmap_param.ioctl_cookie,
						 mmap_param.kaddr);

	__xn_copy_to_user(curr,
			  (void __user *)__xn_reg_arg4(regs),
			  &mmap_param, sizeof(mmap_param));

	return 0;
}

/* mmap_epilogue(uaddr, pse51_mmap_param_t *mmap_param) */
static int __mmap_epilogue(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_mmap_param_t mmap_param;
	pse51_umap_t *umap;
	void *uaddr;
	int err;

	uaddr = (void *)__xn_reg_arg1(regs);

	if (!__xn_access_ok
	    (curr, VERIFY_READ, __xn_reg_arg2(regs), sizeof(mmap_param)))
		return -EFAULT;

	__xn_copy_from_user(curr,
			    &mmap_param,
			    (void __user *)__xn_reg_arg2(regs),
			    sizeof(mmap_param));

	if (uaddr == MAP_FAILED) {
		munmap(mmap_param.kaddr, mmap_param.len);
		return 0;
	}

	umap = (pse51_umap_t *) xnmalloc(sizeof(*umap));

	if (!umap) {
		munmap(mmap_param.kaddr, mmap_param.len);
		return -EAGAIN;
	}

	umap->kaddr = mmap_param.kaddr;
	umap->len = mmap_param.len;

	err =
	    pse51_assoc_insert(&pse51_queues()->umaps, &umap->assoc,
			       (u_long)uaddr);

	if (err)
		munmap(mmap_param.kaddr, mmap_param.len);

	return err;
}

/* munmap_prologue(uaddr, len, &unmap) */
static int __munmap_prologue(struct task_struct *curr, struct pt_regs *regs)
{
	struct {
		unsigned long mapsize;
		unsigned long offset;
	} uunmap;
	pse51_assoc_t *assoc;
	unsigned long uaddr;
	pse51_umap_t *umap;
	xnheap_t *heap;
	size_t len;
	int err;

	uaddr = (unsigned long)__xn_reg_arg1(regs);
	len = (size_t) __xn_reg_arg2(regs);
	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg3(regs), sizeof(uunmap)))
		return -EFAULT;

	assoc = pse51_assoc_lookup(&pse51_queues()->umaps, uaddr);

	if (!assoc)
		return -EBADF;

	umap = assoc2umap(assoc);

	err = pse51_xnheap_get(&heap, umap->kaddr);

	if (err)
		return err;

	uunmap.mapsize = xnheap_extentsize(heap);
	uunmap.offset = xnheap_mapped_offset(heap, umap->kaddr);
	__xn_copy_to_user(curr,
			  (void __user *)__xn_reg_arg3(regs),
			  &uunmap, sizeof(uunmap));

	return 0;
}

/* munmap_epilogue(uaddr, len) */
static int __munmap_epilogue(struct task_struct *curr, struct pt_regs *regs)
{
	pse51_assoc_t *assoc;
	unsigned long uaddr;
	pse51_umap_t *umap;
	size_t len;
	spl_t s;
	int err;

	uaddr = (unsigned long)__xn_reg_arg1(regs);
	len = (size_t) __xn_reg_arg2(regs);

	xnlock_get_irqsave(&pse51_assoc_lock, s);
	assoc = pse51_assoc_lookup(&pse51_queues()->umaps, uaddr);

	if (!assoc) {
		xnlock_put_irqrestore(&pse51_assoc_lock, s);
		return -EBADF;
	}

	umap = assoc2umap(assoc);

	if (umap->len != len) {
		xnlock_put_irqrestore(&pse51_assoc_lock, s);
		return -EINVAL;
	}

	pse51_assoc_remove(&pse51_queues()->umaps,  uaddr);
	xnlock_put_irqrestore(&pse51_assoc_lock, s);

	err = munmap(umap->kaddr, len);

	return !err ? 0 : -thread_get_errno();
}
#else /* !CONFIG_XENO_OPT_POSIX_SHM */

#define __shm_open        __pse51_call_not_available
#define __shm_unlink      __pse51_call_not_available
#define __shm_close       __pse51_call_not_available
#define __ftruncate       __pse51_call_not_available
#define __mmap_prologue   __pse51_call_not_available
#define __mmap_epilogue   __pse51_call_not_available
#define __munmap_prologue __pse51_call_not_available
#define __munmap_epilogue __pse51_call_not_available

#endif /* !CONFIG_XENO_OPT_POSIX_SHM */

int __pse51_call_not_available(struct task_struct *curr, struct pt_regs *regs)
{
	return -ENOSYS;
}

static xnsysent_t __systab[] = {
	[__pse51_thread_create] = {&__pthread_create, __xn_exec_init},
	[__pse51_thread_detach] = {&__pthread_detach, __xn_exec_any},
	[__pse51_thread_setschedparam] =
	    {&__pthread_setschedparam, __xn_exec_conforming},
	[__pse51_thread_getschedparam] =
	{&__pthread_getschedparam, __xn_exec_any},
	[__pse51_sched_yield] = {&__sched_yield, __xn_exec_primary},
	[__pse51_thread_make_periodic] =
	    {&__pthread_make_periodic_np, __xn_exec_conforming},
	[__pse51_thread_wait] = {&__pthread_wait_np, __xn_exec_primary},
	[__pse51_thread_set_mode] = {&__pthread_set_mode_np, __xn_exec_primary},
	[__pse51_thread_set_name] = {&__pthread_set_name_np, __xn_exec_any},
	[__pse51_thread_kill] = {&__pthread_kill, __xn_exec_any},
	[__pse51_sem_init] = {&__sem_init, __xn_exec_any},
	[__pse51_sem_destroy] = {&__sem_destroy, __xn_exec_any},
	[__pse51_sem_post] = {&__sem_post, __xn_exec_any},
	[__pse51_sem_wait] = {&__sem_wait, __xn_exec_primary},
	[__pse51_sem_timedwait] = {&__sem_timedwait, __xn_exec_primary},
	[__pse51_sem_trywait] = {&__sem_trywait, __xn_exec_primary},
	[__pse51_sem_getvalue] = {&__sem_getvalue, __xn_exec_any},
	[__pse51_sem_open] = {&__sem_open, __xn_exec_any},
	[__pse51_sem_close] = {&__sem_close, __xn_exec_any},
	[__pse51_sem_unlink] = {&__sem_unlink, __xn_exec_any},
	[__pse51_clock_getres] = {&__clock_getres, __xn_exec_any},
	[__pse51_clock_gettime] = {&__clock_gettime, __xn_exec_any},
	[__pse51_clock_settime] = {&__clock_settime, __xn_exec_any},
	[__pse51_clock_nanosleep] = {&__clock_nanosleep, __xn_exec_primary},
	[__pse51_mutex_init] = {&__pthread_mutex_init, __xn_exec_any},
	[__pse51_mutex_destroy] = {&__pthread_mutex_destroy, __xn_exec_any},
	[__pse51_mutex_lock] = {&__pthread_mutex_lock, __xn_exec_primary},
	[__pse51_mutex_timedlock] =
	    {&__pthread_mutex_timedlock, __xn_exec_primary},
	[__pse51_mutex_trylock] = {&__pthread_mutex_trylock, __xn_exec_primary},
	[__pse51_mutex_unlock] = {&__pthread_mutex_unlock, __xn_exec_primary},
	[__pse51_cond_init] = {&__pthread_cond_init, __xn_exec_any},
	[__pse51_cond_destroy] = {&__pthread_cond_destroy, __xn_exec_any},
	[__pse51_cond_wait_prologue] =
	{&__pthread_cond_wait_prologue, __xn_exec_primary},
	[__pse51_cond_wait_epilogue] =
	    {&__pthread_cond_wait_epilogue, __xn_exec_primary},
	[__pse51_cond_signal] = {&__pthread_cond_signal, __xn_exec_any},
	[__pse51_cond_broadcast] = {&__pthread_cond_broadcast, __xn_exec_any},
	[__pse51_mq_open] = {&__mq_open, __xn_exec_lostage},
	[__pse51_mq_close] = {&__mq_close, __xn_exec_lostage},
	[__pse51_mq_unlink] = {&__mq_unlink, __xn_exec_lostage},
	[__pse51_mq_getattr] = {&__mq_getattr, __xn_exec_any},
	[__pse51_mq_setattr] = {&__mq_setattr, __xn_exec_any},
	[__pse51_mq_send] = {&__mq_send, __xn_exec_primary},
	[__pse51_mq_timedsend] = {&__mq_timedsend, __xn_exec_primary},
	[__pse51_mq_receive] = {&__mq_receive, __xn_exec_primary},
	[__pse51_mq_timedreceive] = {&__mq_timedreceive, __xn_exec_primary},
	[__pse51_mq_notify] = {&__mq_notify, __xn_exec_primary},
	[__pse51_intr_attach] = {&__intr_attach, __xn_exec_any},
	[__pse51_intr_detach] = {&__intr_detach, __xn_exec_any},
	[__pse51_intr_wait] = {&__intr_wait, __xn_exec_primary},
	[__pse51_intr_control] = {&__intr_control, __xn_exec_any},
	[__pse51_timer_create] = {&__timer_create, __xn_exec_any},
	[__pse51_timer_delete] = {&__timer_delete, __xn_exec_any},
	[__pse51_timer_settime] = {&__timer_settime, __xn_exec_primary},
	[__pse51_timer_gettime] = {&__timer_gettime, __xn_exec_any},
	[__pse51_timer_getoverrun] = {&__timer_getoverrun, __xn_exec_any},
	[__pse51_shm_open] = {&__shm_open, __xn_exec_lostage},
	[__pse51_shm_unlink] = {&__shm_unlink, __xn_exec_lostage},
	[__pse51_shm_close] = {&__shm_close, __xn_exec_lostage},
	[__pse51_ftruncate] = {&__ftruncate, __xn_exec_lostage},
	[__pse51_mmap_prologue] = {&__mmap_prologue, __xn_exec_lostage},
	[__pse51_mmap_epilogue] = {&__mmap_epilogue, __xn_exec_lostage},
	[__pse51_munmap_prologue] = {&__munmap_prologue, __xn_exec_lostage},
	[__pse51_munmap_epilogue] = {&__munmap_epilogue, __xn_exec_lostage},
	[__pse51_mutexattr_init] = {&__pthread_mutexattr_init, __xn_exec_any},
	[__pse51_mutexattr_destroy] =
	    {&__pthread_mutexattr_destroy, __xn_exec_any},
	[__pse51_mutexattr_gettype] =
	    {&__pthread_mutexattr_gettype, __xn_exec_any},
	[__pse51_mutexattr_settype] =
	    {&__pthread_mutexattr_settype, __xn_exec_any},
	[__pse51_mutexattr_getprotocol] =
	    {&__pthread_mutexattr_getprotocol, __xn_exec_any},
	[__pse51_mutexattr_setprotocol] =
	    {&__pthread_mutexattr_setprotocol, __xn_exec_any},
	[__pse51_mutexattr_getpshared] =
	    {&__pthread_mutexattr_getpshared, __xn_exec_any},
	[__pse51_mutexattr_setpshared] =
	    {&__pthread_mutexattr_setpshared, __xn_exec_any},
	[__pse51_condattr_init] = {&__pthread_condattr_init, __xn_exec_any},
	[__pse51_condattr_destroy] = {&__pthread_condattr_destroy,__xn_exec_any},
	[__pse51_condattr_getclock] =
	    {&__pthread_condattr_getclock, __xn_exec_any},
	[__pse51_condattr_setclock] =
	    {&__pthread_condattr_setclock, __xn_exec_any},
	[__pse51_condattr_getpshared] =
	    {&__pthread_condattr_getpshared, __xn_exec_any},
	[__pse51_condattr_setpshared] =
	    {&__pthread_condattr_setpshared, __xn_exec_any},
	[__pse51_select] = {&__select, __xn_exec_primary},
};

static void __shadow_delete_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == PSE51_SKIN_MAGIC &&
	    xnthread_test_state(thread, XNSHADOW)) {
		pthread_t k_tid = thread2pthread(thread);
		__pthread_unhash(&k_tid->hkey);
		if (xnthread_test_state(thread, XNMAPPED))
			xnshadow_unmap(thread);
	}
}

static void *pse51_eventcb(int event, void *data)
{
	pse51_queues_t *q;
	
	switch(event) {
	case XNSHADOW_CLIENT_ATTACH:

		q = (pse51_queues_t *) xnarch_alloc_host_mem(sizeof(*q));
		if (!q)
			return ERR_PTR(-ENOSPC);

		initq(&q->kqueues.condq);
#ifdef CONFIG_XENO_OPT_POSIX_INTR
		initq(&q->kqueues.intrq);
#endif /* CONFIG_XENO_OPT_POSIX_INTR */
		initq(&q->kqueues.mutexq);
		initq(&q->kqueues.semq);
		initq(&q->kqueues.threadq);
		initq(&q->kqueues.timerq);
		pse51_assocq_init(&q->uqds);
		pse51_assocq_init(&q->usems);
#ifdef CONFIG_XENO_OPT_POSIX_SHM
		pse51_assocq_init(&q->umaps);
		pse51_assocq_init(&q->ufds);
#endif /* CONFIG_XENO_OPT_POSIX_SHM */
		
		return &q->ppd;
		
	case XNSHADOW_CLIENT_DETACH:
		q = ppd2queues((xnshadow_ppd_t *) data);

#ifdef CONFIG_XENO_OPT_POSIX_SHM
		pse51_shm_ufds_cleanup(q);
		pse51_shm_umaps_cleanup(q);
#endif /* CONFIG_XENO_OPT_POSIX_SHM */
		pse51_sem_usems_cleanup(q);
		pse51_mq_uqds_cleanup(q);
		pse51_timerq_cleanup(&q->kqueues);
		pse51_threadq_cleanup(&q->kqueues);
		pse51_semq_cleanup(&q->kqueues);
		pse51_mutexq_cleanup(&q->kqueues);
#ifdef CONFIG_XENO_OPT_POSIX_INTR
		pse51_intrq_cleanup(&q->kqueues);
#endif /* CONFIG_XENO_OPT_POSIX_INTR */
		pse51_condq_cleanup(&q->kqueues);
		
		xnarch_free_host_mem(q, sizeof(*q));

		return NULL;
	}

	return ERR_PTR(-EINVAL);
}

extern xntbase_t *pse51_tbase;

static struct xnskin_props __props = {
	.name = "posix",
	.magic = PSE51_SKIN_MAGIC,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = &pse51_eventcb,
	.timebasep = &pse51_tbase,
	.module = THIS_MODULE
};

int pse51_syscall_init(void)
{
	pse51_muxid = xnshadow_register_interface(&__props);

	if (pse51_muxid < 0)
		return -ENOSYS;
	
	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	
	return 0;
}

void pse51_syscall_cleanup(void)
{
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	xnshadow_unregister_interface(pse51_muxid);
}
