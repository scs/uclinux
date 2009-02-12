/**
 *
 * @note Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org> 
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

#include <nucleus/pod.h>
#include <nucleus/heap.h>
#include <nucleus/shadow.h>
#include <rtai/syscall.h>
#include <rtai/task.h>
#include <rtai/timer.h>
#include <rtai/sem.h>
#include <rtai/shm.h>
#include <rtai/intr.h>
#include <rtai/fifo.h>

/* This file implements the Xenomai syscall wrappers;
 *
 * o Unchecked uaccesses are used to fetch args since the syslib is
 * trusted. We currently assume that the caller's memory is locked and
 * committed.
 *
 * o All skin services (re-)check the object descriptor they are
 * passed; so there is no race between a call to rt_registry_fetch()
 * where the user-space handle is converted to a descriptor pointer,
 * and the use of it in the actual syscall.
 */

static int __rtai_muxid;

static void __shadow_delete_hook(xnthread_t *thread)
{
	if (xnthread_get_magic(thread) == RTAI_SKIN_MAGIC &&
	    xnthread_test_state(thread, XNMAPPED))
		xnshadow_unmap(thread);
}

#ifdef CONFIG_XENO_OPT_RTAI_SHM

/*
 * int __rtai_shm_heap_open(unsigned long name,
 *                      int *size,
 *                      int suprt,
 *                      int in_kheap,
 *                      unsigned long *off)
 *
 * returns "opaque" on success
 */

static int __rt_shm_heap_open(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned long name;
	int size;
	int suprt, in_kheap;

	unsigned long off;
	unsigned long opaque;
	void *ret;
	extern void *_shm_alloc(unsigned long name, int size, int suprt,
				int in_kheap, unsigned long *opaque);

	if (!__xn_access_ok
	    (curr, VERIFY_WRITE, __xn_reg_arg2(regs), sizeof(size))
	    || !__xn_access_ok(curr, VERIFY_WRITE, __xn_reg_arg5(regs),
			       sizeof(off)))
		return 0;

	name = (unsigned long)__xn_reg_arg1(regs);
	/* Size of heap space. */
	__xn_copy_from_user(curr, &size, (void __user *)__xn_reg_arg2(regs),
			    sizeof(size));
	/* Creation mode. */
	suprt = (int)__xn_reg_arg3(regs);
	in_kheap = (int)__xn_reg_arg4(regs);

	ret = _shm_alloc(name, size, suprt, in_kheap, &opaque);

	if (!ret)
		goto free_and_fail;

	off = xnheap_mapped_offset((xnheap_t *)opaque, ret);

	size = (int)((xnheap_t *)opaque)->extentsize;
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg2(regs), &size,
			  sizeof(size));
	__xn_copy_to_user(curr, (void __user *)__xn_reg_arg5(regs), &off,
			  sizeof(off));

	return (int)opaque;

      free_and_fail:

	return 0;
}

/*
 * int __rt_shm_heap_close(unsigned long name)
 */
static int __rt_shm_heap_close(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned long name;
	int err = 0;
	spl_t s;

	// => Not an address, no need to check
	name = (unsigned long)__xn_reg_arg1(regs);

	xnlock_get_irqsave(&nklock, s);

	err = rt_shm_free(name);

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

#else /* CONFIG_XENO_OPT_RTAI_SHM */

#define __rt_shm_heap_open    __rtai_call_not_available
#define __rt_shm_heap_close	__rtai_call_not_available

#endif /* CONFIG_XENO_OPT_RTAI_SHM */

static __attribute__ ((unused))
int __rtai_call_not_available(struct task_struct *curr, struct pt_regs *regs)
{
	return -ENOSYS;
}

static xnsysent_t __systab[] = {
	[__rtai_shm_heap_open] = {&__rt_shm_heap_open, __xn_exec_lostage},
	[__rtai_shm_heap_close] = {&__rt_shm_heap_close, __xn_exec_any},
};

extern xntbase_t *rtai_tbase;

static struct xnskin_props __props = {
	.name = "rtai",
	.magic = RTAI_SKIN_MAGIC,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = NULL,
	.timebasep = &rtai_tbase,
	.module = THIS_MODULE
};

int __rtai_syscall_init(void)
{
	__rtai_muxid = xnshadow_register_interface(&__props);

	if (__rtai_muxid < 0)
		return -ENOSYS;

	xnpod_add_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);

	return 0;
}

void __rtai_syscall_cleanup(void)
{
	xnpod_remove_hook(XNHOOK_THREAD_DELETE, &__shadow_delete_hook);
	xnshadow_unregister_interface(__rtai_muxid);
}
