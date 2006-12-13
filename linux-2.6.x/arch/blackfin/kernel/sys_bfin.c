/*
 * File:         arch/blackfin/kernel/sys_bfin.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:  This file contains various random system calls that
 *               have a non-standard calling sequence on the Linux/bfin
 *               platform.
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/syscalls.h>
#include <linux/mman.h>
#include <linux/file.h>

#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <asm/ipc.h>
#include <asm/dma.h>

/*
 * sys_pipe() is the normal C calling standard for creating
 * a pipe. It's not the way unix traditionally does this, though.
 */
asmlinkage int sys_pipe(unsigned long *fildes)
{
	int fd[2];
	int error;

	error = do_pipe(fd);
	if (!error) {
		if (copy_to_user(fildes, fd, 2 * sizeof(int)))
			error = -EFAULT;
	}
	return error;
}

/* common code for old and new mmaps */
static inline long
do_mmap2(unsigned long addr, unsigned long len,
	 unsigned long prot, unsigned long flags,
	 unsigned long fd, unsigned long pgoff)
{
	int error = -EBADF;
	struct file *file = NULL;

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
	if (!(flags & MAP_ANONYMOUS)) {
		file = fget(fd);
		if (!file)
			goto out;
	}

	down_write(&current->mm->mmap_sem);
	error = do_mmap_pgoff(file, addr, len, prot, flags, pgoff);
	up_write(&current->mm->mmap_sem);

	if (file)
		fput(file);
      out:
	return error;
}

asmlinkage long sys_mmap2(unsigned long addr, unsigned long len,
			  unsigned long prot, unsigned long flags,
			  unsigned long fd, unsigned long pgoff)
{
	return do_mmap2(addr, len, prot, flags, fd, pgoff);
}

asmlinkage int sys_mmap(unsigned long addr, unsigned long len,
			unsigned long prot, unsigned long flags,
			unsigned long fd, unsigned long pgoff)
{
	int error = -EINVAL;

	if (pgoff & ~PAGE_MASK)
		goto out;

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);

	error = do_mmap2(addr, len, prot, flags, fd, pgoff >> PAGE_SHIFT);
out:
	return error;
}

/*
 * sys_ipc() is the de-multiplexer for the SysV IPC calls..
 *
 * This is really horribly ugly.
 */
asmlinkage int
sys_ipc(uint call, int first, int second, int third, void *ptr, long fifth)
{
	int version, ret;

	version = call >> 16;	/* hack for backward compatibility */
	call &= 0xffff;

	if (call <= SEMCTL)
		switch (call) {
		case SEMOP:
			return sys_semop(first, (struct sembuf *)ptr, second);
		case SEMGET:
			return sys_semget(first, second, third);
		case SEMCTL:
			{
				union semun fourth;
				if (!ptr)
					return -EINVAL;
				if (get_user(fourth.__pad, (void **)ptr))
					return -EFAULT;
				return sys_semctl(first, second, third, fourth);
			}
		default:
			return -ENOSYS;
		}
	if (call <= MSGCTL)
		switch (call) {
		case MSGSND:
			return sys_msgsnd(first, (struct msgbuf *)ptr, second,
					  third);
		case MSGRCV:
			switch (version) {
			case 0:
				{
					struct ipc_kludge tmp;
					if (!ptr)
						return -EINVAL;
					if (copy_from_user(&tmp,
							   (struct ipc_kludge *)
							   ptr, sizeof(tmp)))
						return -EFAULT;
					return sys_msgrcv(first, tmp.msgp,
							  second, tmp.msgtyp,
							  third);
				}
			default:
				return sys_msgrcv(first,
						  (struct msgbuf *)ptr, second,
						  fifth, third);
			}
		case MSGGET:
			return sys_msgget((key_t) first, second);
		case MSGCTL:
			return sys_msgctl(first, second,
					  (struct msqid_ds *)ptr);
		default:
			return -ENOSYS;
		}
	if (call <= SHMCTL)
		switch (call) {
		case SHMAT:
			switch (version) {
			default:{
					ulong raddr;
					ret =
					    do_shmat(first, ptr, second,
						     &raddr);
					if (ret)
						return ret;
					return put_user(raddr,
							(ulong __user *) third);
				}
			}
		case SHMDT:
			return sys_shmdt(ptr);
		case SHMGET:
			return sys_shmget(first, second, third);
		case SHMCTL:
			return sys_shmctl(first, second, ptr);
		default:
			return -ENOSYS;
		}

	return -EINVAL;
}

asmlinkage int sys_getpagesize(void)
{
	return PAGE_SIZE;
}

asmlinkage void *sys_sram_alloc(size_t size, unsigned long flags)
{
	return sram_alloc_with_lsl(size, flags);
}

asmlinkage int sys_sram_free(const void *addr)
{
	return sram_free_with_lsl(addr);
}

asmlinkage void *sys_dma_memcpy(void *dest, const void *src, size_t len)
{
	return safe_dma_memcpy(dest, src, len);
}
