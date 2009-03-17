/*
 * Copyright (C) 2005 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

/**
 * @ingroup posix
 * @defgroup posix_shm Shared memory services.
 *
 * Shared memory services.
 *
 * Shared memory objects are memory regions that can be mapped into processes
 * address space, allowing them to share these regions as well as to share them
 * with kernel-space modules.
 *
 * Shared memory are also the only mean by which anonymous POSIX skin
 * synchronization objects (mutexes, condition variables or semaphores) may be
 * shared between kernel-space modules and user-space processes, or between
 * several processes.
 *
 *@{*/

#include <nucleus/heap.h>
#include <posix/registry.h>
#include <posix/internal.h>
#include <posix/thread.h>
#include <posix/shm.h>

typedef struct pse51_shm {
	pse51_node_t nodebase;

#define node2shm(naddr) \
    ((pse51_shm_t *) (((char *)(naddr)) - offsetof(pse51_shm_t, nodebase)))

	xnholder_t link;	/* link in shmq */

#define link2shm(laddr)                                                 \
    ((pse51_shm_t *) (((char *)(laddr)) - offsetof(pse51_shm_t, link)))

	struct semaphore maplock;
	xnheap_t heapbase;
	void *addr;
	size_t size;

#define heap2shm(haddr) \
    ((pse51_shm_t *) (((char *)(haddr)) - offsetof(pse51_shm_t, heapbase)))

	xnqueue_t mappings;

} pse51_shm_t;

typedef struct pse51_shm_map {
	void *addr;
	size_t size;

	xnholder_t link;

#define link2map(laddr) \
    ((pse51_shm_map_t *) (((char *)(laddr)) - offsetof(pse51_shm_map_t, link)))

} pse51_shm_map_t;

static xnqueue_t pse51_shmq;

static void pse51_shm_init(pse51_shm_t * shm)
{
	shm->addr = NULL;
	shm->size = 0;
	sema_init(&shm->maplock, 1);
	initq(&shm->mappings);

	inith(&shm->link);
	appendq(&pse51_shmq, &shm->link);
}

#ifndef CONFIG_XENO_OPT_PERVASIVE
static void pse51_free_heap_extent(xnheap_t *heap,
				   void *extent, u_long size, void *cookie)
{
	xnarch_free_host_mem(extent, size);
}
#endif /* !CONFIG_XENO_OPT_PERVASIVE */

/* Must be called nklock locked, irq off. */
static void pse51_shm_destroy(pse51_shm_t * shm, int force)
{
	spl_t ignored;

	removeq(&pse51_shmq, &shm->link);
	xnlock_clear_irqon(&nklock);

	down(&shm->maplock);

	if (shm->addr) {
		xnheap_free(&shm->heapbase, shm->addr);

#ifdef CONFIG_XENO_OPT_PERVASIVE
		xnheap_destroy_mapped(&shm->heapbase, NULL, NULL);
#else /* !CONFIG_XENO_OPT_PERVASIVE. */
		xnheap_destroy(&shm->heapbase, &pse51_free_heap_extent, NULL);
#endif /* !CONFIG_XENO_OPT_PERVASIVE. */

		shm->addr = NULL;
		shm->size = 0;
	}

	if (force) {
		xnholder_t *holder;

		while ((holder = getq(&shm->mappings))) {
			up(&shm->maplock);
			xnfree(link2map(holder));
			down(&shm->maplock);
		}
	}

	up(&shm->maplock);
	xnlock_get_irqsave(&nklock, ignored);
}

static pse51_shm_t *pse51_shm_get(pse51_desc_t ** pdesc, int fd, unsigned inc)
{
	pse51_shm_t *shm;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	shm =
	    (pse51_shm_t *)
	    ERR_PTR(-pse51_desc_get(pdesc, fd, PSE51_SHM_MAGIC));

	if (IS_ERR(shm))
		goto out;

	shm = node2shm(pse51_desc_node(*pdesc));

	shm->nodebase.refcount += inc;

      out:
	xnlock_put_irqrestore(&nklock, s);

	return shm;
}

static void pse51_shm_put(pse51_shm_t * shm, unsigned dec)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while (dec--)
		pse51_node_put(&shm->nodebase);

	if (pse51_node_removed_p(&shm->nodebase)) {
		xnlock_put_irqrestore(&nklock, s);
		pse51_shm_destroy(shm, 0);
		xnfree(shm);
	} else
		xnlock_put_irqrestore(&nklock, s);
}

/**
 * Open a shared memory object.
 *
 * This service establishes a connection between a shared memory object and a
 * file descriptor. Further use of this descriptor will allow to dimension and
 * map the shared memory into the calling context address space.
 *
 * One of the following access mode should be set in @a oflags:
 * - O_RDONLY, meaning that the shared memory object may only be mapped with the
 *   PROT_READ flag;
 * - O_WRONLY, meaning that the shared memory object may only be mapped with the
 *   PROT_WRITE flag;
 * - O_RDWR, meaning that the shared memory object may be mapped with the
 *   PROT_READ | PROT_WRITE flag.
 *
 * If no shared memory object  named @a name exists, and @a oflags has the @a
 * O_CREAT bit set, the shared memory object is created by this function.
 *
 * If @a oflags has the two bits @a O_CREAT and @a O_EXCL set and the shared
 * memory object alread exists, this service fails.
 *
 * If @a oflags has the bit @a O_TRUNC set, the shared memory exists and is not
 * currently mapped, its size is truncated to 0.
 *
 * @a name may be any arbitrary string, in which slashes have no particular
 * meaning. However, for portability, using a name which starts with a slash and
 * contains no other slash is recommended.
 *
 * @param name name of the shared memory object to open;
 *
 * @param oflags flags.
 *
 * @param mode ignored.
 *
 * @return a file descriptor on success;
 * @return -1 with @a errno set if:
 * - ENAMETOOLONG, the length of the @a name argument exceeds 64 characters;
 * - EEXIST, the bits @a O_CREAT and @a O_EXCL were set in @a oflags and the
 *   shared memory object already exists;
 * - ENOENT, the bit @a O_CREAT is not set in @a oflags and the shared memory
 *   object does not exist;
 * - ENOSPC, insufficient memory exists in the system heap to create the shared
 *   memory object, increase CONFIG_XENO_OPT_SYS_HEAPSZ;
 * - EPERM, the caller context is invalid;
 * - EINVAL, the O_TRUNC flag was specified and the shared memory object is
 *   currently mapped;
 * - EMFILE, too many descriptors are currently open.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/shm_open.html">
 * Specification.</a>
 * 
 */
int shm_open(const char *name, int oflags, mode_t mode)
{
	pse51_node_t *node;
	pse51_desc_t *desc;
	pse51_shm_t *shm;
	int err, fd;
	spl_t s;

	/* From root context only. */
	if (xnpod_asynch_p() || !xnpod_root_p()) {
		thread_set_errno(EPERM);
		return -1;
	}

	xnlock_get_irqsave(&nklock, s);
	err = pse51_node_get(&node, name, PSE51_SHM_MAGIC, oflags);
	xnlock_put_irqrestore(&nklock, s);
	if (err)
		goto error;

	if (node) {
		shm = node2shm(node);
		goto got_shm;
	}

	/* We must create the shared memory object, not yet allocated. */
	shm = (pse51_shm_t *) xnmalloc(sizeof(*shm));
	if (!shm) {
		err = ENOSPC;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);
	err = pse51_node_add(&shm->nodebase, name, PSE51_SHM_MAGIC);
	if (err && err != EEXIST)
		goto err_unlock;

	if (err == EEXIST) {
		/* same shm was created in the mean time, rollback. */
		err = pse51_node_get(&node, name, PSE51_SHM_MAGIC, oflags);
	  err_unlock:
		xnlock_put_irqrestore(&nklock, s);
		xnfree(shm);
		if (err)
			goto error;

		shm = node2shm(node);
		goto got_shm;
	}

	pse51_shm_init(shm);
	xnlock_put_irqrestore(&nklock, s);

  got_shm:
	err = pse51_desc_create(&desc, &shm->nodebase,
				oflags & PSE51_PERMS_MASK);
	if (err)
		goto err_shm_put;

	fd = pse51_desc_fd(desc);

	if ((oflags & O_TRUNC) && ftruncate(fd, 0)) {
		close(fd);
		return -1;
	}

	return fd;

  err_shm_put:
	pse51_shm_put(shm, 1);
  error:
	thread_set_errno(err);
	return -1;
}

/**
 * Close a file descriptor.
 *
 * This service closes the file descriptor @a fd. In kernel-space, this service
 * only works for file descriptors opened with shm_open(), i.e. shared memory
 * objects. A shared memory object is only destroyed once all file descriptors
 * are closed with this service, it is unlinked with the shm_unlink() service,
 * and all mappings are unmapped with the munmap() service.
 *
 * @param fd file descriptor.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EBADF, @a fd is not a valid file descriptor (in kernel-space, it was not
 *   obtained with shm_open());
 * - EPERM, the caller context is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - kernel-space cancellation cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode);
 * - user-space cancellation cleanup routine.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/close.html">
 * Specification.</a>
 * 
 */
int close(int fd)
{
	pse51_desc_t *desc;
	pse51_shm_t *shm;
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);

	shm = pse51_shm_get(&desc, fd, 0);

	if (IS_ERR(shm)) {
		err = -PTR_ERR(shm);
		goto err_put;
	}

	if (xnpod_interrupt_p() || !xnpod_root_p()) {
		err = EPERM;
		goto err_put;
	}

	pse51_shm_put(shm, 1);
	xnlock_put_irqrestore(&nklock, s);

	err = pse51_desc_destroy(desc);
	if (err)
		goto error;

	return 0;

  err_put:
	xnlock_put_irqrestore(&nklock, s);
  error:
	thread_set_errno(err);
	return -1;
}

/**
 * Unlink a shared memory object.
 *
 * This service unlinks the shared memory object named @a name. The shared
 * memory object is not destroyed until every file descriptor obtained with the
 * shm_open() service is closed with the close() service and all mappings done
 * with mmap() are unmapped with munmap(). However, after a call to this
 * service, the unlinked shared memory object may no longer be reached 
 * with the shm_open() service.
 *
 * @param name name of the shared memory obect to be unlinked.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EPERM, the caller context is invalid;
 * - ENAMETOOLONG, the length of the @a name argument exceeds 64 characters;
 * - ENOENT, the shared memory object does not exist.
 * 
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - kernel-space cancellation cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode);
 * - user-space cancellation cleanup routine.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/shm_unlink.html">
 * Specification.</a>
 * 
 */
int shm_unlink(const char *name)
{
	pse51_node_t *node;
	pse51_shm_t *shm;
	int err;
	spl_t s;

	if (xnpod_interrupt_p() || !xnpod_root_p()) {
		err = EPERM;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);

	err = pse51_node_remove(&node, name, PSE51_SHM_MAGIC);

	if (err) {
		xnlock_put_irqrestore(&nklock, s);
	      error:
		thread_set_errno(err);
		return -1;
	}

	shm = node2shm(node);
	pse51_shm_put(shm, 0);

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Truncate a file or shared memory object to a specified length.
 *
 * When used in kernel-space, this service set to @a len the size of a shared
 * memory object opened with the shm_open() service. In user-space this service
 * falls back to Linux regular ftruncate service for file descriptors not
 * obtained with shm_open(). When this service is used to increase the size of a
 * shared memory object, the added space is zero-filled.
 *
 * Shared memory are suitable for direct memory access (allocated in physically
 * contiguous memory) if their size is less than or equal to 128 K.
 *
 * Shared memory objects may only be resized if they are not currently mapped.
 *
 * @param fd file descriptor;
 *
 * @param len new length of the underlying file or shared memory object.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EBADF, @a fd is not a valid file descriptor;
 * - EPERM, the caller context is invalid;
 * - EINVAL, the specified length is invalid;
 * - EINTR, this service was interrupted by a signal;
 * - EBUSY, @a fd is a shared memory object descriptor and the underlying shared
 *   memory is currently mapped;
 * - EFBIG, allocation of system memory failed.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/ftruncate.html">
 * Specification.</a>
 * 
 */
int ftruncate(int fd, off_t len)
{
	unsigned desc_flags;
	pse51_desc_t *desc;
	pse51_shm_t *shm;
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	shm = pse51_shm_get(&desc, fd, 1);

	if (IS_ERR(shm)) {
		err = -PTR_ERR(shm);
		xnlock_put_irqrestore(&nklock, s);
		goto error;
	}

	if (xnpod_asynch_p() || !xnpod_root_p()) {
		err = EPERM;
		xnlock_put_irqrestore(&nklock, s);
		goto err_shm_put;
	}

	if (len < 0) {
		err = EINVAL;
		xnlock_put_irqrestore(&nklock, s);
		goto err_shm_put;
	}

	desc_flags = pse51_desc_getflags(desc);
	xnlock_put_irqrestore(&nklock, s);

	if (down_interruptible(&shm->maplock)) {
		err = EINTR;
		goto err_shm_put;
	}

	/* Allocate one more page for alignment (the address returned by mmap
	   must be aligned on a page boundary). */
	if (len)
		len = xnheap_rounded_size(len + PAGE_SIZE, PAGE_SIZE);

	err = 0;
	if (emptyq_p(&shm->mappings)) {
		/* Temporary storage, in order to preserve the memory contents upon
		   resizing, if possible. */
		void *addr = NULL;
		size_t size = 0;

		if (shm->addr) {
			if (len == xnheap_extentsize(&shm->heapbase)) {
				/* Size unchanged, skip copy and reinit. */
				err = 0;
				goto err_up;
			}

			size = xnheap_max_contiguous(&shm->heapbase);
			addr = xnarch_alloc_host_mem(size);
			if (!addr) {
				err = ENOMEM;
				goto err_up;
			}

			memcpy(addr, shm->addr, size);

			xnheap_free(&shm->heapbase, shm->addr);
#ifdef CONFIG_XENO_OPT_PERVASIVE
			xnheap_destroy_mapped(&shm->heapbase, NULL, NULL);
#else /* !CONFIG_XENO_OPT_PERVASIVE. */
			xnheap_destroy(&shm->heapbase, &pse51_free_heap_extent,
				       NULL);
#endif /* !CONFIG_XENO_OPT_PERVASIVE. */

			shm->addr = NULL;
			shm->size = 0;
		}

		if (len) {
#ifdef CONFIG_XENO_OPT_PERVASIVE
			int flags = (XNARCH_SHARED_HEAP_FLAGS ?:
				     len <= 128 * 1024 ? GFP_USER : 0);
			err = -xnheap_init_mapped(&shm->heapbase, len, flags);
#else /* !CONFIG_XENO_OPT_PERVASIVE. */
			{
				void *heapaddr = xnarch_alloc_host_mem(len);

				if (heapaddr)
					err =
					    -xnheap_init(&shm->heapbase,
							 heapaddr, len,
							 XNCORE_PAGE_SIZE);
				else
					err = ENOMEM;

				if (err)
					goto err_up;
			}
#endif /* !CONFIG_XENO_OPT_PERVASIVE. */

			shm->size = xnheap_max_contiguous(&shm->heapbase);
			shm->addr = xnheap_alloc(&shm->heapbase, shm->size);
			/* Required. */
			memset(shm->addr, '\0', shm->size);

			/* Copy the previous contents. */
			if (addr)
				memcpy(shm->addr, addr,
				       shm->size < size ? shm->size : size);

			shm->size -= PAGE_SIZE;
		}

		if (addr)
			xnarch_free_host_mem(addr, size);
	} else if (len != xnheap_extentsize(&shm->heapbase))
		err = EBUSY;

      err_up:
	up(&shm->maplock);

      err_shm_put:
	pse51_shm_put(shm, 1);

	if (!err)
		return 0;

      error:
	thread_set_errno(err == ENOMEM ? EFBIG : err);
	return -1;
}

/**
 * Map pages of memory.
 *
 * This service allow shared memory regions to be accessed by the caller.
 *
 * When used in kernel-space, this service returns the address of the offset @a
 * off of the shared memory object underlying @a fd. The protection flags @a
 * prot, are only checked for consistency with @a fd open flags, but memory
 * protection is unsupported. An existing shared memory region exists before it
 * is mapped, this service only increments a reference counter.
 *
 * The only supported value for @a flags is @a MAP_SHARED.
 *
 * When used in user-space, this service maps the specified shared memory region
 * into the caller address-space. If @a fd is not a shared memory object
 * descriptor (i.e. not obtained with shm_open()), this service falls back to
 * the regular Linux mmap service.
 *
 * @param addr ignored.
 *
 * @param len size of the shared memory region to be mapped.
 *
 * @param prot protection bits, checked in kernel-space, but only useful in
 * user-space, are a bitwise or of the following values:
 * - PROT_NONE, meaning that the mapped region can not be accessed;
 * - PROT_READ, meaning that the mapped region can be read;
 * - PROT_WRITE, meaning that the mapped region can be written;
 * - PROT_EXEC, meaning that the mapped region can be executed.
 *
 * @param flags only MAP_SHARED is accepted, meaning that the mapped memory
 * region is shared.
 *
 * @param fd file descriptor, obtained with shm_open().
 *
 * @param off offset in the shared memory region.
 *
 * @retval 0 on success;
 * @retval MAP_FAILED with @a errno set if:
 * - EINVAL, @a len is null or @a addr is not a multiple of @a PAGE_SIZE;
 * - EBADF, @a fd is not a shared memory object descriptor (obtained with
 *   shm_open());
 * - EPERM, the caller context is invalid;
 * - ENOTSUP, @a flags is not @a MAP_SHARED;
 * - EACCES, @a fd is not opened for reading or is not opend for writing and
 *   PROT_WRITE is set in @a prot;
 * - EINTR, this service was interrupted by a signal;
 * - ENXIO, the range [off;off+len) is invalid for the shared memory region
 *   specified by @a fd;
 * - EAGAIN, insufficient memory exists in the system heap to create the
 *   mapping, increase CONFIG_XENO_OPT_SYS_HEAPSZ.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mmap.html">
 * Specification.</a>
 * 
 */
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	pse51_shm_map_t *map;
	unsigned desc_flags;
	pse51_desc_t *desc;
	pse51_shm_t *shm;
	void *result;
	int err;
	spl_t s;

	if (!len) {
		err = EINVAL;
		goto error;
	}

	if (((unsigned long)addr) % PAGE_SIZE) {
		err = EINVAL;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);

	shm = pse51_shm_get(&desc, fd, 1);

	if (IS_ERR(shm)) {
		xnlock_put_irqrestore(&nklock, s);
		err = -PTR_ERR(shm);
		goto error;
	}

	if (xnpod_asynch_p() || !xnpod_root_p()) {
		err = EPERM;
		xnlock_put_irqrestore(&nklock, s);
		goto err_shm_put;
	}

	if (flags != MAP_SHARED) {
		err = ENOTSUP;
		xnlock_put_irqrestore(&nklock, s);
		goto err_shm_put;
	}

	desc_flags = pse51_desc_getflags(desc);
	xnlock_put_irqrestore(&nklock, s);

	if ((desc_flags != O_RDWR && desc_flags != O_RDONLY) ||
	    ((prot & PROT_WRITE) && desc_flags == O_RDONLY)) {
		err = EACCES;
		goto err_shm_put;
	}

	map = (pse51_shm_map_t *) xnmalloc(sizeof(*map));
	if (!map) {
		err = EAGAIN;
		goto err_shm_put;
	}

	if (down_interruptible(&shm->maplock)) {
		err = EINTR;
		goto err_free_map;
	}

	if (!shm->addr || off + len > shm->size) {
		err = ENXIO;
		up(&shm->maplock);
		goto err_free_map;
	}

	/* Align the heap address on a page boundary. */
	result = (void *)PAGE_ALIGN((u_long)shm->addr);
	map->addr = result = (void *)((char *)result + off);
	map->size = len;
	inith(&map->link);
	prependq(&shm->mappings, &map->link);
	up(&shm->maplock);

	return result;

  err_free_map:
	xnfree(map);
  err_shm_put:
	pse51_shm_put(shm, 1);
  error:
	thread_set_errno(err);
	return MAP_FAILED;
}

static pse51_shm_t *pse51_shm_lookup(void *addr)
{
	xnholder_t *holder;
	pse51_shm_t *shm = NULL;
	off_t off;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	for (holder = getheadq(&pse51_shmq);
	     holder; holder = nextq(&pse51_shmq, holder)) {
		shm = link2shm(holder);

		if (!shm->addr)
			continue;

		off = (off_t) (addr - shm->addr);
		if (off >= 0 && off < shm->size)
			break;
	}

	if (!holder) {
		xnlock_put_irqrestore(&nklock, s);
		return NULL;
	}

	xnlock_put_irqrestore(&nklock, s);

	return shm;
}

/**
 * Unmap pages of memory.
 *
 * This service unmaps the shared memory region [addr;addr+len) from the caller
 * address-space.
 *
 * When called from kernel-space the memory region remain accessible as long as
 * it exists, and this service only decrements a reference counter.
 *
 * When called from user-space, if the region is not a shared memory region,
 * this service falls back to the regular Linux munmap() service.
 *
 * @param addr start address of shared memory area;
 *
 * @param len length of the shared memory area.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a len is null, @a addr is not a multiple of the page size or the
 *   range [addr;addr+len) is not a mapped region;
 * - ENXIO, @a addr is not the address of a shared memory area;
 * - EPERM, the caller context is invalid;
 * - EINTR, this service was interrupted by a signal.
 * 
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - kernel-space cancellation cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode);
 * - user-space cancellation cleanup routine.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/munmap.html">
 * Specification.</a>
 * 
 */
int munmap(void *addr, size_t len)
{
	pse51_shm_map_t *mapping = NULL;
	xnholder_t *holder;
	pse51_shm_t *shm;
	int err;
	spl_t s;

	if (!len) {
		err = EINVAL;
		goto error;
	}

	if (((unsigned long)addr) % PAGE_SIZE) {
		err = EINVAL;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);
	shm = pse51_shm_lookup(addr);

	if (!shm) {
		xnlock_put_irqrestore(&nklock, s);
		err = ENXIO;
		goto error;
	}

	if (xnpod_asynch_p() || !xnpod_root_p()) {
		xnlock_put_irqrestore(&nklock, s);
		err = EPERM;
		goto error;
	}

	++shm->nodebase.refcount;
	xnlock_put_irqrestore(&nklock, s);

	if (down_interruptible(&shm->maplock)) {
		err = EINTR;
		goto err_shm_put;
	}

	for (holder = getheadq(&shm->mappings);
	     holder; holder = nextq(&shm->mappings, holder)) {
		mapping = link2map(holder);

		if (mapping->addr == addr && mapping->size == len)
			break;
	}

	if (!holder) {
		xnlock_put_irqrestore(&nklock, s);
		err = EINVAL;
		goto err_up;
	}

	removeq(&shm->mappings, holder);
	up(&shm->maplock);

	xnfree(mapping);
	pse51_shm_put(shm, 2);
	return 0;

      err_up:
	up(&shm->maplock);
      err_shm_put:
	pse51_shm_put(shm, 1);
      error:
	thread_set_errno(err);
	return -1;
}

#ifdef CONFIG_XENO_OPT_PERVASIVE
int pse51_xnheap_get(xnheap_t **pheap, void *addr)
{
	pse51_shm_t *shm;

	shm = pse51_shm_lookup(addr);

	if (!shm)
		return -EBADF;

	*pheap = &shm->heapbase;
	return 0;
}

static void ufd_cleanup(pse51_assoc_t *assoc)
{
	pse51_ufd_t *ufd = assoc2ufd(assoc);
#if XENO_DEBUG(POSIX)
	xnprintf("Posix: closing shared memory descriptor %lu.\n",
		 pse51_assoc_key(assoc));
#endif /* XENO_DEBUG(POSIX) */
	pse51_shm_close(ufd->kfd);
	xnfree(ufd);
}

static void umap_cleanup(pse51_assoc_t *assoc)
{
	pse51_umap_t *umap = assoc2umap(assoc);
#if XENO_DEBUG(POSIX)
	xnprintf("Posix: unmapping shared memory 0x%08lx.\n",
		 pse51_assoc_key(assoc));
#endif /* XENO_DEBUG(POSIX) */
	munmap(umap->kaddr, umap->len);
	xnfree(umap);
}

void pse51_shm_ufds_cleanup(pse51_queues_t *q)
{
	pse51_assocq_destroy(&q->ufds, &ufd_cleanup);
}

void pse51_shm_umaps_cleanup(pse51_queues_t *q)
{
	pse51_assocq_destroy(&q->umaps, &umap_cleanup);
}

#endif /* CONFIG_XENO_OPT_PERVASIVE */

int pse51_shm_pkg_init(void)
{
	initq(&pse51_shmq);

	return 0;
}

void pse51_shm_pkg_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&pse51_shmq))) {
		pse51_shm_t *shm = link2shm(holder);
		pse51_node_t *node;

		pse51_node_remove(&node, shm->nodebase.name, PSE51_SHM_MAGIC);
		xnlock_put_irqrestore(&nklock, s);
#if XENO_DEBUG(POSIX)
		xnprintf("Posix: unlinking shared memory \"%s\".\n",
			 shm->nodebase.name);
#endif /* XENO_DEBUG(POSIX) */
		xnlock_get_irqsave(&nklock, s);
		pse51_shm_destroy(shm, 1);
	}

	xnlock_put_irqrestore(&nklock, s);
}

/*@}*/

EXPORT_SYMBOL(shm_open);
EXPORT_SYMBOL(shm_unlink);
EXPORT_SYMBOL(pse51_shm_close);
EXPORT_SYMBOL(ftruncate);
EXPORT_SYMBOL(mmap);
EXPORT_SYMBOL(munmap);
