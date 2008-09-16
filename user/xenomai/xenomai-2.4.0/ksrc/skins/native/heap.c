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
 *
 * \ingroup native_heap
 */

/*!
 * \ingroup native
 * \defgroup native_heap Memory heap services.
 *
 * Memory heaps are regions of memory used for dynamic memory
 * allocation in a time-bounded fashion. Blocks of memory are
 * allocated and freed in an arbitrary order and the pattern of
 * allocation and size of blocks is not known until run time.
 *
 * The implementation of the memory allocator follows the algorithm
 * described in a USENIX 1988 paper called "Design of a General
 * Purpose Memory Allocator for the 4.3BSD Unix Kernel" by Marshall
 * K. McKusick and Michael J. Karels.
 *
 * Xenomai memory heaps are built over the nucleus's heap objects, which
 * in turn provide the needed support for sharing a memory area
 * between kernel and user-space using direct memory mapping.
 *
 *@{*/

/** @example local_heap.c */
/** @example shared_mem.c */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <native/task.h>
#include <native/heap.h>

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __heap_read_proc(char *page,
			    char **start,
			    off_t off, int count, int *eof, void *data)
{
	RT_HEAP *heap = (RT_HEAP *)data;
	char *p = page;
	int len;
	spl_t s;

	p += sprintf(p, "type=%s:size=%lu:used=%lu\n",
		     (heap->mode & H_SHARED) == H_SHARED ? "shared" :
		     (heap->mode & H_MAPPABLE) ? "mappable" : "kernel",
		     xnheap_usable_mem(&heap->heap_base), xnheap_used_mem(&heap->heap_base));

	xnlock_get_irqsave(&nklock, s);

	if (xnsynch_nsleepers(&heap->synch_base) > 0) {
		xnpholder_t *holder;

		/* Pended heap -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&heap->synch_base));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			RT_TASK *task = thread2rtask(sleeper);
			size_t size = task->wait_args.heap.size;
			p += sprintf(p, "+%s (size=%zd)\n",
				     xnthread_name(sleeper), size);
			holder =
			    nextpq(xnsynch_wait_queue(&heap->synch_base),
				   holder);
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	len = (p - page) - off;
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}

extern xnptree_t __native_ptree;

static xnpnode_t __heap_pnode = {

	.dir = NULL,
	.type = "heaps",
	.entries = 0,
	.read_proc = &__heap_read_proc,
	.write_proc = NULL,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __heap_pnode = {

	.type = "heaps"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static void __heap_flush_private(xnheap_t *heap,
				 void *heapmem, u_long heapsize, void *cookie)
{
	xnarch_free_host_mem(heapmem, heapsize);
}

/*! 
 * \fn int rt_heap_create(RT_HEAP *heap,const char *name,size_t heapsize,int mode);
 * \brief Create a memory heap or a shared memory segment.
 *
 * Initializes a memory heap suitable for time-bounded allocation
 * requests of dynamic memory. Memory heaps can be local to the kernel
 * address space, or mapped to user-space.
 *
 * In their simplest form, heaps are only accessible from kernel
 * space, and are merely usable as regular memory allocators.
 *
 * Heaps existing in kernel space can be mapped by user-space
 * processes to their own address space provided H_MAPPABLE has been
 * passed into the @a mode parameter.
 *
 * By default, heaps support allocation of multiple blocks of memory
 * in an arbitrary order. However, it is possible to ask for
 * single-block management by passing the H_SINGLE flag into the @a
 * mode parameter, in which case the entire memory space managed by
 * the heap is made available as a unique block.  In this mode, all
 * allocation requests made through rt_heap_alloc() will then return
 * the same block address, pointing at the beginning of the heap
 * memory.
 *
 * H_SHARED is a shorthand for creating shared memory segments
 * transparently accessible from kernel and user-space contexts, which
 * are basically single-block, mappable heaps. By proper use of a
 * common @a name, all tasks can bind themselves to the same heap and
 * thus share the same memory space, which start address should be
 * subsequently retrieved by a call to rt_heap_alloc().
 *
 * @param heap The address of a heap descriptor Xenomai will use to store
 * the heap-related data.  This descriptor must always be valid while
 * the heap is active therefore it must be allocated in permanent
 * memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * heap. When non-NULL and non-empty, this string is copied to a safe
 * place into the descriptor, and passed to the registry package if
 * enabled for indexing the created heap. Mappable heaps must be given
 * a valid name.
 *
 * @param heapsize The size (in bytes) of the block pool which is
 * going to be pre-allocated to the heap. Memory blocks will be
 * claimed and released to this pool.  The block pool is not
 * extensible, so this value must be compatible with the highest
 * memory pressure that could be expected. A minimum of 2 * PAGE_SIZE
 * will be enforced for mappable heaps, 2 * XNCORE_PAGE_SIZE
 * otherwise.
 *
 * @param mode The heap creation mode. The following flags can be
 * OR'ed into this bitmask, each of them affecting the new heap:
 *
 * - H_FIFO makes tasks pend in FIFO order on the heap when waiting
 * for available blocks.
 *
 * - H_PRIO makes tasks pend in priority order on the heap when
 * waiting for available blocks.
 *
 * - H_MAPPABLE causes the heap to be sharable between kernel and
 * user-space contexts. Otherwise, the new heap is only available for
 * kernel-based usage. This flag is implicitely set when the caller is
 * running in user-space. This feature requires the real-time support
 * in user-space to be configured in (CONFIG_XENO_OPT_PERVASIVE).
 *
 * - H_SINGLE causes the entire heap space to be managed as a single
 * memory block.
 *
 * - H_SHARED is a shorthand for H_MAPPABLE|H_SINGLE, creating a
 * global shared memory segment accessible from both the kernel and
 * user-space contexts.
 *
 * - H_DMA causes the block pool associated to the heap to be
 * allocated in physically contiguous memory, suitable for DMA
 * operations with I/O devices. A 128Kb limit exists for @a heapsize
 * when this flag is passed.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EEXIST is returned if the @a name is already in use by some
 * registered object.
 *
 * - -EINVAL is returned if @a heapsize is null, greater than the
 * system limit, or @a name is null or empty for a mappable heap.
 *
 * - -ENOMEM is returned if not enough system memory is available to
 * create or register the heap. Additionally, and if H_MAPPABLE has
 * been passed in @a mode, errors while mapping the block pool in the
 * caller's address space might beget this return code too.
 *
 * - -EPERM is returned if this service was called from an invalid
 * context.
 *
 * - -ENOSYS is returned if @a mode specifies H_MAPPABLE, but the
 * real-time support in user-space is unavailable.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - User-space task (switches to secondary mode)
 *
 * Rescheduling: possible.
 */

int rt_heap_create(RT_HEAP *heap, const char *name, size_t heapsize, int mode)
{
	int err;
	spl_t s;

	if (!xnpod_root_p())
		return -EPERM;

	if (heapsize == 0)
		return -EINVAL;

	/* Make sure we won't hit trivial argument errors when calling
	   xnheap_init(). */

	heap->csize = heapsize;	/* Record this for SBA management and inquiry. */

#ifdef __KERNEL__
	if (mode & H_MAPPABLE) {
		if (!name || !*name)
			return -EINVAL;

#ifdef CONFIG_XENO_OPT_PERVASIVE
		heapsize = xnheap_rounded_size(heapsize, PAGE_SIZE);

		err = xnheap_init_mapped(&heap->heap_base,
					 heapsize,
					 (mode & H_DMA) ? GFP_DMA : 0);
		if (err)
			return err;

		heap->cpid = 0;
#else /* !CONFIG_XENO_OPT_PERVASIVE */
		return -ENOSYS;
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	} else
#endif /* __KERNEL__ */
	{
		void *heapmem;

		heapsize = xnheap_rounded_size(heapsize, XNCORE_PAGE_SIZE);

		heapmem = xnarch_alloc_host_mem(heapsize);

		if (!heapmem)
			return -ENOMEM;

		err = xnheap_init(&heap->heap_base, heapmem, heapsize, XNCORE_PAGE_SIZE);
		if (err) {
			xnarch_free_host_mem(heapmem, heapsize);
			return err;
		}
	}

	xnsynch_init(&heap->synch_base, mode & (H_PRIO | H_FIFO));
	heap->handle = 0;	/* i.e. (still) unregistered heap. */
	heap->magic = XENO_HEAP_MAGIC;
	heap->mode = mode;
	heap->sba = NULL;
	xnobject_copy_name(heap->name, name);
	inith(&heap->rlink);
	heap->rqueue = &xeno_get_rholder()->heapq;
	xnlock_get_irqsave(&nklock, s);
	appendq(heap->rqueue, &heap->rlink);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	/* <!> Since xnregister_enter() may reschedule, only register
	   complete objects, so that the registry cannot return handles to
	   half-baked objects... */

	if (name) {
		xnpnode_t *pnode = &__heap_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			   from user-space, it gets registered under an unique
			   internal name but is not exported through /proc. */
			xnobject_create_name(heap->name, sizeof(heap->name),
					     (void *)heap);
			pnode = NULL;
		}

		err = xnregistry_enter(heap->name, heap, &heap->handle, pnode);

		if (err)
			rt_heap_delete(heap);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return err;
}

/**
 * @fn int rt_heap_delete(RT_HEAP *heap)
 *
 * @brief Delete a real-time heap.
 *
 * Destroy a heap and release all the tasks currently pending on it.
 * A heap exists in the system since rt_heap_create() has been called
 * to create it, so this service must be called in order to destroy it
 * afterwards.
 *
 * @param heap The descriptor address of the affected heap.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EBUSY is returned if @a heap is in use by another process and the
 * descriptor is not destroyed.
 *
 * - -EINVAL is returned if @a heap is not a heap descriptor.
 *
 * - -EIDRM is returned if @a heap is a deleted heap descriptor.
 *
 * - -EPERM is returned if this service was called from an
 * invalid context.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - User-space task (switches to secondary mode).
 *
 * Rescheduling: possible.
 */

int rt_heap_delete(RT_HEAP *heap)
{
	int err = 0;
	spl_t s;

	if (!xnpod_root_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	heap = xeno_h2obj_validate(heap, XENO_HEAP_MAGIC, RT_HEAP);

	if (!heap) {
		err = xeno_handle_error(heap, XENO_HEAP_MAGIC, RT_HEAP);
		xnlock_put_irqrestore(&nklock, s);
		return err;
	}

	xeno_mark_deleted(heap);

	/* Get out of the nklocked section before releasing the heap
	   memory, since we are about to invoke Linux kernel
	   services. */

	xnlock_put_irqrestore(&nklock, s);

	/* The heap descriptor has been marked as deleted before we
	   released the superlock thus preventing any sucessful subsequent
	   calls of rt_heap_delete(), so now we can actually destroy
	   it safely. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (heap->mode & H_MAPPABLE)
		err = xnheap_destroy_mapped(&heap->heap_base);
	else
#endif /* CONFIG_XENO_OPT_PERVASIVE */
		err = xnheap_destroy(&heap->heap_base, &__heap_flush_private, NULL);

	xnlock_get_irqsave(&nklock, s);

	if (!err) {
		removeq(heap->rqueue, &heap->rlink);

#ifdef CONFIG_XENO_OPT_REGISTRY
		if (heap->handle)
			xnregistry_remove(heap->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

		if (xnsynch_destroy(&heap->synch_base) == XNSYNCH_RESCHED)
			/* Some task has been woken up as a result of
			   the deletion: reschedule now. */
			xnpod_schedule();
	} else
		/* Deletion failed, likely due to a busy state;
		 * restore the magic word, to re-enable the
		 * descriptor. */
		heap->magic = XENO_HEAP_MAGIC;

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_heap_alloc(RT_HEAP *heap,size_t size,RTIME timeout,void **blockp)
 *
 * @brief Allocate a block or return the single segment base.
 *
 * This service allocates a block from the heap's internal pool, or
 * returns the address of the single memory segment in the caller's
 * address space. Tasks may wait for some requested amount of memory
 * to become available from local heaps.
 *
 * @param heap The descriptor address of the heap to allocate a block
 * from.
 *
 * @param size The requested size in bytes of the block. If the heap
 * is managed as a single-block area (H_SINGLE), this value can be
 * either zero, or the same value given to rt_heap_create(). In that
 * case, the same block covering the entire heap space will always be
 * returned to all callers of this service.
 *
 * @param timeout The number of clock ticks to wait for a block of
 * sufficient size to be available from a local heap (see
 * note). Passing TM_INFINITE causes the caller to block indefinitely
 * until some block is eventually available. Passing TM_NONBLOCK
 * causes the service to return immediately without waiting if no
 * block is available on entry. This parameter has no influence if the
 * heap is managed as a single-block area since the entire heap space
 * is always available.
 *
 * @param blockp A pointer to a memory location which will be written
 * upon success with the address of the allocated block, or the start
 * address of the single memory segment. In the former case, the block
 * should be freed using rt_heap_free().
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a heap is not a heap descriptor, or @a
 * heap is managed as a single-block area (i.e. H_SINGLE mode) and @a
 * size is non-zero but does not match the original heap size passed
 * to rt_heap_create().
 *
 * - -EIDRM is returned if @a heap is a deleted heap descriptor.
 *
 * - -ETIMEDOUT is returned if @a timeout is different from
 * TM_NONBLOCK and no block is available within the specified amount
 * of time.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and no block is immediately available on entry.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before any block was available.
 *
 * - -EPERM is returned if this service should block but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 *   only if @a timeout is equal to TM_NONBLOCK, or the heap is
 *   managed as a single-block area.
 *
 * - Kernel-based task
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation. Operations on
 * single-block heaps never start the rescheduling procedure.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

int rt_heap_alloc(RT_HEAP *heap, size_t size, RTIME timeout, void **blockp)
{
	void *block = NULL;
	RT_TASK *task;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xeno_h2obj_validate(heap, XENO_HEAP_MAGIC, RT_HEAP);

	if (!heap) {
		err = xeno_handle_error(heap, XENO_HEAP_MAGIC, RT_HEAP);
		goto unlock_and_exit;
	}

	/* In single-block mode, there is only a single allocation
	   returning the whole addressable heap space to the user. All
	   users referring to this heap are then returned the same
	   block. */

	if (heap->mode & H_SINGLE) {
		block = heap->sba;

		if (!block) {
			/* It's ok to pass zero for size here, since the requested
			   size is implicitely the whole heap space; but if
			   non-zero is given, it must match the original heap
			   size. */

			if (size > 0 && size != heap->csize) {
				err = -EINVAL;
				goto unlock_and_exit;
			}

			block = heap->sba = xnheap_alloc(&heap->heap_base,
							 xnheap_max_contiguous
							 (&heap->heap_base));
		}

		if (block)
			goto unlock_and_exit;

		err = -ENOMEM;	/* This should never happen. Paranoid. */
		goto unlock_and_exit;
	}

	block = xnheap_alloc(&heap->heap_base, size);

	if (block)
		goto unlock_and_exit;

	if (timeout == TM_NONBLOCK) {
		err = -EWOULDBLOCK;
		goto unlock_and_exit;
	}

	if (xnpod_unblockable_p()) {
		err = -EPERM;
		goto unlock_and_exit;
	}

	task = xeno_current_task();
	task->wait_args.heap.size = size;
	task->wait_args.heap.block = NULL;
	xnsynch_sleep_on(&heap->synch_base, timeout, XN_RELATIVE);

	if (xnthread_test_info(&task->thread_base, XNRMID))
		err = -EIDRM;	/* Heap deleted while pending. */
	else if (xnthread_test_info(&task->thread_base, XNTIMEO))
		err = -ETIMEDOUT;	/* Timeout. */
	else if (xnthread_test_info(&task->thread_base, XNBREAK))
		err = -EINTR;	/* Unblocked. */
	else
		block = task->wait_args.heap.block;

      unlock_and_exit:

	*blockp = block;

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_heap_free(RT_HEAP *heap,void *block)
 *
 * @brief Free a block.
 *
 * This service releases a block to the heap's internal pool. If some
 * task is currently waiting for a block so that it's pending request
 * could be satisfied as a result of the release, it is immediately
 * resumed.
 *
 * If the heap is defined as a single-block area (i.e. H_SINGLE mode),
 * this service leads to a null-effect and always returns
 * successfully.
 *
 * @param heap The address of the heap descriptor to which the block
 * @a block belong.
 *
 * @param block The address of the block to free.
 *
 * @return 0 is returned upon success, or -EINVAL if @a block is not a
 * valid block previously allocated by the rt_heap_alloc() service.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: possible.
 */

int rt_heap_free(RT_HEAP *heap, void *block)
{
	int err, nwake;
	spl_t s;

	if (block == NULL)
		return -EINVAL;

	xnlock_get_irqsave(&nklock, s);

	heap = xeno_h2obj_validate(heap, XENO_HEAP_MAGIC, RT_HEAP);

	if (!heap) {
		err = xeno_handle_error(heap, XENO_HEAP_MAGIC, RT_HEAP);
		goto unlock_and_exit;
	}

	if (heap->mode & H_SINGLE) {	/* No-op in single-block mode. */
		err = 0;
		goto unlock_and_exit;
	}

	err = xnheap_free(&heap->heap_base, block);

	if (!err && xnsynch_nsleepers(&heap->synch_base) > 0) {
		xnpholder_t *holder, *nholder;

		nholder = getheadpq(xnsynch_wait_queue(&heap->synch_base));
		nwake = 0;

		while ((holder = nholder) != NULL) {
			RT_TASK *sleeper =
			    thread2rtask(link2thread(holder, plink));
			void *block;

			block = xnheap_alloc(&heap->heap_base,
					     sleeper->wait_args.heap.size);
			if (block) {
				nholder =
				    xnsynch_wakeup_this_sleeper(&heap->
								synch_base,
								holder);
				sleeper->wait_args.heap.block = block;
				nwake++;
			} else
				nholder =
				    nextpq(xnsynch_wait_queue
					   (&heap->synch_base), holder);
		}

		if (nwake > 0)
			xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_heap_inquire(RT_HEAP *heap, RT_HEAP_INFO *info)
 *
 * @brief Inquire about a heap.
 *
 * Return various information about the status of a given heap.
 *
 * @param heap The descriptor address of the inquired heap.
 *
 * @param info The address of a structure the heap information will
 * be written to.

 * @return 0 is returned and status information is written to the
 * structure pointed at by @a info upon success. Otherwise:
 *
 * - -EINVAL is returned if @a heap is not a message queue descriptor.
 *
 * - -EIDRM is returned if @a heap is a deleted queue descriptor.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int rt_heap_inquire(RT_HEAP *heap, RT_HEAP_INFO *info)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	heap = xeno_h2obj_validate(heap, XENO_HEAP_MAGIC, RT_HEAP);

	if (!heap) {
		err = xeno_handle_error(heap, XENO_HEAP_MAGIC, RT_HEAP);
		goto unlock_and_exit;
	}

	strcpy(info->name, heap->name);
	info->nwaiters = xnsynch_nsleepers(&heap->synch_base);
	info->heapsize = heap->csize;
	info->usablemem = xnheap_usable_mem(&heap->heap_base);
	info->usedmem = xnheap_used_mem(&heap->heap_base);
	info->mode = heap->mode;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_heap_bind(RT_HEAP *heap,const char *name,RTIME timeout)
 *
 * @brief Bind to a mappable heap.
 *
 * This user-space only service retrieves the uniform descriptor of a
 * given mappable Xenomai heap identified by its symbolic name. If the
 * heap does not exist on entry, this service blocks the caller until
 * a heap of the given name is created.
 *
 * @param name A valid NULL-terminated name which identifies the
 * heap to bind to.
 *
 * @param heap The address of a heap descriptor retrieved by the
 * operation. Contents of this memory is undefined upon failure.
 *
 * @param timeout The number of clock ticks to wait for the
 * registration to occur (see note). Passing TM_INFINITE causes the
 * caller to block indefinitely until the object is
 * registered. Passing TM_NONBLOCK causes the service to return
 * immediately without waiting if the object is not registered on
 * entry.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EFAULT is returned if @a heap or @a name is referencing invalid
 * memory.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before the retrieval has completed.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and the searched object is not registered on entry.
 *
 * - -ETIMEDOUT is returned if the object cannot be retrieved within
 * the specified amount of time.
 *
 * - -EPERM is returned if this service should block, but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * - -ENOENT is returned if the special file /dev/rtheap
 * (character-mode, major 10, minor 254) is not available from the
 * filesystem. This device is needed to map the shared heap memory
 * into the caller's address space. udev-based systems should not need
 * manual creation of such device entry.  Environments:
 *
 * This service can be called from:
 *
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

/**
 * @fn int rt_heap_unbind(RT_HEAP *heap)
 *
 * @brief Unbind from a mappable heap.
 *
 * This user-space only service unbinds the calling task from the heap
 * object previously retrieved by a call to rt_heap_bind().
 *
 * Unbinding from a heap when it is no longer needed is especially
 * important in order to properly release the mapping resources used
 * to attach the heap memory to the caller's address space.
 *
 * @param heap The address of a heap descriptor to unbind from.
 *
 * @return 0 is always returned.
 *
 * This service can be called from:
 *
 * - User-space task.
 *
 * Rescheduling: never.
 */

int __native_heap_pkg_init(void)
{
	return 0;
}

void __native_heap_pkg_cleanup(void)
{
	__native_heap_flush_rq(&__native_global_rholder.heapq);
}

/*@}*/

EXPORT_SYMBOL(rt_heap_create);
EXPORT_SYMBOL(rt_heap_delete);
EXPORT_SYMBOL(rt_heap_alloc);
EXPORT_SYMBOL(rt_heap_free);
EXPORT_SYMBOL(rt_heap_inquire);
