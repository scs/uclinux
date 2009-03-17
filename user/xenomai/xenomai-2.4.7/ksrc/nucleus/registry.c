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
 * \ingroup registry
 */

/*!
 * \ingroup nucleus
 * \defgroup registry Registry services.
 *
 * The registry provides a mean to index real-time object descriptors
 * created by Xenomai skins on unique alphanumeric keys. When labeled
 * this way, a real-time object is globally exported; it can be
 * searched for, and its descriptor returned to the caller for further
 * use; the latter operation is called a "binding". When no object has
 * been registered under the given name yet, the registry can be asked
 * to set up a rendez-vous, blocking the caller until the object is
 * eventually registered.
 *
 *@{*/

#include <nucleus/pod.h>
#include <nucleus/heap.h>
#include <nucleus/registry.h>
#include <nucleus/thread.h>
#include <nucleus/assert.h>

#ifndef CONFIG_XENO_OPT_DEBUG_REGISTRY
#define CONFIG_XENO_OPT_DEBUG_REGISTRY  0
#endif

static xnobject_t *registry_obj_slots;

static xnqueue_t registry_obj_freeq;	/* Free objects. */

static xnqueue_t registry_obj_busyq;	/* Active and exported objects. */

static u_long registry_obj_stamp;

static xnobjhash_t **registry_hash_table;

static int registry_hash_entries;

static xnsynch_t registry_hash_synch;

#ifdef CONFIG_XENO_EXPORT_REGISTRY

#include <linux/workqueue.h>

extern struct proc_dir_entry *rthal_proc_root;

static DECLARE_WORK_FUNC(registry_proc_callback);

static void registry_proc_schedule(void *cookie);

static xnqueue_t registry_obj_procq;	/* Objects waiting for /proc handling. */

#ifndef CONFIG_PREEMPT_RT
static DECLARE_WORK_NODATA(registry_proc_work, &registry_proc_callback);
#endif /* !CONFIG_PREEMPT_RT */

static struct proc_dir_entry *registry_proc_root;

static int registry_proc_apc;

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

int xnregistry_init(void)
{
	static const int primes[] = {
		101, 211, 307, 401, 503, 601,
		701, 809, 907, 1009, 1103
	};

#define obj_hash_max(n)			 \
((n) < sizeof(primes) / sizeof(int) ? \
 (n) : sizeof(primes) / sizeof(int) - 1)

	int n;

	registry_obj_slots =
		xnarch_alloc_host_mem(CONFIG_XENO_OPT_REGISTRY_NRSLOTS * sizeof(xnobject_t));
	if (registry_obj_slots == NULL)
		return -ENOMEM;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
	registry_proc_apc =
	    rthal_apc_alloc("registry_export", &registry_proc_schedule, NULL);

	if (registry_proc_apc < 0)
		return registry_proc_apc;

	registry_proc_root = create_proc_entry("registry",
					       S_IFDIR, rthal_proc_root);
	if (!registry_proc_root) {
		rthal_apc_free(registry_proc_apc);
		return -ENOMEM;
	}

	initq(&registry_obj_procq);
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

	initq(&registry_obj_freeq);
	initq(&registry_obj_busyq);
	registry_obj_stamp = 0;

	for (n = 0; n < CONFIG_XENO_OPT_REGISTRY_NRSLOTS; n++) {
		inith(&registry_obj_slots[n].link);
		registry_obj_slots[n].objaddr = NULL;
		appendq(&registry_obj_freeq, &registry_obj_slots[n].link);
	}

	getq(&registry_obj_freeq);	/* Slot #0 is reserved/invalid. */

	registry_hash_entries =
	    primes[obj_hash_max(CONFIG_XENO_OPT_REGISTRY_NRSLOTS / 100)];
	registry_hash_table =
	    (xnobjhash_t **) xnarch_alloc_host_mem(sizeof(xnobjhash_t *) *
					     registry_hash_entries);

	if (!registry_hash_table) {
#ifdef CONFIG_XENO_EXPORT_REGISTRY
		rthal_apc_free(registry_proc_apc);
		remove_proc_entry("registry", rthal_proc_root);
#endif /* CONFIG_XENO_EXPORT_REGISTRY */
		return -ENOMEM;
	}

	for (n = 0; n < registry_hash_entries; n++)
		registry_hash_table[n] = NULL;

	xnsynch_init(&registry_hash_synch, XNSYNCH_FIFO);

	return 0;
}

void xnregistry_cleanup(void)
{
	xnobjhash_t *ecurr, *enext;
	int n;

	for (n = 0; n < registry_hash_entries; n++) {
		for (ecurr = registry_hash_table[n]; ecurr; ecurr = enext) {
			enext = ecurr->next;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
			if (ecurr->object && ecurr->object->pnode) {
				remove_proc_entry(ecurr->object->key,
						  ecurr->object->pnode->dir);

				if (--ecurr->object->pnode->entries <= 0) {
					remove_proc_entry(ecurr->object->pnode->
							  type,
							  ecurr->object->pnode->
							  root->dir);
					ecurr->object->pnode->dir = NULL;

					if (--ecurr->object->pnode->root->
					    entries <= 0) {
						remove_proc_entry(ecurr->
								  object->
								  pnode->root->
								  name,
								  registry_proc_root);
						ecurr->object->pnode->root->
						    dir = NULL;
					}
				}
			}
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

			xnfree(ecurr);
		}
	}

	xnarch_free_host_mem(registry_hash_table,
		       sizeof(xnobjhash_t *) * registry_hash_entries);

	xnsynch_destroy(&registry_hash_synch);

#ifdef CONFIG_XENO_EXPORT_REGISTRY
	rthal_apc_free(registry_proc_apc);
	flush_scheduled_work();
	remove_proc_entry("registry", rthal_proc_root);
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

	xnarch_free_host_mem(registry_obj_slots,
			     CONFIG_XENO_OPT_REGISTRY_NRSLOTS * sizeof(xnobject_t));
}

static inline xnobject_t *registry_validate(xnhandle_t handle)
{
	if (handle > 0 && handle < CONFIG_XENO_OPT_REGISTRY_NRSLOTS) {
		xnobject_t *object = &registry_obj_slots[handle];
		return object->objaddr ? object : NULL;
	}

	return NULL;
}

#ifdef CONFIG_XENO_EXPORT_REGISTRY

/* The following stuff implements the mechanism for delegating
   export/unexport requests to/from the /proc interface from the
   Xenomai domain to the Linux kernel (i.e. the "lower stage"). This
   ends up being a bit complex due to the fact that such requests
   might lag enough before being processed by the Linux kernel so that
   subsequent requests might just contradict former ones before they
   even had a chance to be applied (e.g. export -> unexport in the
   Xenomai domain for short-lived objects). This situation and the
   like are hopefully properly handled due to a careful
   synchronization of operations across domains. */

static struct proc_dir_entry *add_proc_leaf(const char *name,
					    read_proc_t rdproc,
					    write_proc_t wrproc,
					    void *data,
					    struct proc_dir_entry *parent)
{
	int mode = wrproc ? 0644 : 0444;
	struct proc_dir_entry *entry;

	entry = create_proc_entry(name, mode, parent);

	if (!entry)
		return NULL;

	entry->nlink = 1;
	entry->data = data;
	entry->read_proc = rdproc;
	entry->write_proc = wrproc;
	entry->owner = THIS_MODULE;

	return entry;
}

static struct proc_dir_entry *add_proc_link(const char *name,
					    link_proc_t *link_proc,
					    void *data,
					    struct proc_dir_entry *parent)
{
	struct proc_dir_entry *entry;
	char target[128];

	if (link_proc(target, sizeof(target), data) <= 0)
		return NULL;

	entry = proc_symlink(name, parent, target);

	if (!entry)
		return NULL;

	entry->owner = THIS_MODULE;

	return entry;
}

static DECLARE_WORK_FUNC(registry_proc_callback)
{
	struct proc_dir_entry *rdir, *dir, *entry;
	const char *root, *type;
	xnholder_t *holder;
	xnobject_t *object;
	xnpnode_t *pnode;
	int entries;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getq(&registry_obj_procq)) != NULL) {
		object = link2xnobj(holder);
		pnode = object->pnode;
		type = pnode->type;
		dir = pnode->dir;
		rdir = pnode->root->dir;
		root = pnode->root->name;

		if (object->proc != XNOBJECT_PROC_RESERVED1)
			goto unexport;

		++pnode->entries;
		object->proc = XNOBJECT_PROC_RESERVED2;
		appendq(&registry_obj_busyq, holder);

		xnlock_put_irqrestore(&nklock, s);

		if (!rdir) {
			/* Create the root directory on the fly as needed. */
			rdir =
			    create_proc_entry(root, S_IFDIR,
					      registry_proc_root);

			if (!rdir) {
				object->proc = NULL;
				goto fail;
			}

			pnode->root->dir = rdir;
		}

		if (!dir) {
			/* Create the class directory on the fly as needed. */
			dir = create_proc_entry(type, S_IFDIR, rdir);

			if (!dir) {
				object->proc = NULL;
				goto fail;
			}

			pnode->dir = dir;
			++pnode->root->entries;
		}

		if (pnode->link_proc)
			/* Entry is a symlink to somewhere else. */
			object->proc = add_proc_link(object->key,
						     pnode->link_proc,
						     object->objaddr, dir);
		else
			/* Entry allows to get/set object properties. */
			object->proc = add_proc_leaf(object->key,
						     pnode->read_proc,
						     pnode->write_proc,
						     object->objaddr, dir);
	      fail:
		xnlock_get_irqsave(&nklock, s);

		if (!object->proc) {
			/* On error, pretend that the object has never been
			   exported. */
			object->pnode = NULL;
			--pnode->entries;
		}

		continue;

	unexport:
		entries = --pnode->entries;
		entry = object->proc;
		object->proc = NULL;
		object->pnode = NULL;

		if (entries <= 0) {
			pnode->dir = NULL;

			if (--pnode->root->entries <= 0)
				pnode->root->dir = NULL;
		}

		if (object->objaddr)
			appendq(&registry_obj_busyq, holder);
		else
			/* Trap the case where we are unexporting an already
			   unregistered object. */
			appendq(&registry_obj_freeq, holder);

		xnlock_put_irqrestore(&nklock, s);

		remove_proc_entry(entry->name, dir);

		if (entries <= 0) {
			remove_proc_entry(type, rdir);

			if (pnode->root->entries <= 0)
				remove_proc_entry(root, registry_proc_root);
		}

		xnlock_get_irqsave(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);
}

static void registry_proc_schedule(void *cookie)
{
#ifdef CONFIG_PREEMPT_RT
	/* On PREEMPT_RT, we are already running over a thread context, so
	   we don't need the workqueue indirection: let's invoke the
	   export handler directly. */
	registry_proc_callback(cookie);
#else /* CONFIG_PREEMPT_RT */
	/* schedule_work() will check for us if the work has already been
	   scheduled, so just be lazy and submit blindly. */
	schedule_work(&registry_proc_work);
#endif /* CONFIG_PREEMPT_RT */
}

static inline void registry_proc_export(xnobject_t *object, xnpnode_t *pnode)
{
	object->proc = XNOBJECT_PROC_RESERVED1;
	object->pnode = pnode;
	removeq(&registry_obj_busyq, &object->link);
	appendq(&registry_obj_procq, &object->link);
	rthal_apc_schedule(registry_proc_apc);
}

static inline void registry_proc_unexport(xnobject_t *object)
{
	if (object->proc != XNOBJECT_PROC_RESERVED1) {
		removeq(&registry_obj_busyq, &object->link);
		appendq(&registry_obj_procq, &object->link);
		rthal_apc_schedule(registry_proc_apc);
	} else {
		/* Unexporting before the lower stage has had a chance to
		   export. Move back the object to the busyq just like if no
		   export had been requested. */
		removeq(&registry_obj_procq, &object->link);
		appendq(&registry_obj_busyq, &object->link);
		object->pnode = NULL;
		object->proc = NULL;
	}
}

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static unsigned registry_hash_crunch(const char *key)
{
	unsigned h = 0, g;

#define HQON    24		/* Higher byte position */
#define HBYTE   0xf0000000	/* Higher nibble on */

	while (*key) {
		h = (h << 4) + *key++;
		if ((g = (h & HBYTE)) != 0)
			h = (h ^ (g >> HQON)) ^ g;
	}

	return h % registry_hash_entries;
}

static inline int registry_hash_enter(const char *key, xnobject_t *object)
{
	xnobjhash_t *enew, *ecurr;
	unsigned s;

	object->key = key;
	s = registry_hash_crunch(key);

	for (ecurr = registry_hash_table[s]; ecurr != NULL; ecurr = ecurr->next) {
		if (ecurr->object == object || !strcmp(key, ecurr->object->key))
			return -EEXIST;
	}

	enew = (xnobjhash_t *) xnmalloc(sizeof(*enew));

	if (!enew)
		return -ENOMEM;

	enew->object = object;
	enew->next = registry_hash_table[s];
	registry_hash_table[s] = enew;

	return 0;
}

static inline int registry_hash_remove(xnobject_t *object)
{
	unsigned s = registry_hash_crunch(object->key);
	xnobjhash_t *ecurr, *eprev;

	for (ecurr = registry_hash_table[s], eprev = NULL;
	     ecurr != NULL; eprev = ecurr, ecurr = ecurr->next) {
		if (ecurr->object == object) {
			if (eprev)
				eprev->next = ecurr->next;
			else
				registry_hash_table[s] = ecurr->next;

			xnfree(ecurr);

			return 0;
		}
	}

	return -ESRCH;
}

static xnobject_t *registry_hash_find(const char *key)
{
	xnobjhash_t *ecurr;

	for (ecurr = registry_hash_table[registry_hash_crunch(key)];
	     ecurr != NULL; ecurr = ecurr->next) {
		if (!strcmp(key, ecurr->object->key))
			return ecurr->object;
	}

	return NULL;
}

static inline unsigned registry_wakeup_sleepers(const char *key)
{
	xnpholder_t *holder, *nholder;
	unsigned cnt = 0;

	nholder = getheadpq(xnsynch_wait_queue(&registry_hash_synch));

	while ((holder = nholder) != NULL) {
		xnthread_t *sleeper = link2thread(holder, plink);

		if (*key == *sleeper->registry.waitkey &&
		    !strcmp(key, sleeper->registry.waitkey)) {
			sleeper->registry.waitkey = NULL;
			nholder =
			    xnsynch_wakeup_this_sleeper(&registry_hash_synch,
							holder);
			++cnt;
		} else
			nholder =
			    nextpq(xnsynch_wait_queue(&registry_hash_synch),
				   holder);
	}

	return cnt;
}

/**
 * @fn int xnregistry_enter(const char *key,void *objaddr,xnhandle_t *phandle,xnpnode_t *pnode)
 * @brief Register a real-time object.
 *
 * This service allocates a new registry slot for an associated
 * object, and indexes it by an alphanumeric key for later retrieval.
 *
 * @param key A valid NULL-terminated string by which the object will
 * be indexed and later retrieved in the registry. Since it is assumed
 * that such key is stored into the registered object, it will *not*
 * be copied but only kept by reference in the registry.
 *
 * @param objaddr An opaque pointer to the object to index by @a
 * key.
 *
 * @param phandle A pointer to a generic handle defined by the
 * registry which will uniquely identify the indexed object, until the
 * latter is unregistered using the xnregistry_remove() service.
 *
 * @param pnode A pointer to an optional /proc node class
 * descriptor. This structure provides the information needed to
 * export all objects from the given class through the /proc
 * filesystem, under the /proc/xenomai/registry entry. Passing NULL
 * indicates that no /proc support is available for the newly
 * registered object.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a key or @a objaddr are NULL, or if @a
 * key constains an invalid '/' character.
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * object.
 *
 * - -EEXIST is returned if the @a key is already in use.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based thread
 *
 * Rescheduling: possible.
 */

int xnregistry_enter(const char *key,
		     void *objaddr, xnhandle_t *phandle, xnpnode_t *pnode)
{
	xnholder_t *holder;
	xnobject_t *object;
	spl_t s;
	int err;

	if (!key || !objaddr || strchr(key, '/'))
		return -EINVAL;

	xnlock_get_irqsave(&nklock, s);

	holder = getq(&registry_obj_freeq);

	if (!holder) {
		err = -ENOMEM;
		goto unlock_and_exit;
	}

	object = link2xnobj(holder);

	err = registry_hash_enter(key, object);

	if (err) {
		appendq(&registry_obj_freeq, holder);
		goto unlock_and_exit;
	}

	xnsynch_init(&object->safesynch, XNSYNCH_FIFO);
	object->objaddr = objaddr;
	object->cstamp = ++registry_obj_stamp;
	object->safelock = 0;
	appendq(&registry_obj_busyq, holder);

	/* <!> Make sure the handle is written back before the
	   rescheduling takes place. */
	*phandle = object - registry_obj_slots;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
	if (pnode)
		registry_proc_export(object, pnode);
	else {
		object->proc = NULL;
		object->pnode = NULL;
	}
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

	if (registry_wakeup_sleepers(key))
		xnpod_schedule();

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

#if XENO_DEBUG(REGISTRY)
	if (err)
		xnlogerr("FAILED to register object %s (%s), status %d\n",
			 key,
			 pnode ? pnode->type : "unknown type",
			 err);
	else if (pnode)
		xnloginfo("registered exported object %s (%s)\n",
			  key, pnode->type);
#endif

	return err;
}

/**
 * @fn int xnregistry_bind(const char *key,xnticks_t timeout,int timeout_mode,xnhandle_t *phandle)
 * @brief Bind to a real-time object.
 *
 * This service retrieves the registry handle of a given object
 * identified by its key. Unless otherwise specified, this service
 * will block the caller if the object is not registered yet, waiting
 * for such registration to occur.
 *
 * @param key A valid NULL-terminated string which identifies the
 * object to bind to.
 *
 * @param timeout The timeout which may be used to limit the time the
 * thread wait for the object to be registered. This value is a wait
 * time given in ticks (see note). It can either be relative, absolute
 * monotonic (XN_ABSOLUTE), or absolute adjustable (XN_REALTIME)
 * depending on @a timeout_mode. Passing XN_INFINITE @b and setting @a
 * timeout_mode to XN_RELATIVE specifies an unbounded wait. Passing
 * XN_NONBLOCK causes the service to return immediately without
 * waiting if the object is not registered on entry. All other values
 * are used as a wait limit.
 *
 * @param timeout_mode The mode of the @a timeout parameter. It can
 * either be set to XN_RELATIVE, XN_ABSOLUTE, or XN_REALTIME (see also
 * xntimer_start()).
 *
 * @param phandle A pointer to a memory location which will be written
 * upon success with the generic handle defined by the registry for
 * the retrieved object. Contents of this memory is undefined upon
 * failure.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a key is NULL.
 *
 * - -EINTR is returned if xnpod_unblock_thread() has been called for
 * the waiting thread before the retrieval has completed.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to XN_NONBLOCK
 * and the searched object is not registered on entry. As a special
 * exception, this error is also returned if this service should
 * block, but was called from a context which cannot sleep
 * (e.g. interrupt, non-realtime or scheduler locked).
 *
 * - -ETIMEDOUT is returned if the object cannot be retrieved within
 * the specified amount of time.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 *   only if @a timeout is equal to XN_NONBLOCK.
 *
 * - Kernel-based thread.
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if @a
 * thread is bound to a periodic time base (see xnpod_init_thread), or
 * nanoseconds otherwise.
 */

int xnregistry_bind(const char *key, xnticks_t timeout, int timeout_mode,
		    xnhandle_t *phandle)
{
	xnobject_t *object;
	xnthread_t *thread;
	xntbase_t *tbase;
	int err = 0;
	spl_t s;

	if (!key)
		return -EINVAL;

	thread = xnpod_current_thread();
	tbase = xnthread_time_base(thread);

	xnlock_get_irqsave(&nklock, s);

	if (timeout_mode == XN_RELATIVE &&
	    timeout != XN_INFINITE && timeout != XN_NONBLOCK) {
		timeout_mode = XN_REALTIME;
		timeout += xntbase_get_time(tbase);
	}

	for (;;) {
		object = registry_hash_find(key);

		if (object) {
			*phandle = object - registry_obj_slots;
			goto unlock_and_exit;
		}

		if ((timeout_mode == XN_RELATIVE && timeout == XN_NONBLOCK) ||
		    xnpod_unblockable_p()) {
			err = -EWOULDBLOCK;
			goto unlock_and_exit;
		}

		thread->registry.waitkey = key;
		xnsynch_sleep_on(&registry_hash_synch, timeout, timeout_mode);

		if (xnthread_test_info(thread, XNTIMEO)) {
			err = -ETIMEDOUT;
			goto unlock_and_exit;
		}

		if (xnthread_test_info(thread, XNBREAK)) {
			err = -EINTR;
			goto unlock_and_exit;
		}
	}

      unlock_and_exit:

#if XENO_DEBUG(REGISTRY) && 0	/* XXX: GCC emits bad code. */
	if (err)
		xnlogerr("FAILED to bind to object %s (%s), status %d\n",
			 key, object->pnode ? object->pnode->type : "unknown type",
			 err);
	else if (object->pnode)
		xnloginfo("bound to exported object %s (%s)\n",
			  key, object->pnode->type);
#endif

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int xnregistry_remove(xnhandle_t handle)
 * @brief Forcibly unregister a real-time object.
 *
 * This service forcibly removes an object from the registry. The
 * removal is performed regardless of the current object's locking
 * status.
 *
 * @param handle The generic handle of the object to remove.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ESRCH is returned if @a handle does not reference a registered
 * object.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based thread
 *
 * Rescheduling: never.
 */

int xnregistry_remove(xnhandle_t handle)
{
	xnobject_t *object;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	object = registry_validate(handle);

	if (!object) {
		err = -ESRCH;
		goto unlock_and_exit;
	}

#if XENO_DEBUG(REGISTRY)
	/* We must keep the lock and report early, when the object
	 * slot is still valid. Note: we only report about exported
	 * objects. */
	if (object->pnode)
		xnloginfo("unregistered exported object %s (%s)\n",
			  object->key,
			  object->pnode->type);
#endif

	registry_hash_remove(object);
	object->objaddr = NULL;
	object->cstamp = 0;

#ifdef CONFIG_XENO_EXPORT_REGISTRY
	if (object->pnode) {
		registry_proc_unexport(object);

		/* Leave the update of the object queues to the work callback
		   if it has been kicked. */

		if (object->pnode)
			goto unlock_and_exit;
	}
#endif /* CONFIG_XENO_EXPORT_REGISTRY */

	removeq(&registry_obj_busyq, &object->link);
	appendq(&registry_obj_freeq, &object->link);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int xnregistry_remove_safe(xnhandle_t handle,xnticks_t timeout)
 * @brief Unregister an idle real-time object.
 *
 * This service removes an object from the registry. The caller might
 * sleep as a result of waiting for the target object to be unlocked
 * prior to the removal (see xnregistry_put()).
 *
 * @param handle The generic handle of the object to remove.
 *
 * @param timeout If the object is locked on entry, @a param gives the
 * number of clock ticks to wait for the unlocking to occur (see
 * note). Passing XN_INFINITE causes the caller to block
 * indefinitely until the object is unlocked. Passing XN_NONBLOCK
 * causes the service to return immediately without waiting if the
 * object is locked on entry.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ESRCH is returned if @a handle does not reference a registered
 * object.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to XN_NONBLOCK
 * and the object is locked on entry.
 *
 * - -EBUSY is returned if @a handle refers to a locked object and the
 * caller could not sleep until it is unlocked.
 *
 * - -ETIMEDOUT is returned if the object cannot be removed within the
 * specified amount of time.
 *
 * - -EINTR is returned if xnpod_unblock_thread() has been called for
 * the calling thread waiting for the object to be unlocked.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 *   only if @a timeout is equal to XN_NONBLOCK.
 *
 * - Kernel-based thread.
 *
 * Rescheduling: possible if the object to remove is currently locked
 * and the calling context can sleep.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * current thread is bound to a periodic time base (see
 * xnpod_init_thread), or nanoseconds otherwise.
 */

int xnregistry_remove_safe(xnhandle_t handle, xnticks_t timeout)
{
	xnobject_t *object;
	u_long cstamp;
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	object = registry_validate(handle);

	if (!object) {
		err = -ESRCH;
		goto unlock_and_exit;
	}

	if (object->safelock == 0)
		goto remove;

	if (timeout == XN_NONBLOCK) {
		err = -EWOULDBLOCK;
		goto unlock_and_exit;
	}

	if (xnpod_unblockable_p()) {
		err = -EBUSY;
		goto unlock_and_exit;
	}

	/*
	 * The object creation stamp is here to deal with situations like this
	 * one:
	 *
	 * Thread(A) locks Object(T) using xnregistry_get()
	 * Thread(B) attempts to remove Object(T) using xnregistry_remove()
	 * Thread(C) attempts the same removal, waiting like Thread(B) for
	 * the object's safe count to fall down to zero.
	 * Thread(A) unlocks Object(T), unblocking Thread(B) and (C).
	 * Thread(B) wakes up and successfully removes Object(T)
	 * Thread(D) preempts Thread(C) and recycles Object(T) for another object
	 * Thread(C) wakes up and attempts to finalize the removal of the
	 * _former_ Object(T), which leads to the spurious removal of the
	 * _new_ Object(T).
	 */

	cstamp = object->cstamp;

	do {
		xnsynch_sleep_on(&object->safesynch, timeout, XN_RELATIVE);

		if (xnthread_test_info(xnpod_current_thread(), XNBREAK)) {
			err = -EINTR;
			goto unlock_and_exit;
		}

		if (xnthread_test_info(xnpod_current_thread(), XNTIMEO)) {
			err = -ETIMEDOUT;
			goto unlock_and_exit;
		}
	}
	while (object->safelock > 0);

	if (object->cstamp != cstamp) {
		/* The caller should silently abort the removal process. */
		err = -ESRCH;
		goto unlock_and_exit;
	}

      remove:

	err = xnregistry_remove(handle);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn void *xnregistry_get(xnhandle_t handle)
 * @brief Find and lock a real-time object into the registry.
 *
 * This service retrieves an object from its handle into the registry
 * and prevents it removal atomically. A locking count is tracked, so
 * that xnregistry_get() and xnregistry_put() must be used in pair.
 *
 * @param handle The generic handle of the object to find and lock. If
 * XNOBJECT_SELF is passed, the object is the calling Xenomai
 * thread.
 *
 * @return The memory address of the object's descriptor is returned
 * on success. Otherwise, NULL is returned if @a handle does not
 * reference a registered object, or if @a handle is equal to
 * XNOBJECT_SELF but the current context is not a real-time thread.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * only if @a handle is different from XNOBJECT_SELF.
 *
 * - Kernel-based thread.
 *
 * Rescheduling: never.
 */

void *xnregistry_get(xnhandle_t handle)
{
	xnobject_t *object;
	void *objaddr;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (handle == XNOBJECT_SELF) {
		if (!xnpod_primary_p()) {
			objaddr = NULL;
			goto unlock_and_exit;
		}
		handle = xnpod_current_thread()->registry.handle;
	}

	object = registry_validate(handle);

	if (object) {
		++object->safelock;
		objaddr = object->objaddr;
	} else
		objaddr = NULL;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return objaddr;
}

/**
 * @fn u_long xnregistry_put(xnhandle_t handle)
 * @brief Unlock a real-time object from the registry.
 *
 * This service decrements the lock count of a registered object
 * previously locked by a call to xnregistry_get(). The object is
 * actually unlocked from the registry when the locking count falls
 * down to zero, thus waking up any thread currently blocked on
 * xnregistry_remove() for unregistering it.
 *
 * @param handle The generic handle of the object to unlock. If
 * XNOBJECT_SELF is passed, the object is the calling Xenomai thread.
 *
 * @return The decremented lock count is returned upon success. Zero
 * is also returned if @a handle does not reference a registered
 * object, or if @a handle is equal to XNOBJECT_SELF but the current
 * context is not a real-time thread.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * only if @a handle is different from XNOBJECT_SELF.
 *
 * - Kernel-based thread
 *
 * Rescheduling: possible if the lock count falls down to zero and
 * some thread is currently waiting for the object to be unlocked.
 */

u_long xnregistry_put(xnhandle_t handle)
{
	xnobject_t *object;
	u_long newlock;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (handle == XNOBJECT_SELF) {
		if (!xnpod_primary_p()) {
			newlock = 0;
			goto unlock_and_exit;
		}

		handle = xnpod_current_thread()->registry.handle;
	}

	object = registry_validate(handle);

	if (!object) {
		newlock = 0;
		goto unlock_and_exit;
	}

	if ((newlock = object->safelock) > 0 &&
	    (newlock = --object->safelock) == 0 &&
	    xnsynch_nsleepers(&object->safesynch) > 0) {
		xnsynch_flush(&object->safesynch, 0);
		xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return newlock;
}

/**
 * @fn u_long xnregistry_fetch(xnhandle_t handle)
 * @brief Find a real-time object into the registry.
 *
 * This service retrieves an object from its handle into the registry
 * and returns the memory address of its descriptor.
 *
 * @param handle The generic handle of the object to fetch. If
 * XNOBJECT_SELF is passed, the object is the calling Xenomai thread.
 *
 * @return The memory address of the object's descriptor is returned
 * on success. Otherwise, NULL is returned if @a handle does not
 * reference a registered object, or if @a handle is equal to
 * XNOBJECT_SELF but the current context is not a real-time thread.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * only if @a handle is different from XNOBJECT_SELF.
 *
 * - Kernel-based thread
 *
 * Rescheduling: never.
 */

void *xnregistry_fetch(xnhandle_t handle)
{
	xnobject_t *object;
	void *objaddr;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (handle == XNOBJECT_SELF) {
		objaddr = xnpod_primary_p()? xnpod_current_thread() : NULL;
		goto unlock_and_exit;
	}

	object = registry_validate(handle);

	if (object)
		objaddr = object->objaddr;
	else
		objaddr = NULL;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return objaddr;
}

/*@}*/

EXPORT_SYMBOL(xnregistry_enter);
EXPORT_SYMBOL(xnregistry_bind);
EXPORT_SYMBOL(xnregistry_remove);
EXPORT_SYMBOL(xnregistry_remove_safe);
EXPORT_SYMBOL(xnregistry_get);
EXPORT_SYMBOL(xnregistry_fetch);
EXPORT_SYMBOL(xnregistry_put);
