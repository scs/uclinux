/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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

/**
 * @ingroup posix
 * @defgroup posix_tsd Thread-specific data.
 *
 * Thread-specific data.
 *
 * Programs often need global or static variables that have different values in
 * different threads. Since threads share one memory space, this cannot be
 * achieved with regular variables. Thread-specific data is the POSIX threads
 * answer to this need.
 *
 * Each thread possesses a private memory block, the thread-specific data area,
 * or TSD area for short. This area is indexed by TSD keys. The TSD area
 * associates values of type `void *' to TSD keys. TSD keys are common to all
 * threads, but the value associated with a given TSD key can be different in
 * each thread.
 *
 * When a thread is created, its TSD area initially associates @a NULL with all
 * keys.
 *
 * The services documented here are valid in kernel-space context; when called
 * in user-space, the underlying Linux threading library (LinuxThreads or NPTL)
 * services are used.
 *
 *@{*/

#include <posix/thread.h>
#include <posix/tsd.h>

typedef void pse51_key_destructor_t(void *);

struct pse51_key {

	unsigned magic;
	unsigned key;
	pse51_key_destructor_t *destructor;
	xnholder_t link;	/* link in the list of free keys or
				   valid keys. */
#define link2key(laddr) ({                                              \
        void *_laddr = laddr;                                           \
        (!_laddr                                                        \
         ? NULL :                                                       \
         ((pthread_key_t) (((void *)_laddr) - offsetof(struct pse51_key, \
                                                       link))));        \
})

};

static xnqueue_t free_keys, valid_keys;

static unsigned allocated_keys;

/**
 * Create a thread-specific data key.
 *
 * This service create a TSD key. The NULL value is associated for all threads
 * with the new key and the new key is returned at the address @a key. If @a
 * destructor is not null, it is executed when a thread is terminated as long as
 * the datum associated with the key is not NULL, up to
 * PTHREAD_DESTRUCTOR_ITERATIONS times.
 *
 * @param key address where the new key will be stored on success;
 *
 * @param destructor function to be invoked when a thread terminates and has a
 * non NULL value associated with the new key.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EAGAIN, the total number of keys PTHREAD_KEYS_MAX TSD has been exceeded;
 * - ENOMEM, insufficient memory exists in the system heap to create a new key,
 *   increase CONFIG_XENO_OPT_SYS_HEAPSZ.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_key_create.html">
 * Specification.</a>
 * 
 */
int pthread_key_create(pthread_key_t *key, void (*destructor) (void *))
{
	pthread_key_t result;
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (allocated_keys < PTHREAD_KEYS_MAX) {
		xnlock_put_irqrestore(&nklock, s);

		result = xnmalloc(sizeof(*result));
		if (!result)
			return ENOMEM;

		xnlock_get_irqsave(&nklock, s);
		if (allocated_keys == PTHREAD_KEYS_MAX) {
			xnlock_put_irqrestore(&nklock, s);
			xnfree(result);
			xnlock_get_irqsave(&nklock, s);
			goto all_allocated;
		}

		result->key = allocated_keys++;
	} else {
	  all_allocated:

		result = link2key(getq(&free_keys));
		if (!result) {
			xnlock_put_irqrestore(&nklock, s);
			return EAGAIN;
		}

		/* We are reusing a deleted key, we hence need to make sure
		   that the values previously associated with this key are
		   NULL. We only check the global threads queue, because
		   user-space threads do not use these TSD services. */

		for (holder = getheadq(&pse51_global_kqueues.threadq); holder;
		     holder = nextq(&pse51_global_kqueues.threadq, holder))
			thread_settsd(link2pthread(holder), result->key, NULL);
	}

	result->magic = PSE51_KEY_MAGIC;
	result->destructor = destructor;
	inith(&result->link);
	prependq(&valid_keys, &result->link);

	*key = result;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Associate a thread-specific value with the specified key.
 *
 * This service associates, for the calling thread, the value @a value to the
 * key @a key.
 *
 * @param key TSD key, obtained with pthread_key_create();
 *
 * @param value value.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EPERM, the caller context is invalid;
 * - EINVAL, @a key is invalid.
 * 
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_setspecific.html">
 * Specification.</a>
 * 
 */
int pthread_setspecific(pthread_key_t key, const void *value)
{
	pthread_t cur = pse51_current_thread();
	spl_t s;

	if (!cur)
		return EPERM;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(key, PSE51_KEY_MAGIC, struct pse51_key)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	xnlock_put_irqrestore(&nklock, s);

	thread_settsd(cur, key->key, value);

	return 0;
}

/**
 * Get the thread-specific value bound to the specified key.
 *
 * This service returns the value associated, for the calling thread, with the
 * key @a key.
 *
 * @param key TSD key, obtained with pthread_key_create().
 *
 * @return the value associated with @a key;
 * @return NULL if the context is invalid.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_getspecific.html">
 * Specification.</a>
 * 
 */
void *pthread_getspecific(pthread_key_t key)
{
	pthread_t cur = pse51_current_thread();
	const void *value;
	spl_t s;

	if (!cur)
		return NULL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(key, PSE51_KEY_MAGIC, struct pse51_key)) {
		xnlock_put_irqrestore(&nklock, s);
		return NULL;
	}

	xnlock_put_irqrestore(&nklock, s);

	value = thread_gettsd(cur, key->key);

	return (void *)value;
}

/**
 * Delete a thread-specific data key.
 *
 * This service deletes the TSD key @a key. Note that the key destructor
 * function is not called, so, if any thread has a value associated with @a key
 * that is a pointer to dynamically allocated memory, the application has to
 * manage to free that memory by other means.
 *
 * @param key the TSD key to be destroyed.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a key is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_key_delete.html">
 * Specification.</a>
 * 
 */
int pthread_key_delete(pthread_key_t key)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(key, PSE51_KEY_MAGIC, struct pse51_key)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	pse51_mark_deleted(key);
	removeq(&valid_keys, &key->link);
	inith(&key->link);
	appendq(&free_keys, &key->link);

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

void pse51_tsd_init_thread(pthread_t thread)
{
	unsigned key;

	for (key = 0; key < PTHREAD_KEYS_MAX; key++)
		thread_settsd(thread, key, NULL);
}

void pse51_tsd_cleanup_thread(pthread_t thread)
{
	int i, again = 1;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	for (i = 0; again && i < PTHREAD_DESTRUCTOR_ITERATIONS; i++) {
		xnholder_t *holder = getheadq(&valid_keys);

		again = 0;

		while (holder) {
			pthread_key_t key = link2key(holder);
			const void *value;

			if (!pse51_obj_active
			    (key, PSE51_KEY_MAGIC, struct pse51_key)) {
				/* A destructor destroyed this key. */
				again = 1;
				break;
			}

			holder = nextq(&valid_keys, holder);
			value = thread_gettsd(thread, key->key);

			if (value) {
				thread_settsd(thread, key->key, NULL);

				if (key->destructor) {
					again = 1;
					xnlock_put_irqrestore(&nklock, s);
					key->destructor((void *)value);
					xnlock_get_irqsave(&nklock, s);
				}
			}
		}
	}

	xnlock_put_irqrestore(&nklock, s);
}

void pse51_tsd_pkg_init(void)
{
	initq(&free_keys);
	initq(&valid_keys);
}

void pse51_tsd_pkg_cleanup(void)
{
	pthread_key_t key;

	while ((key = link2key(getq(&valid_keys))) != NULL) {
		pse51_mark_deleted(key);
		xnfree(key);
	}

	while ((key = link2key(getq(&free_keys))) != NULL)
		xnfree(key);
}

/*@}*/

EXPORT_SYMBOL(pthread_key_create);
EXPORT_SYMBOL(pthread_key_delete);
EXPORT_SYMBOL(pthread_getspecific);
EXPORT_SYMBOL(pthread_setspecific);
