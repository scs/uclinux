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
 * @addtogroup posix_mutex
 *
 *@{*/

#include <posix/internal.h>

static const pthread_mutexattr_t default_mutex_attr = {
	magic: PSE51_MUTEX_ATTR_MAGIC,
	type: PTHREAD_MUTEX_NORMAL,
	protocol: PTHREAD_PRIO_NONE,
	pshared: PTHREAD_PROCESS_PRIVATE
};

/**
 * Initialize a mutex attributes object.
 *
 * This services initializes the mutex attributes object @a attr with default
 * values for all attributes. Default value are :
 * - for the @a type attribute, @a PTHREAD_MUTEX_NORMAL;
 * - for the @a protocol attribute, @a PTHREAD_PRIO_NONE;
 * - for the @a pshared attribute, @a PTHREAD_PROCESS_PRIVATE.
 *
 * If this service is called specifying a mutex attributes object that was
 * already initialized, the attributes object is reinitialized.
 *
 * @param attr the mutex attributes object to be initialized.
 *
 * @return 0 on success;
 * @return an error number if:
 * - ENOMEM, the mutex attributes object pointer @a attr is @a NULL.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_init.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_init(pthread_mutexattr_t * attr)
{
	if (!attr)
		return ENOMEM;

	*attr = default_mutex_attr;

	return 0;
}

/**
 * Destroy a mutex attributes object.
 *
 * This service destroys the mutex attributes object @a attr. The object becomes
 * invalid for all mutex services (they all return EINVAL) except
 * pthread_mutexattr_init().
 *
 * @param attr the initialized mutex attributes object to be destroyed.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, the mutex attributes object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_destroy.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_destroy(pthread_mutexattr_t * attr)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	pse51_mark_deleted(attr);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get the mutex type attribute from a mutex attributes object.
 *
 * This service stores, at the address @a type, the value of the @a type
 * attribute in the mutex attributes object @a attr.
 *
 * See pthread_mutex_lock() and pthread_mutex_unlock() documentations for a
 * description of the values of the @a type attribute and their effect on a
 * mutex.
 *
 * @param attr an initialized mutex attributes object,
 *
 * @param type address where the @a type attribute value will be stored on
 * success.
 *
 * @return 0 on sucess,
 * @return an error number if:
 * - EINVAL, the @a type address is invalid;
 * - EINVAL, the mutex attributes object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_gettype.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_gettype(const pthread_mutexattr_t * attr, int *type)
{
	spl_t s;

	if (!type || !attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*type = attr->type;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the mutex type attribute of a mutex attributes object.
 *
 * This service set the @a type attribute of the mutex attributes object
 * @a attr.
 *
 * See pthread_mutex_lock() and pthread_mutex_unlock() documentations for a
 * description of the values of the @a type attribute and their effect on a
 * mutex.
 *
 * The @a PTHREAD_MUTEX_DEFAULT default @a type is the same as @a
 * PTHREAD_MUTEX_NORMAL. Note that using a Xenomai POSIX skin recursive mutex
 * with a Xenomai POSIX skin condition variable is safe (see pthread_cond_wait()
 * documentation).
 *
 * @param attr an initialized mutex attributes object,
 *
 * @param type value of the @a type attribute. 
 *
 * @return 0 on success,
 * @return an error number if:
 * - EINVAL, the mutex attributes object @a attr is invalid;
 * - EINVAL, the value of @a type is invalid for the @a type attribute.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_settype.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_settype(pthread_mutexattr_t * attr, int type)
{
	spl_t s;

	if (!attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	switch (type) {
	default:

		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;

	case PTHREAD_MUTEX_NORMAL:
	case PTHREAD_MUTEX_RECURSIVE:
	case PTHREAD_MUTEX_ERRORCHECK:
		break;
	}

	attr->type = type;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get the protocol attribute from a mutex attributes object.
 *
 * This service stores, at the address @a proto, the value of the @a protocol
 * attribute in the mutex attributes object @a attr.
 *
 * The @a protcol attribute may only be one of @a PTHREAD_PRIO_NONE or @a
 * PTHREAD_PRIO_INHERIT. See pthread_mutexattr_setprotocol() for the meaning of
 * these two constants.
 *
 * @param attr an initialized mutex attributes object;
 *
 * @param proto address where the value of the @a protocol attribute will be
 * stored on success.
 *
 * @return 0 on success,
 * @return an error number if:
 * - EINVAL, the @a proto address is invalid;
 * - EINVAL, the mutex attributes object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_getprotocol.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t * attr, int *proto)
{
	spl_t s;

	if (!proto || !attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*proto = attr->protocol;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the protocol attribute of a mutex attributes object.
 *
 * This service set the @a type attribute of the mutex attributes object
 * @a attr.
 *
 * @param attr an initialized mutex attributes object,
 *
 * @param proto value of the @a protocol attribute, may be one of:
 * - PTHREAD_PRIO_NONE, meaning that a mutex created with the attributes object
 *   @a attr will not follow any priority protocol;
 * - PTHREAD_PRIO_INHERIT, meaning that a mutex created with the attributes
 *   object @a attr, will follow the priority inheritance protocol.
 *
 * The value PTHREAD_PRIO_PROTECT (priority ceiling protocol) is unsupported.
 *
 * @return 0 on success,
 * @return an error number if:
 * - EINVAL, the mutex attributes object @a attr is invalid;
 * - ENOTSUP, the value of @a proto is unsupported;
 * - EINVAL, the value of @a proto is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_setprotocol.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_setprotocol(pthread_mutexattr_t * attr, int proto)
{
	spl_t s;

	if (!attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	switch (proto) {
	default:

		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;

	case PTHREAD_PRIO_PROTECT:

		xnlock_put_irqrestore(&nklock, s);
		return ENOTSUP;

	case PTHREAD_PRIO_NONE:
	case PTHREAD_PRIO_INHERIT:
		break;
	}

	attr->protocol = proto;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get the process-shared attribute of a mutex attributes object.
 *
 * This service stores, at the address @a pshared, the value of the @a pshared
 * attribute in the mutex attributes object @a attr.
 *
 * The @a pashared attribute may only be one of @a PTHREAD_PROCESS_PRIVATE or
 * @a PTHREAD_PROCESS_SHARED. See pthread_mutexattr_setpshared() for the meaning
 * of these two constants.
 *
 * @param attr an initialized mutex attributes object;
 *
 * @param pshared address where the value of the @a pshared attribute will be
 * stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, the @a pshared address is invalid;
 * - EINVAL, the mutex attributes object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_getpshared.html">
 * Specification.</a>
 *
 */
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared)
{
	spl_t s;

	if (!pshared || !attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*pshared = attr->pshared;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the process-shared attribute of a mutex attributes object.
 *
 * This service set the @a pshared attribute of the mutex attributes object @a
 * attr.
 *
 * @param attr an initialized mutex attributes object.
 *
 * @param pshared value of the @a pshared attribute, may be one of:
 * - PTHREAD_PROCESS_PRIVATE, meaning that a mutex created with the attributes
 *   object @a attr will only be accessible by threads within the same process
 *   as the thread that initialized the mutex;
 * - PTHREAD_PROCESS_SHARED, meaning that a mutex created with the attributes
 *   object @a attr will be accessible by any thread that has access to the
 *   memory where the mutex is allocated.
 *
 * @return 0 on success,
 * @return an error status if:
 * - EINVAL, the mutex attributes object @a attr is invalid;
 * - EINVAL, the value of @a pshared is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_mutexattr_setpshared.html">
 * Specification.</a>
 * 
 */
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared)
{
	spl_t s;

	if (!attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_MUTEX_ATTR_MAGIC,pthread_mutexattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	switch (pshared) {
	default:
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;

	case PTHREAD_PROCESS_PRIVATE:
	case PTHREAD_PROCESS_SHARED:
		break;
	}

	attr->pshared = pshared;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}


/*@}*/

EXPORT_SYMBOL(pthread_mutexattr_init);
EXPORT_SYMBOL(pthread_mutexattr_destroy);
EXPORT_SYMBOL(pthread_mutexattr_gettype);
EXPORT_SYMBOL(pthread_mutexattr_settype);
EXPORT_SYMBOL(pthread_mutexattr_getprotocol);
EXPORT_SYMBOL(pthread_mutexattr_setprotocol);
EXPORT_SYMBOL(pthread_mutexattr_getpshared);
EXPORT_SYMBOL(pthread_mutexattr_setpshared);
