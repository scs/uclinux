/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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
 * @addtogroup posix_cond
 *
 *@{*/

#include <posix/internal.h>

static pthread_condattr_t default_cond_attr = {

      magic:PSE51_COND_ATTR_MAGIC,
      clock:CLOCK_REALTIME
};

/**
 * Initialize a condition variable attributes object.
 *
 * This services initializes the condition variable attributes object @a attr
 * with default values for all attributes. Default value are:
 * - for the @a clock attribute, @a CLOCK_REALTIME;
 * - for the @a pshared attribute @a PTHREAD_PROCESS_PRIVATE.
 *
 * If this service is called specifying a condition variable attributes object
 * that was already initialized, the attributes object is reinitialized.
 *
 * @param attr the condition variable attributes object to be initialized.
 *
 * @return 0 on success;
 * @return an error number if:
 * - ENOMEM, the condition variable attribute object pointer @a attr is @a
 *   NULL.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_condattr_init.html">
 * Specification.</a>
 * 
 */
int pthread_condattr_init(pthread_condattr_t * attr)
{
	if (!attr)
		return ENOMEM;

	*attr = default_cond_attr;

	return 0;
}

/**
 * Destroy a condition variable attributes object.
 *
 * This service destroys the condition variable attributes object @a attr. The
 * object becomes invalid for all condition variable services (they all return
 * EINVAL) except pthread_condattr_init().
 *
 * @param attr the initialized mutex attributes object to be destroyed.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, the mutex attributes object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_condattr_destroy.html">
 * Specification.</a>
 * 
 */
int pthread_condattr_destroy(pthread_condattr_t * attr)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_COND_ATTR_MAGIC, pthread_condattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	pse51_mark_deleted(attr);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get the clock selection attribute from a condition variable attributes
 * object.
 *
 * This service stores, at the address @a clk_id, the value of the @a clock
 * attribute in the condition variable attributes object @a attr.
 *
 * See pthread_cond_timedwait() documentation for a description of the effect of
 * this attribute on a condition variable. The clock ID returned is @a
 * CLOCK_REALTIME or @a CLOCK_MONOTONIC.
 *
 * @param attr an initialized condition variable attributes object,
 *
 * @param clk_id address where the @a clock attribute value will be stored on
 * success.
 *
 * @return 0 on success,
 * @return an error number if:
 * - EINVAL, the attribute object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_condattr_getclock.html">
 * Specification.</a>
 * 
 */
int pthread_condattr_getclock(const pthread_condattr_t * attr,
			      clockid_t * clk_id)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_COND_ATTR_MAGIC, pthread_condattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*clk_id = attr->clock;
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the clock selection attribute of a condition variable attributes object.
 *
 * This service set the @a clock attribute of the condition variable attributes
 * object @a attr.
 *
 * See pthread_cond_timedwait() documentation for a description of the effect
 * of this attribute on a condition variable.
 *
 * @param attr an initialized condition variable attributes object,
 *
 * @param clk_id value of the @a clock attribute, may be @a CLOCK_REALTIME or @a
 * CLOCK_MONOTONIC.
 *
 * @return 0 on success,
 * @return an error number if:
 * - EINVAL, the condition variable attributes object @a attr is invalid;
 * - EINVAL, the value of @a clk_id is invalid for the @a clock attribute.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_condattr_setclock.html">
 * Specification.</a>
 * 
 */
int pthread_condattr_setclock(pthread_condattr_t * attr, clockid_t clk_id)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_COND_ATTR_MAGIC, pthread_condattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	switch (clk_id) {
	default:

		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;

	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
		break;
	}

	attr->clock = clk_id;
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get the process-shared attribute from a condition variable attributes
 * object.
 *
 * This service stores, at the address @a pshared, the value of the @a pshared
 * attribute in the condition variable attributes object @a attr.
 *
 * The @a pshared attribute may only be one of @a PTHREAD_PROCESS_PRIVATE or @a
 * PTHREAD_PROCESS_SHARED. See pthread_condattr_setpshared() for the meaning of
 * these two constants.
 *
 * @param attr an initialized condition variable attributes object.
 *
 * @param pshared address where the value of the @a pshared attribute will be
 * stored on success.
 *
 * @return 0 on success,
 * @return an error number if:
 * - EINVAL, the @a pshared address is invalid;
 * - EINVAL, the condition variable attributes object @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_condattr_getpshared.html">
 * Specification.</a>
 * 
 */
int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared)
{
	spl_t s;

	if (!pshared || !attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_COND_ATTR_MAGIC,pthread_condattr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*pshared = attr->pshared;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the process-shared attribute of a condition variable attributes object.
 *
 * This service set the @a pshared attribute of the condition variable
 * attributes object @a attr.
 *
 * @param attr an initialized condition variable attributes object.
 *
 * @param pshared value of the @a pshared attribute, may be one of:
 * - PTHREAD_PROCESS_PRIVATE, meaning that a condition variable created with the
 *   attributes object @a attr will only be accessible by threads within the
 *   same process as the thread that initialized the condition variable;
 * - PTHREAD_PROCESS_SHARED, meaning that a condition variable created with the
 *   attributes object @a attr will be accessible by any thread that has access
 *   to the memory where the condition variable is allocated.
 *
 * @return 0 on success,
 * @return an error status if:
 * - EINVAL, the condition variable attributes object @a attr is invalid;
 * - EINVAL, the value of @a pshared is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_condattr_setpshared.html">
 * Specification.</a>
 * 
 */
int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared)
{
	spl_t s;

	if (!attr)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr,PSE51_COND_ATTR_MAGIC,pthread_condattr_t)) {
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

EXPORT_SYMBOL(pthread_condattr_init);
EXPORT_SYMBOL(pthread_condattr_destroy);
EXPORT_SYMBOL(pthread_condattr_getclock);
EXPORT_SYMBOL(pthread_condattr_setclock);
EXPORT_SYMBOL(pthread_condattr_getpshared);
EXPORT_SYMBOL(pthread_condattr_setpshared);
